//! Protocol-owned final checks. These are mandatory hooks in the Host dispatch path,
//! separate from admission and from execution-budget reservation.
use super::session_security::{reverse::ResponseTicket, tasks::Ticket};
#[cfg(feature = "gateway-llm")]
use crate::proxy::model_execution::Call as ModelCall;
use crate::{http::Request, proxy::ProxyError, store::BackendPolicies};

/// Local state only: an awaited authorization result cannot outlive its request/session.
pub(crate) fn current<B>(request: &::http::Request<B>) -> Result<(), ProxyError> {
	if request
		.extensions()
		.get::<super::upstream::IssuedCapability>()
		.is_some_and(|grant| grant.expires_at <= chrono::Utc::now())
	{
		return Err(ProxyError::AuthorizationFailed);
	}
	if request
		.extensions()
		.get::<gateway_contracts::ConfigLease>()
		.is_some_and(|r| !r.is_current())
		|| request
			.extensions()
			.get::<crate::http::jwt::Claims>()
			.and_then(|c| c.inner.get("exp"))
			.and_then(serde_json::Value::as_i64)
			.is_some_and(|exp| exp <= chrono::Utc::now().timestamp())
	{
		return Err(ProxyError::AuthorizationFailed);
	}
	if let Some(access) = request
		.extensions()
		.get::<super::session_security::SessionAccess>()
	{
		access.current()?;
	}
	if let Some(flow) = request
		.extensions()
		.get::<crate::security_flow::FlowAccess>()
	{
		flow.current()?;
	}
	if let Some(error) = request
		.extensions()
		.get::<crate::execution_budget::ExecutionScope>()
		.and_then(|scope| scope.failure())
	{
		return Err(error);
	}
	Ok(())
}

/// Stop waiting on remote authorization when the trusted request lifecycle ends. The worker
/// retains its admission slot until completion; no result is published from this future on error.
pub(crate) async fn authorize<T>(
	request: ::http::Request<()>,
	action: &security_types::ActionRequest,
	future: impl std::future::Future<Output = Result<T, security_pipeline::GatewayError>>,
) -> Result<Result<T, security_pipeline::GatewayError>, ProxyError> {
	current(&request).inspect_err(|_| {
		super::session_security::deny(action, "request-lifecycle");
	})?;
	let mut revision = request
		.extensions()
		.get::<gateway_contracts::ConfigLease>()
		.cloned();
	let expires = request
		.extensions()
		.get::<crate::http::jwt::Claims>()
		.and_then(|c| c.inner.get("exp"))
		.and_then(serde_json::Value::as_i64);
	let changed = async {
		match &mut revision {
			Some(revision) => revision.changed().await,
			None => std::future::pending().await,
		}
	};
	let expired = async {
		match expires {
			Some(expires) => {
				match tokio::time::Instant::now().checked_add(std::time::Duration::from_millis(
					expires
						.saturating_mul(1000)
						.saturating_sub(chrono::Utc::now().timestamp_millis())
						.max(0) as u64,
				)) {
					Some(deadline) => tokio::time::sleep_until(deadline).await,
					None => std::future::pending().await,
				}
			},
			None => std::future::pending().await,
		}
	};
	let work = async {
		if let Some(scope) = request
			.extensions()
			.get::<crate::execution_budget::ExecutionScope>()
		{
			scope.run_for(action, future).await
		} else {
			Ok(future.await)
		}
	};
	tokio::select! {
		biased;
		_ = changed => Err(super::session_security::deny(action, "config-changed")),
		_ = expired => Err(super::session_security::deny(action, "credential-expired")),
		result = work => {
			current(&request).inspect_err(|_| { super::session_security::deny(action, "request-lifecycle"); })?;
			result
		}
	}
}

pub(crate) fn is_model_call(request: &Request) -> bool {
	#[cfg(feature = "gateway-llm")]
	return request.extensions().get::<ModelCall>().is_some();
	#[cfg(not(feature = "gateway-llm"))]
	{
		let _ = request;
		false
	}
}

pub(crate) async fn verify(
	request: &mut Request,
	_policies: &BackendPolicies,
) -> Result<(), ProxyError> {
	if let Some(ticket) = request.extensions().get::<Ticket>().cloned() {
		Box::pin(ticket.verify_dispatch(request)).await?;
	}
	if let Some(ticket) = request.extensions().get::<ResponseTicket>().cloned() {
		Box::pin(ticket.verify_dispatch(request)).await?;
	}
	#[cfg(feature = "gateway-llm")]
	if let Some(call) = request.extensions().get::<ModelCall>().cloned() {
		Box::pin(call.verify(request, _policies)).await?;
	}
	Ok(())
}

pub(crate) fn before_send(request: &Request) -> Result<(), ProxyError> {
	current(request)?;
	if let Some(ticket) = request.extensions().get::<Ticket>() {
		ticket.before_send()?;
	}
	if let Some(ticket) = request.extensions().get::<ResponseTicket>() {
		ticket.before_send()?;
	}
	#[cfg(feature = "gateway-llm")]
	if let Some(call) = request.extensions().get::<ModelCall>() {
		call.before_send()?;
	}
	Ok(())
}
