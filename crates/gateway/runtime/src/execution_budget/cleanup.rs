//! Explicit cleanup mode on the original A2A RPC route, not an inactive workflow bypass.
use super::*;
use security_integration_runtime::task_cleanup::{CleanupLedger, CleanupResult};
use serde::Deserialize;

pub(crate) const HEADER: &str = "x-aisp-task-cleanup";
#[derive(Clone)]
pub(crate) struct CleanupScope {
	handle: ExecutionHandle,
	fingerprint: String,
	task: String,
	rpc_id: String,
	deadline: Instant,
	action: Arc<ActionRequest>,
	owner: VerifiedOwner,
	revision: crate::a2a::revision::ConfigLease,
	expires: i64,
}
impl std::fmt::Debug for CleanupScope {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.debug_struct("CleanupScope")
			.field("execution_hash", &crate::security::digest(self.handle.id()))
			.finish_non_exhaustive()
	}
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Input {
	jsonrpc: String,
	id: serde_json::Value,
	method: String,
	params: Params,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Params {
	id: String,
}

pub(crate) async fn prepare(
	config: &SecurityConfig,
	request: &mut Request,
) -> Result<(), ProxyError> {
	if request.method() != ::http::Method::POST
		|| request.headers().contains_key(::http::header::UPGRADE)
		|| request
			.headers()
			.contains_key(::http::header::CONTENT_ENCODING)
		|| request.headers().get_all(HEADER).iter().count() != 1
		|| request.headers().get(HEADER).is_none_or(|h| h != "cancel")
		|| request.extensions().get::<ExecutionScope>().is_some()
		|| config.a2a_objects.is_none()
		|| is_control_path(request.uri().path())
	{
		return Err(ProxyError::AuthorizationFailed);
	}
	let budget = config
		.execution_budget
		.as_ref()
		.ok_or(ProxyError::AuthorizationFailed)?;
	let cleanup = budget
		.task_cleanup
		.clone()
		.ok_or(ProxyError::AuthorizationFailed)?;
	crate::security::request_id(request.extensions_mut());
	let action = operation(request, "execution/task/cancel", &budget.namespace);
	crate::security::evaluate(config, &action).map_err(|_| ProxyError::AuthorizationFailed)?;
	let fingerprint = fingerprint(config).map_err(ProxyError::ExecutionBudget)?;
	let owner = owner(request).map_err(ProxyError::ExecutionBudget)?;
	let ids = request
		.headers()
		.get_all(super::HEADER)
		.iter()
		.collect::<Vec<_>>();
	if ids.len() != 1 {
		return Err(ProxyError::AuthorizationFailed);
	}
	let id = ids[0]
		.to_str()
		.ok()
		.filter(|id| !id.is_empty() && id.len() <= 128)
		.ok_or(ProxyError::AuthorizationFailed)?;
	let handle = store(budget)
		.map_err(ProxyError::ExecutionBudget)?
		.resolve_for_control(id, budget, &owner, &fingerprint)
		.map_err(|error| {
			audit(&action, Err(error), Some(id));
			ProxyError::ExecutionBudget(error)
		})?;
	let claims = request
		.extensions()
		.get::<crate::http::jwt::Claims>()
		.ok_or(ProxyError::AuthorizationFailed)?;
	let expires = claims
		.inner
		.get("exp")
		.and_then(|v| v.as_i64())
		.ok_or(ProxyError::AuthorizationFailed)?;
	let revision = request
		.extensions()
		.get::<crate::a2a::revision::ConfigLease>()
		.cloned()
		.ok_or(ProxyError::AuthorizationFailed)?;
	handle.cleanup().map_err(ProxyError::ExecutionBudget)?;
	let deadline = (Instant::now() + std::time::Duration::from_secs(cleanup.timeout_seconds)).min(
		handle
			.cleanup_deadline()
			.map_err(ProxyError::ExecutionBudget)?,
	);
	let bytes = tokio::time::timeout_at(
		deadline.into(),
		http::read_body_with_limit(
			std::mem::replace(request.body_mut(), http::Body::empty()),
			8192,
		),
	)
	.await
	.map_err(|_| ProxyError::RequestTimeout)?
	.map_err(|_| ProxyError::InvalidRequest)?;
	let input: Input = serde_json::from_slice(&bytes).map_err(|_| {
		audit(&action, Err(BudgetError::InvalidContext), Some(handle.id()));
		ProxyError::InvalidRequest
	})?;
	if input.jsonrpc != "2.0"
		|| input.method != "tasks/cancel"
		|| !(input.id.is_string() || input.id.is_number())
		|| input.params.id.is_empty()
		|| input.params.id.len() > 512
		|| input.params.id.trim() != input.params.id
	{
		audit(&action, Err(BudgetError::InvalidContext), Some(handle.id()));
		return Err(ProxyError::AuthorizationFailed);
	}
	let scope = CleanupScope {
		handle,
		fingerprint,
		task: input.params.id,
		rpc_id: uuid::Uuid::new_v4().to_string(),
		deadline,
		action: Arc::new(action),
		owner,
		revision,
		expires,
	};
	scope.check()?;
	*request.body_mut() = http::Body::from(scope.rpc().to_string());
	request.headers_mut().remove(super::HEADER);
	request.headers_mut().remove(HEADER);
	request.headers_mut().remove(INVOCATION_HEADER);
	request.headers_mut().remove(::http::header::CONTENT_LENGTH);
	request.headers_mut().insert(
		::http::header::CONTENT_TYPE,
		"application/json".parse().expect("static header"),
	);
	request.extensions_mut().insert(scope);
	Ok(())
}
impl CleanupScope {
	pub fn check(&self) -> Result<(), ProxyError> {
		if !self.revision.is_current() || self.expires <= chrono::Utc::now().timestamp() {
			return Err(ProxyError::AuthorizationFailed);
		}
		if Instant::now() >= self.deadline {
			return Err(ProxyError::ExecutionBudget(BudgetError::Deadline));
		}
		Ok(())
	}
	pub fn validate(&self, config: &SecurityConfig, request: &Request) -> Result<(), ProxyError> {
		self.check()?;
		if fingerprint(config).map_err(ProxyError::ExecutionBudget)? != self.fingerprint
			|| owner(request).map_err(ProxyError::ExecutionBudget)? != self.owner
			|| request.headers().contains_key(HEADER)
			|| request.headers().contains_key(super::HEADER)
		{
			return Err(ProxyError::AuthorizationFailed);
		}
		Ok(())
	}
	pub fn binding(&self) -> String {
		crate::security::digest(
			&serde_json::to_string(&(&self.fingerprint, self.handle.id())).expect("strings serialize"),
		)
	}
	pub fn task(&self) -> &str {
		&self.task
	}
	pub fn rpc_id(&self) -> &str {
		&self.rpc_id
	}
	pub fn rpc(&self) -> serde_json::Value {
		serde_json::json!({"jsonrpc":"2.0","id":self.rpc_id,"method":"tasks/cancel","params":{"id":self.task}})
	}
	pub fn ledger(&self) -> Result<Arc<dyn CleanupLedger>, ProxyError> {
		self.handle.cleanup().map_err(ProxyError::ExecutionBudget)
	}
	pub fn authorize(&self, config: &SecurityConfig) -> Result<(), ProxyError> {
		self.check()?;
		if fingerprint(config).map_err(ProxyError::ExecutionBudget)? != self.fingerprint {
			return Err(ProxyError::AuthorizationFailed);
		}
		crate::security::evaluate(config, &self.action).map_err(|_| ProxyError::AuthorizationFailed)
	}
	pub fn audit(&self, action: &ActionRequest, key: &str, phase: &str, success: bool) {
		audit_policy(
			action,
			if success {
				Ok(())
			} else {
				Err(BudgetError::InvalidContext)
			},
			format!(
				"task-cleanup:{phase}:{}:{}",
				crate::security::digest(self.handle.id()),
				crate::security::digest(key)
			),
		);
	}
	pub async fn run<F: std::future::Future>(&self, future: F) -> Result<F::Output, ProxyError> {
		self.check()?;
		let result = tokio::time::timeout_at(self.deadline.into(), future)
			.await
			.map_err(|_| {
				self.audit(&self.action, &self.task, "deadline", false);
				ProxyError::ExecutionBudget(BudgetError::Deadline)
			})?;
		self.check()?;
		Ok(result)
	}
	pub fn receipt(&self, result: CleanupResult) -> Response {
		::http::Response::builder()
			.status(200)
			.header("content-type", "application/json")
			.header("cache-control", "private, no-store")
			.body(http::Body::from(
				serde_json::json!({"requestId":self.action.request_id,"cleanup":result}).to_string(),
			))
			.expect("static response")
	}
}
