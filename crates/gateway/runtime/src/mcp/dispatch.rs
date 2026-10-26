//! Protocol-owned final checks. These are mandatory hooks in the Host dispatch path,
//! separate from admission and from execution-budget reservation.
use super::session_security::{reverse::ResponseTicket, tasks::Ticket};
#[cfg(feature = "gateway-llm")]
use crate::proxy::model_execution::Call as ModelCall;
use crate::{http::Request, proxy::ProxyError, store::BackendPolicies};

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
