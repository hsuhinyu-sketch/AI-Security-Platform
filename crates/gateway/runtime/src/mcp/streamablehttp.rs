use std::sync::Arc;

use ::http::StatusCode;
pub(crate) use gateway_mcp::protocol::{
	RequestProtocol, emit_standard_headers, protocol_version_header,
};
use gateway_mcp::protocol::{
	check_session_protocol as reject_modern_session_request, request_protocol,
	validate_standard_headers,
};
use platform_core::prelude::AssertSize;
use rmcp::model::{ClientJsonRpcMessage, ClientNotification, ClientRequest, ServerJsonRpcMessage};
use rmcp::transport::common::http_header::{
	EVENT_STREAM_MIME_TYPE, HEADER_SESSION_ID, JSON_MIME_TYPE,
};

use crate::http::{DropBody, Request, Response};
use crate::mcp::handler::RelayInputs;
use crate::mcp::session::SessionManager;
use crate::proxy::ProxyError;
use crate::*;

#[derive(Debug, Clone)]
pub struct StreamableHttpServerConfig {
	/// If true, the server will create a session for each request and keep it alive.
	pub stateful_mode: bool,
}

#[derive(Debug, Clone)]
pub struct ServerSseMessage {
	pub event_id: Option<String>,
	pub message: Arc<ServerJsonRpcMessage>,
}

type BoxedSseStream =
	futures::stream::BoxStream<'static, Result<sse_stream::Sse, sse_stream::Error>>;
#[allow(clippy::large_enum_variant)]
pub enum StreamableHttpPostResponse {
	Accepted,
	Json(ServerJsonRpcMessage, Option<String>),
	Sse(BoxedSseStream, Option<String>),
}

impl std::fmt::Debug for StreamableHttpPostResponse {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		match self {
			Self::Accepted => write!(f, "Accepted"),
			Self::Json(arg0, arg1) => f.debug_tuple("Json").field(arg0).field(arg1).finish(),
			Self::Sse(_, arg1) => f.debug_tuple("Sse").field(arg1).finish(),
		}
	}
}
pub struct StreamableHttpService {
	config: StreamableHttpServerConfig,
	session_manager: Arc<SessionManager>,
}

impl StreamableHttpService {
	pub fn new(session_manager: Arc<SessionManager>, config: StreamableHttpServerConfig) -> Self {
		Self {
			config,
			session_manager,
		}
	}

	pub async fn handle(
		&self,
		request: Request,
		inputs: RelayInputs,
	) -> Result<Response, ProxyError> {
		let method = request.method().clone();

		match (method, self.config.stateful_mode) {
			(http::Method::POST, _) => {
				Box::pin(
					self
						.handle_post(request, inputs)
						.assert_size::<{ 4 * 1024 }>(),
				)
				.await
			},
			// if we're not in stateful mode, we don't support GET or DELETE because there is no session
			(http::Method::GET, true) => self.handle_get(request, inputs).await,
			(http::Method::DELETE, true) => self.handle_delete(request, inputs).await,
			_ => Err(ProxyError::MCP(mcp::Error::MethodNotAllowed)),
		}
	}

	pub async fn handle_post(
		&self,
		request: Request,
		inputs: RelayInputs,
	) -> Result<Response, ProxyError> {
		// check accept header
		if !request
			.headers()
			.get(http::header::ACCEPT)
			.and_then(|header| header.to_str().ok())
			.is_some_and(|header| {
				header.contains(JSON_MIME_TYPE) && header.contains(EVENT_STREAM_MIME_TYPE)
			}) {
			return mcp::Error::InvalidAccept.into();
		}

		// check content type
		if !request
			.headers()
			.get(http::header::CONTENT_TYPE)
			.and_then(|header| header.to_str().ok())
			.is_some_and(|header| header.starts_with(JSON_MIME_TYPE))
		{
			return mcp::Error::InvalidContentType.into();
		}

		let limit = inputs
			.security_audit
			.as_ref()
			.and_then(|c| c.mcp_sessions.as_ref())
			.map_or_else(
				|| http::buffer_limit(&request),
				|c| c.max_message_bytes.min(http::buffer_limit(&request)),
			);
		let (mut part, body) = request.into_parts();
		let message = match json::from_body_with_limit::<ClientJsonRpcMessage>(body, limit).await {
			Ok(b) => b,
			Err(e) => return mcp::Error::Deserialize(e).into(),
		};
		let request_id = gateway_mcp::protocol::request_id(&message);
		let protocol = request_protocol(&part.headers, &message, request_id.clone())?;
		validate_standard_headers(&part.headers, &message, &protocol)?;
		part.extensions.insert(protocol.clone());
		let header_session = part
			.headers
			.get(HEADER_SESSION_ID)
			.and_then(|v| v.to_str().ok())
			.map(str::to_owned);
		let operation = if header_session.is_some() {
			"use"
		} else if matches!(&message, ClientJsonRpcMessage::Request(r) if matches!(r.request, ClientRequest::InitializeRequest(_)))
			&& self.config.stateful_mode
			&& protocol.uses_sessions()
		{
			"create"
		} else {
			"use"
		};
		let mut access = super::session_security::SessionAccess::prepare(
			&mut part,
			&inputs,
			&self.session_manager,
			operation,
			header_session.as_deref(),
		)?;
		if let Some(access) = &access {
			if part.headers.contains_key("last-event-id")
				|| (!self.config.stateful_mode && header_session.is_some())
			{
				return Err(access.denial("unsupported-replay"));
			}
			let supported = match &message {
				ClientJsonRpcMessage::Request(r) => {
					let method = r.request.method().to_string();
					matches!(
						method.as_str(),
						"initialize"
							| "server/discover"
							| "ping"
							| "tools/list"
							| "tools/call"
							| "resources/list"
							| "resources/templates/list"
							| "resources/read"
							| "resources/subscribe"
							| "resources/unsubscribe"
							| "prompts/list"
							| "prompts/get"
							| "tasks/get"
							| "tasks/result"
							| "tasks/cancel"
					) && !(header_session.is_some() && method == "initialize")
						&& (!matches!(&r.request, ClientRequest::CallToolRequest(call) if call.params.task.is_some())
							|| (access.limits.tasks.is_some()
								&& header_session.is_some()
								&& protocol.uses_sessions()))
						&& (!method.starts_with("tasks/")
							|| (access.limits.tasks.is_some()
								&& header_session.is_some()
								&& protocol.uses_sessions()))
				},
				ClientJsonRpcMessage::Notification(n) => {
					matches!(
						n.notification,
						ClientNotification::InitializedNotification(_)
					) || (access.limits.reverse.is_some()
						&& header_session.is_some()
						&& matches!(n.notification, ClientNotification::CancelledNotification(_)))
				},
				ClientJsonRpcMessage::Response(_) | ClientJsonRpcMessage::Error(_) => {
					access.limits.reverse.is_some() && header_session.is_some()
				},
			};
			if !supported {
				return Err(access.denial("unsupported-client-message"));
			}
			if matches!(&message, ClientJsonRpcMessage::Request(r) if matches!(r.request, ClientRequest::SubscribeRequest(_) | ClientRequest::UnsubscribeRequest(_)))
				&& (!self.config.stateful_mode || header_session.is_none() || !protocol.uses_sessions())
			{
				return Err(access.denial("subscription-requires-session"));
			}
			access.install(&mut part);
		}

		if !self.config.stateful_mode {
			let relay = inputs.build_new_connections()?;
			// Use stateless session - not registered in session manager
			let mut session = self.session_manager.create_stateless_session(relay);
			let send: futures_util::future::BoxFuture<'_, Result<Response, ProxyError>> =
				if protocol.uses_sessions() {
					Box::pin(session.stateless_send_and_initialize(part.clone(), message))
				} else {
					// The deployment's statefulMode must not change the protocol era.
					Box::pin(session.send(part.clone(), message))
				};
			let response = match &access {
				Some(a) => a.call(send).await,
				None => send.await,
			};

			let (tx, rx) = tokio::sync::oneshot::channel::<()>();
			// Clean up upstream resources (e.g., stdio processes)
			tokio::task::spawn(async move {
				// Wait until the response is actually completed.
				let _ = rx.await;
				trace!("cleaning up stateless session");
				let _ = session.delete_session(part).await;
			});
			return response
				.map(|r| r.map(|b| DropBody::new(b, tx)))
				.and_then(|r| match &access {
					Some(a) => a.protect_response(r),
					None => Ok(r),
				});
		}

		let session_id = part
			.headers
			.get(HEADER_SESSION_ID)
			.and_then(|v| v.to_str().ok());

		if let Some(session_id) = session_id {
			if !protocol.uses_sessions() {
				return mcp::Error::InvalidSessionIdHeader.into();
			}
			if let Some(access) = &mut access {
				let mut session = self
					.session_manager
					.get_protected(session_id, inputs, access)?;
				access.install(&mut part);
				let response = access.call(Box::pin(session.send(part, message))).await?;
				return access.protect_response(response);
			}
			let Some(mut session) = self
				.session_manager
				.get_or_resume_session(session_id, inputs)?
			else {
				return mcp::Error::UnknownSession.into();
			};

			return Box::pin(session.send(part, message)).await;
		}

		if !protocol.uses_sessions() {
			let relay = inputs.build_new_connections()?;
			let mut session = self.session_manager.create_stateless_session(relay);
			let response = match &access {
				Some(a) => a.call(Box::pin(session.send(part, message))).await?,
				None => Box::pin(session.send(part, message)).await?,
			};
			return match &access {
				Some(a) => a.protect_response(response),
				None => Ok(response),
			};
		}

		// No session header... we need to create one, if it is an initialize.
		// Notifications and responses are subsequent-session messages too.
		let is_initialize_request = match &message {
			ClientJsonRpcMessage::Request(req) => {
				matches!(req.request, ClientRequest::InitializeRequest(_))
			},
			_ => false,
		};
		if !is_initialize_request {
			return mcp::Error::MissingSessionHeader.into();
		}
		let idle_ttl = inputs.backend.session_idle_ttl;
		if let Some(access) = &mut access {
			access.create_binding(&self.session_manager, idle_ttl)?;
			access.install(&mut part);
		}
		let relay = inputs.build_new_connections()?;
		let mut session = self.session_manager.create_session(relay);
		session.binding = access.as_ref().and_then(|a| a.binding.clone());
		let mut resp = match &access {
			Some(a) => a.call(Box::pin(session.send(part, message))).await?,
			None => Box::pin(session.send(part, message)).await?,
		};
		if let Some(access) = &access {
			resp = access
				.verify_initialize(resp, request_id.as_ref().expect("initialize has ID"))
				.await?;
		}

		let Ok(sid) = session.id.parse() else {
			return mcp::Error::InvalidSessionIdHeader.into();
		};
		resp.headers_mut().insert(HEADER_SESSION_ID, sid);
		self.session_manager.insert_session(session, idle_ttl);
		Ok(resp)
	}

	pub async fn handle_get(
		&self,
		request: Request,
		inputs: RelayInputs,
	) -> Result<Response, ProxyError> {
		// The GET event stream is legacy-only (SEP-2567 removed it for modern).
		reject_modern_session_request(request.headers())?;
		// check accept header
		if !request
			.headers()
			.get(http::header::ACCEPT)
			.and_then(|header| header.to_str().ok())
			.is_some_and(|header| header.contains(EVENT_STREAM_MIME_TYPE))
		{
			return mcp::Error::InvalidAcceptGet.into();
		}

		let Some(session_id) = request
			.headers()
			.get(HEADER_SESSION_ID)
			.and_then(|v| v.to_str().ok())
		else {
			return mcp::Error::SessionIdRequired.into();
		};

		let session_id = session_id.to_owned();
		let (mut parts, _) = request.into_parts();
		let mut access = super::session_security::SessionAccess::prepare(
			&mut parts,
			&inputs,
			&self.session_manager,
			"listen",
			Some(&session_id),
		)?;
		if let Some(access) = &mut access {
			if parts.headers.contains_key("last-event-id") {
				return Err(access.denial("unsupported-replay"));
			}
			let session = self
				.session_manager
				.get_protected(&session_id, inputs, access)?;
			access.install(&mut parts);
			return access.protect_response(access.call(Box::pin(session.get_stream(parts))).await?);
		}
		let Some(session) = self.session_manager.get_session(&session_id, inputs) else {
			return mcp::Error::UnknownSession.into();
		};

		session.get_stream(parts).await
	}

	pub async fn handle_delete(
		&self,
		request: Request,
		inputs: RelayInputs,
	) -> Result<Response, ProxyError> {
		// Session deletion is legacy-only (SEP-2567 removed sessions for modern).
		reject_modern_session_request(request.headers())?;
		// check session id
		let session_id = request
			.headers()
			.get(HEADER_SESSION_ID)
			.and_then(|v| v.to_str().ok());
		let Some(session_id) = session_id else {
			return mcp::Error::SessionIdRequired.into();
		};
		let session_id = session_id.to_string();
		let (mut parts, _) = request.into_parts();
		if let Some(mut access) = super::session_security::SessionAccess::prepare(
			&mut parts,
			&inputs,
			&self.session_manager,
			"close",
			Some(&session_id),
		)? {
			access.install(&mut parts);
			return self
				.session_manager
				.delete_protected(&session_id, parts, inputs, &mut access)
				.await;
		}
		Ok(
			self
				.session_manager
				.delete_session(&session_id, parts)
				.await
				.unwrap_or_else(accepted_response),
		)
	}
}

fn accepted_response() -> Response {
	::http::Response::builder()
		.status(StatusCode::ACCEPTED)
		.body(crate::http::Body::empty())
		.expect("valid response")
}
