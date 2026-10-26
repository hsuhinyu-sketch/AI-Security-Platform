use std::collections::HashMap;
use std::convert::Infallible;
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use ::http::StatusCode;
use ::http::header::CONTENT_TYPE;
use ::http::request::Parts;
use anyhow::anyhow;
use futures_util::StreamExt;
use headers::HeaderMapExt;
use platform_core::prelude::AssertSize;
use platform_core::version::BuildInfo;
use rmcp::model::{
	ClientInfo, ClientJsonRpcMessage, ClientNotification, ClientRequest, ConstString, GetMeta,
	Implementation, InitializeRequest, JsonRpcRequest, ProtocolVersion, RequestId,
	ServerJsonRpcMessage,
};
use rmcp::transport::common::http_header::{EVENT_STREAM_MIME_TYPE, JSON_MIME_TYPE};
use sse_stream::{KeepAlive, Sse, SseBody, SseStream};
use tokio::sync::mpsc::{Receiver, Sender};

use crate::http::Response;
use crate::mcp::ClientError;
use crate::mcp::execution_bridge::SessionHost;
use crate::mcp::handler::{Relay, RelayInputs};
use crate::mcp::rbac::CelExecWrapper;
use crate::mcp::streamablehttp::{ServerSseMessage, StreamableHttpPostResponse};
use crate::mcp::upstream::{IncomingRequestContext, UpstreamError};
use crate::proxy::ProxyError;
use crate::telemetry::log::{AsyncLog, SpanWriteOnDrop};
use crate::{mcp, *};
use gateway_mcp::execution::{DispatchError, DispatchOutcome, RouteContext};

#[derive(Debug, Clone)]
pub struct Session {
	pub(crate) binding: Option<Arc<super::session_security::SessionBinding>>,
	encoder: http::sessionpersistence::Encoder,
	relay: Arc<Relay>,
	pub id: Arc<str>,
	tx: Option<Sender<ServerJsonRpcMessage>>,
}

#[derive(Debug, Clone)]
struct SessionEntry {
	session: Session,
	last_access: Instant,
	idle_ttl: Duration,
}

const SESSION_REAP_INTERVAL: Duration = Duration::from_secs(30);

async fn dispatch_component(
	relay: &Relay,
	request: JsonRpcRequest<ClientRequest>,
	ctx: IncomingRequestContext,
	span: &mut SpanWriteOnDrop,
	log: &AsyncLog<crate::mcp::MCPInfo>,
	cel: CelExecWrapper,
	mcp_log: Option<AsyncLog<crate::mcp::MCPInfo>>,
) -> Result<Response, UpstreamError> {
	let id = request.id.clone();
	let method = request.request.method().to_string();
	let downstream_modern = super::handler::ctx_downstream_modern(&ctx);
	let route_context = RouteContext {
		default_target: relay.default_target_name(),
	};
	let mut host = SessionHost::new(relay, span, log, cel);
	match gateway_mcp::execution::dispatch(request, route_context, &mut host, ctx).await {
		Ok(DispatchOutcome::Messages(stream)) => {
			super::handler::messages_to_response(id, stream, mcp_log, downstream_modern)
		},
		Ok(DispatchOutcome::Unsupported) => Err(UpstreamError::InvalidMethod(method)),
		Err(DispatchError::Host(error)) => Err(error),
		Err(DispatchError::Route(gateway_mcp::routing::Error::UnsupportedReference)) => {
			Err(UpstreamError::InvalidMethod(method))
		},
		Err(DispatchError::Route(error)) => Err(UpstreamError::InvalidRequest(error.to_string())),
	}
}

impl Session {
	/// send a message to upstream server(s)
	pub async fn send(
		&mut self,
		parts: Parts,
		message: ClientJsonRpcMessage,
	) -> Result<Response, ProxyError> {
		let req_id = match &message {
			ClientJsonRpcMessage::Request(r) => Some(r.id.clone()),
			_ => None,
		};
		let res = self
			.send_internal(parts, message)
			.assert_size::<{ 6 * 1024 }>()
			.await;
		Self::handle_error(req_id, res).await
	}

	/// Send a downstream message to upstream server(s) in gateway stateless mode.
	/// Every non-initialize message gets a gateway-generated InitializeRequest
	/// first, because many legacy servers require initialize before any other
	/// request. Once downstream stateless transport is supported, remove this
	/// wrapper and forward the message as-is.
	pub async fn stateless_send_and_initialize(
		&mut self,
		parts: Parts,
		message: ClientJsonRpcMessage,
	) -> Result<Response, ProxyError> {
		let (req_id, request_type) = match &message {
			ClientJsonRpcMessage::Request(r) => (Some(r.id.clone()), Some(&r.request)),
			_ => (None, None),
		};
		let is_init = request_type.is_some_and(|r| matches!(r, ClientRequest::InitializeRequest(_)));
		if !is_init {
			let mut client_info = get_client_info();
			if let Some(protocol_version) =
				crate::mcp::streamablehttp::protocol_version_header(&parts.headers, req_id.clone())?
			{
				client_info.protocol_version = protocol_version;
			}
			let init_request = rmcp::model::InitializeRequest::new(client_info);
			let target = match gateway_mcp::routing::legacy_initialization_target(
				self.relay.default_target_name(),
				request_type,
			) {
				Ok(target) => target,
				Err(error) => {
					return Self::handle_error(
						req_id.clone(),
						Err(UpstreamError::InvalidRequest(error.to_string())),
					)
					.await;
				},
			};
			match target.as_deref() {
				Some(service_name) => {
					let res = self
						.send_init_single(parts.clone(), init_request, service_name)
						.await;
					if let Some(sessions) = self.relay.get_sessions() {
						let s = http::sessionpersistence::SessionState::MCP(
							http::sessionpersistence::MCPSessionState::new(sessions),
						);
						if let Ok(id) = s.encode(&self.encoder) {
							self.id = id.into();
						}
					}
					Self::handle_error(Some(RequestId::Number(0)), res).await?;
					// Now send the initialized notification
					let _ = Self::handle_error(
						None,
						self
							.send_initialized_notification_single(parts.clone(), service_name)
							.await,
					)
					.await?;
				},
				_ => {
					// We should fan out the initialize request to all MCP servers
					let _ = self
						.send(
							parts.clone(),
							ClientJsonRpcMessage::request(init_request.into(), RequestId::Number(0)),
						)
						.await?;
					let notification = ClientJsonRpcMessage::notification(
						rmcp::model::InitializedNotification {
							method: Default::default(),
							extensions: Default::default(),
						}
						.into(),
					);
					let _ = self.send(parts.clone(), notification).await?;
				},
			}
		}
		// Now we can send the message like normal (if it's tools/call, it'll go to the initialized target)
		self.send(parts, message).await
	}

	pub fn with_inputs(mut self, inputs: RelayInputs) -> Self {
		self.relay = Arc::new(self.relay.with_inputs(inputs));
		self
	}

	/// delete any active sessions
	pub async fn delete_session(&self, parts: Parts) -> Result<Response, ProxyError> {
		let ctx = IncomingRequestContext::new(&parts);
		let (_span, log, _cel) = mcp::handler::setup_request_log(parts, "delete_session");
		let session_id = self.id.to_string();
		log.non_atomic_mutate(|l| {
			// NOTE: l.method_name keep None to respect the metrics logic: not handle GET, DELETE.
			l.session_id = Some(session_id);
		});
		Self::handle_error(None, self.relay.send_fanout_deletion(ctx).await).await
	}

	/// forward_legacy_sse takes an upstream Response and forwards all messages to the SSE data stream.
	/// In SSE, POST requests always just get a 202 response and the messages go on a separate stream.
	/// Note: its plausible we could rewrite the rest of the proxy to return a more structured type than
	/// `Response` here, so we don't have to re-process it. However, since SSE is deprecated its best to
	/// optimize for the non-deprecated code paths; this works fine.
	pub async fn forward_legacy_sse(&self, resp: Response) -> Result<(), ClientError> {
		let Some(tx) = self.tx.clone() else {
			return Err(ClientError::new(anyhow!(
				"may only be called for SSE streams",
			)));
		};
		let content_type = resp.headers().get(CONTENT_TYPE);
		let sse = match content_type {
			Some(ct) if ct.as_bytes().starts_with(EVENT_STREAM_MIME_TYPE.as_bytes()) => {
				trace!("forward SSE got SSE stream response");
				let content_encoding = resp.headers().typed_get::<headers::ContentEncoding>();
				let (body, _encoding) =
					crate::http::compression::decompress_body(resp.into_body(), content_encoding.as_ref())
						.map_err(ClientError::new)?;
				let event_stream = SseStream::from_bytes_stream(body.into_data_stream()).boxed();
				StreamableHttpPostResponse::Sse(event_stream, None)
			},
			Some(ct) if ct.as_bytes().starts_with(JSON_MIME_TYPE.as_bytes()) => {
				trace!("forward SSE got single JSON response");
				let message = json::from_response_body::<ServerJsonRpcMessage>(resp)
					.await
					.map_err(ClientError::new)?;
				StreamableHttpPostResponse::Json(message, None)
			},
			_ => {
				trace!("forward SSE got accepted, no action needed");
				return Ok(());
			},
		};
		let mut ms = crate::mcp::mergestream::from_post_response(sse)?;
		tokio::spawn(async move {
			while let Some(Ok(msg)) = ms.next().await {
				let Ok(()) = tx.send(msg).await else {
					return;
				};
			}
		});
		Ok(())
	}

	/// get_stream establishes a stream for server-sent messages
	pub async fn get_stream(&self, parts: Parts) -> Result<Response, ProxyError> {
		let ctx = IncomingRequestContext::new(&parts);
		let (_span, log, _cel) = mcp::handler::setup_request_log(parts, "get_stream");
		let session_id = self.id.to_string();
		log.non_atomic_mutate(|l| {
			// NOTE: l.method_name keep None to respect the metrics logic: which do not want to handle GET, DELETE.
			l.session_id = Some(session_id);
		});
		Self::handle_error(None, self.relay.send_fanout_get(ctx).await).await
	}

	async fn handle_error(
		req_id: Option<RequestId>,
		d: Result<Response, UpstreamError>,
	) -> Result<Response, ProxyError> {
		match d {
			Ok(r) => Ok(r),
			Err(UpstreamError::Security(error)) => {
				tracing::warn!(kind = error.kind().as_str(), "MCP security check failed");
				Err(mcp::Error::Security(req_id, error.kind()).into())
			},
			Err(UpstreamError::Http(ClientError::Status(resp))) => {
				let resp = http::SendDirectResponse::new(*resp)
					.await
					.map_err(ProxyError::Body)?;
				Err(mcp::Error::UpstreamError(Box::new(resp)).into())
			},
			Err(UpstreamError::Proxy(p)) => Err(p),
			Err(UpstreamError::Authorization {
				resource_type,
				resource_name,
			}) if req_id.is_some() => {
				Err(mcp::Error::Authorization(req_id.unwrap(), resource_type, resource_name).into())
			},
			Err(UpstreamError::McpGuardrails(rej)) if req_id.is_some() => {
				Err(mcp::Error::McpGuardrails(req_id.unwrap(), rej).into())
			},
			// TODO: this is too broad. We have a big tangle of errors to untangle though
			Err(e) => Err(mcp::Error::SendError(req_id, e.to_string()).into()),
		}
	}

	async fn send_init_single(
		&self,
		parts: Parts,
		mut init_request: InitializeRequest,
		service_name: &str,
	) -> Result<Response, UpstreamError> {
		let method = init_request.method.as_str().to_string();
		let ctx = IncomingRequestContext::new(&parts);
		let (_, log, _) = mcp::handler::setup_request_log(parts, &method);
		let session_id = self.id.to_string();
		log.non_atomic_mutate(|l| {
			l.method_name = Some(method.clone());
			l.session_id = Some(session_id);
		});

		self.strip_unsupported_client_capabilities(&mut init_request.params.capabilities);
		self
			.relay
			.send_single(
				JsonRpcRequest::new(RequestId::Number(0), init_request.into()),
				ctx,
				service_name,
				Some(log),
			)
			.await
	}

	async fn send_initialized_notification_single(
		&self,
		parts: Parts,
		service_name: &str,
	) -> Result<Response, UpstreamError> {
		let initialized = rmcp::model::InitializedNotification {
			method: Default::default(),
			extensions: Default::default(),
		};
		let method = initialized.method.as_str().to_string();
		let ctx = IncomingRequestContext::new(&parts);
		let (_, log, _) = mcp::handler::setup_request_log(parts, &method);
		let session_id = self.id.to_string();
		log.non_atomic_mutate(|l| {
			l.method_name = Some(method.clone());
			l.session_id = Some(session_id);
		});

		self
			.relay
			.send_notification_single(initialized.into(), ctx, service_name)
			.await
	}

	async fn send_internal(
		&mut self,
		parts: Parts,
		message: ClientJsonRpcMessage,
	) -> Result<Response, UpstreamError> {
		// Sending a message entails fanning out the message to each upstream, and then aggregating the responses.
		// The responses may include any number of notifications on the same HTTP response, and then finish with the
		// response to the request.
		// To merge these, we use a MergeStream which will join all of the notifications together, and then apply
		// some per-request merge logic across all the responses.
		// For example, this may return [server1-notification, server2-notification, server2-notification, merge(server1-response, server2-response)].
		// It's very common to not have any notifications, though.
		match message {
			message @ (ClientJsonRpcMessage::Response(_) | ClientJsonRpcMessage::Error(_)) => {
				Box::pin(
					self
						.relay
						.send_reverse_response(message, IncomingRequestContext::new(&parts)),
				)
				.await
			},
			ClientJsonRpcMessage::Request(mut r) => {
				let method = r.request.method().to_string();
				let ctx = IncomingRequestContext::new(&parts);
				let (mut span, log, cel) = mcp::handler::setup_request_log(parts, &method);
				let session_id = self.id.to_string();
				log.non_atomic_mutate(|l| {
					l.method_name = Some(method.clone());
					l.session_id = Some(session_id);
				});
				self.strip_unsupported_client_capabilities_from_meta(&mut r.request);
				match &mut r.request {
					ClientRequest::InitializeRequest(ir) => {
						if self
							.relay
							.security_audit
							.as_ref()
							.and_then(|c| c.mcp_sessions.as_ref())
							.is_some_and(|s| s.tasks.is_some())
							&& ir.params.protocol_version.as_str() != "2025-11-25"
						{
							return Err(UpstreamError::InvalidRequest(
								"asynchronous tasks require MCP 2025-11-25".into(),
							));
						}
						if let (Some(binding), Some(reverse)) = (
							&self.binding,
							self
								.relay
								.security_audit
								.as_ref()
								.and_then(|c| c.mcp_sessions.as_ref())
								.and_then(|c| c.reverse.as_ref()),
						) {
							if !matches!(
								ir.params.protocol_version.as_str(),
								"2025-06-18" | "2025-11-25"
							) {
								return Err(UpstreamError::InvalidRequest(
									"reverse RPC requires an adapted 2025 protocol revision".into(),
								));
							}
							// Explicit Gateway-managed sampling: the Gateway is the upstream client.
							if self
								.relay
								.security_audit
								.as_ref()
								.and_then(|c| c.mcp_sessions.as_ref())
								.and_then(|s| s.tasks.as_ref())
								.is_some_and(|t| t.sampling.is_some())
							{
								ir.params.capabilities.sampling = Some(Default::default());
							}
							super::session_security::reverse::negotiate(
								binding,
								reverse,
								&mut ir.params.capabilities,
							)?;
						} else {
							self.strip_unsupported_client_capabilities(&mut ir.params.capabilities);
						}

						let res = Box::pin(dispatch_component(
							&self.relay,
							r,
							ctx,
							&mut span,
							&log,
							cel,
							None,
						))
						.await?;
						if self.binding.is_none()
							&& let Some(sessions) = self.relay.get_sessions()
						{
							let s = http::sessionpersistence::SessionState::MCP(
								http::sessionpersistence::MCPSessionState::new(sessions),
							);
							if let Ok(id) = s.encode(&self.encoder) {
								self.id = id.into();
							}
						}
						Ok(res)
					},
					_ => {
						let mcp_log =
							matches!(&r.request, ClientRequest::CallToolRequest(_)).then(|| log.clone());
						Box::pin(dispatch_component(
							&self.relay,
							r,
							ctx,
							&mut span,
							&log,
							cel,
							mcp_log,
						))
						.await
					},
				}
			},
			ClientJsonRpcMessage::Notification(mut r) => {
				if matches!(r.notification, ClientNotification::CancelledNotification(_))
					&& parts
						.extensions
						.get::<super::session_security::SessionAccess>()
						.is_some()
				{
					return Box::pin(
						self
							.relay
							.send_reverse_cancel(r.notification, IncomingRequestContext::new(&parts)),
					)
					.await;
				}
				let method = gateway_mcp::notification_method(&r.notification);
				let ctx = IncomingRequestContext::new(&parts);
				let (_span, log, _cel) = mcp::handler::setup_request_log(parts, method);
				let session_id = self.id.to_string();
				log.non_atomic_mutate(|l| {
					l.method_name = Some(method.to_string());
					l.session_id = Some(session_id);
				});
				self.strip_unsupported_client_capabilities_from_meta(&mut r.notification);
				// TODO: the notification needs to be fanned out in some cases and sent to a single one in others
				// however, we don't have a way to map to the correct service yet
				Box::pin(self.relay.send_notification(r, ctx)).await
			},
		}
	}

	fn strip_unsupported_client_capabilities(
		&self,
		capabilities: &mut rmcp::model::ClientCapabilities,
	) {
		// Until server-to-client request routing is implemented, do not advertise
		// capabilities that require the proxy to route upstream requests back to
		// the downstream client and route the client's JSON-RPC response upstream.
		capabilities.roots = None;
		capabilities.sampling = None;
		capabilities.elicitation = None;
	}

	fn strip_unsupported_client_capabilities_from_meta<T: GetMeta>(&self, message: &mut T) {
		let Some(mut capabilities) = message.get_meta().client_capabilities() else {
			return;
		};
		self.strip_unsupported_client_capabilities(&mut capabilities);
		message.get_meta_mut().set_client_capabilities(capabilities);
	}
}

#[derive(Debug)]
pub struct SessionManager {
	pub(crate) protected_sessions: Arc<std::sync::atomic::AtomicUsize>,
	pub(crate) protected_streams: Arc<std::sync::atomic::AtomicUsize>,
	encoder: http::sessionpersistence::Encoder,
	sessions: Arc<RwLock<HashMap<String, SessionEntry>>>,
	idle_reaper: OnceLock<tokio::task::AbortHandle>,
}

fn session_id() -> Arc<str> {
	uuid::Uuid::new_v4().to_string().into()
}

impl SessionManager {
	pub fn new(encoder: http::sessionpersistence::Encoder) -> Arc<Self> {
		Arc::new(Self {
			protected_sessions: Default::default(),
			protected_streams: Default::default(),
			encoder,
			sessions: Arc::new(RwLock::new(HashMap::new())),
			idle_reaper: OnceLock::new(),
		})
	}

	pub(super) fn shutdown(&self) {
		if let Some(abort) = self.idle_reaper.get() {
			abort.abort();
		}
		let mut sessions = self
			.sessions
			.write()
			.unwrap_or_else(|error| error.into_inner());
		for entry in sessions.values() {
			if let Some(binding) = &entry.session.binding {
				binding
					.closed
					.store(true, std::sync::atomic::Ordering::Release);
			}
		}
		sessions.clear();
	}

	pub fn ensure_idle_running(&self) {
		self
			.idle_reaper
			.get_or_init(|| tokio::spawn(run_idle_reaper(self.sessions.clone())).abort_handle());
	}

	pub fn get_session(&self, id: &str, builder: RelayInputs) -> Option<Session> {
		let mut sessions = self.sessions.write().ok()?;
		let entry = sessions.get_mut(id)?;
		if entry.session.binding.is_some() {
			return None;
		}
		entry.last_access = Instant::now();
		Some(entry.session.clone().with_inputs(builder))
	}

	pub fn get_or_resume_session(
		&self,
		id: &str,
		builder: RelayInputs,
	) -> Result<Option<Session>, mcp::Error> {
		if let Some(s) = self.sessions.write().expect("poisoned").get_mut(id) {
			if s.session.binding.is_some() {
				return Ok(None);
			}
			s.last_access = Instant::now();
			return Ok(Some(s.session.clone().with_inputs(builder)));
		}
		let idle_ttl = builder.backend.session_idle_ttl;
		let d = http::sessionpersistence::SessionState::decode(id, &self.encoder)
			.map_err(|_| mcp::Error::InvalidSessionIdHeader)?;
		let http::sessionpersistence::SessionState::MCP(state) = d else {
			return Ok(None);
		};
		let relay = builder.build_new_connections()?;
		if let Err(err) = relay.set_sessions(state.sessions) {
			warn!("failed to resume session: {err}");
			return Ok(None);
		}

		let sess = Session {
			binding: None,
			id: id.into(),
			relay: Arc::new(relay),
			tx: None,
			encoder: self.encoder.clone(),
		};
		let mut sm = self.sessions.write().expect("write lock");
		sm.insert(
			id.to_string(),
			SessionEntry {
				session: sess.clone(),
				last_access: Instant::now(),
				idle_ttl,
			},
		);
		Ok(Some(sess))
	}

	/// create_session establishes an MCP session.
	pub fn create_session(&self, relay: Relay) -> Session {
		let id = session_id();

		// Do NOT insert yet
		Session {
			binding: None,
			id: id.clone(),
			relay: Arc::new(relay),
			tx: None,
			encoder: self.encoder.clone(),
		}
	}

	pub fn insert_session(&self, sess: Session, idle_ttl: Duration) {
		let mut sm = self.sessions.write().expect("write lock");
		sm.insert(
			sess.id.to_string(),
			SessionEntry {
				session: sess,
				last_access: Instant::now(),
				idle_ttl,
			},
		);
	}

	/// create_stateless_session creates a session for stateless mode.
	/// Unlike create_session, this does NOT register the session in the session manager.
	/// The caller is responsible for calling session.delete_session() when done
	/// to clean up upstream resources (e.g., stdio processes).
	pub fn create_stateless_session(&self, relay: Relay) -> Session {
		let id = session_id();
		Session {
			binding: None,
			id,
			relay: Arc::new(relay),
			tx: None,
			encoder: self.encoder.clone(),
		}
	}

	/// create_legacy_session establishes a legacy SSE session.
	/// These will have the ability to send messages to them via a channel.
	pub fn create_legacy_session(
		&self,
		relay: Relay,
		idle_ttl: Duration,
	) -> (Session, Receiver<ServerJsonRpcMessage>) {
		let (tx, rx) = tokio::sync::mpsc::channel(64);
		let id = session_id();
		let sess = Session {
			binding: None,
			id: id.clone(),
			relay: Arc::new(relay),
			tx: Some(tx),
			encoder: self.encoder.clone(),
		};
		let mut sm = self.sessions.write().expect("write lock");
		sm.insert(
			id.to_string(),
			SessionEntry {
				session: sess.clone(),
				last_access: Instant::now(),
				idle_ttl,
			},
		);
		(sess, rx)
	}

	pub async fn delete_session(&self, id: &str, parts: Parts) -> Option<Response> {
		let sess = {
			let mut sm = self.sessions.write().expect("write lock");
			if sm.get(id)?.session.binding.is_some() {
				return None;
			}
			sm.remove(id)?.session
		};
		// Swallow the error
		sess.delete_session(parts).await.ok()
	}

	pub fn get_protected(
		&self,
		id: &str,
		inputs: RelayInputs,
		access: &mut super::session_security::SessionAccess,
	) -> Result<Session, ProxyError> {
		let session = self
			.sessions
			.read()
			.map_err(|_| access.denial("store-unavailable"))?
			.get(id)
			.map(|entry| entry.session.clone())
			.ok_or_else(|| access.denial("unknown-or-not-owner"))?;
		let binding = session
			.binding
			.clone()
			.ok_or_else(|| access.denial("unknown-or-not-owner"))?;
		// Current policy/PDP evaluation may perform I/O: never hold the session map lock.
		access.bind(binding.clone())?;
		let mut sessions = self
			.sessions
			.write()
			.map_err(|_| access.denial("store-unavailable"))?;
		let entry = sessions
			.get_mut(id)
			.filter(|entry| {
				entry
					.session
					.binding
					.as_ref()
					.is_some_and(|b| Arc::ptr_eq(b, &binding) && !b.expired())
			})
			.ok_or_else(|| access.denial("unknown-or-not-owner"))?;
		entry.last_access = Instant::now();
		Ok(session.with_inputs(inputs))
	}
	pub async fn delete_protected(
		&self,
		id: &str,
		parts: Parts,
		inputs: RelayInputs,
		access: &mut super::session_security::SessionAccess,
	) -> Result<Response, ProxyError> {
		let checked = self.get_protected(id, inputs, access)?;
		let session = {
			let mut sessions = self
				.sessions
				.write()
				.map_err(|_| access.denial("store-unavailable"))?;
			let entry = sessions
				.get(id)
				.ok_or_else(|| access.denial("unknown-or-not-owner"))?;
			if !entry
				.session
				.binding
				.as_ref()
				.zip(checked.binding.as_ref())
				.is_some_and(|(a, b)| Arc::ptr_eq(a, b) && !a.expired())
			{
				return Err(access.denial("unknown-or-not-owner"));
			}
			sessions.remove(id).expect("entry still locked");
			let session = checked;
			if let Some(binding) = &session.binding {
				binding
					.closed
					.store(true, std::sync::atomic::Ordering::Release);
			}
			session
		};
		session.delete_session(parts).await
	}
	pub fn prune_protected(&self) {
		if let Ok(mut sessions) = self.sessions.write() {
			sessions.retain(|_, entry| entry.session.binding.as_ref().is_none_or(|b| !b.expired()));
		}
	}
}

impl Drop for SessionManager {
	fn drop(&mut self) {
		if let Some(abort) = self.idle_reaper.take() {
			abort.abort();
		}
	}
}

async fn run_idle_reaper(sessions: Arc<RwLock<HashMap<String, SessionEntry>>>) {
	let mut ticker = tokio::time::interval(SESSION_REAP_INTERVAL);
	ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
	loop {
		ticker.tick().await;
		reap_expired_entries(&sessions);
	}
}

fn reap_expired_entries(sessions: &Arc<RwLock<HashMap<String, SessionEntry>>>) {
	let now = Instant::now();
	let mut guard = sessions.write().expect("write lock");
	let pre = guard.len();
	guard.retain(|_, entry| {
		let keep = now.duration_since(entry.last_access) < entry.idle_ttl
			&& entry.session.binding.as_ref().is_none_or(|b| !b.expired());
		if !keep && let Some(binding) = &entry.session.binding {
			binding
				.closed
				.store(true, std::sync::atomic::Ordering::Release);
		}
		keep
	});
	let post = guard.len();
	if post < pre {
		tracing::debug!("reaped {} sessions", pre - post);
	}
}

#[derive(Debug, Clone)]
pub struct SessionDropper {
	sm: Arc<SessionManager>,
	s: Option<(Session, Parts)>,
}

/// Dropper returns a handle that, when dropped, removes the session
pub fn dropper(sm: Arc<SessionManager>, s: Session, parts: Parts) -> SessionDropper {
	SessionDropper {
		sm,
		s: Some((s, parts)),
	}
}

impl Drop for SessionDropper {
	fn drop(&mut self) {
		let Some((s, parts)) = self.s.take() else {
			return;
		};
		let mut sm = self.sm.sessions.write().expect("write lock");
		debug!("delete session {}", s.id);
		sm.remove(s.id.as_ref());
		tokio::task::spawn(async move { s.delete_session(parts).await });
	}
}

pub(crate) fn sse_stream_response(
	stream: impl futures::Stream<Item = ServerSseMessage> + Send + 'static,
	keep_alive: Option<Duration>,
) -> Response {
	use futures::StreamExt;
	let stream = SseBody::new(stream.map(|message| {
		let data = serde_json::to_string(&message.message).expect("valid message");
		let mut sse = Sse::default().data(data);
		sse.id = message.event_id;
		Result::<Sse, Infallible>::Ok(sse)
	}));
	let stream = match keep_alive {
		Some(duration) => {
			http::Body::new(stream.with_keep_alive::<TokioSseTimer>(KeepAlive::new().interval(duration)))
		},
		None => http::Body::new(stream),
	};
	::http::Response::builder()
		.status(StatusCode::OK)
		.header(http::header::CONTENT_TYPE, EVENT_STREAM_MIME_TYPE)
		.header(http::header::CACHE_CONTROL, "no-cache")
		.body(stream)
		.expect("valid response")
}

pin_project_lite::pin_project! {
		struct TokioSseTimer {
				#[pin]
				sleep: tokio::time::Sleep,
		}
}
impl Future for TokioSseTimer {
	type Output = ();

	fn poll(
		self: std::pin::Pin<&mut Self>,
		cx: &mut std::task::Context<'_>,
	) -> std::task::Poll<Self::Output> {
		let this = self.project();
		this.sleep.poll(cx)
	}
}
impl sse_stream::Timer for TokioSseTimer {
	fn from_duration(duration: Duration) -> Self {
		Self {
			sleep: tokio::time::sleep(duration),
		}
	}

	fn reset(self: std::pin::Pin<&mut Self>, when: std::time::Instant) {
		let this = self.project();
		this.sleep.reset(tokio::time::Instant::from_std(when));
	}
}

fn get_client_info() -> ClientInfo {
	let mut client_info = ClientInfo::default();
	client_info.protocol_version = ProtocolVersion::V_2025_11_25;
	client_info.capabilities = rmcp::model::ClientCapabilities::default();
	client_info.client_info =
		Implementation::new("agentgateway", BuildInfo::new().version.to_string());
	client_info
}
