//! Standard A2A Push terminated in the Gateway's durable inbox, not an opaque webhook tunnel.
use super::*;
use security_types::ActionType;
use std::{
	collections::HashMap,
	sync::{
		Mutex, OnceLock,
		atomic::{AtomicBool, Ordering},
	},
	time::{Duration, Instant},
};

pub(crate) use gateway_a2a::push::{PREFIX, is_callback_path};
static CHANNELS: OnceLock<Mutex<HashMap<String, Arc<Channel>>>> = OnceLock::new();
static RECEIVERS: OnceLock<Arc<tokio::sync::Semaphore>> = OnceLock::new();
fn channels() -> &'static Mutex<HashMap<String, Arc<Channel>>> {
	CHANNELS.get_or_init(Default::default)
}

#[derive(Clone)]
struct Proof {
	config: Arc<SecurityConfig>,
	credential: TaskCredential,
	identity: GatewayIdentity,
	scope: String,
	task: String,
	generation: String,
	invocation: ActionRequest,
	action: ActionRequest,
	flow: Option<crate::security_flow::FlowAccess>,
	guards: Option<crate::proxy::RoutingGuards>,
	execution: Option<crate::execution_budget::ExecutionScope>,
}
pub(super) struct Channel {
	id: String,
	url: String,
	secret_hash: String,
	fingerprint: String,
	created_millis: i64,
	expires: Instant,
	proof: OnceLock<Proof>,
	ready: AtomicBool,
	closed: AtomicBool,
	busy: AtomicBool,
	last: Mutex<Option<(i64, String)>>,
}
pub(super) enum Operation {
	Set(Arc<Channel>),
	Get(String),
	List,
	Delete(Arc<Channel>),
}
fn push_action(call: &AuthorizedCall, name: &str) -> ActionRequest {
	let mut action = call.action.clone();
	action.action.action_type = ActionType::AgentPushOperation;
	action.action.name = name.into();
	action
}
fn authorize(call: &AuthorizedCall, name: &str) -> Result<(), ProxyError> {
	call.check_continuation()?;
	let action = push_action(call, name);
	crate::security::evaluate(&call.config, &action).map_err(|_| deny(&action, ObjectError::Push))?;
	if let Some(guards) = &call.download_guards {
		guards
			.authorize_a2a_push(&call.config, &[&action])
			.map_err(|_| deny(&action, ObjectError::Push))?;
	}
	audit_object_check(&action, Ok(()), &UiSecurityAuditSink);
	Ok(())
}
impl Channel {
	fn check(&self, action: &ActionRequest) -> Result<(), ProxyError> {
		if !self.live() {
			return Err(deny(action, ObjectError::Push));
		}
		Ok(())
	}
	fn public(&self) -> Value {
		gateway_a2a::push::public_config(
			self
				.proof
				.get()
				.map(|p| p.task.as_str())
				.unwrap_or_default(),
			&self.id,
			&self.url,
		)
	}

	fn live(&self) -> bool {
		Instant::now() < self.expires
			&& !self.closed.load(Ordering::Acquire)
			&& self.proof.get().is_none_or(|p| {
				p.credential.revision.is_current()
					&& chrono::Utc::now().timestamp() < p.credential.expires_at
			})
	}
	fn matches(&self, call: &AuthorizedCall) -> bool {
		self.live()
			&& self.proof.get().is_some_and(|p| {
				p.scope == call.scope
					&& call.permit.cleanup_key().is_ok_and(|k| k == p.generation)
					&& p.config.same_configuration(&call.config).unwrap_or(false)
			})
	}
}
impl AuthorizedCall {
	pub(super) fn prepare_push(&mut self, req: &mut Request, rpc: &Rpc) -> Result<(), ProxyError> {
		let Some(method) = gateway_a2a::Method::parse(&rpc.method).and_then(|m| m.push_operation())
		else {
			return Ok(());
		};
		let settings = self
			.config
			.a2a_objects
			.as_ref()
			.and_then(|o| o.push.as_ref())
			.ok_or_else(|| deny(&self.action, ObjectError::Unsupported))?;
		let method = method.name();
		authorize(self, method)?;
		if method == "set" {
			if self
				.permit
				.snapshot_state()
				.is_none_or(|s| s.terminal() || s == TaskState::Unknown)
			{
				return Err(deny(&self.action, ObjectError::Terminal));
			}
			let requested =
				gateway_a2a::push::requested_url(rpc).map_err(|e| deny(&self.action, object_error(e)))?;
			if requested != Some(settings.callback_base_url.as_str()) {
				return Err(deny(&self.action, ObjectError::Push));
			}

			security_audit::StateJournal::encoded_len(
				&(&self.action, &self.scope, &self.credential.issuer),
				16384,
			)
			.map_err(|_| deny(&self.action, ObjectError::Capacity))?;
			let fingerprint = crate::security::digest(
				&serde_json::to_string(&self.config).map_err(|_| deny(&self.action, ObjectError::Push))?,
			);
			let mut registry = channels()
				.lock()
				.map_err(|_| deny(&self.action, ObjectError::Unavailable))?;
			registry.retain(|_, c| c.live());
			let same = registry
				.values()
				.filter(|c| c.fingerprint == fingerprint)
				.count();
			if registry.len() >= 256 || same >= settings.max_channels {
				return Err(deny(&self.action, ObjectError::Capacity));
			}
			let id = uuid::Uuid::new_v4().to_string();
			let secret = format!(
				"{}{}",
				uuid::Uuid::new_v4().simple(),
				uuid::Uuid::new_v4().simple()
			);
			let channel = Arc::new(Channel {
				id: id.clone(),
				url: format!("{}{id}", settings.callback_base_url),
				secret_hash: crate::security::digest(&secret),
				fingerprint,
				created_millis: chrono::Utc::now().timestamp_millis(),
				expires: Instant::now() + Duration::from_secs(settings.max_channel_seconds),
				proof: OnceLock::new(),
				ready: AtomicBool::new(false),
				closed: AtomicBool::new(false),
				busy: AtomicBool::new(false),
				last: Mutex::new(None),
			});
			let rewritten = gateway_a2a::push::registration_request(
				rpc,
				self.permit.task_id.as_deref(),
				&id,
				&channel.url,
				&secret,
			);
			*req.body_mut() =
				crate::json::to_body(rewritten).map_err(|_| deny(&self.action, ObjectError::Push))?;
			req.headers_mut().remove(header::CONTENT_LENGTH);
			registry.insert(id, channel.clone());
			self.push = Some(Operation::Set(channel));
		} else {
			let id = rpc
				.params
				.get("pushNotificationConfigId")
				.map(identifier)
				.transpose()
				.map_err(|e| deny(&self.action, e))?
				.map(ToOwned::to_owned);
			self.push = Some(match method {
				"list" => Operation::List,
				"get" => Operation::Get(id.ok_or_else(|| deny(&self.action, ObjectError::Push))?),
				"delete" => {
					let registry = channels()
						.lock()
						.map_err(|_| deny(&self.action, ObjectError::Unavailable))?;
					let channel = registry
						.get(&id.ok_or_else(|| deny(&self.action, ObjectError::Push))?)
						.filter(|c| c.matches(self) && c.ready.load(Ordering::Acquire))
						.cloned()
						.ok_or_else(|| deny(&self.action, ObjectError::Push))?;
					Operation::Delete(channel)
				},
				_ => return Err(deny(&self.action, ObjectError::Unsupported)),
			});
		}
		Ok(())
	}
	pub(crate) fn install_push_constraints(&self) -> Result<(), ProxyError> {
		// Parent Guards are installed only after initial object authorization. Recheck
		// before any upstream registration/deletion or local revocation takes effect.
		match &self.push {
			Some(Operation::Set(_)) => authorize(self, "set")?,
			Some(Operation::Delete(channel)) => {
				authorize(self, "delete")?;
				channel.check(&self.action)?;
				channel.closed.store(true, Ordering::Release);
			},
			_ => {},
		}
		if let Some(Operation::Set(channel)) = &self.push {
			security_audit::StateJournal::encoded_len(
				&(&self.action, &self.scope, &self.credential.issuer),
				16384,
			)
			.map_err(|_| deny(&self.action, ObjectError::Capacity))?;
			channel
				.proof
				.set(Proof {
					config: self.config.clone(),
					credential: self.credential.clone(),
					identity: self.identity.clone(),
					scope: self.scope.clone(),
					task: self.permit.task_id.clone().expect("known"),
					generation: self
						.permit
						.cleanup_key()
						.map_err(|e| deny(&self.action, e))?,
					invocation: self.invocation.clone(),
					action: self.action.clone(),
					flow: self.flow.clone(),
					guards: self.download_guards.clone(),
					execution: self.execution.clone(),
				})
				.map_err(|_| deny(&self.action, ObjectError::Push))?;
		}
		Ok(())
	}
	pub(crate) fn is_push_registration(&self) -> bool {
		matches!(self.push, Some(Operation::Set(_)))
	}
	pub(crate) fn local_push_response(&self) -> Result<Option<Response>, ProxyError> {
		let result = match &self.push {
			Some(Operation::Get(id)) => {
				authorize(self, "get")?;
				channels()
					.lock()
					.map_err(|_| deny(&self.action, ObjectError::Unavailable))?
					.get(id)
					.filter(|c| c.matches(self) && c.ready.load(Ordering::Acquire))
					.ok_or_else(|| deny(&self.action, ObjectError::Push))?
					.public()
			},
			Some(Operation::List) => {
				authorize(self, "list")?;
				let list = channels()
					.lock()
					.map_err(|_| deny(&self.action, ObjectError::Unavailable))?
					.values()
					.filter(|c| c.matches(self) && c.ready.load(Ordering::Acquire))
					.map(|c| c.public())
					.collect::<Vec<_>>();
				Value::Array(list)
			},
			_ => return Ok(None),
		};
		let body = crate::json::to_body(gateway_a2a::push::response(&self.rpc_id, result))
			.map_err(|_| deny(&self.action, ObjectError::Push))?;
		Ok(Some(
			::http::Response::builder()
				.header(header::CONTENT_TYPE, "application/json")
				.header(header::CACHE_CONTROL, "private, no-store")
				.body(body)
				.expect("static response"),
		))
	}
	pub(super) async fn apply_push_response(
		&self,
		response: &mut Response,
		rpc: &mut Value,
	) -> Result<(), ProxyError> {
		let error = self.validate_envelope(rpc)?;
		if error {
			rpc["error"]["message"] = serde_json::json!("push operation failed");
		}
		match &self.push {
			Some(Operation::Set(channel)) => {
				if error || !response.status().is_success() {
					channel.closed.store(true, Ordering::Release);
					if !error {
						return Err(deny(&self.action, ObjectError::Push));
					}
				} else {
					authorize(self, "set")?;
					let result = &rpc["result"];
					if gateway_a2a::push::validate_registration(
						result,
						self.permit.task_id.as_deref().unwrap_or_default(),
						&channel.id,
						&channel.url,
					)
					.is_err()
					{
						channel.closed.store(true, Ordering::Release);
						return Err(deny(&self.action, ObjectError::ResponseBinding));
					}

					// Checkpoint uses the current observed Task metadata; it is not a new remote event.
					let call = channel
						.proof
						.get()
						.ok_or_else(|| deny(&self.action, ObjectError::Push))?
						.call(&self.action.request_id)?;
					let state = call
						.permit
						.snapshot_state()
						.ok_or_else(|| deny(&self.action, ObjectError::Push))?;
					let checkpoint = serde_json::json!({"result":{"kind":"task","id":call.permit.task_id,"contextId":call.permit.context_id,"status":{"state":state}}});
					let cursor = call
						.record_event(&checkpoint)
						.await?
						.ok_or_else(|| deny(&self.action, ObjectError::EventStorage))?;
					response.headers_mut().insert(
						"x-aisp-event-cursor",
						cursor
							.parse()
							.map_err(|_| deny(&self.action, ObjectError::Push))?,
					);
					channel.check(&self.action)?;
					rpc["result"] = channel.public();
					channel.ready.store(true, Ordering::Release);
				}
			},
			Some(Operation::Delete(channel)) => {
				if !channel.closed.load(Ordering::Acquire) {
					return Err(deny(&self.action, ObjectError::Push));
				}
				authorize(self, "delete")?;
				if !error
					&& (!response.status().is_success()
						|| !gateway_a2a::push::valid_delete_result(&rpc["result"]))
				{
					return Err(deny(&self.action, ObjectError::ResponseBinding));
				}
			},
			_ => return Err(deny(&self.action, ObjectError::Push)),
		}
		for key in [
			"content-length",
			"etag",
			"content-encoding",
			"digest",
			"content-digest",
			"content-md5",
		] {
			response.headers_mut().remove(key);
		}
		response.headers_mut().insert(
			header::CACHE_CONTROL,
			"private, no-store".parse().expect("constant"),
		);
		*response.body_mut() =
			crate::json::to_body(&*rpc).map_err(|_| deny(&self.action, ObjectError::Push))?;
		Ok(())
	}
}
impl Proof {
	fn call(&self, request_id: &str) -> Result<AuthorizedCall, ProxyError> {
		let mut permit = self
			.config
			.a2a_task_store
			.begin(
				self.config.a2a_objects.as_ref().expect("enabled"),
				&self.identity,
				&self.credential.issuer,
				&self.scope,
				Some(&self.task),
				TaskOperation::Read,
			)
			.map_err(|e| deny(&self.action, e))?;
		permit
			.bind_execution(
				task_binding(
					self.execution.as_ref().map(|e| e.binding()),
					self.flow.as_ref(),
					self.guards.as_ref(),
				)?
				.as_deref(),
			)
			.map_err(|e| deny(&self.action, e))?;
		if permit.cleanup_key().map_err(|e| deny(&self.action, e))? != self.generation {
			return Err(deny(&self.action, ObjectError::Push));
		}
		let mut action = self.action.clone();
		action.request_id = request_id.into();
		let mut invocation = self.invocation.clone();
		invocation.request_id = request_id.into();
		let call = AuthorizedCall {
			push: None,
			recovery: None,
			download_guards: self.guards.clone(),
			flow: self.flow.clone(),
			execution: self.execution.clone(),
			credential: self.credential.clone(),
			invocation,
			streaming: true,
			_stream_lease: None,
			permit,
			config: self.config.clone(),
			identity: self.identity.clone(),
			rpc_id: serde_json::json!(0),
			scope: self.scope.clone(),
			action,
		};
		call.check_continuation()?;
		Ok(call)
	}
}
struct Busy(Arc<Channel>);
// A cancelled/failed receiver may have committed in spawn_blocking. Do not accept another
// callback on an uncertain channel, even when its future was dropped before returning.
struct CommitGuard {
	channel: Arc<Channel>,
	confirmed: bool,
}
impl Drop for CommitGuard {
	fn drop(&mut self) {
		if !self.confirmed {
			self.channel.closed.store(true, Ordering::Release);
		}
	}
}

impl Drop for Busy {
	fn drop(&mut self) {
		self.0.busy.store(false, Ordering::Release);
	}
}
pub(crate) async fn receive(mut req: Request) -> Result<Response, ProxyError> {
	let fallback = agent_object_for_identity(
		crate::security::request_id(req.extensions_mut()),
		GatewayIdentity::default(),
		"push-receive",
		ResourceType::Agent,
		PREFIX,
	);
	let id = req
		.uri()
		.path()
		.strip_prefix(PREFIX)
		.filter(|id| uuid::Uuid::parse_str(id).is_ok_and(|u| u.to_string() == *id))
		.ok_or_else(|| deny(&fallback, ObjectError::Push))?;
	let channel = {
		let mut registry = channels()
			.lock()
			.map_err(|_| deny(&fallback, ObjectError::Unavailable))?;
		registry.retain(|_, c| c.live());
		registry
			.get(id)
			.cloned()
			.ok_or_else(|| deny(&fallback, ObjectError::Push))?
	};
	if req.method() != http::Method::POST
		|| req.uri().query().is_some()
		|| !channel.ready.load(Ordering::Acquire)
		|| req.headers().get_all(header::AUTHORIZATION).iter().count() != 1
	{
		return Err(deny(&fallback, ObjectError::Push));
	}
	let secret = req
		.headers()
		.get(header::AUTHORIZATION)
		.and_then(|v| v.to_str().ok())
		.and_then(|v| v.strip_prefix("Bearer "))
		.filter(|s| s.len() == 64)
		.ok_or_else(|| deny(&fallback, ObjectError::Identity))?;
	if crate::security::digest(secret) != channel.secret_hash {
		return Err(deny(&fallback, ObjectError::Identity));
	}
	let loopback = req
		.extensions()
		.get::<crate::transport::stream::TCPConnectionInfo>()
		.is_some_and(|t| t.raw_peer_addr.unwrap_or(t.peer_addr).ip().is_loopback());
	if !loopback
		&& req
			.extensions()
			.get::<crate::transport::stream::TLSConnectionInfo>()
			.is_none()
	{
		return Err(deny(&fallback, ObjectError::Push));
	}
	if req
		.headers()
		.get(header::CONTENT_TYPE)
		.and_then(|v| v.to_str().ok())
		.and_then(|v| v.split(';').next())
		.map(str::trim)
		!= Some("application/json")
		|| req
			.headers()
			.get(header::CONTENT_ENCODING)
			.is_some_and(|e| e != "identity")
	{
		return Err(deny(&fallback, ObjectError::Push));
	}
	let _slot = RECEIVERS
		.get_or_init(|| Arc::new(tokio::sync::Semaphore::new(8)))
		.clone()
		.try_acquire_owned()
		.map_err(|_| deny(&fallback, ObjectError::Capacity))?;
	if channel
		.busy
		.compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
		.is_err()
	{
		return Err(deny(&fallback, ObjectError::Capacity));
	}
	let _busy = Busy(channel.clone());
	let proof = channel
		.proof
		.get()
		.ok_or_else(|| deny(&fallback, ObjectError::Push))?;
	let settings = proof
		.config
		.a2a_objects
		.as_ref()
		.and_then(|o| o.push.as_ref())
		.ok_or_else(|| deny(&fallback, ObjectError::Push))?;
	let request_id = crate::security::request_id(req.extensions_mut());
	let work = async {
		let mut call = proof.call(&request_id)?;
		authorize(&call, "receive")?;
		let bytes = axum::body::to_bytes(req.into_body(), settings.max_payload_bytes)
			.await
			.map_err(|_| deny(&call.action, ObjectError::Push))?;
		channel.check(&call.action)?;
		authorize(&call, "receive")?;
		let hash = crate::security::digest(
			std::str::from_utf8(&bytes).map_err(|_| deny(&call.action, ObjectError::Push))?,
		);
		let mut task: Value = serde_json::from_slice(&bytes)
			.map_err(|_| deny(&call.action, ObjectError::ResponseBinding))?;
		if task["kind"] != "task" {
			return Err(deny(&call.action, ObjectError::ResponseBinding));
		}
		let timestamp = task["status"]["timestamp"]
			.as_str()
			.and_then(|v| chrono::DateTime::parse_from_rfc3339(v).ok())
			.map(|d| d.timestamp_millis())
			.ok_or_else(|| deny(&call.action, ObjectError::Push))?;
		if timestamp > chrono::Utc::now().timestamp_millis() + 5000
			|| timestamp < channel.created_millis - 5000
		{
			return Err(deny(&call.action, ObjectError::Push));
		}
		{
			let last = channel
				.last
				.lock()
				.map_err(|_| deny(&call.action, ObjectError::Unavailable))?;
			if let Some((old, digest)) = &*last {
				if *digest == hash {
					return Ok(());
				}
				if timestamp <= *old {
					return Err(deny(&call.action, ObjectError::Push));
				}
			}
		}
		// Validate and project without updating Task metadata ahead of durable event admission.
		call.process_result_inner(&mut task, false)?;
		call.project_event(Some(&mut task))?;
		authorize(&call, "receive")?;
		channel.check(&call.action)?;
		let mut commit_guard = CommitGuard {
			channel: channel.clone(),
			confirmed: false,
		};
		let call = Arc::new(call);
		call.commit_push_event(task).await?;
		authorize(&call, "receive")?;
		channel.check(&call.action)?;
		*channel
			.last
			.lock()
			.map_err(|_| deny(&call.action, ObjectError::Unavailable))? = Some((timestamp, hash));
		commit_guard.confirmed = true;
		Ok(())
	};
	tokio::time::timeout(Duration::from_secs(settings.timeout_seconds), work)
		.await
		.map_err(|_| deny(&fallback, ObjectError::StreamTimeout))??;
	Ok(
		::http::Response::builder()
			.status(202)
			.header(header::CACHE_CONTROL, "private, no-store")
			.body(Body::empty())
			.expect("static response"),
	)
}
