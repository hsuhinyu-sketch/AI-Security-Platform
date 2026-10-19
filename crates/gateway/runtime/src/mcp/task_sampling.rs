//! Gateway-managed text sampling. No downstream result is an execution receipt.
use super::*;
use crate::mcp::upstream::{IncomingRequestContext, UpstreamGroup};
use crate::proxy::httpproxy::LocalDispatch;
use headers::HeaderMapExt;
use std::sync::OnceLock;

pub(crate) struct Transport {
	pub upstreams: Arc<UpstreamGroup>,
	pub context: IncomingRequestContext,
}
struct State {
	model: OnceLock<String>,
	sent: AtomicBool,
}
#[derive(Clone)]
pub(crate) struct ModelCall {
	parent: Arc<Parent>,
	access: SessionAccess,
	max_tokens: u64,
	state: Arc<State>,
}
impl ModelCall {
	fn check(&self) -> Result<(), ProxyError> {
		if !self.parent.is_live() {
			return Err(self.access.denial("task-sampling-parent-closed"));
		}
		let task = self
			.parent
			.task
			.as_ref()
			.ok_or(ProxyError::AuthorizationFailed)?;
		for phase in ["request", "respond"] {
			task.check(&self.access, "sampling/createMessage", phase)?;
			authorize_inner(
				&self.access,
				&self.parent.server,
				"sampling/createMessage",
				phase,
				true,
			)?;
		}
		check_business(&self.access, &self.parent)
	}
	pub(crate) async fn verify(
		&self,
		req: &mut crate::http::Request,
		policies: &crate::store::BackendPolicies,
	) -> Result<(), ProxyError> {
		self.check()?;
		let active = policies
			.security_audit
			.as_ref()
			.ok_or(ProxyError::AuthorizationFailed)?;
		let route_config = serde_json::to_value(active).map_err(|_| ProxyError::AuthorizationFailed)?;
		let task_config =
			serde_json::to_value(&self.access.config).map_err(|_| ProxyError::AuthorizationFailed)?;
		if route_config != task_config
			|| active.execution_budget.is_none()
			|| req
				.extensions()
				.get::<crate::execution_budget::ExecutionScope>()
				.is_none()
			|| !policies
				.llm_provider
				.as_ref()
				.is_some_and(|p| matches!(p.provider, crate::llm::AIProvider::OpenAI(_)))
		{
			return Err(self.access.denial("task-sampling-model-route-contract"));
		}
		let body: Value = crate::json::inspect_body(req)
			.await
			.map_err(|_| self.access.denial("task-sampling-model-body"))?;
		let tokens = body
			.get("max_tokens")
			.or_else(|| body.get("max_completion_tokens"))
			.and_then(Value::as_u64);
		let model = body["model"]
			.as_str()
			.filter(|m| !m.is_empty() && m.len() <= 128)
			.ok_or(ProxyError::AuthorizationFailed)?;
		if req.method() != http::Method::POST
			|| security_audit::StateJournal::encoded_len(&body, 32768).is_err()
			|| !self
				.access
				.limits
				.reverse
				.as_ref()
				.is_some_and(|r| r.sampling_models.iter().any(|m| m == model))
			|| !allowed(
				&body,
				&[
					"model",
					"messages",
					"max_tokens",
					"max_completion_tokens",
					"stream",
					"stop",
				],
			) || body.get("stream").is_some_and(|v| v != false)
			|| (body.get("max_tokens").is_some() && body.get("max_completion_tokens").is_some())
			|| !tokens.is_some_and(|n| n > 0 && n <= self.max_tokens)
			|| !body["messages"].as_array().is_some_and(|a| {
				!a.is_empty()
					&& a.len() <= 17
					&& a.iter().all(|m| {
						allowed(m, &["role", "content"])
							&& matches!(m["role"].as_str(), Some("system" | "user" | "assistant"))
							&& bounded_text(&m["content"], 8192)
					})
			}) || self.state.model.set(model.into()).is_err()
		{
			return Err(self.access.denial("task-sampling-final-model-request"));
		}
		self.check()
	}
	pub(crate) fn before_send(&self) -> Result<(), ProxyError> {
		self.check()?;
		if self.state.model.get().is_none() || self.state.sent.swap(true, Ordering::AcqRel) {
			return Err(self.access.denial("task-sampling-model-replay"));
		}
		Ok(())
	}
}
pub(crate) fn is_request(message: &ServerJsonRpcMessage) -> bool {
	serde_json::to_value(message)
		.ok()
		.is_some_and(|v| v["method"] == "sampling/createMessage")
}

pub(crate) async fn execute(
	access: &SessionAccess,
	parent: Option<&ParentLease>,
	message: &ServerJsonRpcMessage,
	transport: Option<&Transport>,
) -> Result<(), ProxyError> {
	let parent = parent
		.map(|p| p.parent.clone())
		.ok_or(ProxyError::AuthorizationFailed)?;
	let transport = transport.ok_or_else(|| access.denial("task-sampling-no-dispatcher"))?;
	let http = transport.context.as_request();
	let dispatch = http
		.extensions()
		.get::<LocalDispatch>()
		.cloned()
		.ok_or_else(|| access.denial("task-sampling-no-dispatcher"))?;
	let scope = http
		.extensions()
		.get::<crate::execution_budget::ExecutionScope>()
		.cloned()
		.ok_or(ProxyError::AuthorizationFailed)?;
	let cfg = access
		.limits
		.tasks
		.as_ref()
		.and_then(|t| t.sampling.as_ref())
		.ok_or(ProxyError::AuthorizationFailed)?;
	let rpc = serde_json::to_value(message).map_err(|_| access.denial("reverse-shape"))?;
	let params = &rpc["params"];
	if !params["modelPreferences"]["hints"]
		.as_array()
		.is_some_and(|a| a.iter().all(|h| h["name"] == cfg.model))
	{
		return Err(access.denial("task-sampling-fixed-model"));
	}
	let mut messages = Vec::new();
	if let Some(system) = params.get("systemPrompt") {
		messages.push(json!({"role":"system","content":system}));
	}
	for m in params["messages"]
		.as_array()
		.ok_or(ProxyError::AuthorizationFailed)?
	{
		messages.push(json!({"role":m["role"],"content":m["content"]["text"]}));
	}
	let mut body =
		json!({"model":cfg.model,"messages":messages,"max_tokens":params["maxTokens"],"stream":false});
	if let Some(stop) = params.get("stopSequences") {
		body["stop"] = stop.clone();
	}
	let proof = ModelCall {
		parent: parent.clone(),
		access: access.clone(),
		max_tokens: params["maxTokens"]
			.as_u64()
			.ok_or(ProxyError::AuthorizationFailed)?,
		state: Arc::new(State {
			model: OnceLock::new(),
			sent: AtomicBool::new(false),
		}),
	};
	proof.check()?;
	let mut request = ::http::Request::builder()
		.method("POST")
		.uri(format!("http://{}{}", cfg.authority, cfg.path))
		.header("content-type", "application/json")
		.header("accept", "application/json")
		.body(crate::json::to_body(body).map_err(|_| ProxyError::AuthorizationFailed)?)
		.map_err(|_| ProxyError::AuthorizationFailed)?;
	// Only the verified caller credential crosses into the local route; never copy MCP,
	// capability, arbitrary forwarding headers, original invocation or request extensions.
	let authorization = dispatch
		.authorization()
		.ok_or_else(|| access.denial("task-sampling-caller-credential-unavailable"))?;
	request
		.headers_mut()
		.insert(http::header::AUTHORIZATION, authorization);
	request.extensions_mut().insert(scope.fork_call());
	request.extensions_mut().insert(proof.clone());
	if let Some(guards) = parent.task.as_ref().and_then(|task| task.model_guards()) {
		request.extensions_mut().insert(guards);
	}
	let model_request_id = crate::security::request_id(request.extensions_mut());
	parent
		.task
		.as_ref()
		.ok_or(ProxyError::AuthorizationFailed)?
		.correlate_model(access, model_request_id)?;
	request.extensions_mut().insert(access.revision.clone());
	if let Some(flow) = &access.flow {
		request.extensions_mut().insert(flow.clone());
	}
	let timeout = access
		.limits
		.reverse
		.as_ref()
		.ok_or(ProxyError::AuthorizationFailed)?
		.timeout_seconds;
	let deadline = (Instant::now() + Duration::from_secs(timeout)).min(
		parent
			.task
			.as_ref()
			.ok_or(ProxyError::AuthorizationFailed)?
			.deadline(),
	);
	let generation = async {
		let response = dispatch.call(request).await?;
		if response.status() != http::StatusCode::OK || !proof.state.sent.load(Ordering::Acquire) {
			return Err(access.denial("task-sampling-model-failed"));
		}
		if !response
			.headers()
			.get(http::header::CONTENT_TYPE)
			.and_then(|h| h.to_str().ok())
			.is_some_and(|s| s.starts_with("application/json"))
		{
			return Err(access.denial("task-sampling-model-format"));
		}
		let encoding = response.headers().typed_get::<headers::ContentEncoding>();
		let bytes = crate::http::compression::to_bytes_with_decompression(
			response.into_body(),
			encoding.as_ref(),
			65536,
		)
		.await
		.map_err(|_| access.denial("task-sampling-output-limit"))?
		.1;
		let generated: Value =
			serde_json::from_slice(&bytes).map_err(|_| access.denial("task-sampling-output-shape"))?;
		let choice = &generated["choices"][0];
		if !generated["choices"]
			.as_array()
			.is_some_and(|c| c.len() == 1)
			|| choice["message"]["role"] != "assistant"
			|| !bounded_text(&choice["message"]["content"], 8192)
			|| choice["message"].get("tool_calls").is_some()
			|| choice["message"].get("function_call").is_some()
			|| !matches!(choice["finish_reason"].as_str(), Some("stop" | "length"))
		{
			return Err(access.denial("task-sampling-output-shape"));
		}
		proof.check()?;
		let model = proof
			.state
			.model
			.get()
			.ok_or(ProxyError::AuthorizationFailed)?;
		let result = json!({"role":"assistant","model":model,"content":{"type":"text","text":choice["message"]["content"]},"stopReason":if choice["finish_reason"]=="length" {"maxTokens"} else {"endTurn"},"_meta":params["_meta"]});
		let answer = serde_json::from_value(json!({"jsonrpc":"2.0","id":rpc["id"],"result":result}))
			.map_err(|_| access.denial("task-sampling-output-shape"))?;
		let (server, answer, action, ticket) = response_inner(access, answer, true)?;
		let ticket = ticket.ok_or(ProxyError::AuthorizationFailed)?;
		let mut context = transport.context.clone();
		context
			.extensions_mut()
			.remove::<super::super::tasks::Ticket>();
		context
			.extensions_mut()
			.remove::<crate::execution_budget::BoundInvocation>();
		context
			.extensions_mut()
			.remove::<Arc<super::super::tasks::interaction::Lease>>();
		context.extensions_mut().insert(ticket.clone());
		context
			.extensions_mut()
			.insert(crate::mcp::security::McpEgressContext {
				server: server.clone(),
				action,
				supported: true,
			});
		let send = transport
			.upstreams
			.get(&server)
			.map_err(|_| ProxyError::AuthorizationFailed)?
			.generic_response(answer, &context);
		ticket
			.run(send)
			.await
			.map_err(|_| access.denial("task-sampling-reply-failed"))?;
		Ok(())
	};
	// No spawned producer or unbounded queue. Dropping the result body drops inference.
	let run = async {
		let mut revision = access.revision.clone();
		tokio::pin!(generation);
		loop {
			tokio::select! {
				biased;
				_ = revision.changed() => return Err(access.denial("task-sampling-config-changed")),
				_ = tokio::time::sleep_until(deadline.into()) => return Err(access.denial("task-sampling-timeout")),
				_ = tokio::time::sleep(Duration::from_secs(access.limits.reauthorize_seconds)) => { proof.check()?; },
				result = &mut generation => return result,
			}
		}
	};
	scope.run(run).await?
}
