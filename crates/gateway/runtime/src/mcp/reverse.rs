//! Opt-in 2025-era reverse RPC. IDs are gateway-owned, single-use and bound to a
//! live originating POST and verified session. Never fan out a client response.
use super::*;
use rmcp::model::{
	ClientJsonRpcMessage, ClientRequest, JsonRpcRequest, RequestId, ServerJsonRpcMessage,
};
use security_types::ResourceType;
use serde_json::{Value, json};
use std::collections::HashMap;
use std::sync::Weak;
#[path = "reverse_task_response.rs"]
mod task_response;
pub(crate) use task_response::ResponseTicket;
#[cfg(feature = "gateway-llm")]
#[path = "task_sampling.rs"]
pub(crate) mod sampling;

#[cfg(test)]
#[path = "reverse_tests.rs"]
mod tests;

#[derive(Debug, Default)]
pub(super) struct Registry {
	capabilities: Value,
	parents: HashMap<String, Weak<Parent>>,
	pending: HashMap<String, Pending>,
}
#[derive(Debug)]
pub(crate) struct Parent {
	task: Option<super::tasks::interaction::Link>,
	id: RequestId,
	server: String,
	cancelled: AtomicBool,
	live: Weak<()>,
	credential_expires: i64,
	business: Arc<(security_types::ActionRequest, Option<Value>)>,
	rbac: super::super::rbac::ResourceType,
}
impl Parent {
	fn is_live(&self) -> bool {
		self.live.strong_count() > 0
			&& self.task.as_ref().is_none_or(|t| t.live())
			&& !self.cancelled.load(Ordering::Acquire)
			&& self.credential_expires > chrono::Utc::now().timestamp()
	}
}
/// Only the originating response stream owns this lease. A response authorization
/// may retain Parent metadata, but must never extend the originating stream's life.
pub(crate) struct ParentLease {
	_task_lease: Option<Arc<super::tasks::interaction::Lease>>,
	parent: Arc<Parent>,
	_live: Arc<()>,
	binding: Weak<SessionBinding>,
}
impl Drop for ParentLease {
	fn drop(&mut self) {
		self.parent.cancelled.store(true, Ordering::Release);
		if let Some(lease) = &self._task_lease {
			lease.release();
		}
		if let Some(binding) = self.binding.upgrade()
			&& let Ok(mut state) = binding.reverse.lock()
		{
			let key = key(&self.parent.server, &self.parent.id);
			if state
				.parents
				.get(&key)
				.and_then(Weak::upgrade)
				.is_some_and(|p| Arc::ptr_eq(&p, &self.parent))
			{
				state.parents.remove(&key);
			}
			state.pending.retain(|_, p| {
				p.parent
					.upgrade()
					.is_some_and(|p| !Arc::ptr_eq(&p, &self.parent) && p.is_live())
			});
		}
	}
}
#[derive(Debug)]
struct Pending {
	parent: Weak<Parent>,
	upstream_id: Value,
	method: String,
	params: Value,
	expires: Instant,
}

fn key(server: &str, id: &RequestId) -> String {
	serde_json::to_string(&(server, id)).expect("strings serialize")
}
/// Called only for the real initialize request, never `_meta` capability updates.
pub(crate) fn negotiate(
	binding: &SessionBinding,
	config: &security_integration_runtime::mcp_sessions::McpReverseConfig,
	capabilities: &mut rmcp::model::ClientCapabilities,
) -> Result<(), ProxyError> {
	let mut value =
		serde_json::to_value(&*capabilities).map_err(|_| ProxyError::AuthorizationFailed)?;
	let map = value
		.as_object_mut()
		.ok_or(ProxyError::AuthorizationFailed)?;
	map.retain(|name, capability| match name.as_str() {
		"sampling" => cfg!(feature = "gateway-llm") && !config.sampling_models.is_empty(),
		"elicitation" => {
			config.elicitation
				&& capability
					.as_object()
					.is_some_and(|c| c.is_empty() || c.get("form").is_some_and(Value::is_object))
		},
		"roots" => !config.roots.is_empty(),
		_ => false,
	});
	// Do not advertise tools, URL elicitation, listChanged or experimental methods.
	if map.contains_key("sampling") {
		map.insert("sampling".into(), json!({}));
	}
	if map.contains_key("elicitation") {
		map.insert("elicitation".into(), json!({"form":{}}));
	}
	if map.contains_key("roots") {
		map.insert("roots".into(), json!({}));
	}
	*capabilities =
		serde_json::from_value(value.clone()).map_err(|_| ProxyError::AuthorizationFailed)?;
	binding
		.reverse
		.lock()
		.map_err(|_| ProxyError::AuthorizationFailed)?
		.capabilities = value;
	Ok(())
}

pub(crate) fn parent(
	access: &SessionAccess,
	server: &str,
	request: Option<&JsonRpcRequest<ClientRequest>>,
	business: Option<Arc<(security_types::ActionRequest, Option<Value>)>>,
) -> Result<Option<ParentLease>, ProxyError> {
	if access.limits.reverse.is_none() {
		return Ok(None);
	}
	let Some(request) = request else {
		return Ok(None);
	};
	if server.len() > 512 || security_audit::StateJournal::encoded_len(&request.id, 512).is_err() {
		return Err(access.denial("reverse-parent-id-limit"));
	}
	if !matches!(
		request.request,
		ClientRequest::CallToolRequest(_)
			| ClientRequest::GetPromptRequest(_)
			| ClientRequest::ReadResourceRequest(_)
	) {
		return Ok(None);
	}
	if security_audit::StateJournal::encoded_len(request, 16384).is_err() {
		return Err(access.denial("reverse-parent-message-limit"));
	}
	let business = business.ok_or_else(|| access.denial("reverse-parent-operation"))?;
	use super::super::rbac::{ResourceId, ResourceType as Kind};
	let rbac = match &request.request {
		ClientRequest::CallToolRequest(call) => {
			Kind::Tool(ResourceId::new(server.into(), call.params.name.to_string()))
		},
		ClientRequest::GetPromptRequest(call) => {
			Kind::Prompt(ResourceId::new(server.into(), call.params.name.clone()))
		},
		ClientRequest::ReadResourceRequest(call) => {
			Kind::Resource(ResourceId::new(server.into(), call.params.uri.clone()))
		},
		_ => return Err(access.denial("reverse-parent-operation")),
	};
	let Some(binding) = &access.binding else {
		return Err(access.denial("reverse-requires-session"));
	};
	install_parent(
		access,
		binding,
		server,
		request.id.clone(),
		business,
		rbac,
		None,
		None,
	)
	.map(Some)
}

pub(crate) fn task_parent(
	access: &SessionAccess,
	server: &str,
	request: Option<&JsonRpcRequest<ClientRequest>>,
	ticket: &super::tasks::Ticket,
) -> Result<Option<ParentLease>, ProxyError> {
	let Some(request) = request else {
		return Ok(None);
	};
	let Some((task, lease)) = super::tasks::interaction::Link::attach(ticket, access, server)? else {
		return Ok(None);
	};
	security_audit::StateJournal::encoded_len(&request.id, 512)
		.map_err(|_| access.denial("reverse-parent-id-limit"))?;
	let binding = access
		.binding
		.as_ref()
		.ok_or_else(|| access.denial("reverse-requires-session"))?;
	let business = task.business();
	let rbac = task.rbac();
	install_parent(
		access,
		binding,
		server,
		request.id.clone(),
		business,
		rbac,
		Some(task),
		Some(lease),
	)
	.map(Some)
}

fn install_parent(
	access: &SessionAccess,
	binding: &Arc<SessionBinding>,
	server: &str,
	id: RequestId,
	business: Arc<(security_types::ActionRequest, Option<Value>)>,
	rbac: super::super::rbac::ResourceType,
	task: Option<super::tasks::interaction::Link>,
	task_lease: Option<Arc<super::tasks::interaction::Lease>>,
) -> Result<ParentLease, ProxyError> {
	let mut state = binding
		.reverse
		.lock()
		.map_err(|_| access.denial("reverse-unavailable"))?;
	state
		.parents
		.retain(|_, parent| parent.upgrade().is_some_and(|p| p.is_live()));
	state
		.pending
		.retain(|_, p| p.expires > Instant::now() && p.parent.upgrade().is_some_and(|p| p.is_live()));
	let key = key(server, &id);
	if state.parents.len() >= 64 || state.parents.contains_key(&key) {
		return Err(access.denial("reverse-parent-capacity-or-duplicate"));
	}
	let live = Arc::new(());
	let parent = Arc::new(Parent {
		task,
		id,
		server: server.into(),
		cancelled: AtomicBool::new(false),
		live: Arc::downgrade(&live),
		credential_expires: access.expires,
		business,
		rbac,
	});
	state.parents.insert(key, Arc::downgrade(&parent));
	Ok(ParentLease {
		_task_lease: task_lease,
		parent,
		_live: live,
		binding: Arc::downgrade(binding),
	})
}

fn authorize(
	access: &SessionAccess,
	server: &str,
	method: &str,
	phase: &str,
) -> Result<security_types::ActionRequest, ProxyError> {
	authorize_inner(access, server, method, phase, false)
}
fn authorize_inner(
	access: &SessionAccess,
	server: &str,
	method: &str,
	phase: &str,
	managed: bool,
) -> Result<security_types::ActionRequest, ProxyError> {
	access.check()?;
	// Sampling asks the downstream client to run inference outside this process.
	// MCP server egress does not prove its actual model destination or debit this
	// workflow's model budget. Refuse protected flows until that adapter exists.
	if method == "sampling/createMessage"
		&& !managed
		&& (access.flow.is_some()
			|| access.config.data_egress.is_some()
			|| access.config.execution_budget.is_some())
	{
		return Err(access.denial("reverse-sampling-requires-model-execution-adapter"));
	}
	let action = security_pipeline::mcp_operation_for_identity(
		&access.action.request_id,
		access.identity.clone(),
		format!("{method}/{phase}"),
		ResourceType::McpServer,
		server,
	);
	crate::security::evaluate(&access.config, &action)
		.map_err(|_| access.denial("reverse-authorization"))?;
	if let Some(legacy) = &access.legacy {
		legacy
			.build(crate::security_events::UiSecurityAuditSink)
			.authorize(&action, None)
			.map_err(|_| access.denial("reverse-legacy-authorization"))?;
	}
	if let Some(flow) = &access.flow {
		flow.check(&action, server)?;
	}
	if let Some(egress) = &access.config.data_egress {
		security_integration_runtime::check_data_egress(
			egress,
			&action,
			server,
			&crate::security_events::UiSecurityAuditSink,
		)
		.map_err(|_| access.denial("reverse-egress"))?;
	}
	// A blocking PDP may have consumed the last milliseconds of a credential or
	// session lifetime. Check local state again without another remote decision.
	if access.expires <= chrono::Utc::now().timestamp()
		|| !access.revision.is_current()
		|| access.binding.as_ref().is_some_and(|b| b.expired())
	{
		return Err(access.denial("reverse-authorization-expired"));
	}
	if let Some(flow) = &access.flow {
		flow.current()?;
	}
	Ok(action)
}

fn check_business(access: &SessionAccess, parent: &Parent) -> Result<(), ProxyError> {
	let (action, args) = parent.business.as_ref();
	security_integration_runtime::evaluate_with_audit(
		&access.config,
		action,
		args.as_ref(),
		&crate::security_events::UiSecurityAuditSink,
	)
	.map_err(|_| access.denial("reverse-parent-business-authorization"))?;
	if let Some(legacy) = &access.legacy {
		legacy
			.build(crate::security_events::UiSecurityAuditSink)
			.authorize(action, args.as_ref())
			.map_err(|_| access.denial("reverse-parent-business-authorization"))?;
	}
	let cel = super::super::rbac::CelExecWrapper::new((*access.authorization_request).clone());
	if !access.policies.validate(&parent.rbac, &cel) {
		return Err(access.denial("reverse-parent-rbac"));
	}
	let destination = if action.action.action_type == security_types::ActionType::ToolInvoke {
		format!("{}/{}", parent.server, action.resource.id)
	} else {
		parent.server.clone()
	};
	if let Some(flow) = &access.flow {
		flow.check(action, &destination)?;
	}
	if let Some(egress) = &access.config.data_egress {
		security_integration_runtime::check_data_egress(
			egress,
			action,
			&destination,
			&crate::security_events::UiSecurityAuditSink,
		)
		.map_err(|_| access.denial("reverse-parent-egress"))?;
	}
	Ok(())
}

pub(crate) fn request(
	access: &SessionAccess,
	parent: Option<&ParentLease>,
	message: &mut ServerJsonRpcMessage,
) -> Result<(), ProxyError> {
	let cfg = access
		.limits
		.reverse
		.as_ref()
		.ok_or_else(|| access.denial("reverse-disabled"))?;
	let parent = parent
		.map(|p| &p.parent)
		.filter(|p| p.is_live())
		.ok_or_else(|| access.denial("reverse-no-live-parent"))?;
	let binding = access
		.binding
		.as_ref()
		.ok_or_else(|| access.denial("reverse-requires-session"))?;
	if security_audit::StateJournal::encoded_len(&*message, 16384).is_err() {
		return Err(access.denial("reverse-size"));
	}
	let mut rpc = serde_json::to_value(&*message).map_err(|_| access.denial("reverse-shape"))?;
	if security_audit::StateJournal::encoded_len(&rpc, access.limits.max_message_bytes).is_err() {
		return Err(access.denial("reverse-size"));
	}
	let method = rpc["method"]
		.as_str()
		.ok_or_else(|| access.denial("reverse-shape"))?
		.to_string();
	let params = rpc.get("params").cloned().unwrap_or_else(|| json!({}));
	if let Some(task) = &parent.task {
		if !matches!(
			method.as_str(),
			"elicitation/create" | "roots/list" | "sampling/createMessage"
		) || !task.valid_meta(&params["_meta"], true)
		{
			return Err(access.denial("task-interaction-association"));
		}
		// The SDK merges params and extension metadata when serializing. Do not let
		// conflicting in-process params metadata be hidden by an extension override.
		if let ServerJsonRpcMessage::Request(r) = &*message
			&& let rmcp::model::ServerRequest::ElicitRequest(r) = &r.request
			&& let rmcp::model::ElicitRequestParams::FormElicitationParams {
				meta: Some(meta), ..
			} = &r.params
			&& !task.valid_meta(
				&serde_json::to_value(meta).map_err(|_| access.denial("reverse-shape"))?,
				true,
			) {
			return Err(access.denial("task-elicitation-association"));
		}
		if let ServerJsonRpcMessage::Request(r) = &*message
			&& let rmcp::model::ServerRequest::CustomRequest(r) = &r.request
			&& matches!(r.method.as_str(), "roots/list" | "sampling/createMessage")
			&& !r
				.params
				.as_ref()
				.is_some_and(|p| task.valid_meta(&p["_meta"], true))
		{
			return Err(access.denial("task-reverse-association"));
		}
		task.check(access, &method, "request")?;
		check_business(access, parent)?;
	} else if params
		.get("_meta")
		.and_then(|m| m.get("io.modelcontextprotocol/related-task"))
		.is_some()
	{
		return Err(access.denial("reverse-unbound-task-association"));
	}
	let capability = match method.as_str() {
		"sampling/createMessage" => {
			if !cfg!(feature = "gateway-llm") {
				return Err(access.denial("sampling-not-compiled"));
			}
			gateway_mcp::sampling::Request::validate(
				&params,
				&cfg.sampling_models,
				cfg.max_sampling_tokens,
			)
			.map_err(|_| access.denial("reverse-sampling-contract"))?;
			"sampling"
		},
		"elicitation/create" => {
			if !cfg.elicitation
				|| !gateway_mcp::reverse::valid_form_request(&params, &cfg.elicitation_fields)
			{
				return Err(access.denial("reverse-elicitation-contract"));
			}
			"elicitation"
		},
		"roots/list" => {
			if cfg.roots.is_empty() || !gateway_mcp::reverse::valid_roots_request(&params) {
				return Err(access.denial("reverse-roots-contract"));
			}
			"roots"
		},
		_ => return Err(access.denial("reverse-unsupported-method")),
	};
	authorize_inner(
		access,
		&parent.server,
		&method,
		"request",
		parent.task.is_some() && method == "sampling/createMessage",
	)?;
	let id = uuid::Uuid::new_v4().to_string();
	let mut clean = params.clone();
	clean.as_object_mut().expect("validated").remove("_meta");
	rpc["params"] = clean;
	let upstream_id = rpc["id"].clone();
	if let Some(task) = &parent.task {
		task.claim(access, &upstream_id)?;
		rpc["params"]["_meta"] =
			json!({"io.modelcontextprotocol/related-task":{"taskId":task.gateway_id()}});
	}
	rpc["id"] = json!(id);
	let rewritten =
		crate::mcp::wire::decode_server(rpc).map_err(|_| access.denial("reverse-shape"))?;
	let mut state = binding
		.reverse
		.lock()
		.map_err(|_| access.denial("reverse-unavailable"))?;
	state
		.pending
		.retain(|_, p| p.expires > Instant::now() && p.parent.upgrade().is_some_and(|p| p.is_live()));
	if state.capabilities.get(capability).is_none()
		|| state.pending.len() >= cfg.max_pending
		|| state.pending.values().any(|p| {
			p.parent.upgrade().is_some_and(|p| Arc::ptr_eq(&p, parent)) && p.upstream_id == upstream_id
		}) {
		return Err(access.denial("reverse-not-negotiated-or-capacity"));
	}
	state.pending.insert(
		id,
		Pending {
			parent: Arc::downgrade(parent),
			upstream_id,
			method,
			params,
			expires: (Instant::now() + Duration::from_secs(cfg.timeout_seconds)).min(
				parent
					.task
					.as_ref()
					.map(|t| t.deadline())
					.unwrap_or_else(|| Instant::now() + Duration::from_secs(cfg.timeout_seconds)),
			),
		},
	);
	*message = rewritten;
	Ok(())
}

/// Consumes the correlation before network IO. Errors are projected without upstream data.
pub(crate) fn response(
	access: &SessionAccess,
	message: ClientJsonRpcMessage,
) -> Result<
	(
		String,
		ClientJsonRpcMessage,
		security_types::ActionRequest,
		Option<ResponseTicket>,
	),
	ProxyError,
> {
	response_inner(access, message, false)
}
fn response_inner(
	access: &SessionAccess,
	message: ClientJsonRpcMessage,
	managed: bool,
) -> Result<
	(
		String,
		ClientJsonRpcMessage,
		security_types::ActionRequest,
		Option<ResponseTicket>,
	),
	ProxyError,
> {
	access.check()?;
	if security_audit::StateJournal::encoded_len(&message, 16384).is_err() {
		return Err(access.denial("reverse-size"));
	}
	let cfg = access
		.limits
		.reverse
		.as_ref()
		.ok_or_else(|| access.denial("reverse-disabled"))?;
	let binding = access
		.binding
		.as_ref()
		.ok_or_else(|| access.denial("reverse-requires-session"))?;
	let mut rpc = serde_json::to_value(message).map_err(|_| access.denial("reverse-shape"))?;
	let id = rpc["id"]
		.as_str()
		.ok_or_else(|| access.denial("reverse-unknown-response"))?;
	let state = binding
		.reverse
		.lock()
		.map_err(|_| access.denial("reverse-unavailable"))?;
	let (candidate, method) = state
		.pending
		.get(id)
		.and_then(|p| p.parent.upgrade().map(|parent| (parent, p.method.clone())))
		.ok_or_else(|| access.denial("reverse-unknown-response"))?;
	drop(state);
	if method == "sampling/createMessage" && candidate.task.is_some() && !managed {
		return Err(access.denial("task-sampling-requires-gateway-result"));
	}
	// A different workflow must not consume another workflow's legitimate question.
	if let Some(task) = &candidate.task {
		task.check(access, &method, "respond")?;
	}
	let mut state = binding
		.reverse
		.lock()
		.map_err(|_| access.denial("reverse-unavailable"))?;
	let pending = state
		.pending
		.remove(id)
		.ok_or_else(|| access.denial("reverse-unknown-response"))?;
	drop(state);
	let parent = pending
		.parent
		.upgrade()
		.filter(|p| p.is_live())
		.ok_or_else(|| access.denial("reverse-parent-closed"))?;
	if pending.expires <= Instant::now() {
		return Err(access.denial("reverse-expired"));
	}
	let action = authorize_inner(access, &parent.server, &pending.method, "respond", managed)?;
	if let Some(task) = &parent.task {
		task.check(access, &pending.method, "respond")?;
		if rpc.get("error").is_some() || !task.valid_meta(&rpc["result"]["_meta"], false) {
			return Err(access.denial("task-elicitation-response-association"));
		}
	}
	check_business(access, &parent)?;
	if !parent.is_live() || pending.expires <= Instant::now() {
		return Err(access.denial("reverse-parent-closed-or-expired"));
	}
	if rpc.get("error").is_some() {
		rpc["error"] = json!({"code":-32603,"message":"Client declined reverse request"});
	} else {
		let result = &mut rpc["result"];
		let valid = match pending.method.as_str() {
			"sampling/createMessage" => {
				if !cfg!(feature = "gateway-llm") {
					return Err(access.denial("sampling-not-compiled"));
				}
				gateway_mcp::reverse::valid_sampling_response(result, &cfg.sampling_models)
			},
			"elicitation/create" => {
				gateway_mcp::reverse::valid_form_response(result, &pending.params["requestedSchema"])
			},
			"roots/list" => {
				gateway_mcp::reverse::filter_roots_response(result, &cfg.roots, parent.task.is_some())
			},
			_ => false,
		};
		if !valid {
			return Err(access.denial("reverse-response-disclosure-contract"));
		}
		result.as_object_mut().expect("validated").remove("_meta");
		if let Some(task) = &parent.task {
			result["_meta"] = json!({"io.modelcontextprotocol/related-task":{"taskId":task.upstream_id().ok_or_else(|| access.denial("task-unconfirmed"))?}});
		}
	}
	rpc["id"] = pending.upstream_id;
	let ticket = parent
		.task
		.as_ref()
		.map(|_| ResponseTicket::new(parent.clone(), pending.expires, &pending.method, &rpc));
	let message = serde_json::from_value(rpc).map_err(|_| access.denial("reverse-shape"))?;
	Ok((parent.server.clone(), message, action, ticket))
}

/// Only a currently-owned originating request may be cancelled. No unbounded fanout.
pub(crate) fn cancel(
	access: &SessionAccess,
	message: &rmcp::model::ClientNotification,
) -> Result<String, ProxyError> {
	access.check()?;
	if access.limits.reverse.is_none() {
		return Err(access.denial("reverse-disabled"));
	}
	let rpc = serde_json::to_value(message).map_err(|_| access.denial("reverse-shape"))?;
	let id: RequestId = serde_json::from_value(rpc["params"]["requestId"].clone())
		.map_err(|_| access.denial("reverse-cancel-id"))?;
	let binding = access
		.binding
		.as_ref()
		.ok_or_else(|| access.denial("reverse-requires-session"))?;
	let state = binding
		.reverse
		.lock()
		.map_err(|_| access.denial("reverse-unavailable"))?;
	let parents: Vec<_> = state
		.parents
		.values()
		.filter_map(Weak::upgrade)
		.filter(|p| p.id == id && p.is_live())
		.collect();
	drop(state);
	if parents.len() != 1 {
		return Err(access.denial("reverse-unknown-or-ambiguous-cancel"));
	}
	let parent = &parents[0];
	authorize(access, &parent.server, "notifications/cancelled", "request")?;
	if !parent.is_live() {
		return Err(access.denial("reverse-parent-closed"));
	}
	parent.cancelled.store(true, Ordering::Release);
	let mut state = binding
		.reverse
		.lock()
		.map_err(|_| access.denial("reverse-unavailable"))?;
	state
		.pending
		.retain(|_, p| p.parent.upgrade().is_some_and(|p| p.is_live()));
	Ok(parent.server.clone())
}

pub(crate) fn check_parent(
	access: &SessionAccess,
	parent: Option<&ParentLease>,
) -> Result<(), ProxyError> {
	if parent.is_some_and(|p| !p.parent.is_live()) {
		return Err(access.denial("reverse-parent-cancelled"));
	}
	Ok(())
}
