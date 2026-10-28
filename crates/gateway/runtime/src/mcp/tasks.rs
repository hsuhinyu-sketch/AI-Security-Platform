//! Single-source, session-owned async Tool Tasks. No background polling, fanout or resurrection.
use super::*;
use crate::mcp::upstream::{IncomingRequestContext, UpstreamError};
use rmcp::model::{ClientRequest, GetMeta, JsonRpcRequest, ServerResult, Task, TaskStatus};
use serde_json::{Value, json};
use std::{collections::HashMap, sync::OnceLock};

const RELATED: &str = "io.modelcontextprotocol/related-task";
static GLOBAL: OnceLock<Arc<AtomicUsize>> = OnceLock::new();
static OWNERS: OnceLock<Mutex<Vec<std::sync::Weak<SessionBinding>>>> = OnceLock::new();
#[path = "task_interaction.rs"]
pub(crate) mod interaction;

#[cfg(test)]
#[path = "task_tests.rs"]
mod tests;

// Reclaim expired rows across idle sessions before taking the global admission slot.
// Weak indexing never keeps a session/config alive; no policy/network call under these locks.
fn prune_owners() -> Result<(), UpstreamError> {
	let owners = OWNERS
		.get_or_init(Default::default)
		.lock()
		.map_err(|_| UpstreamError::InvalidRequest("task owner registry unavailable".into()))?
		.clone();
	for owner in owners.into_iter().filter_map(|o| o.upgrade()) {
		if let Ok(mut state) = owner.tasks.lock() {
			state.records.retain(|_, r| !r.expired());
		}
	}
	let mut owners = OWNERS
		.get_or_init(Default::default)
		.lock()
		.map_err(|_| UpstreamError::InvalidRequest("task owner registry unavailable".into()))?;
	owners.retain(|o| {
		o.upgrade()
			.is_some_and(|b| b.tasks.try_lock().map_or(true, |r| !r.records.is_empty()))
	});
	Ok(())
}
fn register_owner(owner: &Arc<SessionBinding>) -> Result<(), UpstreamError> {
	let mut owners = OWNERS
		.get_or_init(Default::default)
		.lock()
		.map_err(|_| UpstreamError::InvalidRequest("task owner registry unavailable".into()))?;
	if !owners.iter().any(|o| o.ptr_eq(&Arc::downgrade(owner))) {
		if owners.len() >= 1024 {
			return Err(UpstreamError::InvalidRequest(
				"task owner registry capacity".into(),
			));
		}
		owners.push(Arc::downgrade(owner));
	}
	Ok(())
}

#[derive(Debug, Default)]
pub(super) struct Registry {
	source: Option<(String, bool)>,
	tools: HashMap<String, bool>,
	records: HashMap<String, Arc<Record>>,
}
struct Record {
	interaction_active: AtomicBool,
	interaction_ids: Mutex<std::collections::HashSet<String>>,
	execution: Option<crate::execution_budget::ExecutionScope>,
	budget: OnceLock<crate::execution_budget::BoundInvocation>,
	accepted: AtomicBool,
	task_metadata: Value,
	id: String,
	server: String,
	rpc: String,
	tool: String,
	arguments: Value,
	business: ActionRequest,
	guards: Option<crate::proxy::RoutingGuards>,
	expires: Instant,
	credential_expires: i64,
	upstream: OnceLock<String>,
	peer_deadline: OnceLock<Instant>,
	snapshot: Mutex<Option<Task>>,
	receipt: Mutex<Option<(TaskStatus, String)>>,
	cancel: AtomicBool,
	cancel_sent: AtomicBool,
	_slot: Arc<Slot>,
}
impl std::fmt::Debug for Record {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.debug_struct("AsyncTask")
			.field("id", &self.id)
			.finish_non_exhaustive()
	}
}
impl Record {
	fn expired(&self) -> bool {
		Instant::now() >= self.expires
			|| self
				.peer_deadline
				.get()
				.is_some_and(|e| Instant::now() >= *e)
			|| chrono::Utc::now().timestamp() >= self.credential_expires
	}
}
#[derive(Clone)]
pub(crate) struct Ticket {
	interaction: std::sync::Weak<interaction::Lease>,
	cleanup: Option<crate::execution_budget::mcp_task_cleanup::Scope>,
	attempt: Option<Arc<crate::execution_budget::mcp_task_cleanup::Attempt>>,
	record: Arc<Record>,
	method: String,
	requested_ttl: u64,
}
fn fail(access: &SessionAccess, rule: &str) -> UpstreamError {
	UpstreamError::Proxy(access.denial(rule))
}
fn access(ctx: &IncomingRequestContext) -> Result<SessionAccess, UpstreamError> {
	ctx
		.as_request()
		.extensions()
		.get::<SessionAccess>()
		.cloned()
		.ok_or_else(|| {
			UpstreamError::InvalidRequest("async Task requires a protected live session".into())
		})
}
fn binding(access: &SessionAccess) -> Result<&Arc<SessionBinding>, ProxyError> {
	access.check()?;
	if access.limits.tasks.is_none() {
		return Err(access.denial("task-unadapted-combination"));
	}
	access
		.binding
		.as_ref()
		.ok_or_else(|| access.denial("task-requires-session"))
}
pub(crate) fn observe_initialize(
	access: &SessionAccess,
	server: &str,
	init: &rmcp::model::InitializeResult,
) -> Result<(), ProxyError> {
	if access.limits.tasks.is_none() {
		return Ok(());
	}
	let binding = binding(access)?;
	let cap =
		serde_json::to_value(&init.capabilities).map_err(|_| access.denial("task-capabilities"))?;
	let supported = init.protocol_version.as_str() == "2025-11-25"
		&& cap["tasks"]["requests"]["tools"]["call"].is_object();
	let mut registry = binding
		.tasks
		.lock()
		.map_err(|_| access.denial("task-store"))?;
	if supported {
		registry.source = Some((server.into(), cap["tasks"]["cancel"].is_object()));
	}
	Ok(())
}
pub(crate) fn capabilities(access: &SessionAccess, cap: &mut rmcp::model::ServerCapabilities) {
	let source = access
		.binding
		.as_ref()
		.and_then(|b| b.tasks.lock().ok().and_then(|r| r.source.clone()));
	if access.limits.tasks.is_some()
		&& let Some((_, cancel)) = source
	{
		let value = if cancel {
			json!({"requests":{"tools":{"call":{}}},"cancel":{}})
		} else {
			json!({"requests":{"tools":{"call":{}}}})
		};
		cap.tasks = serde_json::from_value(value).ok();
	}
}
pub(crate) fn observe_tools(
	access: &SessionAccess,
	server: &str,
	list: &mut rmcp::model::ListToolsResult,
) -> Result<(), ProxyError> {
	let Some(config) = &access.limits.tasks else {
		list
			.tools
			.retain(|t| t.task_support() != rmcp::model::TaskSupport::Required);
		for tool in &mut list.tools {
			tool.execution = None;
		}
		return Ok(());
	};
	let binding = binding(access)?;
	let mut registry = binding
		.tasks
		.lock()
		.map_err(|_| access.denial("task-store"))?;
	let supported = registry.source.as_ref().is_some_and(|s| s.0 == server);
	registry.tools.clear();
	list.tools.retain_mut(|tool| {
		let allowed = supported && config.tools.iter().any(|t| t == tool.name.as_ref());
		let support = tool.task_support();
		if allowed && support != rmcp::model::TaskSupport::Forbidden {
			registry.tools.insert(
				tool.name.to_string(),
				support == rmcp::model::TaskSupport::Required,
			);
			true
		} else {
			tool.execution = None;
			support != rmcp::model::TaskSupport::Required
		}
	});
	Ok(())
}
fn operation(access: &SessionAccess, name: &str, server: &str, id: &str) -> ActionRequest {
	let mut action = security_pipeline::mcp_operation_for_identity(
		&access.action.request_id,
		access.identity.clone(),
		name,
		security_types::ResourceType::McpTask,
		security_pipeline::mcp_object_id(server, id),
	);
	action.action.action_type = security_types::ActionType::McpTaskOperation;
	action
}
impl Ticket {
	pub(crate) fn before_send(&self) -> Result<(), ProxyError> {
		if self.method == "tasks/cancel"
			&& self
				.record
				.cancel_sent
				.compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
				.is_err()
		{
			return Err(ProxyError::AuthorizationFailed);
		}
		if let Some(attempt) = &self.attempt {
			attempt.sent()?;
		}
		Ok(())
	}
	pub(crate) async fn verify_dispatch(
		&self,
		request: &mut crate::http::Request,
	) -> Result<(), ProxyError> {
		let access = request
			.extensions()
			.get::<SessionAccess>()
			.cloned()
			.ok_or(ProxyError::AuthorizationFailed)?;
		self.check(&access)?;
		let rpc: Value = crate::json::inspect_body(request)
			.await
			.map_err(|_| access.denial("task-dispatch"))?;
		if rpc["method"].as_str() != Some(&self.method) {
			return Err(access.denial("task-dispatch"));
		}
		if self.method == "tools/call" {
			if rpc["params"]["name"].as_str() != Some(&self.record.tool)
				|| rpc["params"]
					.get("arguments")
					.cloned()
					.unwrap_or_else(|| json!({}))
					!= self.record.arguments
			{
				return Err(access.denial("task-dispatch-arguments"));
			}
			if rpc["params"]
				.get("_meta")
				.and_then(|m| m.get(RELATED))
				.is_some()
				|| rpc["params"].as_object().is_none_or(|p| {
					p.keys()
						.any(|k| !matches!(k.as_str(), "name" | "arguments" | "task" | "_meta"))
				}) {
				return Err(access.denial("task-dispatch"));
			}
			if rpc["params"]["task"] != self.record.task_metadata {
				return Err(access.denial("task-dispatch"));
			}
		} else if rpc["params"]
			!= json!({"taskId": self.record.upstream.get().ok_or_else(|| access.denial("task-unconfirmed"))?})
		{
			return Err(access.denial("task-dispatch"));
		}
		self.check(&access)
	}
	fn check_execution(&self, access: &SessionAccess) -> Result<(), ProxyError> {
		if let Some(cleanup) = &self.cleanup {
			if self.method != "tasks/cancel"
				|| !self
					.record
					.execution
					.as_ref()
					.is_some_and(|e| cleanup.matches(e, &self.record.id))
			{
				return Err(access.denial("task-cleanup-binding"));
			}
			return cleanup.authorize(&access.config);
		}
		if access.config.execution_budget.is_some() != self.record.execution.is_some() {
			return Err(access.denial("task-execution-required"));
		}
		let current = access
			.authorization_request
			.extensions()
			.get::<crate::execution_budget::ExecutionScope>();
		match (&self.record.execution, current) {
			(Some(original), Some(current)) if original.binding() == current.binding() => {
				if let Some(error) = original.failure().or_else(|| current.failure()) {
					return Err(error);
				}
			},
			(None, None) => {},
			_ => return Err(access.denial("task-execution-binding")),
		}
		Ok(())
	}
	pub(super) fn check(&self, access: &SessionAccess) -> Result<(), ProxyError> {
		let binding = binding(access)?;
		self.check_execution(access)?;
		if self.record.expired()
			|| (self.record.cancel.load(Ordering::Acquire) && self.method == "tasks/result")
		{
			return Err(access.denial("task-expired-or-cancelled"));
		}
		{
			let registry = binding
				.tasks
				.lock()
				.map_err(|_| access.denial("task-store"))?;
			if !registry
				.records
				.get(&self.record.id)
				.is_some_and(|r| Arc::ptr_eq(r, &self.record))
			{
				return Err(access.denial("task-unknown"));
			}
		}
		let action = operation(access, &self.method, &self.record.server, &self.record.id);
		crate::security::evaluate(&access.config, &action)
			.map_err(|_| access.denial("task-authorization"))?;
		let transport = security_pipeline::mcp_operation_for_identity(
			&access.action.request_id,
			access.identity.clone(),
			&self.method,
			security_types::ResourceType::McpServer,
			&self.record.server,
		);
		if self.method != "tools/call" {
			crate::security::evaluate(&access.config, &transport)
				.map_err(|_| access.denial("task-transport-authorization"))?;
		}
		if self.cleanup.is_none() {
			access
				.security()
				.authorize(&self.record.business, Some(&self.record.arguments))
				.map_err(|_| access.denial("task-business-authorization"))?;
			let cel = super::super::rbac::CelExecWrapper::new((*access.authorization_request).clone());
			if !access.policies.validate(
				&super::super::rbac::ResourceType::Tool(super::super::rbac::ResourceId::new(
					self.record.server.clone(),
					self.record.tool.clone(),
				)),
				&cel,
			) {
				return Err(access.denial("task-rbac"));
			}
		}
		if let Some(flow) = &access.flow {
			if self.cleanup.is_some() {
				flow.check(&action, &self.record.server)?;
			} else {
				flow.check(
					&self.record.business,
					&format!("{}/{}", self.record.server, self.record.tool),
				)?;
			}
		}
		if let Some(guards) = &self.record.guards {
			if let Some(cleanup) = &self.cleanup {
				guards.authorize_mcp_task(&access.config, &[&action, &transport, cleanup.action()])?;
			} else {
				guards.authorize_mcp_task(&access.config, &[&self.record.business, &action])?;
			}
		}
		access.check()?;
		self.check_execution(access)?;
		if self.record.expired()
			|| (self.record.cancel.load(Ordering::Acquire) && self.method == "tasks/result")
		{
			return Err(access.denial("task-expired-or-cancelled"));
		}
		Ok(())
	}
	pub(super) fn response(
		&self,
		access: &SessionAccess,
		result: &mut ServerResult,
	) -> Result<(), ProxyError> {
		self.check(access)?;
		match (self.method.as_str(), result) {
			("tools/call", ServerResult::CreateTaskResult(created)) => {
				self.update(access, &mut created.task, true)?;
				created.meta = None;
				self.check(access)?;
				if let Some(proof) = self.record.budget.get() {
					proof.accept_task(&self.record.id)?;
				}
				self.record.accepted.store(true, Ordering::Release);
			},
			("tasks/get", ServerResult::GetTaskResult(task)) => {
				self.update(access, &mut task.task, false)?;
				task.meta = None;
			},
			("tasks/cancel", ServerResult::CancelTaskResult(task)) => {
				if task.task.status != TaskStatus::Cancelled {
					return Err(access.denial("task-cancel-not-confirmed"));
				}
				self.update(access, &mut task.task, false)?;
				task.meta = None;
				if let Some(proof) = self.record.budget.get() {
					proof.abandon_task();
				}
				if let Some(attempt) = &self.attempt {
					attempt.confirmed()?;
				}
			},
			// Untagged SDK deserialization may select GetTaskResult for a cancel result.
			("tasks/cancel", ServerResult::GetTaskResult(task)) => {
				if task.task.status != TaskStatus::Cancelled {
					return Err(access.denial("task-cancel-not-confirmed"));
				}
				self.update(access, &mut task.task, false)?;
				task.meta = None;
				if let Some(proof) = self.record.budget.get() {
					proof.abandon_task();
				}
				if let Some(attempt) = &self.attempt {
					attempt.confirmed()?;
				}
			},
			("tasks/result", ServerResult::CallToolResult(payload)) => {
				let meta = payload
					.meta
					.as_ref()
					.map(|m| serde_json::to_value(m).unwrap_or(Value::Null))
					.unwrap_or(Value::Null);
				if meta[RELATED]["taskId"].as_str() != self.record.upstream.get().map(String::as_str) {
					return Err(access.denial("task-result-binding"));
				}
				payload.meta = Some(
					serde_json::from_value(json!({RELATED:{"taskId":self.record.id}}))
						.map_err(|_| access.denial("task-result-binding"))?,
				);
				let state = if payload.is_error.unwrap_or(false) {
					TaskStatus::Failed
				} else {
					TaskStatus::Completed
				};
				let hash = security_pipeline::arguments_hash(
					&serde_json::to_value(&*payload).map_err(|_| access.denial("task-result-binding"))?,
				);
				let snapshot = self
					.record
					.snapshot
					.lock()
					.map_err(|_| access.denial("task-store"))?;
				if snapshot.as_ref().is_some_and(|s| {
					matches!(
						s.status,
						TaskStatus::Completed | TaskStatus::Failed | TaskStatus::Cancelled
					) && s.status != state
				}) {
					return Err(access.denial("task-result-state"));
				}
				let mut receipt = self
					.record
					.receipt
					.lock()
					.map_err(|_| access.denial("task-store"))?;
				if receipt
					.as_ref()
					.is_some_and(|(s, h)| s != &state || h != &hash)
				{
					return Err(access.denial("task-result-changed"));
				}
				if self.record.cancel.load(Ordering::Acquire) {
					return Err(access.denial("task-cancelled"));
				}
				if receipt.is_none()
					&& let Some(proof) = self.record.budget.get()
				{
					proof.finish_task(payload)?;
				}
				*receipt = Some((state, hash));
			},
			_ => return Err(access.denial("task-response-shape")),
		}
		self.check(access)
	}
	fn update(
		&self,
		access: &SessionAccess,
		task: &mut Task,
		create: bool,
	) -> Result<(), ProxyError> {
		if create && task.status != TaskStatus::Working {
			return Err(access.denial("task-initial-state"));
		}
		if task.created_at.len() > 64
			|| task.last_updated_at.len() > 64
			|| task.poll_interval.is_some_and(|v| v > 3_600_000)
		{
			return Err(access.denial("task-metadata-limit"));
		}
		let ttl = task
			.ttl
			.filter(|v| *v > 0 && *v <= self.requested_ttl)
			.ok_or_else(|| access.denial("task-ttl"))?;
		let created = chrono::DateTime::parse_from_rfc3339(&task.created_at)
			.map_err(|_| access.denial("task-time"))?
			.timestamp_millis();
		let updated = chrono::DateTime::parse_from_rfc3339(&task.last_updated_at)
			.map_err(|_| access.denial("task-time"))?
			.timestamp_millis();
		let now = chrono::Utc::now().timestamp_millis();
		if task.task_id.is_empty()
			|| task.task_id.len() > 512
			|| created > now + 5000
			|| updated < created
			|| updated > now + 5000
			|| now >= created.saturating_add(ttl as i64)
		{
			return Err(access.denial("task-time-or-id"));
		}
		let binding = binding(access)?;
		if create {
			let registry = binding
				.tasks
				.lock()
				.map_err(|_| access.denial("task-store"))?;
			if registry
				.records
				.values()
				.any(|r| !Arc::ptr_eq(r, &self.record) && r.upstream.get() == Some(&task.task_id))
			{
				return Err(access.denial("task-upstream-id-reuse"));
			}
			self
				.record
				.upstream
				.set(task.task_id.clone())
				.map_err(|_| access.denial("task-duplicate-response"))?;
			self
				.record
				.peer_deadline
				.set(
					Instant::now()
						+ Duration::from_millis(
							created
								.saturating_add(ttl as i64)
								.saturating_sub(now)
								.max(0) as u64,
						),
				)
				.map_err(|_| access.denial("task-duplicate-response"))?;
		} else if self.record.upstream.get() != Some(&task.task_id) {
			return Err(access.denial("task-response-binding"));
		}
		let mut previous = self
			.record
			.snapshot
			.lock()
			.map_err(|_| access.denial("task-store"))?;
		if self
			.record
			.receipt
			.lock()
			.map_err(|_| access.denial("task-store"))?
			.as_ref()
			.is_some_and(|(state, _)| state != &task.status)
		{
			return Err(access.denial("task-state-regression"));
		}
		if let Some(old) = &*previous {
			if old.created_at != task.created_at
				|| old.ttl != task.ttl
				|| updated
					< chrono::DateTime::parse_from_rfc3339(&old.last_updated_at)
						.map_err(|_| access.denial("task-time"))?
						.timestamp_millis()
				|| (matches!(
					old.status,
					TaskStatus::Completed | TaskStatus::Failed | TaskStatus::Cancelled
				) && old.status != task.status)
			{
				return Err(access.denial("task-state-regression"));
			}
		}
		task.status_message = None;
		*previous = Some(task.clone());
		task.task_id = self.record.id.clone();
		Ok(())
	}
}
/// Keeps a dropped/unconfirmed create from remaining inFlight merely because its Task row lives.
pub(crate) struct Admission(Ticket);
impl Drop for Admission {
	fn drop(&mut self) {
		if !self.0.record.accepted.load(Ordering::Acquire)
			&& let Some(proof) = self.0.record.budget.get()
		{
			proof.abandon_task();
		}
	}
}
pub(crate) fn bind_budget(ctx: &IncomingRequestContext) -> Result<Option<Admission>, ProxyError> {
	let http = ctx.as_request();
	let Some(ticket) = http.extensions().get::<Ticket>() else {
		return Ok(None);
	};
	if ticket.method != "tools/call" {
		return Ok(None);
	}
	if ticket.record.execution.is_some() {
		let proof = http
			.extensions()
			.get::<crate::execution_budget::BoundInvocation>()
			.cloned()
			.ok_or(ProxyError::AuthorizationFailed)?;
		ticket
			.record
			.budget
			.set(proof)
			.map_err(|_| ProxyError::AuthorizationFailed)?;
	}
	Ok(Some(Admission(ticket.clone())))
}
pub(crate) fn hold_admission(stream: Messages, admission: Option<Admission>) -> Messages {
	Messages::from_stream(stream.map(move |item| {
		let _keep = &admission;
		item
	}))
}
pub(crate) fn route(
	request: &mut JsonRpcRequest<ClientRequest>,
	ctx: &mut IncomingRequestContext,
) -> Result<String, UpstreamError> {
	let access = access(ctx)?;
	let binding = binding(&access)?;
	let mut value = serde_json::to_value(&*request).map_err(|_| fail(&access, "task-request"))?;
	let params = value["params"]
		.as_object_mut()
		.ok_or_else(|| fail(&access, "task-params"))?;
	if params.keys().any(|k| k != "taskId" && k != "_meta") {
		return Err(fail(&access, "task-params"));
	}
	let id = params
		.get("taskId")
		.and_then(Value::as_str)
		.filter(|s| s.len() <= 128)
		.ok_or_else(|| fail(&access, "task-id"))?;
	let record = {
		let mut registry = binding
			.tasks
			.lock()
			.map_err(|_| fail(&access, "task-store"))?;
		registry.records.retain(|_, r| !r.expired());
		registry
			.records
			.get(id)
			.cloned()
			.ok_or_else(|| fail(&access, "task-unknown"))?
	};
	let mut ticket = Ticket {
		interaction: std::sync::Weak::new(),
		cleanup: ctx
			.as_request()
			.extensions()
			.get::<crate::execution_budget::mcp_task_cleanup::Scope>()
			.cloned(),
		attempt: None,
		record,
		method: request.request.method().to_string(),
		requested_ttl: access.limits.tasks.as_ref().unwrap().max_task_seconds * 1000,
	};
	ticket.check(&access)?;
	interaction::reserve_result(&mut ticket, &access, ctx)?;
	if ticket.method == "tasks/cancel" {
		if ticket.record.cancel_sent.load(Ordering::Acquire) {
			return Err(fail(&access, "task-cancel-already-sent"));
		}
		if ticket
			.record
			.receipt
			.lock()
			.map_err(|_| fail(&access, "task-store"))?
			.is_some()
		{
			return Err(fail(&access, "task-terminal"));
		}
		if !binding
			.tasks
			.lock()
			.map_err(|_| fail(&access, "task-store"))?
			.source
			.as_ref()
			.is_some_and(|s| s.1)
		{
			return Err(fail(&access, "task-cancel-not-negotiated"));
		}
		if ticket
			.record
			.snapshot
			.lock()
			.map_err(|_| fail(&access, "task-store"))?
			.as_ref()
			.is_some_and(|t| {
				matches!(
					t.status,
					TaskStatus::Completed | TaskStatus::Failed | TaskStatus::Cancelled
				)
			}) {
			return Err(fail(&access, "task-terminal"));
		}
		let receipt = ticket
			.record
			.receipt
			.lock()
			.map_err(|_| fail(&access, "task-store"))?;
		if receipt.is_some() {
			return Err(fail(&access, "task-terminal"));
		}
		if let Some(cleanup) = &ticket.cleanup {
			ticket.attempt = Some(Arc::new(cleanup.begin()?));
		}
		ticket.record.cancel.store(true, Ordering::Release);
		drop(receipt);
	}
	params.remove("_meta");
	params.insert(
		"taskId".into(),
		json!(
			ticket
				.record
				.upstream
				.get()
				.ok_or_else(|| fail(&access, "task-unconfirmed"))?
		),
	);
	*request = serde_json::from_value(value).map_err(|_| fail(&access, "task-request"))?;
	let server = ticket.record.server.clone();
	ctx.extensions_mut().insert(ticket);
	Ok(server)
}
pub(crate) fn prepare(
	request: &JsonRpcRequest<ClientRequest>,
	ctx: &mut IncomingRequestContext,
	server: &str,
	guardrails: bool,
) -> Result<(), UpstreamError> {
	let ClientRequest::CallToolRequest(call) = &request.request else {
		return Ok(());
	};
	// rmcp moves wire `_meta` into Request.extensions during deserialization.
	// Params can also carry metadata added by an in-process policy processor.
	if request.request.get_meta().get(RELATED).is_some()
		|| call
			.params
			.meta
			.as_ref()
			.is_some_and(|meta| meta.get(RELATED).is_some())
	{
		return Err(UpstreamError::InvalidRequest(
			"caller cannot attach a Tool call to an existing task".into(),
		));
	}
	if call.params.task.is_none() {
		if let Ok(access) = access(ctx)
			&& let Some(binding) = &access.binding
			&& binding
				.tasks
				.lock()
				.map_err(|_| fail(&access, "task-store"))?
				.tools
				.get(call.params.name.as_ref())
				== Some(&true)
		{
			return Err(fail(&access, "task-required"));
		}
		return Ok(());
	}
	let access = access(ctx)?;
	let binding = binding(&access)?;
	if guardrails {
		return Err(fail(&access, "task-external-guardrails-unadapted"));
	}
	let limits = access.limits.tasks.as_ref().unwrap();
	let args = Value::Object(call.params.arguments.clone().unwrap_or_default());
	if security_audit::StateJournal::encoded_len(&access.action, 4096).is_err() {
		return Err(fail(&access, "task-owner-limit"));
	}
	if security_audit::StateJournal::encoded_len(&args, limits.max_argument_bytes).is_err()
		|| security_audit::StateJournal::encoded_len(&request.id, 512).is_err()
	{
		return Err(fail(&access, "task-argument-limit"));
	}
	let requested = call
		.params
		.task
		.as_ref()
		.and_then(|t| t.ttl)
		.unwrap_or(limits.max_task_seconds * 1000);
	if requested == 0 || requested > limits.max_task_seconds * 1000 {
		return Err(fail(&access, "task-ttl"));
	}
	prune_owners()?;
	let mut registry = binding
		.tasks
		.lock()
		.map_err(|_| fail(&access, "task-store"))?;
	registry.records.retain(|_, r| !r.expired());
	if !registry.source.as_ref().is_some_and(|s| s.0 == server)
		|| !registry.tools.contains_key(call.params.name.as_ref())
	{
		return Err(fail(&access, "task-not-negotiated"));
	}
	if registry.records.len() >= limits.max_tasks
		|| registry
			.records
			.values()
			.any(|r| r.rpc == request.id.to_string())
	{
		return Err(fail(&access, "task-capacity-or-duplicate"));
	}
	let slot = reserve(GLOBAL.get_or_init(Default::default), 1024)
		.ok_or_else(|| fail(&access, "task-global-capacity"))?;
	let id = uuid::Uuid::new_v4().to_string();
	let record = Arc::new(Record {
		interaction_active: AtomicBool::new(false),
		interaction_ids: Mutex::new(Default::default()),
		execution: ctx
			.as_request()
			.extensions()
			.get::<crate::execution_budget::ExecutionScope>()
			.cloned(),
		budget: OnceLock::new(),
		accepted: AtomicBool::new(false),
		task_metadata: serde_json::to_value(&call.params.task)
			.map_err(|_| fail(&access, "task-metadata"))?,
		id: id.clone(),
		server: server.into(),
		rpc: request.id.to_string(),
		tool: call.params.name.to_string(),
		arguments: args,
		business: security_pipeline::tool_invoke_for_identity(
			&access.action.request_id,
			access.identity.clone(),
			call.params.name.to_string(),
		),
		guards: ctx
			.as_request()
			.extensions()
			.get::<crate::proxy::RoutingGuards>()
			.cloned(),
		expires: Instant::now() + Duration::from_millis(requested),
		credential_expires: access.expires,
		upstream: OnceLock::new(),
		peer_deadline: OnceLock::new(),
		snapshot: Mutex::new(None),
		receipt: Mutex::new(None),
		cancel: AtomicBool::new(false),
		cancel_sent: AtomicBool::new(false),
		_slot: slot,
	});
	registry.records.insert(id, record.clone());
	drop(registry);
	if let Err(error) = register_owner(binding) {
		binding
			.tasks
			.lock()
			.map_err(|_| fail(&access, "task-store"))?
			.records
			.remove(&record.id);
		return Err(error);
	}
	let ticket = Ticket {
		interaction: std::sync::Weak::new(),
		cleanup: None,
		attempt: None,
		record,
		method: "tools/call".into(),
		requested_ttl: requested,
	};
	if let Err(error) = ticket.check(&access) {
		binding
			.tasks
			.lock()
			.map_err(|_| fail(&access, "task-store"))?
			.records
			.remove(&ticket.record.id);
		return Err(UpstreamError::Proxy(error));
	}
	ctx.extensions_mut().insert(ticket);
	Ok(())
}
