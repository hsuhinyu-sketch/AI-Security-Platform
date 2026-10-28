//! Explicit workflow association. A context handle is never an authentication credential.
pub(crate) mod cleanup;
pub(crate) mod mcp_task_cleanup;
#[cfg(test)]
mod streaming_tests;
use crate::{
	http::{self, Request, Response},
	proxy::ProxyError,
};
use security_integration_runtime::{
	SecurityConfig, execution_budget::*, identity_binding::VerifiedOwner,
};
use security_types::{ActionRequest, ActionType, ResourceType};
use std::sync::{Arc, OnceLock};
use std::{
	pin::Pin,
	task::{Context, Poll},
	time::Instant,
};

pub(crate) const HEADER: &str = "x-aisp-execution-id";
pub(crate) const CREATE_PATH: &str = "/v1/executions";
pub(crate) const INVOCATION_PATH: &str = "/v1/executions/invocations";
pub(crate) const CANCEL_PATH: &str = "/v1/executions/cancel";
pub(crate) const INVOCATION_STATUS_PATH: &str = "/v1/executions/invocations/status";
pub(crate) fn is_control_path(path: &str) -> bool {
	matches!(
		path,
		CREATE_PATH | INVOCATION_PATH | CANCEL_PATH | INVOCATION_STATUS_PATH
	)
}
pub(crate) const INVOCATION_HEADER: &str = "x-aisp-invocation-id";
pub(crate) const OPERATION_HEADER: &str = security_capability_broker::OPERATION_HEADER;
fn store(config: &ExecutionBudgetConfig) -> Result<Arc<dyn ExecutionBudgetStore>, BudgetError> {
	if let Some(prepared) = config.prepared_store()? {
		return Ok(prepared);
	}
	// The process-global memory store retains the existing cross-route capacity boundary.
	static MEMORY: OnceLock<Arc<InMemoryExecutionBudgetStore>> = OnceLock::new();
	Ok(MEMORY.get_or_init(Default::default).clone())
}

#[derive(Clone)]
pub(crate) struct ExecutionScope {
	handle: ExecutionHandle,
	fingerprint: String,
	logical: Arc<LogicalCharge>,
	action: Arc<ActionRequest>,
}
impl std::fmt::Debug for ExecutionScope {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.debug_struct("ExecutionScope")
			.field("id_hash", &crate::security::digest(self.handle.id()))
			.finish_non_exhaustive()
	}
}
fn owner(request: &Request) -> Result<VerifiedOwner, BudgetError> {
	let issuer = request
		.extensions()
		.get::<crate::http::jwt::Claims>()
		.and_then(|c| c.inner.get("iss"))
		.and_then(|v| v.as_str())
		.ok_or(BudgetError::InvalidContext)?;
	VerifiedOwner::from_identity(
		&crate::security::identity_from_extensions(request.extensions()),
		issuer,
	)
	.map_err(|_| BudgetError::InvalidContext)
}
fn fingerprint(config: &SecurityConfig) -> Result<String, BudgetError> {
	crate::security::configuration_fingerprint(config).map_err(|_| BudgetError::InvalidContext)
}
fn operation(request: &Request, name: &str, resource: &str) -> ActionRequest {
	let mut extensions = request.extensions().clone();
	let mut action = security_pipeline::model_invoke_for_identity(
		crate::security::request_id(&mut extensions),
		crate::security::identity_from_extensions(request.extensions()),
		resource,
	);
	action.action.action_type = ActionType::ExecutionOperation;
	action.action.name = name.into();
	action.resource.resource_type = ResourceType::Execution;
	action
}
fn audit(action: &ActionRequest, result: Result<(), BudgetError>, id: Option<&str>) {
	let rule = result.err().map_or("allow", BudgetError::rule);
	audit_policy(
		action,
		result,
		format!(
			"execution-budget:{rule}:{}",
			id.map(crate::security::digest).unwrap_or_default()
		),
	);
}
fn audit_invocation(
	action: &ActionRequest,
	result: Result<(), BudgetError>,
	scope: &ExecutionScope,
	id: Option<&str>,
	phase: &str,
) {
	let outcome = result.err().map_or("allow", BudgetError::rule);
	audit_policy(
		action,
		result,
		format!(
			"execution-invocation:{phase}:{outcome}:{}:{}",
			crate::security::digest(scope.handle.id()),
			id.map(crate::security::digest).unwrap_or_default()
		),
	);
}
fn audit_policy(action: &ActionRequest, result: Result<(), BudgetError>, policy_id: String) {
	use security_audit::AuditSink;
	let decision = security_types::Decision {
		request_id: action.request_id.clone(),
		effect: if result.is_ok() {
			security_types::DecisionEffect::Allow
		} else {
			security_types::DecisionEffect::Deny
		},
		policy_id: Some(policy_id),
		policy_version: None,
		expires_at: None,
	};
	crate::security_events::UiSecurityAuditSink.record(security_audit::event_from_decision(
		uuid::Uuid::new_v4().to_string(),
		action,
		&decision,
	));
}

/// No implicit creation on missing/unknown IDs. Repeated preparation preserves request accounting.
pub(crate) fn prepare(config: &SecurityConfig, request: &mut Request) -> Result<(), ProxyError> {
	if let Some(cleanup) = request.extensions().get::<mcp_task_cleanup::Scope>() {
		return cleanup.validate(config, request);
	}
	if let Some(cleanup) = request.extensions().get::<cleanup::CleanupScope>() {
		return cleanup.validate(config, request);
	}
	let Some(budget) = &config.execution_budget else {
		return Ok(());
	};
	let result = (|| {
		// A WebSocket handshake is not a bounded execution lifetime.
		if request.headers().contains_key(::http::header::UPGRADE) {
			return Err(BudgetError::InvalidContext);
		}
		let fingerprint = fingerprint(config)?;
		let previous = request.extensions().get::<ExecutionScope>().cloned();
		let headers = request.headers().get_all(HEADER).iter().collect::<Vec<_>>();
		if headers.len() > 1 {
			return Err(BudgetError::InvalidContext);
		}
		let id = headers
			.first()
			.map(|v| v.to_str().map_err(|_| BudgetError::InvalidContext))
			.transpose()?
			.or_else(|| previous.as_ref().map(|s| s.handle.id()))
			.ok_or(BudgetError::InvalidContext)?;
		if id.is_empty()
			|| id.len() > 128
			|| previous
				.as_ref()
				.is_some_and(|s| s.handle.id() != id || s.fingerprint != fingerprint)
		{
			return Err(BudgetError::InvalidContext);
		}
		let handle = store(budget)?.resolve(id, budget, &owner(request)?, &fingerprint)?;
		Ok(ExecutionScope {
			handle,
			fingerprint,
			logical: previous.map(|p| p.logical).unwrap_or_default(),
			action: Arc::new(operation(request, "execution/use", &budget.namespace)),
		})
	})();
	if let Err(error) = &result {
		let correlation = request
			.extensions()
			.get::<ExecutionScope>()
			.map(|s| s.handle.id())
			.or_else(|| request.headers().get(HEADER).and_then(|v| v.to_str().ok()));
		audit(
			&operation(request, "execution/use", &budget.namespace),
			Err(*error),
			correlation,
		);
	}
	request
		.extensions_mut()
		.insert(result.map_err(ProxyError::ExecutionBudget)?);
	request.headers_mut().remove(HEADER);
	Ok(())
}

pub(crate) async fn create(
	config: &SecurityConfig,
	mut request: Request,
) -> Result<Response, ProxyError> {
	let budget = config
		.execution_budget
		.as_ref()
		.ok_or(ProxyError::AuthorizationFailed)?;
	if request.method() != ::http::Method::POST {
		return Err(ProxyError::MethodNotAllowed);
	}
	crate::security::request_id(request.extensions_mut());
	let action = operation(&request, "execution/create", &budget.namespace);
	crate::security::evaluate(config, &action).map_err(|_| ProxyError::AuthorizationFailed)?;
	let owner = owner(&request).map_err(ProxyError::ExecutionBudget)?;
	let fingerprint = fingerprint(config).map_err(ProxyError::ExecutionBudget)?;
	let expires = request
		.extensions()
		.get::<crate::http::jwt::Claims>()
		.and_then(|c| c.inner.get("exp"))
		.and_then(|v| v.as_i64());
	let body = tokio::time::timeout(
		std::time::Duration::from_secs(5),
		http::read_body_with_limit(request.into_body(), 1024),
	)
	.await
	.map_err(|_| ProxyError::RequestTimeout)?
	.map_err(|_| ProxyError::InvalidRequest)?;
	if expires.is_some_and(|e| e <= chrono::Utc::now().timestamp()) {
		return Err(ProxyError::ExecutionBudget(BudgetError::InvalidContext));
	}
	if !body.is_empty()
		&& serde_json::from_slice::<serde_json::Value>(&body).ok() != Some(serde_json::json!({}))
	{
		return Err(ProxyError::InvalidRequest);
	}
	let result = store(budget).and_then(|store| store.create(budget, owner, fingerprint));
	audit(
		&action,
		result.as_ref().map(|_| ()).map_err(|e| *e),
		result.as_ref().ok().map(|h| h.id()),
	);
	let handle = result.map_err(ProxyError::ExecutionBudget)?;
	Ok(::http::Response::builder().status(201).header("content-type", "application/json")
		.body(http::Body::from(serde_json::json!({"executionId":handle.id(),"expiresInSeconds":budget.max_duration_seconds}).to_string())).expect("static response"))
}

impl ExecutionScope {
	/// Same ledger/owner/config/deadline; a distinct nested logical model invocation.
	pub(crate) fn fork_call(&self) -> Self {
		Self {
			logical: Arc::new(LogicalCharge::default()),
			..self.clone()
		}
	}
	pub fn is_active(&self) -> bool {
		self.handle.check_active().is_ok()
	}
	pub fn failure(&self) -> Option<ProxyError> {
		self
			.handle
			.check_active()
			.err()
			.map(|error| self.denial(&self.action, error))
	}
	fn denial(&self, action: &ActionRequest, error: BudgetError) -> ProxyError {
		audit(
			&self.correlated_action(action),
			Err(error),
			Some(self.handle.id()),
		);
		ProxyError::ExecutionBudget(error)
	}
	/// Cooperative local stop. Dropping a future does not undo remote side effects.
	pub async fn run<F: std::future::Future>(&self, future: F) -> Result<F::Output, ProxyError> {
		self.run_for(&self.action, future).await
	}
	pub async fn run_for<F: std::future::Future>(
		&self,
		action: &ActionRequest,
		future: F,
	) -> Result<F::Output, ProxyError> {
		self
			.handle
			.check_active()
			.map_err(|e| self.denial(action, e))?;
		tokio::select! {
			biased;
			_ = self.handle.cancellation() => Err(self.denial(action, self.handle.check_active().err().unwrap_or(BudgetError::Cancelled))),
			_ = tokio::time::sleep_until(self.deadline().into()) => Err(self.deadline_denial(action)),
			result = future => {
				self.handle.check_active().map_err(|e| self.denial(action, e))?;
				Ok(result)
			}
		}
	}
	pub fn binding(&self) -> String {
		crate::security::digest(
			&serde_json::to_string(&(&self.fingerprint, self.handle.id())).expect("strings serialize"),
		)
	}
	fn correlated_action(&self, action: &ActionRequest) -> ActionRequest {
		let mut action = action.clone();
		// MCP RPC IDs are caller-owned. Budget events use the gateway HTTP request UUID.
		action.request_id = self.action.request_id.clone();
		action
	}
	pub fn timeout_error(&self) -> ProxyError {
		self.deadline_denial(&self.action)
	}
	pub fn deadline_denial(&self, action: &ActionRequest) -> ProxyError {
		self.denial(action, BudgetError::Deadline)
	}
	pub fn deadline(&self) -> Instant {
		self.handle.deadline()
	}
	pub fn reserve(
		&self,
		kind: CallKind,
		action: &ActionRequest,
	) -> Result<Box<dyn ExecutionLease>, ProxyError> {
		let result = self.handle.reserve(kind, &self.logical);
		audit(
			&self.correlated_action(action),
			result.as_ref().map(|_| ()).map_err(|e| *e),
			Some(self.handle.id()),
		);
		result.map_err(ProxyError::ExecutionBudget)
	}
}

pub(crate) async fn control(
	config: &SecurityConfig,
	request: Request,
) -> Result<Response, ProxyError> {
	match request.uri().path() {
		INVOCATION_PATH => create_invocation(config, request).await,
		CANCEL_PATH => cancel(config, request).await,
		INVOCATION_STATUS_PATH => invocation_status(config, request).await,
		CREATE_PATH => create(config, request).await,
		_ => Err(ProxyError::InvalidRequest),
	}
}

async fn cancel(config: &SecurityConfig, mut request: Request) -> Result<Response, ProxyError> {
	if request.method() != ::http::Method::POST {
		return Err(ProxyError::MethodNotAllowed);
	}
	let budget = config
		.execution_budget
		.as_ref()
		.ok_or(ProxyError::AuthorizationFailed)?;
	crate::security::request_id(request.extensions_mut());
	let action = operation(&request, "execution/cancel", &budget.namespace);
	crate::security::evaluate(config, &action).map_err(|_| ProxyError::AuthorizationFailed)?;
	let owner = owner(&request).map_err(ProxyError::ExecutionBudget)?;
	let fingerprint = fingerprint(config).map_err(ProxyError::ExecutionBudget)?;
	let ids = request.headers().get_all(HEADER).iter().collect::<Vec<_>>();
	if ids.len() != 1 {
		audit(&action, Err(BudgetError::InvalidContext), None);
		return Err(ProxyError::ExecutionBudget(BudgetError::InvalidContext));
	}
	let id = ids[0]
		.to_str()
		.ok()
		.filter(|id| !id.is_empty() && id.len() <= 128)
		.ok_or(ProxyError::ExecutionBudget(BudgetError::InvalidContext))?
		.to_owned();
	let expires = request
		.extensions()
		.get::<crate::http::jwt::Claims>()
		.and_then(|c| c.inner.get("exp"))
		.and_then(|v| v.as_i64());
	let body = tokio::time::timeout(
		std::time::Duration::from_secs(5),
		http::read_body_with_limit(request.into_body(), 1024),
	)
	.await
	.map_err(|_| ProxyError::RequestTimeout)?
	.map_err(|_| ProxyError::InvalidRequest)?;
	if expires.is_some_and(|e| e <= chrono::Utc::now().timestamp()) {
		return Err(ProxyError::ExecutionBudget(BudgetError::InvalidContext));
	}
	if !body.is_empty()
		&& serde_json::from_slice::<serde_json::Value>(&body).ok() != Some(serde_json::json!({}))
	{
		return Err(ProxyError::InvalidRequest);
	}
	// Deliberately do not prepare/reserve: exhausted or already cancelled records are cancellable.
	let result = store(budget)
		.and_then(|store| store.resolve_for_control(&id, budget, &owner, &fingerprint))
		.and_then(|h| h.cancel());
	let outcome = match &result {
		Ok(ExecutionState::Cancelled) => "cancelled",
		Ok(ExecutionState::Expired) => "expired",
		Ok(ExecutionState::Active) => "active",
		Err(e) => e.rule(),
	};
	audit_policy(
		&action,
		result.as_ref().map(|_| ()).map_err(|e| *e),
		format!(
			"execution-lifecycle:cancel:{outcome}:{}",
			crate::security::digest(&id)
		),
	);
	let state = result.map_err(ProxyError::ExecutionBudget)?;
	Ok(
		::http::Response::builder()
			.status(200)
			.header("content-type", "application/json")
			.body(http::Body::from(
				serde_json::json!({"state":state}).to_string(),
			))
			.expect("static response"),
	)
}
async fn invocation_status(
	config: &SecurityConfig,
	mut request: Request,
) -> Result<Response, ProxyError> {
	if request.method() != ::http::Method::POST {
		return Err(ProxyError::MethodNotAllowed);
	}
	let budget = config
		.execution_budget
		.as_ref()
		.ok_or(ProxyError::AuthorizationFailed)?;
	crate::security::request_id(request.extensions_mut());
	let action = operation(&request, "execution/invocation/read", &budget.namespace);
	crate::security::evaluate(config, &action).map_err(|_| ProxyError::AuthorizationFailed)?;
	let owner = owner(&request).map_err(ProxyError::ExecutionBudget)?;
	let fingerprint = fingerprint(config).map_err(ProxyError::ExecutionBudget)?;
	let ids = request.headers().get_all(HEADER).iter().collect::<Vec<_>>();
	if ids.len() != 1 {
		return Err(ProxyError::AuthorizationFailed);
	}
	let id = ids[0]
		.to_str()
		.ok()
		.filter(|s| !s.is_empty() && s.len() <= 128)
		.ok_or(ProxyError::AuthorizationFailed)?
		.to_owned();
	let expires = request
		.extensions()
		.get::<crate::http::jwt::Claims>()
		.and_then(|c| c.inner.get("exp"))
		.and_then(|v| v.as_i64())
		.ok_or(ProxyError::AuthorizationFailed)?;
	let revision = request
		.extensions()
		.get::<gateway_contracts::ConfigLease>()
		.cloned();
	let bytes = tokio::time::timeout(
		std::time::Duration::from_secs(5),
		http::read_body_with_limit(request.into_body(), 1024),
	)
	.await
	.map_err(|_| ProxyError::RequestTimeout)?
	.map_err(|_| ProxyError::InvalidRequest)?;
	#[derive(serde::Deserialize)]
	#[serde(rename_all = "camelCase", deny_unknown_fields)]
	struct Input {
		invocation_id: String,
	}
	let input: Input = serde_json::from_slice(&bytes).map_err(|_| ProxyError::InvalidRequest)?;
	if expires <= chrono::Utc::now().timestamp()
		|| revision.as_ref().is_some_and(|r| !r.is_current())
		|| uuid::Uuid::parse_str(&input.invocation_id).is_err()
	{
		return Err(ProxyError::AuthorizationFailed);
	}
	let result = store(budget)
		.and_then(|s| s.resolve_for_control(&id, budget, &owner, &fingerprint))
		.and_then(|h| h.invocation_receipt(&input.invocation_id));
	audit_policy(
		&action,
		result.as_ref().map(|_| ()).map_err(|e| *e),
		format!(
			"execution-invocation:read:{}:{}",
			crate::security::digest(&id),
			crate::security::digest(&input.invocation_id)
		),
	);
	let receipt = result.map_err(ProxyError::ExecutionBudget)?;
	Ok(
		::http::Response::builder()
			.status(200)
			.header("content-type", "application/json")
			.header("cache-control", "private, no-store")
			.body(http::Body::from(
				serde_json::json!({"invocation": receipt}).to_string(),
			))
			.expect("static response"),
	)
}
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct InvocationInput {
	server: String,
	tool: String,
	arguments: serde_json::Map<String, serde_json::Value>,
}
async fn create_invocation(
	config: &SecurityConfig,
	mut request: Request,
) -> Result<Response, ProxyError> {
	if request.method() != ::http::Method::POST {
		return Err(ProxyError::MethodNotAllowed);
	}
	prepare(config, &mut request)?;
	let scope = request
		.extensions()
		.get::<ExecutionScope>()
		.cloned()
		.ok_or(ProxyError::AuthorizationFailed)?;
	let action = operation(
		&request,
		"execution/invocation/create",
		&config
			.execution_budget
			.as_ref()
			.ok_or(ProxyError::AuthorizationFailed)?
			.namespace,
	);
	crate::security::evaluate(config, &action).map_err(|_| ProxyError::AuthorizationFailed)?;
	let expires = request
		.extensions()
		.get::<crate::http::jwt::Claims>()
		.and_then(|c| c.inner.get("exp"))
		.and_then(|v| v.as_i64());
	let bytes = tokio::time::timeout(
		std::time::Duration::from_secs(5),
		http::read_body_with_limit(request.into_body(), 65536),
	)
	.await
	.map_err(|_| ProxyError::RequestTimeout)?
	.map_err(|_| ProxyError::InvalidRequest)?;
	if expires.is_some_and(|e| e <= chrono::Utc::now().timestamp()) {
		return Err(ProxyError::ExecutionBudget(BudgetError::InvalidContext));
	}
	let input: InvocationInput =
		serde_json::from_slice(&bytes).map_err(|_| ProxyError::InvalidRequest)?;
	if input.server.is_empty()
		|| input.server.len() > 253
		|| !input
			.server
			.bytes()
			.all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'.')
		|| input.tool.is_empty()
		|| input.tool.len() > 512
		|| input.tool.trim() != input.tool
	{
		return Err(ProxyError::InvalidRequest);
	}
	let hash = security_pipeline::arguments_hash(&serde_json::Value::Object(input.arguments));
	let result = scope
		.handle
		.issue_invocation(&format!("{}/{}", input.server, input.tool), &hash);
	audit_invocation(
		&action,
		result.as_ref().map(|_| ()).map_err(|e| *e),
		&scope,
		result.as_ref().ok().map(String::as_str),
		"issue",
	);
	let id = result.map_err(ProxyError::ExecutionBudget)?;
	Ok(
		::http::Response::builder()
			.status(201)
			.header("content-type", "application/json")
			.body(http::Body::from(
				serde_json::json!({"invocationId":id}).to_string(),
			))
			.expect("static response"),
	)
}

#[derive(Debug, Clone)]
pub(crate) struct BoundInvocation {
	execution: String,
	target: String,
	arguments_hash: String,
	tracker: Option<Arc<InvocationTracker>>,
}
struct InvocationTracker {
	handle: ExecutionHandle,
	id: String,
	action: Arc<ActionRequest>,
	execution_hash: String,
	done: std::sync::atomic::AtomicBool,
	gate: std::sync::Mutex<()>,
}
impl InvocationTracker {
	fn finish(&self, receipt: InvocationReceipt) -> Result<(), BudgetError> {
		let _gate = self.gate.lock().map_err(|_| BudgetError::Unavailable)?;
		if self.done.load(std::sync::atomic::Ordering::Acquire) {
			return if receipt.state == InvocationState::Unknown
				|| self.handle.invocation_receipt(&self.id)? == receipt
			{
				Ok(())
			} else {
				Err(BudgetError::InvocationBinding)
			};
		}
		let phase = match receipt.state {
			InvocationState::Returned => "returned",
			_ => "unknown",
		};
		let result = self.handle.finish_invocation(&self.id, receipt);
		audit_policy(
			&self.action,
			result,
			format!(
				"execution-invocation:result:{phase}:{}:{}",
				self.execution_hash,
				crate::security::digest(&self.id)
			),
		);
		if result.is_ok() {
			self.done.store(true, std::sync::atomic::Ordering::Release);
		}
		result
	}
}
impl std::fmt::Debug for InvocationTracker {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.write_str("InvocationTracker { .. }")
	}
}
impl BoundInvocation {
	#[cfg(feature = "gateway-mcp")]
	pub(crate) fn accept_task(&self, task: &str) -> Result<(), ProxyError> {
		let tracker = self
			.tracker
			.as_ref()
			.ok_or(ProxyError::AuthorizationFailed)?;
		let _gate = tracker
			.gate
			.lock()
			.map_err(|_| ProxyError::AuthorizationFailed)?;
		let binding = security_pipeline::arguments_hash(&serde_json::json!((
			&self.execution,
			&self.target,
			&self.arguments_hash,
			task
		)));
		let result = tracker.handle.accept_invocation(&tracker.id, &binding);
		audit_policy(
			&tracker.action,
			result,
			format!(
				"execution-invocation:accepted:{}:{}",
				tracker.execution_hash,
				crate::security::digest(&tracker.id)
			),
		);
		result.map_err(ProxyError::ExecutionBudget)
	}
	#[cfg(feature = "gateway-mcp")]
	pub(crate) fn finish_task(&self, result: &rmcp::model::CallToolResult) -> Result<(), ProxyError> {
		let value = serde_json::to_value(result).map_err(|_| ProxyError::AuthorizationFailed)?;
		self
			.tracker
			.as_ref()
			.ok_or(ProxyError::AuthorizationFailed)?
			.finish(InvocationReceipt {
				state: InvocationState::Returned,
				result_hash: Some(security_pipeline::arguments_hash(&value)),
				tool_error: Some(result.is_error.unwrap_or(false)),
			})
			.map_err(ProxyError::ExecutionBudget)
	}
	#[cfg(feature = "gateway-mcp")]
	pub(crate) fn abandon_task(&self) {
		if let Some(tracker) = &self.tracker {
			let _ = tracker.finish(InvocationReceipt::unknown());
		}
	}
}
impl Drop for InvocationTracker {
	fn drop(&mut self) {
		if !self.done.load(std::sync::atomic::Ordering::Acquire) {
			let _ = self.finish(InvocationReceipt::unknown());
		}
	}
}
/// Record only results that have passed the protected session's RPC and business checks.
#[cfg(feature = "gateway-mcp")]
pub(crate) fn record_mcp_result(
	stream: crate::mcp::Messages,
	context: &crate::mcp::IncomingRequestContext,
	id: rmcp::model::RequestId,
) -> crate::mcp::Messages {
	use futures_util::StreamExt;
	if context
		.as_request()
		.extensions()
		.get::<crate::mcp::session_security::tasks::Ticket>()
		.is_some()
	{
		return stream; // Task adapter commits accepted/final phases only after its own binding checks.
	}
	let Some(proof) = context
		.as_request()
		.extensions()
		.get::<BoundInvocation>()
		.cloned()
	else {
		return stream;
	};
	let Some(tracker) = proof.tracker else {
		return stream;
	};
	crate::mcp::Messages::from_stream(stream.map(move |message| {
		let message = message?;
		if let rmcp::model::ServerJsonRpcMessage::Response(response) = &message
			&& response.id == id
			&& let rmcp::model::ServerResult::CallToolResult(result) = &response.result
			&& !tracker.done.load(std::sync::atomic::Ordering::Acquire)
		{
			let value = serde_json::to_value(result).map_err(|_| {
				crate::mcp::ClientError::new(anyhow::anyhow!("cannot fingerprint Tool result"))
			})?;
			tracker
				.finish(InvocationReceipt {
					state: InvocationState::Returned,
					result_hash: Some(security_pipeline::arguments_hash(&value)),
					tool_error: Some(result.is_error.unwrap_or(false)),
				})
				.map_err(|_| crate::mcp::ClientError::new(anyhow::anyhow!("cannot commit Tool receipt")))?;
		}
		Ok(message)
	}))
}
#[cfg(feature = "gateway-mcp")]
pub(crate) fn bind_mcp_invocation(
	request: &rmcp::model::JsonRpcRequest<rmcp::model::ClientRequest>,
	context: &mut crate::mcp::IncomingRequestContext,
	server: &str,
) -> Result<(), ProxyError> {
	let http = context.as_request();
	let Some(scope) = http.extensions().get::<ExecutionScope>() else {
		return Ok(());
	};
	let rmcp::model::ClientRequest::CallToolRequest(call) = &request.request else {
		return Ok(());
	};
	let target = format!("{server}/{}", call.params.name);
	let arguments_hash = security_pipeline::arguments_hash(&serde_json::Value::Object(
		call.params.arguments.clone().unwrap_or_default(),
	));
	let result = (|| {
		let values = http
			.headers()
			.get_all(INVOCATION_HEADER)
			.iter()
			.collect::<Vec<_>>();
		if values.len() != 1 {
			return Err(BudgetError::InvocationBinding);
		}
		let id = values[0]
			.to_str()
			.map_err(|_| BudgetError::InvocationBinding)?;
		scope
			.handle
			.claim_invocation(id, &target, &arguments_hash)?;
		Ok(id.to_owned())
	})();
	let action = security_pipeline::tool_invoke_for_identity(
		scope.action.request_id.clone(),
		crate::security::identity_from_extensions(http.extensions()),
		call.params.name.to_string(),
	);
	audit_invocation(
		&action,
		result.as_ref().map(|_| ()).map_err(|e| *e),
		scope,
		http
			.headers()
			.get(INVOCATION_HEADER)
			.and_then(|h| h.to_str().ok()),
		"claim",
	);
	let invocation_id = result.map_err(ProxyError::ExecutionBudget)?;
	context.extensions_mut().insert(BoundInvocation {
		execution: scope.binding(),
		target,
		arguments_hash,
		tracker: Some(Arc::new(InvocationTracker {
			handle: scope.handle.clone(),
			id: invocation_id,
			action: scope.action.clone(),
			execution_hash: crate::security::digest(scope.handle.id()),
			done: false.into(),
			gate: Default::default(),
		})),
	});
	context.headers_mut().remove(INVOCATION_HEADER);
	Ok(())
}

#[cfg(feature = "gateway-mcp")]
pub(crate) async fn verify_mcp_dispatch(
	request: &mut Request,
	scope: &ExecutionScope,
	mcp: &crate::mcp::McpEgressContext,
	proof: Option<&BoundInvocation>,
) -> Result<(), ProxyError> {
	if mcp.action.action.action_type != ActionType::ToolInvoke {
		return Ok(());
	}
	let result = async {
		let proof = proof.ok_or(BudgetError::InvocationBinding)?;
		if proof.execution != scope.binding()
			|| proof.target != format!("{}/{}", mcp.server, mcp.action.resource.id)
		{
			return Err(BudgetError::InvocationBinding);
		}
		let rpc: serde_json::Value = crate::json::inspect_body(request)
			.await
			.map_err(|_| BudgetError::InvocationBinding)?;
		if rpc["method"] != "tools/call" || rpc["params"]["name"] != mcp.action.resource.id {
			return Err(BudgetError::InvocationBinding);
		}
		let arguments = rpc["params"]
			.get("arguments")
			.cloned()
			.unwrap_or_else(|| serde_json::json!({}));
		if security_pipeline::arguments_hash(&arguments) != proof.arguments_hash {
			return Err(BudgetError::InvocationBinding);
		}
		Ok(())
	}
	.await;
	if result.is_err() {
		audit(
			&scope.correlated_action(&mcp.action),
			result,
			Some(scope.handle.id()),
		);
	}
	result.map_err(ProxyError::ExecutionBudget)?;
	// Only the final verified Tool call gets a stable key. It is correlation, not a grant;
	// the protected backend must authenticate this gateway and consume its capability.
	request.headers_mut().remove(OPERATION_HEADER);
	if let Some(proof) = proof
		&& let Some(tracker) = &proof.tracker
	{
		let key = security_pipeline::arguments_hash(&serde_json::json!((
			&proof.execution,
			&tracker.id,
			&proof.target,
			&proof.arguments_hash,
		)));
		request.headers_mut().insert(
			OPERATION_HEADER,
			::http::HeaderValue::from_str(&key).expect("hex header"),
		);
	}
	Ok(())
}

pin_project_lite::pin_project! {
	struct BudgetBody {
		handle: ExecutionHandle,
		#[pin] body: Option<http::Body>,
		#[pin] deadline: tokio::time::Sleep,
		#[pin] cancellation: ExecutionCancellation,
		lease: Option<Box<dyn ExecutionLease>>,
		action: ActionRequest,
		id: String,
	}
}
impl BudgetBody {
	/// Register stop notifications and check availability at the delivery boundary.
	fn check_available(
		self: Pin<&mut Self>,
		cx: &mut Context<'_>,
	) -> Result<(), axum_core::BoxError> {
		use std::future::Future;
		let mut this = self.project();
		if let Err(error) = this.handle.check_active() {
			audit(this.action, Err(error), Some(this.id));
			this.body.set(None);
			this.lease.take();
			return Err(std::io::Error::other("execution no longer available").into());
		}
		if this.cancellation.as_mut().poll(cx).is_ready() {
			audit(this.action, Err(BudgetError::Cancelled), Some(this.id));
			this.body.set(None);
			this.lease.take();
			return Err(
				std::io::Error::new(
					std::io::ErrorKind::Interrupted,
					"execution cancelled locally",
				)
				.into(),
			);
		}
		if this.deadline.as_mut().poll(cx).is_ready() {
			audit(this.action, Err(BudgetError::Deadline), Some(this.id));
			this.body.set(None);
			this.lease.take();
			return Err(
				std::io::Error::new(std::io::ErrorKind::TimedOut, "execution deadline exhausted").into(),
			);
		}
		Ok(())
	}
}
impl http_body::Body for BudgetBody {
	type Data = bytes::Bytes;
	type Error = axum_core::BoxError;
	fn poll_frame(
		mut self: Pin<&mut Self>,
		cx: &mut Context<'_>,
	) -> Poll<Option<Result<http_body::Frame<Self::Data>, Self::Error>>> {
		if self.body.is_none() {
			return Poll::Ready(None);
		}
		if let Err(error) = self.as_mut().check_available(cx) {
			return Poll::Ready(Some(Err(error)));
		}
		let frame = self
			.as_mut()
			.project()
			.body
			.as_pin_mut()
			.expect("active body")
			.poll_frame(cx);
		// Upstream polling can commit cancellation synchronously. Check again before
		// delivering data, trailers or successful EOF; preserve upstream errors.
		// Cancellation after this final check cannot retract an already delivered frame.
		if matches!(frame, Poll::Ready(None | Some(Ok(_))))
			&& let Err(error) = self.as_mut().check_available(cx)
		{
			return Poll::Ready(Some(Err(error)));
		}
		let mut this = self.project();
		match frame {
			Poll::Ready(None) => {
				this.body.set(None);
				this.lease.take();
				Poll::Ready(None)
			},
			Poll::Ready(Some(Err(error))) => {
				this.body.set(None);
				this.lease.take();
				Poll::Ready(Some(Err(error.into())))
			},
			other => other.map(|f| f.map(|r| r.map_err(Into::into))),
		}
	}
	fn is_end_stream(&self) -> bool {
		self.body.as_ref().is_none_or(|body| body.is_end_stream())
	}
	fn size_hint(&self) -> http_body::SizeHint {
		self
			.body
			.as_ref()
			.map_or_else(http_body::SizeHint::default, |body| body.size_hint())
	}
}
pub(crate) fn protect_response(
	response: Response,
	scope: &ExecutionScope,
	lease: Box<dyn ExecutionLease>,
	action: ActionRequest,
) -> Response {
	protect_body(response, scope, Some(lease), action)
}
/// Also guard the post-adaptation body: buffered frames must not bypass a local stop.
pub(crate) fn protect_output(response: Response, scope: &ExecutionScope) -> Response {
	protect_body(response, scope, None, scope.action.as_ref().clone())
}
fn protect_body(
	response: Response,
	scope: &ExecutionScope,
	lease: Option<Box<dyn ExecutionLease>>,
	action: ActionRequest,
) -> Response {
	response.map(|body| {
		use http_body::Body as _;
		if body.is_end_stream() {
			drop(lease);
			return body;
		}
		http::Body::new(BudgetBody {
			handle: scope.handle.clone(),
			body: Some(body),
			deadline: tokio::time::sleep_until(scope.deadline().into()),
			cancellation: scope.handle.cancellation(),
			lease,
			action: scope.correlated_action(&action),
			id: scope.handle.id().into(),
		})
	})
}
