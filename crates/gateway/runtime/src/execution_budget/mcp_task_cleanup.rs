//! One explicit, independently authorized cancellation on the original live MCP session.
use super::*;
use futures_util::StreamExt;
use security_integration_runtime::task_cleanup::{
	CleanupAdmission, CleanupLease, CleanupOutcome, CleanupResult,
};
pub(crate) const HEADER: &str = "x-aisp-mcp-task-cleanup";
#[derive(Clone)]
pub(crate) struct Scope {
	handle: ExecutionHandle,
	fingerprint: String,
	owner: VerifiedOwner,
	task: String,
	deadline: Instant,
	expires: i64,
	revision: crate::a2a::revision::ConfigLease,
	action: Arc<ActionRequest>,
}
pub(crate) async fn prepare(
	config: &SecurityConfig,
	request: &mut Request,
) -> Result<(), ProxyError> {
	if !config
		.mcp_sessions
		.as_ref()
		.is_some_and(|s| s.tasks.is_some())
		|| request.method() != ::http::Method::POST
		|| request.headers().get_all(HEADER).iter().count() != 1
		|| request.headers().get(HEADER).is_none_or(|h| h != "cancel")
		|| request.headers().get_all("mcp-session-id").iter().count() != 1
		|| request.headers().contains_key(::http::header::UPGRADE)
		|| request
			.headers()
			.contains_key(::http::header::CONTENT_ENCODING)
		|| request.extensions().get::<ExecutionScope>().is_some()
		|| is_control_path(request.uri().path())
	{
		return Err(ProxyError::AuthorizationFailed);
	}
	let budget = config
		.execution_budget
		.as_ref()
		.ok_or(ProxyError::AuthorizationFailed)?;
	let limits = budget
		.task_cleanup
		.as_ref()
		.ok_or(ProxyError::AuthorizationFailed)?;
	let action = operation(request, "execution/mcp-task/cancel", &budget.namespace);
	crate::security::evaluate(config, &action).map_err(|_| ProxyError::AuthorizationFailed)?;
	let fingerprint = fingerprint(config).map_err(ProxyError::ExecutionBudget)?;
	let owner = owner(request).map_err(ProxyError::ExecutionBudget)?;
	if request.headers().get_all(super::HEADER).iter().count() != 1 {
		return Err(ProxyError::AuthorizationFailed);
	}
	let id = request
		.headers()
		.get(super::HEADER)
		.and_then(|h| h.to_str().ok())
		.filter(|s| !s.is_empty() && s.len() <= 128)
		.ok_or(ProxyError::AuthorizationFailed)?;
	let handle = store(budget)
		.and_then(|s| s.resolve_for_control(id, budget, &owner, &fingerprint))
		.map_err(ProxyError::ExecutionBudget)?;
	handle.cleanup().map_err(ProxyError::ExecutionBudget)?;
	let deadline = handle
		.cleanup_deadline()
		.map_err(ProxyError::ExecutionBudget)?
		.min(Instant::now() + std::time::Duration::from_secs(limits.timeout_seconds));
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
	#[derive(serde::Deserialize)]
	#[serde(deny_unknown_fields)]
	struct Input {
		jsonrpc: String,
		id: serde_json::Value,
		method: String,
		params: Params,
	}
	#[derive(serde::Deserialize)]
	#[serde(deny_unknown_fields, rename_all = "camelCase")]
	struct Params {
		task_id: String,
	}
	let input: Input = serde_json::from_slice(&bytes).map_err(|_| ProxyError::InvalidRequest)?;
	if input.jsonrpc != "2.0"
		|| input.method != "tasks/cancel"
		|| !(input.id.is_string() || input.id.is_number())
		|| uuid::Uuid::parse_str(&input.params.task_id).is_err()
	{
		return Err(ProxyError::AuthorizationFailed);
	}
	let scope = Scope {
		handle,
		fingerprint,
		owner,
		task: input.params.task_id,
		deadline,
		expires: request
			.extensions()
			.get::<crate::http::jwt::Claims>()
			.and_then(|c| c.inner.get("exp"))
			.and_then(|e| e.as_i64())
			.ok_or(ProxyError::AuthorizationFailed)?,
		revision: request
			.extensions()
			.get::<crate::a2a::revision::ConfigLease>()
			.cloned()
			.ok_or(ProxyError::AuthorizationFailed)?,
		action: Arc::new(action),
	};
	scope.check()?;
	*request.body_mut() = http::Body::from(bytes);
	for header in [HEADER, super::HEADER, INVOCATION_HEADER, "content-length"] {
		request.headers_mut().remove(header);
	}
	request.extensions_mut().insert(scope);
	Ok(())
}
impl Scope {
	pub(crate) fn action(&self) -> &ActionRequest {
		&self.action
	}
	pub(crate) fn binding(&self) -> String {
		crate::security::digest(
			&serde_json::to_string(&(&self.fingerprint, self.handle.id())).expect("strings"),
		)
	}
	pub(crate) fn matches(&self, execution: &ExecutionScope, task: &str) -> bool {
		self.binding() == execution.binding() && task == self.task
	}
	pub(crate) fn check(&self) -> Result<(), ProxyError> {
		if Instant::now() >= self.deadline
			|| self.expires <= chrono::Utc::now().timestamp()
			|| !self.revision.is_current()
		{
			return Err(ProxyError::AuthorizationFailed);
		}
		self.handle.cleanup().map_err(ProxyError::ExecutionBudget)?;
		Ok(())
	}
	pub(crate) fn authorize(&self, config: &SecurityConfig) -> Result<(), ProxyError> {
		self.check()?;
		if fingerprint(config).map_err(ProxyError::ExecutionBudget)? != self.fingerprint {
			return Err(ProxyError::AuthorizationFailed);
		}
		crate::security::evaluate(config, &self.action).map_err(|_| ProxyError::AuthorizationFailed)?;
		self.check()
	}
	pub(crate) fn validate(
		&self,
		config: &SecurityConfig,
		request: &Request,
	) -> Result<(), ProxyError> {
		self.authorize(config)?;
		if owner(request).map_err(ProxyError::ExecutionBudget)? != self.owner
			|| request.headers().contains_key(super::HEADER)
		{
			return Err(ProxyError::AuthorizationFailed);
		}
		Ok(())
	}
	pub(crate) fn begin(&self) -> Result<Attempt, ProxyError> {
		self.check()?;
		let key = crate::security::digest(&format!("mcp:{}:{}", self.binding(), self.task));
		match self
			.handle
			.cleanup()
			.and_then(|l| l.begin(&key, None))
			.map_err(ProxyError::ExecutionBudget)?
		{
			CleanupAdmission::New(lease) => Ok(Attempt {
				lease: std::sync::Mutex::new(lease),
				scope: self.clone(),
			}),
			CleanupAdmission::Existing(_) => Err(ProxyError::AuthorizationFailed), // never redispatch an uncertain cancellation
		}
	}
	pub(crate) async fn run<F: std::future::Future>(
		&self,
		future: F,
	) -> Result<F::Output, ProxyError> {
		self.check()?;
		let result = tokio::time::timeout_at(self.deadline.into(), future)
			.await
			.map_err(|_| ProxyError::RequestTimeout)?;
		self.check()?;
		Ok(result)
	}
	pub(crate) fn protect(&self, response: Response) -> Response {
		let scope = self.clone();
		response.map(|body| {
			http::Body::from_stream(futures_util::stream::try_unfold(
				(body.into_data_stream(), scope),
				|(mut body, scope)| async move {
					let item = scope.run(body.next()).await?;
					scope.check()?;
					match item {
						None => Ok::<_, ProxyError>(None),
						Some(item) => Ok(Some((
							item.map_err(|_| ProxyError::AuthorizationFailed)?,
							(body, scope),
						))),
					}
				},
			))
		})
	}
}
pub(crate) struct Attempt {
	lease: std::sync::Mutex<Box<dyn CleanupLease>>,
	scope: Scope,
}
impl Attempt {
	pub(crate) fn sent(&self) -> Result<(), ProxyError> {
		self.scope.check()?;
		self
			.lease
			.lock()
			.map_err(|_| ProxyError::AuthorizationFailed)?
			.mark_sent()
			.map_err(ProxyError::ExecutionBudget)
	}
	pub(crate) fn confirmed(&self) -> Result<(), ProxyError> {
		self.scope.check()?;
		self
			.lease
			.lock()
			.map_err(|_| ProxyError::AuthorizationFailed)?
			.finish(CleanupResult {
				outcome: CleanupOutcome::Confirmed,
				task_state: Some(security_integration_runtime::a2a_objects::TaskState::Canceled),
			})
			.map_err(ProxyError::ExecutionBudget)
	}
}
