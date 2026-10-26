//! Authorized, bounded tasks/cancel only. Never returns Task content or reopens execution.
use super::*;
use crate::execution_budget::cleanup::CleanupScope;
use security_integration_runtime::task_cleanup::{
	CleanupAdmission, CleanupLease, CleanupOutcome, CleanupResult,
};

pub(crate) struct CleanupCall {
	config: Arc<SecurityConfig>,
	identity: GatewayIdentity,
	credential: TaskCredential,
	scope: CleanupScope,
	object_scope: String,
	binding: String,
	permit: TaskPermit,
	invocation: ActionRequest,
	action: ActionRequest,
	key: String,
	lease: Option<Box<dyn CleanupLease>>,
	sent: bool,
}
impl Drop for CleanupCall {
	fn drop(&mut self) {
		if let Some(mut lease) = self.lease.take() {
			let result = CleanupResult::new(if self.sent {
				CleanupOutcome::Unknown
			} else {
				CleanupOutcome::NotSent
			});
			let _ = lease.finish(result);
			self
				.scope
				.audit(&self.action, &self.key, phase(result.outcome), false);
		}
	}
}
fn phase(outcome: CleanupOutcome) -> &'static str {
	match outcome {
		CleanupOutcome::InFlight => "in-flight",
		CleanupOutcome::Confirmed => "confirmed",
		CleanupOutcome::AlreadyTerminal => "already-terminal",
		CleanupOutcome::Rejected => "rejected",
		CleanupOutcome::Unknown => "unknown",
		CleanupOutcome::NotSent => "not-sent",
	}
}
pub(crate) enum Authorization {
	Cached(Response),
	Send(Box<CleanupCall>),
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn authorize(
	config: Arc<SecurityConfig>,
	req: &mut Request,
	destination: &str,
	identity: GatewayIdentity,
	request_id: String,
	credential: Option<TaskCredential>,
	scope: CleanupScope,
	flow: Option<crate::security_flow::FlowAccess>,
	guards: Option<crate::proxy::RoutingGuards>,
) -> Result<Authorization, ProxyError> {
	scope.authorize(&config)?;
	let credential = credential.ok_or(ProxyError::AuthorizationFailed)?;
	let object_scope = request_scope(req, destination);
	let invocation = security_pipeline::agent_action_for_identity(
		&request_id,
		identity.clone(),
		destination,
		"tasks/cancel",
	);
	let action = agent_object_for_identity(
		request_id,
		identity.clone(),
		"cancel",
		ResourceType::AgentTask,
		task_resource_id(&object_scope, scope.task()),
	);
	let check = || -> Result<(), ProxyError> {
		if !credential.revision.is_current() || credential.expires_at <= chrono::Utc::now().timestamp()
		{
			return Err(deny(&action, ObjectError::CredentialExpired));
		}
		crate::security::evaluate(&config, &invocation).map_err(|_| ProxyError::AuthorizationFailed)?;
		crate::security::evaluate(&config, &action).map_err(|_| ProxyError::AuthorizationFailed)
	};
	check()?;
	// Examine the actual post-policy request, not the caller's original envelope.
	let bytes =
		crate::http::read_body_with_limit(std::mem::replace(req.body_mut(), Body::empty()), 8192)
			.await
			.map_err(|_| deny(&action, ObjectError::ResponseBinding))?;
	*req.body_mut() = Body::from(bytes.clone());
	let rpc: Value =
		serde_json::from_slice(&bytes).map_err(|_| deny(&action, ObjectError::ResponseBinding))?;
	if req.method() != ::http::Method::POST
		|| rpc != scope.rpc()
		|| req.headers().contains_key("last-event-id")
	{
		return Err(deny(&action, ObjectError::Unsupported));
	}
	let objects = config
		.a2a_objects
		.as_ref()
		.ok_or(ProxyError::AuthorizationFailed)?;
	// Read obtains the trusted snapshot, including terminal tasks, but grants no read permission.
	// Authorization above is still AgentInvoke(tasks/cancel) + AgentTaskOperation(cancel).
	let mut permit = config
		.a2a_task_store
		.begin(
			objects,
			&identity,
			&credential.issuer,
			&object_scope,
			Some(scope.task()),
			TaskOperation::Read,
		)
		.map_err(|e| deny(&action, e))?;
	if config.cross_component.is_some() && flow.is_none() {
		return Err(deny(&action, ObjectError::ExecutionBinding));
	}
	let binding = task_binding(Some(scope.binding()), flow.as_ref(), guards.as_ref())?
		.ok_or(ProxyError::AuthorizationFailed)?;
	permit
		.bind_execution(Some(&binding))
		.map_err(|e| deny(&action, e))?;
	let key = crate::security::digest(&permit.cleanup_key().map_err(|e| deny(&action, e))?);
	let terminal = permit.snapshot_state().filter(|state| state.terminal());
	scope.check()?;
	let admission = scope.ledger()?.begin(&key, terminal).map_err(|error| {
		scope.audit(&action, &key, error.rule(), false);
		ProxyError::ExecutionBudget(error)
	})?;
	match admission {
		CleanupAdmission::Existing(result) => {
			scope.audit(
				&action,
				&key,
				&format!("cached-{}", phase(result.outcome)),
				true,
			);
			Ok(Authorization::Cached(scope.receipt(result)))
		},
		CleanupAdmission::New(lease) => {
			scope.audit(&action, &key, "prepared", true);
			Ok(Authorization::Send(Box::new(CleanupCall {
				config,
				identity,
				credential,
				scope,
				object_scope,
				binding,
				permit,
				invocation,
				action,
				key,
				lease: Some(lease),
				sent: false,
			})))
		},
	}
}
impl CleanupCall {
	fn check(&self) -> Result<(), ProxyError> {
		self.scope.authorize(&self.config)?;
		if !self.credential.revision.is_current()
			|| self.credential.expires_at <= chrono::Utc::now().timestamp()
		{
			return Err(deny(&self.action, ObjectError::CredentialExpired));
		}
		crate::security::evaluate(&self.config, &self.invocation)
			.map_err(|_| ProxyError::AuthorizationFailed)?;
		crate::security::evaluate(&self.config, &self.action)
			.map_err(|_| ProxyError::AuthorizationFailed)?;
		self
			.config
			.a2a_task_store
			.validate_permit(
				self.config.a2a_objects.as_ref().expect("enabled"),
				&self.permit,
			)
			.map_err(|e| deny(&self.action, e))?;
		self.scope.check()
	}
	pub fn before_send(&mut self) -> Result<Option<Response>, ProxyError> {
		self.check()?;
		let mut latest = self
			.config
			.a2a_task_store
			.begin(
				self.config.a2a_objects.as_ref().expect("enabled"),
				&self.identity,
				&self.credential.issuer,
				&self.object_scope,
				Some(self.scope.task()),
				TaskOperation::Read,
			)
			.map_err(|e| deny(&self.action, e))?;
		latest
			.bind_execution(Some(&self.binding))
			.map_err(|e| deny(&self.action, e))?;
		if crate::security::digest(&latest.cleanup_key().map_err(|e| deny(&self.action, e))?)
			!= self.key
		{
			return Err(deny(&self.action, ObjectError::ResponseBinding));
		}
		if let Some(state) = latest.snapshot_state().filter(|state| state.terminal()) {
			return self
				.complete(CleanupResult {
					outcome: CleanupOutcome::AlreadyTerminal,
					task_state: Some(state),
				})
				.map(Some);
		}
		self.permit = latest;
		self.scope.check()?;
		self
			.lease
			.as_mut()
			.ok_or(ProxyError::AuthorizationFailed)?
			.mark_sent()
			.map_err(ProxyError::ExecutionBudget)?;
		self.sent = true;
		self.scope.audit(&self.action, &self.key, "sent", true);
		// Durable admission/audit may block: the original deadline and current credential must
		// still hold after those commits, immediately before any network attempt.
		self.scope.check()?;
		Ok(None)
	}
	fn complete(&mut self, result: CleanupResult) -> Result<Response, ProxyError> {
		self
			.lease
			.as_mut()
			.ok_or(ProxyError::AuthorizationFailed)?
			.finish(result)
			.map_err(ProxyError::ExecutionBudget)?;
		self.lease.take();
		self
			.scope
			.audit(&self.action, &self.key, phase(result.outcome), true);
		Ok(self.scope.receipt(result))
	}
	pub async fn finish(
		mut self: Box<Self>,
		response: Result<Response, impl std::fmt::Debug>,
	) -> Result<Response, ProxyError> {
		self.check()?;
		let result = match response {
			Err(_) => CleanupResult::new(CleanupOutcome::Unknown),
			Ok(response)
				if !matches!(
					crate::http::classify_content_type(response.headers()),
					crate::http::WellKnownContentTypes::Json
				) =>
			{
				CleanupResult::new(CleanupOutcome::Unknown)
			},
			Ok(response) => {
				let success = response.status().is_success();
				let rpc = crate::json::from_body_with_limit::<Value>(response.into_body(), 65536).await;
				self.check()?;
				match rpc {
					Ok(rpc) => self.process(&rpc, success),
					Err(_) => CleanupResult::new(CleanupOutcome::Unknown),
				}
			},
		};
		self.complete(result)
	}
	fn process(&mut self, rpc: &Value, success: bool) -> CleanupResult {
		let unknown = CleanupResult::new(CleanupOutcome::Unknown);
		use gateway_a2a::execution::CleanupReply;
		let state = match gateway_a2a::execution::cleanup_reply(
			rpc,
			success,
			self.scope.rpc_id(),
			self.scope.task(),
			self.permit.context_id.as_deref(),
		) {
			CleanupReply::Unknown => return unknown,
			CleanupReply::Rejected => return CleanupResult::new(CleanupOutcome::Rejected),
			CleanupReply::Terminal(state) => state,
		};
		if let Err(error) = self.config.a2a_task_store.finish(
			self.config.a2a_objects.as_ref().expect("enabled"),
			&mut self.permit,
			self.scope.task(),
			rpc["result"]["contextId"].as_str().expect("matched"),
			state,
		) {
			let _ = deny(&self.action, error);
			return unknown;
		}
		CleanupResult {
			outcome: if state == TaskState::Canceled {
				CleanupOutcome::Confirmed
			} else {
				CleanupOutcome::AlreadyTerminal
			},
			task_state: Some(state),
		}
	}
}
