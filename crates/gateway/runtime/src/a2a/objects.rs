//! Fail-closed JSON-RPC v0.3 Task/Artifact adapter.
pub(crate) mod cleanup;
mod downloads;
pub(crate) mod push;
pub(crate) mod recovery;
mod streaming;
use std::sync::Arc;

use security_integration_runtime::a2a_objects::{
	ObjectError, StoreLease, TaskOperation, TaskPermit, TaskState, artifact_resource_id,
	audit_object_check, endpoint_scope, task_resource_id,
};
use security_integration_runtime::{SecurityConfig, SecurityMode};
use security_pipeline::{GatewayIdentity, agent_object_for_identity};
use security_types::{ActionRequest, ResourceType};
use serde_json::Value;

use crate::http::{Body, Request, Response, header};
use crate::proxy::ProxyError;
use crate::security_events::UiSecurityAuditSink;

use gateway_a2a::RequestEnvelope as Rpc;
/// Only extracted from the JWT validator's verified Claims extension, never headers/JSON.
#[derive(Clone)]
pub(crate) struct TaskCredential {
	revision: gateway_contracts::ConfigLease,
	issuer: String,
	expires_at: i64,
}
pub(crate) fn verified_credential(extensions: &::http::Extensions) -> Option<TaskCredential> {
	let claims = extensions.get::<crate::http::jwt::Claims>()?;
	Some(TaskCredential {
		revision: extensions.get::<gateway_contracts::ConfigLease>()?.clone(),
		issuer: claims.inner.get("iss")?.as_str()?.into(),
		expires_at: claims.inner.get("exp")?.as_i64()?,
	})
}

pub(crate) struct AuthorizedCall {
	push: Option<push::Operation>,
	recovery: Option<(String, usize)>,
	download_guards: Option<crate::proxy::RoutingGuards>,
	flow: Option<crate::security_flow::FlowAccess>,
	execution: Option<crate::execution_budget::ExecutionScope>,
	credential: TaskCredential,
	invocation: ActionRequest,
	streaming: bool,
	_stream_lease: Option<StoreLease>,
	permit: TaskPermit,
	config: Arc<SecurityConfig>,
	identity: GatewayIdentity,
	rpc_id: Value,
	scope: String,
	action: ActionRequest,
}

fn deny(action: &ActionRequest, error: ObjectError) -> ProxyError {
	audit_object_check(action, Err(error), &UiSecurityAuditSink);
	ProxyError::AuthorizationFailed
}

fn object_error(error: gateway_a2a::Error) -> ObjectError {
	match error {
		gateway_a2a::Error::Unsupported => ObjectError::Unsupported,
		gateway_a2a::Error::ResponseBinding => ObjectError::ResponseBinding,
		gateway_a2a::Error::EventCursor => ObjectError::EventCursor,
		gateway_a2a::Error::DownloadSource => ObjectError::DownloadSource,
		gateway_a2a::Error::DownloadIntegrity => ObjectError::DownloadIntegrity,
	}
}
fn identifier(value: &Value) -> Result<&str, ObjectError> {
	gateway_a2a::objects::identifier(value).map_err(object_error)
}

fn request_scope(req: &Request, destination: &str) -> String {
	let mut path = req.uri().path().to_owned();
	if let Some(query) = req.uri().query() {
		use base64::Engine;
		use sha2::Digest;
		path.push_str(&format!(
			"?sha256={}",
			base64::engine::general_purpose::URL_SAFE_NO_PAD
				.encode(sha2::Sha256::digest(query.as_bytes()))
		));
	}
	endpoint_scope(destination, &path)
}

/// Bind existing Task metadata to all workflow constraints. This is an identity digest,
/// not a grant. Preserve the legacy budget-only value when no context is installed.
fn task_binding(
	execution: Option<String>,
	flow: Option<&crate::security_flow::FlowAccess>,
	guards: Option<&crate::proxy::RoutingGuards>,
) -> Result<Option<String>, ProxyError> {
	let mut contexts = guards
		.map(|guards| guards.context_bindings())
		.transpose()?
		.unwrap_or_default();
	if let Some(flow) = flow {
		contexts.push(flow.recovery_binding()?);
	}
	contexts.sort_unstable();
	contexts.dedup();
	if contexts.is_empty() {
		return Ok(execution);
	}
	let metadata = serde_json::to_string(&("a2a-context-v1", execution, contexts))
		.map_err(|_| ProxyError::AuthorizationFailed)?;
	Ok(Some(crate::security::digest(&metadata)))
}

#[cfg(all(test, feature = "gateway-rag"))]
#[path = "objects/binding_tests.rs"]
mod binding_tests;

pub(crate) async fn authorize_request(
	config: Arc<SecurityConfig>,
	req: &mut Request,
	destination: &str,
	identity: GatewayIdentity,
	request_id: String,
	credential: Option<TaskCredential>,
	flow: Option<crate::security_flow::FlowAccess>,
	guards: Option<crate::proxy::RoutingGuards>,
	execution: Option<crate::execution_budget::ExecutionScope>,
) -> Result<AuthorizedCall, ProxyError> {
	let scope = request_scope(req, destination);
	let fallback = agent_object_for_identity(
		&request_id,
		identity.clone(),
		"unsupported",
		ResourceType::Agent,
		&scope,
	);
	let objects = config
		.a2a_objects
		.as_ref()
		.ok_or(ProxyError::AuthorizationFailed)?;
	if config.mode != SecurityMode::Enforce || config.validate_composition().is_err() {
		return Err(deny(&fallback, ObjectError::Unavailable));
	}
	let credential = credential.ok_or_else(|| deny(&fallback, ObjectError::Identity))?;
	if !credential.revision.is_current() {
		return Err(deny(&fallback, ObjectError::ConfigChanged));
	}
	if credential.expires_at <= chrono::Utc::now().timestamp() {
		return Err(deny(&fallback, ObjectError::CredentialExpired));
	}
	if req.headers().contains_key("last-event-id") {
		return Err(deny(&fallback, ObjectError::Unsupported));
	}
	let rpc: Rpc = crate::json::inspect_body(req)
		.await
		.map_err(|_| deny(&fallback, ObjectError::Unsupported))?;
	let gateway_a2a::objects::RequestPlan {
		operation,
		task,
		context,
		method,
	} = gateway_a2a::objects::parse_request(&rpc)
		.map_err(|error| deny(&fallback, object_error(error)))?;
	let recovery = if rpc.method == recovery::METHOD {
		let settings = objects
			.event_recovery
			.as_ref()
			.ok_or_else(|| deny(&fallback, ObjectError::Unsupported))?;
		settings.store().map_err(|e| deny(&fallback, e))?;
		Some(
			gateway_a2a::recovery::request(&rpc, settings.max_batch_events)
				.map_err(|e| deny(&fallback, object_error(e)))?,
		)
	} else {
		// Declared-but-unprepared storage must fail before an upstream operation can run.
		if let Some(events) = &objects.event_recovery {
			events.store().map_err(|e| deny(&fallback, e))?;
		}
		None
	};
	let invocation = security_pipeline::agent_action_for_identity(
		&request_id,
		identity.clone(),
		destination,
		&rpc.method,
	);
	crate::security::evaluate(&config, &invocation).map_err(|_| ProxyError::AuthorizationFailed)?;
	let resource_id = task
		.as_ref()
		.map(|id| task_resource_id(&scope, id))
		.unwrap_or_else(|| scope.clone());
	let action = agent_object_for_identity(
		request_id,
		identity.clone(),
		operation.name(),
		if task.is_some() {
			ResourceType::AgentTask
		} else {
			ResourceType::Agent
		},
		resource_id,
	);
	crate::security::evaluate(&config, &action).map_err(|_| ProxyError::AuthorizationFailed)?;
	let mut permit = config
		.a2a_task_store
		.begin(
			objects,
			&identity,
			&credential.issuer,
			&scope,
			task.as_deref(),
			operation,
		)
		.map_err(|error| deny(&action, error))?;
	if config.cross_component.is_some() && flow.is_none() {
		return Err(deny(&action, ObjectError::ExecutionBinding));
	}
	let binding = task_binding(
		execution.as_ref().map(|e| e.binding()),
		flow.as_ref(),
		guards.as_ref(),
	)?;
	permit
		.bind_execution(binding.as_deref())
		.map_err(|e| deny(&action, e))?;
	if context.is_some() && context != permit.context_id {
		return Err(deny(&action, ObjectError::ResponseBinding));
	}
	let streaming = method.streaming();
	let stream_lease = if streaming {
		Some(
			config
				.a2a_task_store
				.reserve_stream(objects)
				.map_err(|e| deny(&action, e))?,
		)
	} else {
		None
	};
	if streaming && permit.task_id.is_some() {
		let read = agent_object_for_identity(
			&action.request_id,
			identity.clone(),
			"read",
			ResourceType::AgentTask,
			task_resource_id(&scope, permit.task_id.as_deref().expect("known")),
		);
		crate::security::evaluate(&config, &read).map_err(|_| ProxyError::AuthorizationFailed)?;
	}
	audit_object_check(&action, Ok(()), &UiSecurityAuditSink);
	let mut call = AuthorizedCall {
		push: None,
		recovery,
		download_guards: guards,
		flow,
		execution,
		credential,
		invocation,
		streaming,
		_stream_lease: stream_lease,
		permit,
		config,
		identity,
		scope,
		action,
		rpc_id: rpc.id.clone(),
	};
	call.prepare_push(req, &rpc)?;
	Ok(call)
}

impl AuthorizedCall {
	pub(crate) async fn apply_response(
		mut self: Box<Self>,
		response: &mut Response,
	) -> Result<(), ProxyError> {
		if self.streaming {
			return self.apply_stream(response);
		}
		self.check_credential().map_err(|e| deny(&self.action, e))?;
		// Non-stream RPCs cannot silently switch to opaque/SSE content.
		if !matches!(
			crate::http::classify_content_type(response.headers()),
			crate::http::WellKnownContentTypes::Json
		) {
			return Err(deny(&self.action, ObjectError::ResponseBinding));
		}
		let limit = crate::http::response_buffer_limit(response);
		let body = std::mem::replace(response.body_mut(), Body::empty());
		let mut rpc: Value = crate::json::from_body_with_limit(body, limit)
			.await
			.map_err(|_| deny(&self.action, ObjectError::ResponseBinding))?;
		if self.push.is_some() {
			return self.apply_push_response(response, &mut rpc).await;
		}
		self
			.config
			.a2a_task_store
			.validate_permit(
				self.config.a2a_objects.as_ref().expect("enabled"),
				&self.permit,
			)
			.map_err(|error| deny(&self.action, error))?;
		self.process_rpc(&mut rpc, response.status().is_success())?;
		Box::pin(self.hydrate_artifacts(&mut rpc)).await?;
		response.headers_mut().remove(header::CONTENT_LENGTH);
		// The body is reserialized/filtered; upstream validators no longer describe it.
		response.headers_mut().remove(header::ETAG);
		response.headers_mut().remove(header::CONTENT_ENCODING);
		for name in ["content-digest", "digest", "content-md5"] {
			response.headers_mut().remove(name);
		}
		response.headers_mut().insert(
			header::CACHE_CONTROL,
			"private, no-store".parse().expect("constant header"),
		);
		let bytes =
			serde_json::to_vec(&rpc).map_err(|_| deny(&self.action, ObjectError::ResponseBinding))?;
		if bytes.len() > limit {
			return Err(deny(&self.action, ObjectError::DownloadLimit));
		}
		*response.body_mut() = Body::from(bytes);
		Ok(())
	}

	fn check_credential(&self) -> Result<(), ObjectError> {
		if self.execution.as_ref().is_some_and(|e| !e.is_active()) {
			return Err(ObjectError::ExecutionBinding);
		}
		if !self.credential.revision.is_current() {
			return Err(ObjectError::ConfigChanged);
		}
		if chrono::Utc::now().timestamp() >= self.credential.expires_at {
			return Err(ObjectError::CredentialExpired);
		}
		Ok(())
	}
	fn context(&self) -> gateway_a2a::execution::Context {
		gateway_a2a::execution::Context {
			operation: self.permit.operation,
			task: self.permit.task_id.clone(),
			context: self.permit.context_id.clone(),
			downloads: !self.streaming
				&& self
					.config
					.a2a_objects
					.as_ref()
					.is_some_and(|c| c.artifact_downloads.is_some()),
		}
	}
	fn validate_envelope(&self, rpc: &mut Value) -> Result<bool, ProxyError> {
		gateway_a2a::execution::validate_envelope(rpc, &self.rpc_id)
			.map_err(|e| deny(&self.action, object_error(e)))
	}
	fn process_rpc(&mut self, rpc: &mut Value, success: bool) -> Result<(), ProxyError> {
		self.check_credential().map_err(|e| deny(&self.action, e))?;
		let context = self.context();
		let id = self.rpc_id.clone();
		gateway_a2a::execution::process_rpc(rpc, &id, success, &context, self)
	}
	fn process_result_inner(&mut self, result: &mut Value, commit: bool) -> Result<(), ProxyError> {
		let context = self.context();
		gateway_a2a::execution::process_result(result, &context, commit, self)
	}
}
impl gateway_a2a::execution::ObjectAccess for AuthorizedCall {
	type Error = ProxyError;
	fn reject(&self, error: gateway_a2a::Error) -> ProxyError {
		deny(&self.action, object_error(error))
	}
	fn stream_reject(&self, error: gateway_a2a::Error) -> ProxyError {
		self.stream_denial(object_error(error))
	}
	fn finish_task(&mut self, id: &str, context: &str, state: TaskState) -> Result<(), ProxyError> {
		self
			.config
			.a2a_task_store
			.finish(
				self.config.a2a_objects.as_ref().expect("enabled"),
				&mut self.permit,
				id,
				context,
				state,
			)
			.map_err(|e| deny(&self.action, e))
	}
	fn read_task(&self, id: &str) -> Result<(), ProxyError> {
		let read = agent_object_for_identity(
			&self.action.request_id,
			self.identity.clone(),
			"read",
			ResourceType::AgentTask,
			task_resource_id(&self.scope, id),
		);
		crate::security::evaluate(&self.config, &read).map_err(|_| ProxyError::AuthorizationFailed)?;
		audit_object_check(&read, Ok(()), &UiSecurityAuditSink);
		Ok(())
	}
	fn artifact_visible(&self, task: &str, artifact: &str) -> bool {
		let action = agent_object_for_identity(
			&self.action.request_id,
			self.identity.clone(),
			"read",
			ResourceType::AgentArtifact,
			artifact_resource_id(&self.scope, task, artifact),
		);
		crate::security::evaluate(&self.config, &action).is_ok()
	}
}
