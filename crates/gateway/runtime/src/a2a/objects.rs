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
use serde::Deserialize;
use serde_json::{Map, Value};

use crate::http::{Body, Request, Response, header};
use crate::proxy::ProxyError;
use crate::security_events::UiSecurityAuditSink;

#[derive(Deserialize)]
struct Rpc {
	jsonrpc: String,
	id: Value,
	method: String,
	params: Value,
}

/// Only extracted from the JWT validator's verified Claims extension, never headers/JSON.
#[derive(Clone)]
pub(crate) struct TaskCredential {
	revision: crate::a2a::revision::ConfigLease,
	issuer: String,
	expires_at: i64,
}
pub(crate) fn verified_credential(extensions: &::http::Extensions) -> Option<TaskCredential> {
	let claims = extensions.get::<crate::http::jwt::Claims>()?;
	Some(TaskCredential {
		revision: extensions
			.get::<crate::a2a::revision::ConfigLease>()?
			.clone(),
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

fn identifier(value: &Value) -> Result<&str, ObjectError> {
	value
		.as_str()
		.filter(|s| !s.is_empty() && s.trim() == *s && s.len() <= 512)
		.ok_or(ObjectError::Unsupported)
}

fn optional_id(value: Option<&Value>) -> Result<Option<&str>, ObjectError> {
	value.filter(|v| !v.is_null()).map(identifier).transpose()
}

fn object<'a>(value: &'a Value, allowed: &[&str]) -> Result<&'a Map<String, Value>, ObjectError> {
	let map = value.as_object().ok_or(ObjectError::Unsupported)?;
	if map.keys().any(|key| !allowed.contains(&key.as_str())) {
		return Err(ObjectError::Unsupported);
	}
	Ok(map)
}

fn no_references(value: &Value) -> Result<(), ObjectError> {
	for field in ["referenceTaskIds", "extensions"] {
		if let Some(value) = value.get(field) {
			if !value.as_array().is_some_and(|a| a.is_empty()) {
				return Err(ObjectError::Unsupported);
			}
		}
	}
	Ok(())
}

fn parse_operation(
	rpc: &Rpc,
) -> Result<(TaskOperation, Option<String>, Option<String>), ObjectError> {
	if rpc.jsonrpc != "2.0" || !(rpc.id.is_string() || rpc.id.is_number()) {
		return Err(ObjectError::Unsupported);
	}
	match rpc.method.as_str() {
		"tasks/pushNotificationConfig/set"
		| "tasks/pushNotificationConfig/get"
		| "tasks/pushNotificationConfig/list"
		| "tasks/pushNotificationConfig/delete" => {
			let set = rpc.method.ends_with("/set");
			object(
				&rpc.params,
				if set {
					&["taskId", "pushNotificationConfig"]
				} else if rpc.method.ends_with("/list") {
					&["id"]
				} else {
					&["id", "pushNotificationConfigId"]
				},
			)?;
			let id = identifier(&rpc.params[if set { "taskId" } else { "id" }])?;
			Ok((TaskOperation::Read, Some(id.to_owned()), None))
		},
		recovery::METHOD => {
			object(&rpc.params, &["id", "after", "limit"])?;
			let id = identifier(&rpc.params["id"])?;
			let after = rpc.params["after"]
				.as_str()
				.ok_or(ObjectError::EventCursor)?;
			if !security_integration_runtime::a2a_objects::events::valid_cursor(after)
				|| rpc.params.get("limit").is_some_and(|v| !v.is_u64())
			{
				return Err(ObjectError::EventCursor);
			}
			Ok((TaskOperation::Read, Some(id.to_owned()), None))
		},
		"tasks/get" | "tasks/cancel" | "tasks/resubscribe" => {
			let params = object(
				&rpc.params,
				if rpc.method == "tasks/get" {
					&["id", "historyLength", "metadata"]
				} else {
					&["id", "metadata"]
				},
			)?;
			if params.get("historyLength").is_some_and(|v| !v.is_u64()) {
				return Err(ObjectError::Unsupported);
			}
			let id = identifier(params.get("id").ok_or(ObjectError::Unsupported)?)?.to_owned();
			Ok((
				if rpc.method == "tasks/get" {
					TaskOperation::Read
				} else if rpc.method == "tasks/resubscribe" {
					TaskOperation::Subscribe
				} else {
					TaskOperation::Cancel
				},
				Some(id),
				None,
			))
		},
		"message/send" | "message/stream" => {
			object(&rpc.params, &["message", "configuration", "metadata"])?;
			let message = rpc.params.get("message").ok_or(ObjectError::Unsupported)?;
			object(
				message,
				&[
					"role",
					"kind",
					"parts",
					"messageId",
					"taskId",
					"contextId",
					"metadata",
					"extensions",
					"referenceTaskIds",
				],
			)?;
			no_references(message)?;
			validate_parts(&message["parts"])?;
			if message.get("kind").and_then(Value::as_str) != Some("message")
				|| message.get("role").and_then(Value::as_str) != Some("user")
				|| !message
					.get("parts")
					.and_then(Value::as_array)
					.is_some_and(|p| !p.is_empty())
			{
				return Err(ObjectError::Unsupported);
			}
			identifier(message.get("messageId").ok_or(ObjectError::Unsupported)?)?;
			if let Some(configuration) = rpc.params.get("configuration") {
				object(
					configuration,
					&["blocking", "historyLength", "acceptedOutputModes"],
				)?;
				if configuration
					.get("blocking")
					.is_some_and(|v| !v.is_boolean())
					|| configuration
						.get("historyLength")
						.is_some_and(|v| !v.is_u64())
					|| configuration
						.get("acceptedOutputModes")
						.is_some_and(|v| !v.as_array().is_some_and(|a| a.iter().all(Value::is_string)))
				{
					return Err(ObjectError::Unsupported);
				}
			}
			let task = optional_id(message.get("taskId"))?.map(ToOwned::to_owned);
			let context = optional_id(message.get("contextId"))?.map(ToOwned::to_owned);
			// A bare context/reference can identify other work without proving task ownership.
			if task.is_none() && context.is_some() {
				return Err(ObjectError::Unsupported);
			}
			Ok((
				if task.is_some() {
					TaskOperation::Continue
				} else {
					TaskOperation::Create
				},
				task,
				context,
			))
		},
		_ => Err(ObjectError::Unsupported),
	}
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

pub(crate) async fn authorize_request(
	config: Arc<SecurityConfig>,
	req: &mut Request,
	destination: &str,
	identity: GatewayIdentity,
	request_id: String,
	credential: Option<TaskCredential>,
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
	let (operation, task, context) = parse_operation(&rpc).map_err(|error| deny(&fallback, error))?;
	let recovery = if rpc.method == recovery::METHOD {
		let settings = objects
			.event_recovery
			.as_ref()
			.ok_or_else(|| deny(&fallback, ObjectError::Unsupported))?;
		settings.store().map_err(|e| deny(&fallback, e))?;
		let limit = rpc
			.params
			.get("limit")
			.and_then(Value::as_u64)
			.unwrap_or(settings.max_batch_events as u64);
		if limit == 0 || limit > settings.max_batch_events as u64 {
			return Err(deny(&fallback, ObjectError::EventCursor));
		}
		Some((
			rpc.params["after"].as_str().expect("validated").to_owned(),
			limit as usize,
		))
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
	let binding = execution.as_ref().map(|e| e.binding());
	permit
		.bind_execution(binding.as_deref())
		.map_err(|e| deny(&action, e))?;
	if context.is_some() && context != permit.context_id {
		return Err(deny(&action, ObjectError::ResponseBinding));
	}
	let streaming = matches!(rpc.method.as_str(), "message/stream" | "tasks/resubscribe");
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
		download_guards: None,
		flow: req
			.extensions()
			.get::<crate::security_flow::FlowAccess>()
			.cloned(),
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

fn validate_message(
	message: &Value,
	task: Option<&str>,
	context: Option<&str>,
) -> Result<(), ObjectError> {
	object(
		message,
		&[
			"role",
			"kind",
			"parts",
			"messageId",
			"taskId",
			"contextId",
			"metadata",
			"extensions",
			"referenceTaskIds",
		],
	)?;
	if message.get("kind").and_then(Value::as_str) != Some("message") {
		return Err(ObjectError::ResponseBinding);
	}
	identifier(
		message
			.get("messageId")
			.ok_or(ObjectError::ResponseBinding)?,
	)?;
	if !matches!(
		message.get("role").and_then(Value::as_str),
		Some("user" | "agent")
	) || !message.get("parts").is_some_and(Value::is_array)
	{
		return Err(ObjectError::ResponseBinding);
	}
	no_references(message)?;
	validate_parts(&message["parts"])?;
	let message_task = optional_id(message.get("taskId"))?;
	let message_context = optional_id(message.get("contextId"))?;
	if message_task.is_some() && message_task != task
		|| context.is_some() && message_context.is_some() && message_context != context
	{
		return Err(ObjectError::ResponseBinding);
	}
	Ok(())
}

/// File URI download is a separate outbound operation, not an incidental part of
/// Task read. Until a download adapter binds owner/target/digest and reauthorizes
/// redirects, protected responses accept inline files only. No remote URL escapes
/// the audited path by being handed directly to the client.
fn validate_parts(parts: &Value) -> Result<(), ObjectError> {
	validate_parts_with_downloads(parts, false)
}

fn validate_parts_with_downloads(parts: &Value, downloads: bool) -> Result<(), ObjectError> {
	use base64::Engine;
	let parts = parts
		.as_array()
		.filter(|p| p.len() <= 64)
		.ok_or(ObjectError::ResponseBinding)?;
	for part in parts {
		match part["kind"].as_str() {
			Some("text") => {
				object(part, &["kind", "text", "metadata"])?;
				if !part["text"].as_str().is_some_and(|s| s.len() <= 262144) {
					return Err(ObjectError::ResponseBinding);
				}
			},
			Some("data") => {
				object(part, &["kind", "data", "metadata"])?;
				if !part["data"].is_object() {
					return Err(ObjectError::ResponseBinding);
				}
			},
			Some("file") => {
				object(part, &["kind", "file", "metadata"])?;
				let file = &part["file"];
				let external = downloads && file.get("uri").is_some();
				object(
					file,
					if external {
						&["name", "mimeType", "uri"]
					} else {
						&["name", "mimeType", "bytes"]
					},
				)?;
				if ["name", "mimeType"].iter().any(|k| {
					file.get(*k).is_some_and(|v| {
						!v.as_str()
							.is_some_and(|s| !s.is_empty() && s.len() <= 256 && !s.chars().any(char::is_control))
					})
				}) {
					return Err(ObjectError::ResponseBinding);
				}
				if external {
					downloads::FileReference::parse(part)?;
					continue;
				}
				let bytes = file["bytes"]
					.as_str()
					.filter(|s| s.len() <= 262144)
					.ok_or(ObjectError::Unsupported)?;
				base64::engine::general_purpose::STANDARD
					.decode(bytes)
					.map_err(|_| ObjectError::ResponseBinding)?;
			},
			_ => return Err(ObjectError::Unsupported),
		}
	}
	Ok(())
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
	fn validate_envelope(&self, rpc: &mut Value) -> Result<bool, ProxyError> {
		if rpc.get("jsonrpc").and_then(Value::as_str) != Some("2.0")
			|| rpc.get("id") != Some(&self.rpc_id)
			|| rpc.get("result").is_some() == rpc.get("error").is_some()
		{
			return Err(deny(&self.action, ObjectError::ResponseBinding));
		}
		object(rpc, &["jsonrpc", "id", "result", "error"]).map_err(|e| deny(&self.action, e))?;
		if let Some(error) = rpc.get_mut("error") {
			object(error, &["code", "message", "data"]).map_err(|e| deny(&self.action, e))?;
			if !error.get("code").is_some_and(Value::is_i64)
				|| !error.get("message").is_some_and(Value::is_string)
			{
				return Err(deny(&self.action, ObjectError::ResponseBinding));
			}
			error.as_object_mut().expect("checked").remove("data");
			return Ok(true);
		}
		Ok(false)
	}
	fn process_rpc(&mut self, rpc: &mut Value, success: bool) -> Result<(), ProxyError> {
		self.check_credential().map_err(|e| deny(&self.action, e))?;
		if self.validate_envelope(rpc)? {
			return Ok(());
		}
		if !success {
			return Err(deny(&self.action, ObjectError::ResponseBinding));
		}
		self.process_result(rpc.get_mut("result").expect("checked"))
	}

	fn process_result(&mut self, result: &mut Value) -> Result<(), ProxyError> {
		self.process_result_inner(result, true)
	}
	fn process_result_inner(&mut self, result: &mut Value, commit: bool) -> Result<(), ProxyError> {
		let checked = || -> Result<(String, String, TaskState), ObjectError> {
			object(
				result,
				&[
					"kind",
					"id",
					"contextId",
					"status",
					"artifacts",
					"history",
					"metadata",
				],
			)?;
			object(&result["status"], &["state", "message", "timestamp"])?;
			let id = identifier(result.get("id").ok_or(ObjectError::ResponseBinding)?)?.to_owned();
			let context = identifier(
				result
					.get("contextId")
					.ok_or(ObjectError::ResponseBinding)?,
			)?
			.to_owned();
			let state: TaskState = serde_json::from_value(result["status"]["state"].clone())
				.map_err(|_| ObjectError::ResponseBinding)?;
			if let Some(message) = result["status"].get("message") {
				validate_message(message, Some(&id), Some(&context))?;
			}
			if let Some(history) = result.get("history") {
				for message in history.as_array().ok_or(ObjectError::ResponseBinding)? {
					validate_message(message, Some(&id), Some(&context))?;
				}
			}
			if let Some(artifacts) = result.get("artifacts") {
				for artifact in artifacts.as_array().ok_or(ObjectError::ResponseBinding)? {
					object(
						artifact,
						&[
							"artifactId",
							"name",
							"description",
							"parts",
							"metadata",
							"extensions",
						],
					)?;
					if artifact
						.get("extensions")
						.is_some_and(|v| !v.as_array().is_some_and(|a| a.is_empty()))
					{
						return Err(ObjectError::Unsupported);
					}
					identifier(
						artifact
							.get("artifactId")
							.ok_or(ObjectError::ResponseBinding)?,
					)?;
					if !artifact.get("parts").is_some_and(Value::is_array) {
						return Err(ObjectError::ResponseBinding);
					}
					validate_parts_with_downloads(
						&artifact["parts"],
						!self.streaming
							&& self
								.config
								.a2a_objects
								.as_ref()
								.is_some_and(|c| c.artifact_downloads.is_some()),
					)?;
				}
			}
			Ok((id, context, state))
		};
		match result.get("kind").and_then(Value::as_str) {
			Some("message")
				if matches!(
					self.permit.operation,
					TaskOperation::Create | TaskOperation::Continue
				) =>
			{
				validate_message(
					result,
					self.permit.task_id.as_deref(),
					self.permit.context_id.as_deref(),
				)
				.map_err(|error| deny(&self.action, error))?;
			},
			Some("task") => {
				let (id, context, state) = checked().map_err(|error| deny(&self.action, error))?;
				if !commit
					&& (self.permit.task_id.as_deref() != Some(&id)
						|| self.permit.context_id.as_deref() != Some(&context))
				{
					return Err(deny(&self.action, ObjectError::ResponseBinding));
				}
				if commit {
					self
						.config
						.a2a_task_store
						.finish(
							self.config.a2a_objects.as_ref().expect("enabled"),
							&mut self.permit,
							&id,
							&context,
							state,
						)
						.map_err(|error| deny(&self.action, error))?;
				}
				let read = agent_object_for_identity(
					&self.action.request_id,
					self.identity.clone(),
					"read",
					ResourceType::AgentTask,
					task_resource_id(&self.scope, &id),
				);
				crate::security::evaluate(&self.config, &read)
					.map_err(|_| ProxyError::AuthorizationFailed)?;
				audit_object_check(&read, Ok(()), &UiSecurityAuditSink);
				if let Some(artifacts) = result.get_mut("artifacts").and_then(Value::as_array_mut) {
					artifacts.retain(|artifact| {
						let action = agent_object_for_identity(
							&self.action.request_id,
							self.identity.clone(),
							"read",
							ResourceType::AgentArtifact,
							artifact_resource_id(
								&self.scope,
								&id,
								artifact["artifactId"].as_str().expect("validated"),
							),
						);
						crate::security::evaluate(&self.config, &action).is_ok()
					});
				}
			},
			_ => return Err(deny(&self.action, ObjectError::ResponseBinding)),
		}
		Ok(())
	}
}
