//! Protected binding validation. No identity, grants, Store or I/O.
use crate::Error as ObjectError;
use security_types::a2a::TaskOperation;
use serde_json::{Map, Value};
pub fn identifier(value: &Value) -> Result<&str, ObjectError> {
	value
		.as_str()
		.filter(|s| !s.is_empty() && s.trim() == *s && s.len() <= 512)
		.ok_or(ObjectError::Unsupported)
}

pub fn optional_id(value: Option<&Value>) -> Result<Option<&str>, ObjectError> {
	value.filter(|v| !v.is_null()).map(identifier).transpose()
}

pub fn object<'a>(
	value: &'a Value,
	allowed: &[&str],
) -> Result<&'a Map<String, Value>, ObjectError> {
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
	rpc: &crate::RequestEnvelope,
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
		crate::EVENT_READ_METHOD => {
			object(&rpc.params, &["id", "after", "limit"])?;
			let id = identifier(&rpc.params["id"])?;
			let after = rpc.params["after"]
				.as_str()
				.ok_or(ObjectError::EventCursor)?;
			if !security_types::a2a::valid_event_cursor(after)
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

pub fn validate_message(
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
pub fn validate_parts(parts: &Value) -> Result<(), ObjectError> {
	validate_parts_with_downloads(parts, false)
}

pub fn validate_parts_with_downloads(parts: &Value, downloads: bool) -> Result<(), ObjectError> {
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
					crate::downloads::FileReference::parse(part)?;
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

#[derive(Debug)]
pub struct RequestPlan {
	pub operation: TaskOperation,
	pub task: Option<String>,
	pub context: Option<String>,
	pub method: crate::Method,
}
pub fn parse_request(rpc: &crate::RequestEnvelope) -> Result<RequestPlan, ObjectError> {
	let (operation, task, context) = parse_operation(rpc)?;
	Ok(RequestPlan {
		operation,
		task,
		context,
		method: crate::Method::parse(&rpc.method).ok_or(ObjectError::Unsupported)?,
	})
}
