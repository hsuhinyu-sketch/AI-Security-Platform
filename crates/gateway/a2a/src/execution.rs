//! Protected Task reply processing. Protocol values carry no permission to execute.
use crate::{
	Error,
	objects::{identifier, object, validate_message, validate_parts_with_downloads},
};
use security_types::a2a::{TaskOperation, TaskState};
use serde_json::Value;

/// Object IDs from a Host-bound permit; no identity, credential, Store or grant is exposed.
pub struct Context {
	pub operation: TaskOperation,
	pub task: Option<String>,
	pub context: Option<String>,
	pub downloads: bool,
}
/// Complete bound operations. Implementations retain authorization and atomic ownership checks.
pub trait ObjectAccess {
	type Error;
	fn reject(&self, error: Error) -> Self::Error;
	fn stream_reject(&self, error: Error) -> Self::Error;
	fn finish_task(&mut self, id: &str, context: &str, state: TaskState) -> Result<(), Self::Error>;
	fn read_task(&self, id: &str) -> Result<(), Self::Error>;
	/// Visibility projection only; this result is never an execution permit.
	fn artifact_visible(&self, task: &str, artifact: &str) -> bool;
}
pub fn validate_envelope(rpc: &mut Value, id: &Value) -> Result<bool, Error> {
	if rpc.get("jsonrpc").and_then(Value::as_str) != Some("2.0")
		|| rpc.get("id") != Some(id)
		|| rpc.get("result").is_some() == rpc.get("error").is_some()
	{
		return Err(Error::ResponseBinding);
	}
	object(rpc, &["jsonrpc", "id", "result", "error"])?;
	if let Some(error) = rpc.get_mut("error") {
		object(error, &["code", "message", "data"])?;
		if !error.get("code").is_some_and(Value::is_i64)
			|| !error.get("message").is_some_and(Value::is_string)
		{
			return Err(Error::ResponseBinding);
		}
		error.as_object_mut().expect("checked").remove("data");
		return Ok(true);
	}
	Ok(false)
}
pub fn process_rpc<A: ObjectAccess>(
	rpc: &mut Value,
	id: &Value,
	success: bool,
	context: &Context,
	access: &mut A,
) -> Result<(), A::Error> {
	if validate_envelope(rpc, id).map_err(|e| access.reject(e))? {
		return Ok(());
	}
	if !success {
		return Err(access.reject(Error::ResponseBinding));
	}
	process_result(
		rpc.get_mut("result").expect("checked"),
		context,
		true,
		access,
	)
}
pub fn process_result<A: ObjectAccess>(
	result: &mut Value,
	context: &Context,
	commit: bool,
	access: &mut A,
) -> Result<(), A::Error> {
	match result.get("kind").and_then(Value::as_str) {
		Some("message")
			if matches!(
				context.operation,
				TaskOperation::Create | TaskOperation::Continue
			) =>
		{
			validate_message(result, context.task.as_deref(), context.context.as_deref())
				.map_err(|e| access.reject(e))?
		},
		Some("task") => {
			let (id, ctx, state) =
				validate_task(result, context.downloads).map_err(|e| access.reject(e))?;
			if !commit
				&& (context.task.as_deref() != Some(&id) || context.context.as_deref() != Some(&ctx))
			{
				return Err(access.reject(Error::ResponseBinding));
			}
			if commit {
				access.finish_task(&id, &ctx, state)?;
			}
			access.read_task(&id)?;
			if let Some(artifacts) = result.get_mut("artifacts").and_then(Value::as_array_mut) {
				artifacts.retain(|artifact| {
					access.artifact_visible(&id, artifact["artifactId"].as_str().expect("validated"))
				});
			}
		},
		_ => return Err(access.reject(Error::ResponseBinding)),
	}
	Ok(())
}

pub fn validate_task(
	result: &Value,
	downloads: bool,
) -> Result<(String, String, TaskState), Error> {
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
	let id = identifier(result.get("id").ok_or(Error::ResponseBinding)?)?.to_owned();
	let context = identifier(result.get("contextId").ok_or(Error::ResponseBinding)?)?.to_owned();
	let state: TaskState = serde_json::from_value(result["status"]["state"].clone())
		.map_err(|_| Error::ResponseBinding)?;
	if let Some(message) = result["status"].get("message") {
		validate_message(message, Some(&id), Some(&context))?;
	}
	if let Some(history) = result.get("history") {
		for message in history.as_array().ok_or(Error::ResponseBinding)? {
			validate_message(message, Some(&id), Some(&context))?;
		}
	}
	if let Some(artifacts) = result.get("artifacts") {
		for artifact in artifacts.as_array().ok_or(Error::ResponseBinding)? {
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
				return Err(Error::Unsupported);
			}
			identifier(artifact.get("artifactId").ok_or(Error::ResponseBinding)?)?;
			if !artifact.get("parts").is_some_and(Value::is_array) {
				return Err(Error::ResponseBinding);
			}
			validate_parts_with_downloads(&artifact["parts"], downloads)?;
		}
	}
	Ok((id, context, state))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CleanupReply {
	Unknown,
	Rejected,
	Terminal(TaskState),
}
/// Parse the cleanup acknowledgement; reservation/once-only consumption and commit are Host-owned.
pub fn cleanup_reply(
	rpc: &Value,
	success: bool,
	rpc_id: &str,
	task: &str,
	context: Option<&str>,
) -> CleanupReply {
	if rpc["jsonrpc"] != "2.0"
		|| rpc["id"].as_str() != Some(rpc_id)
		|| rpc.get("result").is_some() == rpc.get("error").is_some()
		|| object(rpc, &["jsonrpc", "id", "result", "error"]).is_err()
	{
		return CleanupReply::Unknown;
	}
	if let Some(error) = rpc.get("error") {
		return if error["code"].is_i64() && error["message"].is_string() {
			CleanupReply::Rejected
		} else {
			CleanupReply::Unknown
		};
	}
	let result = &rpc["result"];
	if !success
		|| result["kind"] != "task"
		|| result["id"].as_str() != Some(task)
		|| result["contextId"].as_str() != context
	{
		return CleanupReply::Unknown;
	}
	match serde_json::from_value::<TaskState>(result["status"]["state"].clone()) {
		Ok(state) if state.terminal() => CleanupReply::Terminal(state),
		_ => CleanupReply::Unknown,
	}
}
