//! Parsed A2A SSE event transitions; admission, timers and final output checks remain Host-owned.
use crate::{
	Error,
	execution::{self, Context, ObjectAccess},
	objects::{identifier, object, validate_parts},
};
use security_types::a2a::TaskState;
use serde_json::Value;
pub fn process_event<A: ObjectAccess>(
	rpc: &mut Value,
	rpc_id: &Value,
	binding: &Context,
	access: &mut A,
) -> Result<(bool, bool), A::Error> {
	if execution::validate_envelope(rpc, rpc_id).map_err(|e| access.reject(e))? {
		return Ok((true, true));
	}
	let result = rpc.get_mut("result").expect("checked");
	match result.get("kind").and_then(Value::as_str) {
		Some("task") => {
			let state: TaskState = serde_json::from_value(result["status"]["state"].clone())
				.map_err(|_| access.stream_reject(Error::ResponseBinding))?;
			execution::process_result(result, binding, true, access)?;
			Ok((
				true,
				state.terminal()
					|| matches!(
						state,
						TaskState::InputRequired | TaskState::AuthRequired | TaskState::Unknown
					),
			))
		},
		Some("message") => {
			execution::process_result(result, binding, true, access)?;
			Ok((true, true))
		},
		Some("status-update" | "artifact-update") => {
			let status = result["kind"] == "status-update";
			object(
				result,
				if status {
					&["kind", "taskId", "contextId", "status", "final", "metadata"]
				} else {
					&[
						"kind",
						"taskId",
						"contextId",
						"artifact",
						"append",
						"lastChunk",
						"metadata",
					]
				},
			)
			.map_err(|e| access.stream_reject(e))?;
			let id = identifier(&result["taskId"])
				.map_err(|e| access.stream_reject(e))?
				.to_owned();
			let context = identifier(&result["contextId"])
				.map_err(|e| access.stream_reject(e))?
				.to_owned();
			if binding.task.as_deref() != Some(&id) || binding.context.as_deref() != Some(&context) {
				return Err(access.stream_reject(Error::ResponseBinding));
			}
			if status {
				let final_event = result["final"]
					.as_bool()
					.ok_or_else(|| access.stream_reject(Error::ResponseBinding))?;
				// Reuse snapshot validation, owner/state transition and task-read policy.
				let mut snapshot = serde_json::json!({
						"kind":"task", "id":id, "contextId":context, "status":result["status"]
				});
				execution::process_result(&mut snapshot, binding, true, access)?;
				let state: TaskState = serde_json::from_value(result["status"]["state"].clone())
					.map_err(|_| access.stream_reject(Error::ResponseBinding))?;
				Ok((true, final_event || state.terminal()))
			} else {
				for field in ["append", "lastChunk"] {
					if result.get(field).is_some_and(|v| !v.is_boolean()) {
						return Err(access.stream_reject(Error::ResponseBinding));
					}
				}
				let artifact = &result["artifact"];
				validate_artifact(artifact).map_err(|e| access.stream_reject(e))?;
				Ok((
					access.artifact_visible(&id, artifact["artifactId"].as_str().expect("checked")),
					false,
				))
			}
		},
		_ => Err(access.stream_reject(Error::ResponseBinding)),
	}
}

pub fn validate_artifact(artifact: &Value) -> Result<(), Error> {
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
	identifier(&artifact["artifactId"])?;
	if !artifact.get("parts").is_some_and(Value::is_array) {
		return Err(Error::ResponseBinding);
	}
	validate_parts(&artifact["parts"])?;
	Ok(())
}
