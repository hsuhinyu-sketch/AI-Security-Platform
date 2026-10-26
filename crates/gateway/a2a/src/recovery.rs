//! Projection of already admitted events. This module neither replays upstream nor admits storage.
use crate::{Error, objects::identifier};
use serde_json::{Value, json};
pub fn recoverable(result: &Value) -> bool {
	matches!(
		result["kind"].as_str(),
		Some("task" | "status-update" | "artifact-update")
	)
}
pub fn request(rpc: &crate::RequestEnvelope, max_batch: usize) -> Result<(String, usize), Error> {
	let limit = rpc
		.params
		.get("limit")
		.and_then(Value::as_u64)
		.unwrap_or(max_batch as u64);
	if limit == 0 || limit > max_batch as u64 {
		return Err(Error::EventCursor);
	}
	// Envelope and cursor shape are validated by objects::parse_request before store access.
	Ok((
		rpc.params["after"]
			.as_str()
			.ok_or(Error::EventCursor)?
			.to_owned(),
		limit as usize,
	))
}
pub fn project_event(
	result: Option<&mut Value>,
	mut visible: impl FnMut(&str) -> bool,
) -> Result<bool, Error> {
	let Some(result) = result else {
		return Ok(true);
	};
	match result["kind"].as_str() {
		Some("artifact-update") => Ok(visible(identifier(&result["artifact"]["artifactId"])?)),
		Some("task") => {
			if let Some(artifacts) = result.get_mut("artifacts").and_then(Value::as_array_mut) {
				artifacts.retain(|a| a["artifactId"].as_str().is_some_and(&mut visible));
			}
			Ok(true)
		},
		Some("status-update" | "message") => Ok(true),
		_ => Err(Error::ResponseBinding),
	}
}
pub fn project_batch<'a>(
	events: impl IntoIterator<Item = (&'a str, Value)>,
	mut visible: impl FnMut(&str) -> bool,
) -> Result<Vec<Value>, Error> {
	let mut projected = Vec::new();
	for (cursor, mut result) in events {
		if project_event(Some(&mut result), &mut visible)? {
			projected.push(json!({"cursor":cursor,"result":result}));
		}
	}
	Ok(projected)
}
pub fn response(
	id: &Value,
	events: Vec<Value>,
	next_cursor: impl serde::Serialize,
	has_more: bool,
) -> Value {
	json!({"jsonrpc":"2.0","id":id,"result":{"kind":"aisp-event-batch","events":events,"nextCursor":next_cursor,"hasMore":has_more,"scope":"gateway-observed"}})
}
