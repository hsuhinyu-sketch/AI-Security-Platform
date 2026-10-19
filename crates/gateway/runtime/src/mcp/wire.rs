//! Preserve Roots/Sampling params before typed SDK decoding drops security-relevant fields.
//! Still decode the JSON-RPC envelope with the SDK; no new protocol authority here.
use rmcp::model::{CustomRequest, ServerJsonRpcMessage, ServerRequest};
use serde_json::Value;

pub(super) fn decode_server(mut value: Value) -> Result<ServerJsonRpcMessage, serde_json::Error> {
	let method = value["method"].as_str().unwrap_or_default().to_owned();
	let preserved = if matches!(method.as_str(), "roots/list" | "sampling/createMessage") {
		// The SDK's untagged enum can fall back to a notification if an ID is invalid.
		// These are requests, never notifications or envelopes with two roles.
		let _: rmcp::model::RequestId = serde_json::from_value(value["id"].clone())?;
		if value["jsonrpc"] != "2.0" || value.get("result").is_some() || value.get("error").is_some() {
			return Err(<serde_json::Error as serde::de::Error>::custom(
				"invalid reverse request envelope",
			));
		}
		let params = value
			.as_object_mut()
			.expect("method-bearing object")
			.remove("params");
		if params.as_ref().is_some_and(|p| !p.is_object()) {
			return Err(<serde_json::Error as serde::de::Error>::custom(
				"reverse request params must be an object",
			));
		}
		Some(params)
	} else {
		None
	};
	let mut message: ServerJsonRpcMessage = serde_json::from_value(value)?;
	if let (Some(params), ServerJsonRpcMessage::Request(request)) = (preserved, &mut message) {
		request.request = ServerRequest::CustomRequest(CustomRequest::new(method, params));
	}
	Ok(message)
}
