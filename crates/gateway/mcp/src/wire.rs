//! Preserve Roots/Sampling params before typed SDK decoding drops security-relevant fields.
//! Still decode the JSON-RPC envelope with the SDK; no new protocol authority here.
use rmcp::model::{CustomRequest, ServerJsonRpcMessage, ServerRequest, ServerResult};
use serde_json::Value;

pub fn decode_server(mut value: Value) -> Result<ServerJsonRpcMessage, serde_json::Error> {
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

pub fn normalize_outbound_for_protocol(
	mut msg: ServerJsonRpcMessage,
	downstream_modern: bool,
) -> ServerJsonRpcMessage {
	if downstream_modern {
		return msg;
	}

	let ServerJsonRpcMessage::Response(resp) = &mut msg else {
		return msg;
	};

	match &mut resp.result {
		ServerResult::DiscoverResult(r) => {
			r.result_type = None;
			r.ttl_ms = None;
			r.cache_scope = None;
		},
		ServerResult::InitializeResult(r) => r.result_type = None,
		ServerResult::CompleteResult(r) => r.result_type = None,
		ServerResult::GetPromptResult(r) => r.result_type = None,
		ServerResult::ListPromptsResult(r) => {
			r.result_type = None;
			r.ttl_ms = None;
			r.cache_scope = None;
		},
		ServerResult::ListResourcesResult(r) => {
			r.result_type = None;
			r.ttl_ms = None;
			r.cache_scope = None;
		},
		ServerResult::ListResourceTemplatesResult(r) => {
			r.result_type = None;
			r.ttl_ms = None;
			r.cache_scope = None;
		},
		ServerResult::ReadResourceResult(r) => {
			r.result_type = None;
			r.ttl_ms = None;
			r.cache_scope = None;
		},
		ServerResult::ListToolsResult(r) => {
			r.result_type = None;
			r.ttl_ms = None;
			r.cache_scope = None;
		},
		ServerResult::ElicitResult(r) => r.result_type = None,
		ServerResult::CreateTaskResult(r) => r.result_type = None,
		ServerResult::ListTasksResult(r) => r.result_type = None,
		ServerResult::GetTaskResult(r) => r.result_type = None,
		ServerResult::CancelTaskResult(r) => r.result_type = None,
		ServerResult::SubscriptionsListenResult(r) => r.result_type = None,
		ServerResult::CallToolResult(r) => r.result_type = None,
		ServerResult::GetTaskPayloadResult(r) => strip_protocol_result_fields(&mut r.0),
		ServerResult::EmptyResult(r) => r.result_type = None,
		ServerResult::CustomResult(r) => strip_protocol_result_fields(&mut r.0),
		ServerResult::InputRequiredResult(_) => {},
	}

	msg
}

fn strip_protocol_result_fields(value: &mut serde_json::Value) {
	let Some(obj) = value.as_object_mut() else {
		return;
	};
	obj.remove("resultType");
	obj.remove("ttlMs");
	obj.remove("cacheScope");
}

#[cfg(test)]
mod tests;
