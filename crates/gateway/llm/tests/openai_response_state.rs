mod streaming_support;
use gateway_llm::streaming::openai_compat::{Observation, Observer, State};
use gateway_llm::types::completions::typed as chat;
use serde_json::{Value, json};
#[derive(Default)]
struct Observations {
	order: Vec<&'static str>,
	next_id: u64,
}
impl Observer for Observations {
	fn created_at(&mut self) -> u64 {
		self.order.push("timestamp");
		1700000000
	}
	fn tool_id(&mut self) -> String {
		self.next_id += 1;
		format!("call_{:016x}", self.next_id)
	}
	fn observe(&mut self, event: Observation<'_>) {
		self.order.push(match event {
			Observation::FirstDelta => "first",
			Observation::Usage(_) => "usage",
			Observation::Provider { .. } => "provider",
		});
	}
}
#[test]
fn complete_responses_state_matches_original_golden_with_ordered_observations() {
	let fixture = streaming_support::fixture();
	let mut checked = 0;
	for case in fixture["cases"]
		.as_array()
		.unwrap()
		.iter()
		.filter(|c| c["kind"] == "chat-responses")
	{
		let name = case["name"].as_str().unwrap();
		if [
			"oversize",
			"missing-done",
			"truncated",
			"comments",
			"after-done",
		]
		.contains(&name)
		{
			continue;
		}
		let mut state = State::new(
			"resp_0000000000000000".into(),
			"msg_0000000000000000".into(),
		);
		let mut observer = Observations::default();
		let mut output = Vec::new();
		for frame in case["input"].as_str().unwrap().split("\n\n") {
			let Some(data) = frame.lines().find_map(|line| line.strip_prefix("data: ")) else {
				continue;
			};
			let events = if data == "[DONE]" {
				state.finish(&mut observer)
			} else {
				match serde_json::from_str::<chat::StreamResponse>(data) {
					Ok(chunk) => state.push(chunk, &mut observer),
					Err(_) => continue,
				}
			};
			output.extend(events.into_iter().map(|(event, data)| {
				format!(
					"event: {event}\ndata: {}\n\n",
					serde_json::to_string(&data).unwrap()
				)
			}));
		}
		let events = streaming_support::event_values(&streaming_support::normalize_frames(output));
		assert_eq!(json!(events), case["expected"]["events"], "{name}");
		if name == "finish-stop" {
			assert_eq!(
				observer.order,
				[
					"timestamp",
					"provider",
					"first",
					"usage",
					"usage",
					"timestamp"
				]
			);
		}
		checked += 1;
	}
	assert_eq!(checked, 22);
}
#[test]
fn finishing_is_idempotent_and_concurrent_states_do_not_share_arguments() {
	let mut left = State::new("resp_left".into(), "msg_left".into());
	let mut right = State::new("resp_right".into(), "msg_right".into());
	let mut observer = Observations::default();
	let chunk:chat::StreamResponse=serde_json::from_value(json!({"id":"id","object":"chat.completion.chunk","model":"model","created":1,"choices":[{"index":0,"delta":{"content":"hello"}}]})).unwrap();
	left.push(chunk.clone(), &mut observer);
	right.push(chunk, &mut observer);
	let first = left.finish(&mut observer);
	assert!(!first.is_empty());
	assert!(left.finish(&mut observer).is_empty());
	let second = right.finish(&mut observer);
	let value = serde_json::to_value(&second.last().unwrap().1).unwrap();
	assert_eq!(value["response"]["id"], "resp_right");
}
#[test]
fn error_envelopes_preserve_fallbacks_status_and_structured_provider_errors() {
	use bytes::Bytes;
	use gateway_llm::conversion::errors;
	let google = Bytes::from_static(
		br#"[{"error":{"code":403,"message":"denied","status":"PERMISSION_DENIED"}}]"#,
	);
	let out: Value = serde_json::from_slice(&errors::google_to_openai(&google).unwrap()).unwrap();
	assert_eq!(out["error"]["message"], "denied");
	assert_eq!(out["error"]["code"], "PERMISSION_DENIED");
	assert!(errors::google_to_openai(&Bytes::from_static(b"[]")).is_err());
	let raw = Bytes::from_static(b"provider failed");
	let out: Value = serde_json::from_slice(
		&errors::normalize_anthropic(&raw, http::StatusCode::TOO_MANY_REQUESTS).unwrap(),
	)
	.unwrap();
	assert_eq!(out["error"]["type"], "rate_limit_error");
	let structured =
		Bytes::from_static(br#"{"type":"error","error":{"type":"custom","message":"kept"}}"#);
	assert_eq!(
		errors::normalize_anthropic(&structured, http::StatusCode::BAD_GATEWAY).unwrap(),
		structured
	);
	assert!(errors::openai_to_anthropic(&raw, http::StatusCode::FORBIDDEN).is_err());
}

#[test]
fn buffered_formats_preserve_tools_cache_usage_and_terminal_reason() {
	let anthropic=serde_json::from_value(json!({"id":"message","type":"message","role":"assistant","model":"model","content":[{"type":"text","text":"hello"},{"type":"text","text":" world"},{"type":"tool_use","id":"tool-id","name":"danger.tool","input":{"x":1}}],"stop_reason":"tool_use","stop_sequence":null,"usage":{"input_tokens":17,"output_tokens":5,"cache_read_input_tokens":3,"cache_creation_input_tokens":4}})).unwrap();
	let chat = gateway_llm::conversion::messages::from_completions::translate_response(anthropic);
	assert_eq!(
		chat.choices[0].message.content.as_deref(),
		Some("hello world")
	);
	assert_eq!(
		chat.usage.as_ref().unwrap().cache_read_input_tokens,
		Some(3)
	);
	let base =
		gateway_llm::streaming::responses::ResponseBuilder::new_at("resp_fixed", "model", 1700000000)
			.response(
				gateway_llm::types::responses::typed::Status::InProgress,
				None,
				None,
				None,
			);
	let out = gateway_llm::conversion::openai_compat::to_responses::translate_response(chat, base);
	let value = serde_json::to_value(out).unwrap();
	assert_eq!(value["id"], "resp_fixed");
	assert_eq!(value["created_at"], 1700000000);
	assert_eq!(value["status"], "completed");
	assert_eq!(value["output"][1]["name"], "danger.tool");
	assert_eq!(value["output"][1]["arguments"], r#"{"x":1}"#);
	assert_eq!(value["usage"]["input_tokens_details"]["cached_tokens"], 3);
}
