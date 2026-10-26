mod bedrock_support;
use gateway_llm::streaming::bedrock::{CompletionsState, Observation};
use gateway_llm::types::bedrock::*;
use serde_json::{Value, json};

fn verify() {
	let fixture = bedrock_support::fixture();
	let mut count = 0;
	for c in fixture["cases"].as_array().unwrap() {
		if c["direction"] != "chat" || c.get("damage").is_some() {
			continue;
		}
		let mut state = CompletionsState::new("fixture", "fixed-message", 1700000000);
		let mut events = Vec::new();
		let mut first = false;
		let mut stats =
			json!({"input":null,"output":null,"total":null,"cached":null,"cacheWrite":null});
		for input in c["events"].as_array().unwrap() {
			let Some(Ok(mut decoded)) = bedrock_support::decode(input) else {
				continue;
			};
			match CompletionsState::observation(&decoded) {
				Some(Observation::FirstDelta) => first = true,
				Some(Observation::Usage(u)) => {
					stats = json!({"input":u.input_tokens,"output":u.output_tokens,"total":u.total_tokens,"cached":u.cache_read_input_tokens,"cacheWrite":u.cache_write_input_tokens});
				},
				None => {},
			}
			// The original Host restores the request-local alias before the pure transition.
			if let ConverseStreamOutput::ContentBlockStart(start) = &mut decoded
				&& let Some(ContentBlockStart::ToolUse(t)) = &mut start.start
				&& t.name == "danger_tool"
			{
				t.name = "danger.tool".into();
			}
			if let Some(event) = state.push(decoded) {
				events.push(json!({"event":"","data":event}));
			}
		}
		let expected: Vec<Value> = c["expected"]["events"]
			.as_array()
			.unwrap()
			.iter()
			.filter(|e| e["data"] != "[DONE]")
			.cloned()
			.collect();
		assert_eq!(events, expected, "{}", c["name"]);
		assert_eq!(first, c["expected"]["stats"]["firstToken"], "{}", c["name"]);
		for (field, value) in stats.as_object().unwrap() {
			assert_eq!(
				value, &c["expected"]["stats"][field],
				"{} {field}",
				c["name"]
			);
		}
		count += 1;
	}
	assert_eq!(count, 33);
}

#[test]
fn decoded_state_matches_original_stream_events_and_statistics() {
	verify();
}

#[test]
fn concurrent_streams_do_not_share_tool_blocks() {
	let threads: Vec<_> = (0..8).map(|_| std::thread::spawn(verify)).collect();
	for t in threads {
		t.join().unwrap();
	}
}

#[test]
fn messages_state_matches_original_golden_without_host_or_ambient_identity() {
	use gateway_llm::streaming::bedrock::messages::MessagesState;
	let fixture = bedrock_support::fixture();
	let mut tested = 0;
	for c in fixture["cases"].as_array().unwrap() {
		if c["direction"] != "messages" || c.get("damage").is_some() {
			continue;
		}
		let decoded: Option<Vec<_>> = c["events"]
			.as_array()
			.unwrap()
			.iter()
			.map(|e| bedrock_support::decode(e).and_then(Result::ok))
			.collect();
		let Some(decoded) = decoded else {
			continue;
		};
		let mut names = gateway_llm::provider::bedrock::BedrockToolNameMap::default();
		names.register("danger.tool");
		let mut state = MessagesState::new("fixture", Some(names));
		let mut events = Vec::new();
		let mut next = 0;
		for input in decoded {
			let identity = if matches!(input, ConverseStreamOutput::MessageStart(_)) {
				let id = format!("msg_fixture_{next}");
				next += 1;
				id
			} else {
				String::new()
			};
			events.extend(
				state
					.push(input, &identity)
					.into_iter()
					.map(|(event, data)| json!({"event":event,"data":data})),
			);
		}
		assert_eq!(json!(events), c["expected"]["events"], "{}", c["name"]);
		tested += 1;
	}
	assert!(
		tested >= 20,
		"insufficient original protocol cases: {tested}"
	);
}

#[test]
fn responses_state_keeps_tool_indices_arguments_and_terminal_usage_isolated() {
	use gateway_llm::streaming::bedrock::responses::ResponsesState;
	let mut names = gateway_llm::provider::bedrock::BedrockToolNameMap::default();
	names.register("danger.tool");
	let mut first = ResponsesState::new(
		"resp_one".into(),
		"msg_one".into(),
		"fixture".into(),
		1700000000,
		Some(names),
	);
	let mut second = ResponsesState::new(
		"resp_two".into(),
		"msg_two".into(),
		"fixture".into(),
		1700000001,
		None,
	);
	let inputs = [
		json!({"type":"messageStart","payload":r#"{"role":"assistant"}"#}),
		json!({"type":"contentBlockStart","payload":r#"{"contentBlockIndex":2,"start":{"toolUse":{"toolUseId":"upstream-id","name":"danger_tool"}}}"#}),
		json!({"type":"contentBlockDelta","payload":r#"{"contentBlockIndex":2,"delta":{"toolUse":{"input":"{\"x\":1}"}}}"#}),
		json!({"type":"contentBlockStop","payload":r#"{"contentBlockIndex":2}"#}),
		json!({"type":"messageStop","payload":r#"{"stopReason":"max_tokens"}"#}),
		json!({"type":"metadata","payload":r#"{"usage":{"inputTokens":17,"outputTokens":5,"totalTokens":22,"cacheReadInputTokens":3}}"#}),
	];
	let events: Vec<Value> = inputs
		.iter()
		.flat_map(|input| {
			first.push(
				bedrock_support::decode(input).unwrap().unwrap(),
				"call_fixed",
			)
		})
		.map(|(_, e)| serde_json::to_value(e).unwrap())
		.collect();
	assert_eq!(events[0]["response"]["id"], "resp_one");
	let added = events
		.iter()
		.find(|e| e["item"]["type"] == "function_call")
		.unwrap();
	assert_eq!(added["output_index"], 1);
	assert_eq!(added["item"]["name"], "danger.tool");
	let args = events
		.iter()
		.find(|e| e["type"] == "response.function_call_arguments.done")
		.unwrap();
	assert_eq!(args["arguments"], r#"{"x":1}"#);
	assert_eq!(args["output_index"], 1);
	let terminal = events.last().unwrap();
	assert_eq!(terminal["type"], "response.incomplete");
	assert_eq!(terminal["response"]["usage"]["total_tokens"], 22);
	let seq: Vec<u64> = events
		.iter()
		.map(|e| e["sequence_number"].as_u64().unwrap())
		.collect();
	assert!(seq.windows(2).all(|w| w[0] < w[1]));
	let other = second.push(bedrock_support::decode(&inputs[0]).unwrap().unwrap(), "");
	let value = serde_json::to_value(&other[0].1).unwrap();
	assert_eq!(value["sequence_number"], 1);
	assert_eq!(value["response"]["id"], "resp_two");
}
