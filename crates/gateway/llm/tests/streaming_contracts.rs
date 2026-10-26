use gateway_llm::streaming::{completions, messages};
use serde_json::{Value, json};

#[path = "streaming_support/mod.rs"]
mod support;

fn observe(case: &Value) -> Value {
	let mut chat = completions::State::default();
	let mut message = messages::State::new(42);
	let mut events = Vec::new();
	let mut stats = json!({"input":null,"output":null,"total":null,"cached":null,"cacheWrite":null,
		"reasoning":null,"model":null,"tier":null,"firstToken":false});
	let mut first_token_count = 0;
	for data in case["input"]
		.as_str()
		.unwrap()
		.lines()
		.filter_map(|l| l.strip_prefix("data: "))
	{
		if case["kind"] == "chat-messages" {
			let step = if data == "[DONE]" {
				chat.finish()
			} else {
				let Ok(chunk) = serde_json::from_str(data) else {
					continue;
				};
				chat.push(chunk)
			};
			for (name, event) in step.events {
				events.push(json!({"event":name,"data":event}));
			}
			for observation in step.observations {
				match observation {
					completions::Observation::ProviderModel(model) => stats["model"] = json!(model),
					completions::Observation::FirstToken => {
						first_token_count += 1;
						stats["firstToken"] = json!(true);
					},
					completions::Observation::Usage(u) => {
						stats["input"] = json!(u.prompt_tokens);
						stats["output"] = json!(u.completion_tokens);
						stats["total"] = json!(u.total_tokens);
					},
				}
			}
		} else {
			let Ok(event) = serde_json::from_str(data) else {
				continue;
			};
			let step = message.push(event);
			if let Some(event) = step.event {
				let frames = support::normalize_frames(vec![format!(
					"data: {}\n\n",
					serde_json::to_string(&event).unwrap()
				)]);
				events.extend(support::event_values(&frames));
			}
			for observation in step.observations {
				match observation {
					messages::Observation::Start { model, usage } => {
						stats["model"] = json!(model);
						stats["tier"] = json!(usage.service_tier);
						stats["input"] = json!(usage.input_tokens);
						stats["output"] = json!(usage.output_tokens);
						stats["cached"] = json!(usage.cache_read_input_tokens);
						stats["cacheWrite"] = json!(usage.cache_creation_input_tokens);
					},
					messages::Observation::FirstToken => {
						first_token_count += 1;
						stats["firstToken"] = json!(true);
					},
					messages::Observation::Usage(u) => {
						if let Some(v) = u.output_tokens {
							stats["output"] = json!(v);
						}
						if let Some(v) = u.cache_read_input_tokens {
							stats["cached"] = json!(v);
						}
						if let Some(v) = u.cache_creation_input_tokens {
							stats["cacheWrite"] = json!(v);
						}
						if let (Some(i), Some(o)) = (stats["input"].as_u64(), stats["output"].as_u64()) {
							stats["total"] = json!(i + o);
						}
					},
				}
			}
		}
	}
	assert!(first_token_count <= 1);
	json!({"events":events,"stats":stats})
}

fn check(kind: &str) {
	let fixture = support::fixture();
	let mut count = 0;
	for case in fixture["cases"]
		.as_array()
		.unwrap()
		.iter()
		.filter(|c| c["kind"] == kind && c["name"] != "oversize")
	{
		let expected_events: Vec<_> = case["expected"]["events"]
			.as_array()
			.unwrap()
			.iter()
			.filter(|event| event["data"] != "[DONE]")
			.cloned()
			.collect();
		assert_eq!(
			observe(case),
			json!({"events":expected_events,"stats":case["expected"]["stats"]}),
			"{} {}",
			kind,
			case["name"]
		);
		count += 1;
	}
	assert!(count > 20);
}

#[test]
fn completions_to_messages_original_event_and_statistics_contract() {
	check("chat-messages");
}

#[test]
fn messages_to_completions_original_event_and_statistics_contract() {
	check("messages-chat");
}

#[test]
fn concurrent_stream_states_keep_their_own_tools_and_metadata() {
	std::thread::scope(|scope| {
		for _ in 0..4 {
			scope.spawn(|| check("chat-messages"));
			scope.spawn(|| check("messages-chat"));
		}
	});
}
