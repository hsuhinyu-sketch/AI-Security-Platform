use gateway_llm::streaming::responses;
use gateway_llm::types::{completions::typed as chat, responses::typed as wire};
use serde_json::{Value, json};
use std::collections::HashMap;

fn fixture() -> Value {
	serde_json::from_str(include_str!("fixtures/streaming-golden.json")).unwrap()
}

#[test]
fn response_builder_matches_original_created_and_terminal_objects() {
	let fixture = fixture();
	let mut count = 0;
	for case in fixture["cases"]
		.as_array()
		.unwrap()
		.iter()
		.filter(|c| c["kind"] == "chat-responses")
	{
		for event in case["expected"]["events"].as_array().unwrap() {
			let data = &event["data"];
			let response = &data["response"];
			if !response.is_object() {
				continue;
			}
			let builder = responses::ResponseBuilder::new_at(
				response["id"].as_str().unwrap(),
				response["model"].as_str().unwrap(),
				1700000000,
			);
			let seq = data["sequence_number"].as_u64().unwrap();
			let usage =
				serde_json::from_value::<Option<wire::ResponseUsage>>(response["usage"].clone()).unwrap();
			let actual = match data["type"].as_str().unwrap() {
				"response.created" => builder.created_event(seq),
				"response.completed" => builder.completed_event(seq, usage),
				"response.failed" => builder.failed_event(
					seq,
					usage,
					serde_json::from_value(response["error"].clone()).unwrap(),
				),
				"response.incomplete" => builder.incomplete_event(
					seq,
					usage,
					serde_json::from_value(response["incomplete_details"].clone()).unwrap(),
				),
				ty => panic!("unexpected original event {ty}"),
			};
			assert_eq!(
				serde_json::to_value(actual).unwrap(),
				*data,
				"{}",
				case["name"]
			);
			count += 1;
		}
	}
	assert!(count > 40);
}

#[test]
fn responses_terminal_state_matches_original_event_order_and_usage() {
	let fixture = fixture();
	let mut count = 0;
	for case in fixture["cases"]
		.as_array()
		.unwrap()
		.iter()
		.filter(|c| c["kind"] == "chat-responses")
	{
		let expected = case["expected"]["events"].as_array().unwrap();
		let Some(end) = expected.iter().position(|e| {
			matches!(
				e["data"]["type"].as_str(),
				Some("response.completed" | "response.incomplete" | "response.failed")
			)
		}) else {
			continue;
		};
		let start = expected
			.iter()
			.position(|e| {
				matches!(
					e["data"]["type"].as_str(),
					Some(
						"response.function_call_arguments.done"
							| "response.content_part.done"
							| "response.output_item.done"
					)
				)
			})
			.unwrap();
		let response = &expected[end]["data"]["response"];
		let builder = responses::ResponseBuilder::new_at(
			response["id"].as_str().unwrap(),
			response["model"].as_str().unwrap(),
			1700000000,
		);
		let mut sequence = expected[start]["data"]["sequence_number"].as_u64().unwrap() - 1;
		let message = expected
			.iter()
			.find(|e| e["data"]["output_index"] == 0 && e["data"]["item"]["type"] == "message")
			.unwrap()["data"]["item"]["id"]
			.as_str()
			.unwrap();
		let mut tools: HashMap<u32, (String, String, String, u32)> = HashMap::new();
		let mut next = 1;
		let mut reason = None;
		let mut usage = None;
		let mut content = false;
		for data in case["input"]
			.as_str()
			.unwrap()
			.lines()
			.filter_map(|l| l.strip_prefix("data: "))
		{
			if data == "[DONE]" {
				break;
			}
			let Ok(chunk) = serde_json::from_str::<chat::StreamResponse>(data) else {
				continue;
			};
			if let Some(u) = chunk.usage {
				usage = Some(u);
			}
			if let Some(choice) = chunk.choices.first() {
				content |= choice.delta.content.is_some();
				if let Some(calls) = &choice.delta.tool_calls {
					for tc in calls {
						let entry = tools.entry(tc.index).or_insert_with(|| {
							let index = next;
							next += 1;
							let id = expected
								.iter()
								.find(|e| {
									e["data"]["type"] == "response.output_item.added"
										&& e["data"]["output_index"] == index
								})
								.unwrap()["data"]["item"]["id"]
								.as_str()
								.unwrap();
							(id.into(), String::new(), String::new(), index)
						});
						if let Some(f) = &tc.function {
							if let Some(n) = &f.name {
								entry.1 = n.clone();
							}
							if let Some(a) = &f.arguments {
								entry.2.push_str(a);
							}
						}
					}
				}
				if let Some(r) = choice.finish_reason {
					reason = Some(r);
				}
			}
			if reason.is_some() && usage.is_some() {
				break;
			}
		}
		let mut events = Vec::new();
		responses::close_items(&mut events, &mut sequence, &mut tools, message, content);
		let terminal = responses::terminal_event(
			&builder,
			&mut sequence,
			reason,
			responses::normalize_usage(usage),
		);
		events.push(("event", terminal));
		let actual: Vec<_> = events
			.into_iter()
			.map(|(name, event)| json!({"event":name,"data":event}))
			.collect();
		assert_eq!(actual, expected[start..=end], "{}", case["name"]);
		assert!(tools.is_empty());
		assert_eq!(
			sequence,
			expected[end]["data"]["sequence_number"].as_u64().unwrap()
		);
		count += 1;
	}
	assert!(count > 20);
}
