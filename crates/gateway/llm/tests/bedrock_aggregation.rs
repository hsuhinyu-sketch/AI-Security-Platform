use gateway_llm::{
	conversion::bedrock::anthropic_content_and_usage, provider::bedrock::BedrockToolNameMap,
	types::bedrock::*,
};
use serde_json::Value;

#[test]
fn anthropic_aggregate_preserves_original_order_signatures_tools_and_cache() {
	let fixture: Value =
		serde_json::from_str(include_str!("fixtures/bedrock-state-golden.json")).unwrap();
	let mut count = 0;
	let mut rejected = 0;
	for c in fixture["responses"].as_array().unwrap() {
		let response = match serde_json::from_value::<ConverseResponse>(c["input"].clone()) {
			Ok(r) => r,
			Err(e) => {
				assert_eq!(e.to_string(), c["expected"]["parseError"].as_str().unwrap());
				rejected += 1;
				continue;
			},
		};
		let Some(ConverseOutput::Message(message)) = response.output else {
			// The Host's from_response rejects missing/unknown output before aggregation.
			assert_eq!(c["expected"]["error"], "IncompleteResponse");
			rejected += 1;
			continue;
		};
		let mut map = BedrockToolNameMap::default();
		map.register("danger.tool");
		let (content, usage) = anthropic_content_and_usage(&message, response.usage, Some(&map));
		assert_eq!(
			serde_json::to_value(content).unwrap(),
			c["expected"]["ok"]["content"],
			"{}",
			c["name"]
		);
		assert_eq!(
			serde_json::to_value(usage).unwrap(),
			c["expected"]["ok"]["usage"],
			"{}",
			c["name"]
		);
		count += 1;
	}
	assert_eq!(count, 20);
	assert_eq!(rejected, 7);
}

#[test]
fn complete_buffered_adapter_matches_original_golden_including_incomplete_output() {
	use gateway_llm::conversion::bedrock::response::ConverseResponseAdapter;
	use serde_json::json;
	let fixture: Value =
		serde_json::from_str(include_str!("fixtures/bedrock-state-golden.json")).unwrap();
	for case in fixture["responses"].as_array().unwrap() {
		let response = match serde_json::from_value::<ConverseResponse>(case["input"].clone()) {
			Ok(r) => r,
			Err(e) => {
				assert_eq!(
					e.to_string(),
					case["expected"]["parseError"].as_str().unwrap()
				);
				continue;
			},
		};
		let mut names = BedrockToolNameMap::default();
		names.register("danger.tool");
		let actual = match ConverseResponseAdapter::from_response(response, "fixture") {
			Ok(adapter) => {
				let mut out = adapter.to_anthropic(Some(&names)).unwrap();
				assert!(out.id.is_empty());
				out.id = "msg_fixture".into();
				json!({"ok":out})
			},
			Err(e) => json!({"error":format!("{e:?}"),"display":e.to_string()}),
		};
		assert_eq!(actual, case["expected"], "{}", case["name"]);
	}
}
