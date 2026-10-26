use super::*;
use serde_json::{Value, json};

fn observe_map(case: &Value) -> Value {
	let mut map = BedrockToolNameMap::default();
	let mut registrations = Vec::new();
	for name in case["names"].as_array().unwrap() {
		let name = name.as_str().unwrap();
		let mapped = map.register(name);
		let restored = map.restore(&mapped);
		assert_eq!(restored, if name.is_empty() { "tool" } else { name });
		registrations.push(json!({"mapped":mapped,"restored":restored,"empty":map.is_empty()}));
	}
	let probes: Vec<_> = case["probes"]
		.as_array()
		.unwrap()
		.iter()
		.map(|n| map.restore(n.as_str().unwrap()))
		.collect();
	json!({"registrations":registrations,"probes":probes})
}

fn observe_response(case: &Value) -> Value {
	let response = match serde_json::from_value::<bedrock::ConverseResponse>(case["input"].clone()) {
		Ok(r) => r,
		Err(e) => return json!({"parseError":e.to_string()}),
	};
	let mut map = BedrockToolNameMap::default();
	map.register("danger.tool");
	let adapter = match ConverseResponseAdapter::from_response(response, "fixture") {
		Ok(a) => a,
		Err(e) => return json!({"error":format!("{e:?}"),"display":e.to_string()}),
	};
	match adapter.to_anthropic(Some(&map)) {
		Ok(r) => {
			let mut v = serde_json::to_value(r).unwrap();
			let id = v["id"].as_str().unwrap();
			assert!(id.starts_with("msg_"));
			v["id"] = "msg_fixture".into();
			json!({"ok":v})
		},
		Err(e) => json!({"error":format!("{e:?}"),"display":e.to_string()}),
	}
}

#[test]
fn bedrock_mapping_and_aggregation_match_original_golden() {
	let fixture: Value = serde_json::from_str(include_str!(
		"../../../../llm/tests/fixtures/bedrock-state-golden.json"
	))
	.unwrap();
	assert_eq!(fixture["maps"].as_array().unwrap().len(), 5);
	assert_eq!(fixture["responses"].as_array().unwrap().len(), 27);
	for c in fixture["maps"].as_array().unwrap() {
		assert_eq!(observe_map(c), c["expected"], "{c}");
	}
	for c in fixture["responses"].as_array().unwrap() {
		assert_eq!(observe_response(c), c["expected"], "{c}");
	}
}
