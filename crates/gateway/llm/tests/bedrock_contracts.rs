mod bedrock_support;
use gateway_llm::streaming::bedrock::to_anthropic_message_delta_usage;
use serde_json::{Value, json};

#[test]
fn decoded_values_preserve_original_fields_and_unknown_errors() {
	let fixture = bedrock_support::fixture();
	let mut checked = 0;
	for c in fixture["cases"].as_array().unwrap() {
		for (input, expected) in c["events"]
			.as_array()
			.unwrap()
			.iter()
			.zip(c["expected"]["decoded"].as_array().unwrap())
		{
			let Some(result) = bedrock_support::decode(input) else {
				continue;
			};
			let actual = match result {
				Ok(e) => json!({"ok":format!("{e:?}")}),
				Err(e) => json!({"error":e.to_string()}),
			};
			assert_eq!(&actual, expected, "{input}");
			checked += 1;
		}
	}
	assert!(checked > 100);
}

#[test]
fn usage_preserves_missing_zero_cache_and_large_counts() {
	let cases: Vec<Value> =
		serde_json::from_str(include_str!("fixtures/bedrock-usage-golden.json")).unwrap();
	assert_eq!(cases.len(), 6);
	for c in cases {
		let usage = serde_json::from_value(c["input"].clone()).unwrap();
		assert_eq!(
			serde_json::to_value(to_anthropic_message_delta_usage(usage)).unwrap(),
			c["expected"]
		);
	}
}
