use gateway_llm::{CacheTokenConvention, LLMResponse, WireError, types};
use serde_json::Value;

mod support;

fn check_group(prefix: &str) {
	let fixture: Value = serde_json::from_str(include_str!("fixtures/serde-golden.json")).unwrap();
	let cases: Vec<_> = fixture["cases"]
		.as_array()
		.unwrap()
		.iter()
		.filter(|case| case["kind"].as_str().unwrap().starts_with(prefix))
		.collect();
	assert!(!cases.is_empty(), "missing golden group: {prefix}");
	for case in cases {
		assert_eq!(support::observe(case), case["expected"], "{}", case["name"]);
	}
}

macro_rules! golden_group {
	($name:ident, $prefix:literal) => {
		#[test]
		fn $name() {
			check_group($prefix);
		}
	};
}

golden_group!(chat_completions, "chat-");
golden_group!(responses, "responses-");
golden_group!(messages, "messages-");
golden_group!(embeddings, "embeddings-");
golden_group!(token_counting, "count-");
golden_group!(rerank, "rerank-");
golden_group!(bedrock, "bedrock-");
golden_group!(vertex, "vertex-");
golden_group!(normalized_response, "normalized-");
golden_group!(cache_convention, "cache-");

#[test]
fn golden_inventory_is_exhaustive() {
	let fixture: Value = serde_json::from_str(include_str!("fixtures/serde-golden.json")).unwrap();
	assert_eq!(
		fixture["provenance"]["capturedBeforeProductionMigration"],
		true
	);
	let cases = fixture["cases"].as_array().unwrap();
	assert_eq!(cases.len(), 212);
	let mut names = std::collections::HashSet::new();
	for case in cases {
		assert!(
			names.insert(case["name"].as_str().unwrap()),
			"duplicate case"
		);
		let kind = case["kind"].as_str().unwrap();
		assert_eq!(
			[
				"chat-",
				"responses-",
				"messages-",
				"embeddings-",
				"count-",
				"rerank-",
				"bedrock-",
				"vertex-",
				"normalized-",
				"cache-"
			]
			.iter()
			.filter(|prefix| kind.starts_with(**prefix))
			.count(),
			1,
			"case must be tested exactly once: {kind}"
		);
	}
}

#[test]
fn typed_bridge_error_retains_json_category_and_display() {
	let request: types::embeddings::Request =
		serde_json::from_str(r#"{"model":"embed","input":[1,2]}"#).unwrap();
	let result: Result<types::embeddings::typed::Request, WireError> = (&request).try_into();
	let error = result.unwrap_err();
	assert!(error.to_string().starts_with("failed to marshal request: "));
	let WireError::RequestMarshal(source) = error else {
		panic!("typed request bridge returned a different error category")
	};
	assert_eq!(source.classify(), serde_json::error::Category::Data);
}
