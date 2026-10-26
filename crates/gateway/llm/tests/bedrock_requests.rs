use base64::Engine;
use gateway_llm::conversion::bedrock::request::{self, ConverseOptions, PromptCachingConfig};
use serde_json::{Value, json};

#[test]
fn completions_preserve_guardrails_metadata_cache_and_request_local_tool_aliases() {
	let options = ConverseOptions {
		guardrail_identifier: Some("guard"),
		guardrail_version: Some("7"),
		allowed_beta_headers: &[],
	};
	let req = serde_json::from_value(json!({"model":"anthropic.claude-3-5-sonnet-20241022-v2:0","messages":[{"role":"system","content":"rules"},{"role":"user","content":"first"},{"role":"assistant","content":"answer"},{"role":"user","content":"next"}],"tools":[{"type":"function","function":{"name":"danger.tool","parameters":{"type":"object"}}}],"tool_choice":{"type":"function","function":{"name":"danger.tool"}}})).unwrap();
	let mut headers = http::HeaderMap::new();
	headers.insert(
		"x-bedrock-metadata",
		r#"{"tenant":"alpha","nested":{"ignored":true}}"#.parse().unwrap(),
	);
	let cache = PromptCachingConfig {
		min_tokens: None,
		cache_tools: true,
		..Default::default()
	};
	let out =
		request::from_completions::translate(&req, &options, Some(&headers), Some(&cache)).unwrap();
	let body: Value = serde_json::from_slice(&out.body).unwrap();
	assert_eq!(body["guardrailConfig"]["guardrailIdentifier"], "guard");
	assert_eq!(body["guardrailConfig"]["guardrailVersion"], "7");
	assert_eq!(body["requestMetadata"], json!({"tenant":"alpha"}));
	assert_eq!(body["system"][1]["cachePoint"]["type"], "default");
	assert_eq!(
		body["messages"][1]["content"][1]["cachePoint"]["type"],
		"default"
	);
	assert_eq!(body["messages"][2]["content"].as_array().unwrap().len(), 1);
	assert_eq!(
		body["toolConfig"]["tools"][1]["cachePoint"]["type"],
		"default"
	);
	let name = body["toolConfig"]["tools"][0]["toolSpec"]["name"]
		.as_str()
		.unwrap();
	assert_ne!(name, "danger.tool");
	assert_eq!(out.tool_name_map.restore(name), "danger.tool");
	assert_eq!(body["toolConfig"]["toolChoice"]["tool"]["name"], name);
	let separate = request::from_completions::translate(
		&serde_json::from_value(json!({"model":"plain","messages":[]})).unwrap(),
		&options,
		None,
		None,
	)
	.unwrap();
	assert!(separate.tool_name_map.is_empty());
}

#[test]
fn messages_beta_is_explicit_and_responses_use_the_same_converse_tool_contract() {
	let allowed = ["accepted".into()];
	let options = ConverseOptions {
		guardrail_identifier: None,
		guardrail_version: None,
		allowed_beta_headers: &allowed,
	};
	let mut headers = http::HeaderMap::new();
	headers.insert("anthropic-beta", "accepted,untrusted".parse().unwrap());
	let req = serde_json::from_value(
		json!({"model":"claude","max_tokens":32,"messages":[{"role":"user","content":"hi"}]}),
	)
	.unwrap();
	let out = request::from_messages::translate(&req, &options, Some(&headers)).unwrap();
	let body: Value = serde_json::from_slice(&out.body).unwrap();
	assert_eq!(
		body["additionalModelRequestFields"]["anthropic_beta"],
		json!(["accepted"])
	);
	let options = ConverseOptions {
		allowed_beta_headers: &[],
		..options
	};
	let out = request::from_messages::translate(&req, &options, Some(&headers)).unwrap();
	let body: Value = serde_json::from_slice(&out.body).unwrap();
	assert!(body["additionalModelRequestFields"]["anthropic_beta"].is_null());
	let req=serde_json::from_value(json!({"model":"claude","input":"hi","tools":[{"type":"function","name":"danger.tool","parameters":{"type":"object"},"strict":false}]})).unwrap();
	let out = request::from_responses::translate(&req, &options, None, None).unwrap();
	let body: Value = serde_json::from_slice(&out.body).unwrap();
	assert_eq!(body["messages"][0]["content"][0]["text"], "hi");
	let name = body["toolConfig"]["tools"][0]["toolSpec"]["name"]
		.as_str()
		.unwrap();
	assert_eq!(out.tool_name_map.restore(name), "danger.tool");
}

#[test]
fn count_tokens_wraps_anthropic_payload_without_model_or_generation_side_effects() {
	let request = serde_json::from_value(
		json!({"model":"claude","messages":[{"role":"user","content":"hello"}]}),
	)
	.unwrap();
	let mut headers = http::HeaderMap::new();
	headers.insert("anthropic-version", "2023-06-01".parse().unwrap());
	let out = request::from_anthropic_token_count::translate(&request, &headers).unwrap();
	let envelope: Value = serde_json::from_slice(&out).unwrap();
	let payload = base64::engine::general_purpose::STANDARD
		.decode(envelope["input"]["invokeModel"]["body"].as_str().unwrap())
		.unwrap();
	let payload: Value = serde_json::from_slice(&payload).unwrap();
	assert!(payload.get("model").is_none());
	assert_eq!(payload["max_tokens"], 1);
	assert_eq!(payload["anthropic_version"], "2023-06-01");
	assert_eq!(payload["messages"][0]["content"], "hello");
	assert!(serde_json::from_value::<PromptCachingConfig>(json!({"unknown":true})).is_err());
}
