use super::*;
use gateway_protocol_core::{execution::ExecutionFuture, model::TextResponse};

fn params() -> Value {
	json!({"messages":[{"role":"user","content":{"type":"text","text":"hello"}}],
		"modelPreferences":{"hints":[{"name":"local"}]},"maxTokens":8})
}
fn parse(value: &Value) -> Result<Request, InvalidSampling> {
	Request::parse(value, &["local".into()], 256)
}

#[test]
fn sampling_rejects_unbounded_context_and_unsupported_execution_fields() {
	for (field, value) in [
		("includeContext", json!("allServers")),
		("temperature", json!(1)),
		("maxTokens", json!(0)),
		("maxTokens", json!(257)),
		("maxTokens", json!(-1)),
		("messages", json!([])),
		(
			"messages",
			json!([{"role":"system","content":{"type":"text","text":"x"}}]),
		),
		(
			"messages",
			json!([{"role":"user","content":{"type":"image","data":"x","mimeType":"image/png"}}]),
		),
		(
			"messages",
			json!([{"role":"user","content":{"type":"text","text":"x","extra":true}}]),
		),
		(
			"messages",
			json!([{"role":"user","content":{"type":"text","text":"x"},"extra":true}]),
		),
		("modelPreferences", json!({"hints":[{"name":"foreign"}]})),
		("modelPreferences", json!({"hints":[]})),
		(
			"modelPreferences",
			json!({"hints":[{"name":"local","extra":true}]}),
		),
		(
			"modelPreferences",
			json!({"hints":[{"name":"local"}],"costPriority":1}),
		),
		("stopSequences", json!(["x".repeat(257)])),
		("systemPrompt", json!("x".repeat(8193))),
	] {
		let mut value_under_test = params();
		value_under_test[field] = value;
		assert!(parse(&value_under_test).is_err(), "accepted {field}");
	}
}

#[test]
fn limits_count_utf8_bytes_and_preserve_optional_system_and_stops() {
	let mut value = params();
	value["messages"][0]["content"]["text"] = json!("界".repeat(2731));
	assert!(parse(&value).is_err());
	value["messages"][0]["content"]["text"] = json!("x".repeat(8192));
	value["systemPrompt"] = json!("system");
	value["stopSequences"] = json!([]);
	value["includeContext"] = json!("none");
	let request = parse(&value).unwrap();
	assert_eq!(request.text.messages.len(), 2);
	assert_eq!(request.text.messages[0].role, TextRole::System);
	assert_eq!(request.text.stop, Some(vec![]));
	assert!(request.matches_model("local"));
	assert!(!request.matches_model("other"));
	value["messages"] = json!(vec![value["messages"][0].clone(); 17]);
	assert!(parse(&value).is_err());
}

struct Executor(Result<TextResponse, &'static str>);
impl BoundTextGeneration for Executor {
	type Error = &'static str;
	fn generate(&self, request: TextRequest) -> ExecutionFuture<'_, TextResponse, Self::Error> {
		assert_eq!(request.max_tokens, 8);
		assert_eq!(request.messages[0].text, "hello");
		Box::pin(async { self.0.clone() })
	}
}

#[tokio::test]
async fn executor_result_mapping_preserves_metadata_and_propagates_denial() {
	let mut value = params();
	value["_meta"] = json!({"io.modelcontextprotocol/related-task":{"taskId":"gateway-task"}});
	let request = parse(&value).unwrap();
	for (stop, expected) in [
		(TextStop::EndTurn, "endTurn"),
		(TextStop::MaxTokens, "maxTokens"),
	] {
		let result = request
			.generate(&Executor(Ok(TextResponse {
				model: "resolved".into(),
				text: "answer".into(),
				stop,
			})))
			.await
			.unwrap();
		assert_eq!(
			result,
			json!({"role":"assistant","model":"resolved","content":{"type":"text","text":"answer"},"stopReason":expected,"_meta":value["_meta"]})
		);
	}
	assert_eq!(
		request.generate(&Executor(Err("denied"))).await,
		Err("denied")
	);
}
