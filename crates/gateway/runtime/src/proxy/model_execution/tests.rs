use super::*;

fn body() -> Value {
	json!({"model":"local","messages":[{"role":"user","content":"hello"}],"max_tokens":8,"stream":false})
}

#[test]
fn final_request_validation_rejects_model_token_tool_and_stream_mutation() {
	let models = vec!["local".into()];
	assert_eq!(final_model(&body(), 8, &models), Some("local"));
	for (field, value) in [
		("model", json!("foreign")),
		("max_tokens", json!(9)),
		("max_tokens", json!(0)),
		("max_completion_tokens", json!(8)),
		("tools", json!([])),
		("stream", json!(true)),
		("messages", json!([{"role":"tool","content":"x"}])),
		(
			"messages",
			json!([{"role":"user","content":"x","tool_calls":[]}]),
		),
	] {
		let mut modified = body();
		modified[field] = value;
		assert!(
			final_model(&modified, 8, &models).is_none(),
			"accepted {field}"
		);
	}
	let mut completion = body();
	completion.as_object_mut().unwrap().remove("max_tokens");
	completion["max_completion_tokens"] = json!(8);
	assert_eq!(final_model(&completion, 8, &models), Some("local"));
}

#[test]
fn model_response_is_single_bounded_text_choice_without_tool_execution() {
	let response =
		json!({"choices":[{"message":{"role":"assistant","content":"answer"},"finish_reason":"stop"}]});
	let result = decode_response(&response, "verified-final-model").unwrap();
	assert_eq!(result.model, "verified-final-model");
	assert_eq!(result.stop, TextStop::EndTurn);
	for mutation in ["tool", "function", "role", "size", "choices", "finish"] {
		let mut modified = response.clone();
		match mutation {
			"tool" => modified["choices"][0]["message"]["tool_calls"] = json!([]),
			"function" => modified["choices"][0]["message"]["function_call"] = Value::Null,
			"role" => modified["choices"][0]["message"]["role"] = json!("user"),
			"size" => modified["choices"][0]["message"]["content"] = json!("x".repeat(8193)),
			"choices" => modified["choices"] = json!([]),
			"finish" => modified["choices"][0]["finish_reason"] = json!("tool_calls"),
			_ => unreachable!(),
		}
		assert!(
			decode_response(&modified, "local").is_none(),
			"accepted {mutation}"
		);
	}
}
