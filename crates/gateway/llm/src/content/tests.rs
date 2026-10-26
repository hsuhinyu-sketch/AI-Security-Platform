use super::*;
use serde_json::json;

#[test]
fn text_and_function_arguments_share_inspection_and_rewrite_actual_fields() {
	for (format, mut body, pointer) in [
		(
			InputFormat::Completions,
			json!({"choices":[{"message":{"role":"assistant","content":"ordinary", "tool_calls":[{"id":"c","type":"function","function":{"name":"echo","arguments":"{\"value\":\"SECRET\"}"}}]}}]}),
			"/choices/0/message/tool_calls/0/function/arguments",
		),
		(
			InputFormat::Responses,
			json!({"output":[{"type":"function_call","id":"c","call_id":"c","name":"echo","arguments":"{\"value\":\"SECRET\"}"}]}),
			"/output/0/arguments",
		),
		(
			InputFormat::Messages,
			json!({"content":[{"type":"tool_use","id":"c","name":"echo","input":{"value":"SECRET"}}]}),
			"/content/0/input",
		),
	] {
		let projection = project(&body, format).unwrap();
		let text = projection.texts().collect::<Vec<_>>().join("\n");
		assert!(text.contains("SECRET"));
		let replacement = projection
			.texts()
			.map(|s| s.replace("SECRET", "masked"))
			.collect();
		projection.replace(&mut body, replacement).unwrap();
		assert!(
			!body
				.pointer(pointer)
				.unwrap()
				.to_string()
				.contains("SECRET")
		);
		assert!(body.to_string().contains("echo"));
	}
}

#[test]
fn encoded_json_arguments_are_inspected_as_decoded_content() {
	let body = json!({"output":[{"type":"function_call","name":"echo","arguments":r#"{"value":"SE\u0043RET"}"#}]});
	assert!(
		project(&body, InputFormat::Responses)
			.unwrap()
			.texts()
			.any(|s| s.contains("SECRET"))
	);
}

#[test]
fn unsupported_output_families_and_malformed_tools_fail_closed() {
	for (format, body) in [
		(
			InputFormat::Completions,
			json!({"choices":[{"message":{"audio":{"data":"SECRET"}}}]}),
		),
		(
			InputFormat::Completions,
			json!({"choices":[{"message":{"content":"ok","extra_payload":"SECRET"}}]}),
		),
		(
			InputFormat::Messages,
			json!({"content":[{"type":"image","source":{"data":"SECRET"}}]}),
		),
		(
			InputFormat::Responses,
			json!({"output":[{"type":"image_generation_call","result":"SECRET"}]}),
		),
		(
			InputFormat::Responses,
			json!({"output":[{"type":"function_call","arguments":"invalid-json"}]}),
		),
	] {
		assert!(project(&body, format).is_err());
	}
}

#[test]
fn masking_cannot_corrupt_json_or_rewrite_function_identity() {
	let original =
		json!({"output":[{"type":"function_call","name":"echo","arguments":"{\"value\":1}"}]});
	for texts in [
		vec!["other".into(), "{\"value\":1}".into()],
		vec!["echo".into(), "{\"value\":<masked>}".into()],
	] {
		let mut body = original.clone();
		let p = project(&body, InputFormat::Responses).unwrap();
		assert!(p.replace(&mut body, texts).is_err());
		assert_eq!(body, original);
	}
}

#[test]
fn multiple_choices_and_refusals_are_all_inspected_and_preserved() {
	let mut body = json!({"choices":[{"message":{"content":"first"}},{"message":{"content":"second","refusal":"SECRET"}}]});
	let p = project(&body, InputFormat::Completions).unwrap();
	assert_eq!(
		p.texts().collect::<Vec<_>>(),
		vec!["first", "second", "SECRET"]
	);
	p.replace(
		&mut body,
		vec!["first".into(), "second".into(), "masked".into()],
	)
	.unwrap();
	assert_eq!(body["choices"][1]["message"]["refusal"], "masked");
}

#[test]
fn invalid_later_edit_cannot_publish_an_earlier_text_mask() {
	let original = json!({"choices":[{"message":{"content":"first SECRET","tool_calls":[{"id":"c","type":"function","function":{"name":"echo","arguments":"{\"value\":7}"}}]}}]});
	let mut body = original.clone();
	let p = project(&body, InputFormat::Completions).unwrap();
	assert!(
		p.replace(
			&mut body,
			vec![
				"first masked".into(),
				"echo".into(),
				"{\"value\":<masked>}".into()
			]
		)
		.is_err()
	);
	assert_eq!(body, original);
}
