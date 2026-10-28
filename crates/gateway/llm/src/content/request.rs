//! Request text ownership. Known protocol controls are excluded; business metadata stays read-only.
use super::*;

pub fn project_request(body: &Value, format: InputFormat) -> anyhow::Result<Projection> {
	anyhow::ensure!(
		matches!(
			format,
			InputFormat::Completions | InputFormat::Messages | InputFormat::Responses
		),
		"unsupported PII request format"
	);
	let mut p = Projection { fields: Vec::new() };
	let object = body
		.as_object()
		.ok_or_else(|| anyhow::anyhow!("invalid request"))?;
	for (key, value) in object {
		let path = format!("/{}", escape(key));
		match key.as_str() {
			"messages" => messages(&mut p, body, value, &path, 0)?,
			"input" if value.is_array() => messages(&mut p, body, value, &path, 0)?,
			"input" | "system" | "instructions" => content(&mut p, body, value, &path, 0)?,
			"previous_response_id" | "conversation" | "prompt" if !value.is_null() => {
				anyhow::bail!("remote prompt state cannot be inspected")
			},
			_ if protocol_control(key, value, format) => {},
			_ => p.field(body, path, Kind::ReadOnlyJson)?,
		}
	}
	anyhow::ensure!(p.fields.len() <= 128, "too many request fragments");
	Ok(p)
}

// Only controls already represented by the supported request types are exempt. Unexpected
// shapes and extensions remain inspectable data, including fields nested inside metadata/tools.
fn protocol_control(key: &str, value: &Value, format: InputFormat) -> bool {
	match key {
		"model" => value.is_string(),
		"stream" => value.is_boolean(),
		"temperature" | "top_p" => value.is_number(),
		"max_tokens" if matches!(format, InputFormat::Completions | InputFormat::Messages) => {
			value.is_u64()
		},
		"max_output_tokens" if format == InputFormat::Responses => value.is_u64(),
		"max_completion_tokens" if format == InputFormat::Completions => value.is_u64(),
		"frequency_penalty" | "presence_penalty" if format == InputFormat::Completions => {
			value.is_number()
		},
		"seed" if format == InputFormat::Completions => value.is_i64(),
		"stream_options" if format == InputFormat::Completions => {
			value.as_object().is_some_and(|options| {
				options
					.iter()
					.all(|(k, v)| k == "include_usage" && v.is_boolean())
			})
		},
		_ => false,
	}
}

fn escape(key: &str) -> String {
	key.replace('~', "~0").replace('/', "~1")
}
fn messages(
	p: &mut Projection,
	root: &Value,
	value: &Value,
	path: &str,
	depth: usize,
) -> anyhow::Result<()> {
	let items = value
		.as_array()
		.ok_or_else(|| anyhow::anyhow!("invalid messages"))?;
	anyhow::ensure!(items.len() <= 128, "too many messages");
	for (i, item) in items.iter().enumerate() {
		message(p, root, item, &format!("{path}/{i}"), depth + 1)?;
	}
	Ok(())
}
fn content(
	p: &mut Projection,
	root: &Value,
	value: &Value,
	path: &str,
	depth: usize,
) -> anyhow::Result<()> {
	match value {
		Value::Null => Ok(()),
		Value::String(_) => p.field(root, path.into(), Kind::Text),
		Value::Array(_) => messages(p, root, value, path, depth + 1),
		_ => anyhow::bail!("unsupported content"),
	}
}
fn message(
	p: &mut Projection,
	root: &Value,
	value: &Value,
	path: &str,
	depth: usize,
) -> anyhow::Result<()> {
	anyhow::ensure!(
		depth <= 16 && p.fields.len() <= 128,
		"request projection limit"
	);
	let fields = value
		.as_object()
		.ok_or_else(|| anyhow::anyhow!("invalid message"))?;
	if let Some(kind) = value.get("type").and_then(Value::as_str) {
		anyhow::ensure!(
			[
				"message",
				"text",
				"input_text",
				"output_text",
				"tool_result",
				"tool_use",
				"function_call",
				"function_call_output"
			]
			.contains(&kind),
			"unsupported content family"
		);
	}
	for (key, item) in fields {
		let address = format!("{path}/{}", escape(key));
		match key.as_str() {
			"type" if item.is_string() => {}, // The supported content family was checked above.
			"role"
				if matches!(
					item.as_str(),
					Some("system" | "developer" | "user" | "assistant" | "tool" | "function")
				) => {},
			"content" => content(p, root, item, &address, depth + 1)?,
			"text" | "output" => p.field(root, address, Kind::Text)?,
			"arguments" => p.field(root, address, Kind::JsonText)?,
			"input" if value["type"] == "tool_use" => p.field(root, address, Kind::JsonValue)?,
			"tool_calls" => {
				let tools = item
					.as_array()
					.ok_or_else(|| anyhow::anyhow!("invalid tool calls"))?;
				anyhow::ensure!(tools.len() <= 128, "too many tool calls");
				for (i, tool) in tools.iter().enumerate() {
					known(tool, &["id", "type", "function"])?;
					anyhow::ensure!(tool["type"] == "function", "unsupported tool");
					known(&tool["function"], &["name", "arguments"])?;
					p.field(root, format!("{address}/{i}/id"), Kind::ReadOnly)?;
					p.field(root, format!("{address}/{i}/function/name"), Kind::ReadOnly)?;
					p.field(
						root,
						format!("{address}/{i}/function/arguments"),
						Kind::JsonText,
					)?;
				}
			},
			"function_call" => {
				known(item, &["name", "arguments"])?;
				p.field(root, format!("{address}/name"), Kind::ReadOnly)?;
				p.field(root, format!("{address}/arguments"), Kind::JsonText)?;
			},
			_ => p.field(root, address, Kind::ReadOnlyJson)?,
		}
	}
	Ok(())
}

#[cfg(test)]
mod tests {
	use super::*;
	use serde_json::json;

	#[test]
	fn protocol_controls_do_not_become_detector_input_across_request_formats() {
		for (format, body) in [
			(
				InputFormat::Completions,
				json!({"model":"local","stream":false,"temperature":0.5,"top_p":0.9,
					"frequency_penalty":0,"presence_penalty":0,"seed":42,
					"max_tokens":100,"max_completion_tokens":100,"stream_options":{"include_usage":true},
					"messages":[{"role":"user","content":[{"type":"text","text":"business text"}]}]}),
			),
			(
				InputFormat::Messages,
				json!({"model":"local","stream":false,"temperature":0.5,"top_p":0.9,"max_tokens":100,
					"system":[{"type":"text","text":"business text"}],"messages":[]}),
			),
			(
				InputFormat::Responses,
				json!({"model":"local","stream":false,"temperature":0.5,"top_p":0.9,"max_output_tokens":100,
					"input":[{"type":"message","role":"developer","content":[{"type":"input_text","text":"business text"}]}]}),
			),
		] {
			let p = project_request(&body, format).unwrap();
			assert_eq!(p.texts().collect::<Vec<_>>(), ["business text"]);
			let mut expected = body.clone();
			let pointer = &p.fields[0].pointer;
			*expected.pointer_mut(pointer).unwrap() = json!("masked text");
			let mut changed = body;
			p.replace(&mut changed, vec!["masked text".into()]).unwrap();
			assert_eq!(changed, expected);
		}
	}

	#[test]
	fn business_data_cannot_gain_control_exemption_by_reusing_field_names() {
		for (key, value) in [
			("model", json!({"email":"secret"})),
			("stream", json!("secret")),
			("temperature", json!({"value":"secret"})),
			("max_tokens", json!("secret")),
			(
				"stream_options",
				json!({"include_usage":true,"extension":"secret"}),
			),
			(
				"metadata",
				json!({"model":"secret","role":"user","stream":false}),
			),
			("user", json!("secret")),
			("stop", json!(["secret"])),
			(
				"tools",
				json!([{"type":"function","function":{"name":"lookup","description":"secret"}}]),
			),
			("vendor_extension", json!({"payload":"secret"})),
		] {
			let mut body = json!({"messages":[]});
			body[key] = value;
			let p = project_request(&body, InputFormat::Completions).unwrap();
			assert_eq!(p.texts().count(), 1, "{key}");
			assert!(p.texts().next().unwrap().contains("secret"), "{key}");
			let original = body.clone();
			assert!(
				p.replace(&mut body, vec!["masked".into()]).is_err(),
				"{key}"
			);
			assert_eq!(body, original);
		}
		// A numeric business identifier is still data; only known numeric control slots are exempt.
		let body = json!({"messages":[],"customer_id":13800138000u64});
		let p = project_request(&body, InputFormat::Completions).unwrap();
		assert_eq!(p.texts().collect::<Vec<_>>(), ["13800138000"]);
	}

	#[test]
	fn unknown_roles_and_tool_identifiers_remain_read_only_data() {
		let body = json!({"messages":[{"role":"secret","content":"body"},
			{"role":"assistant","tool_calls":[{"id":"secret-id","type":"function",
				"function":{"name":"secret-name","arguments":"{\"email\":\"secret\"}"}}]}]});
		let p = project_request(&body, InputFormat::Completions).unwrap();
		let texts = p.texts().collect::<Vec<_>>();
		assert_eq!(texts.len(), 5);
		assert!(texts.contains(&"\"secret\""));
		assert!(texts.contains(&"secret-id"));
		assert!(texts.contains(&"secret-name"));
		assert!(!texts.contains(&"function"));
		let mut changed = body.clone();
		assert!(
			p.replace(
				&mut changed,
				p.texts().map(|s| s.replace("secret", "masked")).collect()
			)
			.is_err()
		);
		assert_eq!(changed, body);
	}

	#[test]
	fn fragment_budget_counts_inspected_content_and_still_rejects_overflow() {
		let mut body = json!({"model":"local","stream":false,
			"messages":vec![json!({"role":"user","content":"body"});128]});
		assert_eq!(
			project_request(&body, InputFormat::Completions)
				.unwrap()
				.texts()
				.count(),
			128
		);
		body["metadata"] = json!({"extra":"body"});
		assert!(project_request(&body, InputFormat::Completions).is_err());
	}

	#[test]
	fn complete_history_and_tool_arguments_keep_their_addresses_and_json_shape() {
		let mut body = json!({"model":"local","messages":[{"role":"system","content":"secret"},{"role":"assistant","content":null,"tool_calls":[{"id":"c","type":"function","function":{"name":"lookup","arguments":"{\"email\":\"secret\"}"}}]},{"role":"tool","tool_call_id":"c","content":"secret"},{"role":"user","content":[{"type":"text","text":"secret"}]}]});
		let p = project_request(&body, InputFormat::Completions).unwrap();
		let replacements = p.texts().map(|v| v.replace("secret", "[EMAIL]")).collect();
		p.replace(&mut body, replacements).unwrap();
		assert_eq!(body["messages"][0]["role"], "system");
		assert_eq!(body["messages"][2]["tool_call_id"], "c");
		assert_eq!(body["messages"][2]["content"], "[EMAIL]");
		let arguments: Value = serde_json::from_str(
			body["messages"][1]["tool_calls"][0]["function"]["arguments"]
				.as_str()
				.unwrap(),
		)
		.unwrap();
		assert_eq!(arguments["email"], "[EMAIL]");
		assert_eq!(body["messages"][3]["content"][0]["text"], "[EMAIL]");
	}
	#[test]
	fn anthropic_system_and_nested_tools_and_responses_input_are_projected() {
		for (format, mut body) in [
			(
				InputFormat::Messages,
				json!({"system":"secret","messages":[{"role":"user","content":[{"type":"tool_result","tool_use_id":"c","content":[{"type":"text","text":"secret"}]}]}]}),
			),
			(
				InputFormat::Responses,
				json!({"instructions":"secret","input":[{"role":"user","content":[{"type":"input_text","text":"secret"}]},{"type":"function_call_output","call_id":"c","output":"secret"}]}),
			),
		] {
			let p = project_request(&body, format).unwrap();
			p.replace(
				&mut body,
				p.texts().map(|v| v.replace("secret", "masked")).collect(),
			)
			.unwrap();
			assert!(!body.to_string().contains("secret"));
		}
	}
	#[test]
	fn opaque_multimodal_and_remote_state_cannot_silently_skip_inspection() {
		for body in [
			json!({"messages":[{"role":"user","content":[{"type":"image_url","image_url":{"url":"https://example.invalid"}}]}]}),
			json!({"input":"text","previous_response_id":"old"}),
		] {
			assert!(project_request(&body, InputFormat::Responses).is_err());
		}
	}
	#[test]
	fn structural_or_invalid_json_edits_are_atomic_and_rejected() {
		let original = json!({"model":"secret","messages":[{"role":"assistant","tool_calls":[{"type":"function","function":{"name":"f","arguments":"{\"x\":\"secret\"}"}}]}]});
		let mut body = original.clone();
		let p = project_request(&body, InputFormat::Completions).unwrap();
		assert!(
			p.replace(
				&mut body,
				p.texts()
					.map(|v| v.replace("secret", "bad\"quote"))
					.collect()
			)
			.is_err()
		);
		assert_eq!(body, original);
		let too_many = json!({"messages": vec![json!({"role":"user","content":"x"});129]});
		assert!(project_request(&too_many, InputFormat::Completions).is_err());
	}
}
