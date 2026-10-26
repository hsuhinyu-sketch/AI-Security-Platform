//! Bounded, address-preserving content views for non-streaming response guards.
use crate::provider::InputFormat;
use serde_json::Value;

#[derive(Clone, Copy)]
enum Kind {
	Text,
	JsonText,
	JsonValue,
	ReadOnly,
	ReadOnlyJson,
}
struct Field {
	pointer: String,
	text: String,
	kind: Kind,
}

pub struct Projection {
	fields: Vec<Field>,
}
impl Projection {
	pub fn texts(&self) -> impl Iterator<Item = &str> {
		self.fields.iter().map(|f| f.text.as_str())
	}
	pub fn replace(&self, body: &mut Value, replacements: Vec<String>) -> anyhow::Result<()> {
		anyhow::ensure!(
			self.fields.len() == replacements.len(),
			"guard response fragment count mismatch"
		);
		let mut edits = Vec::new();
		for (field, text) in self.fields.iter().zip(replacements) {
			if text == field.text {
				continue;
			}
			let replacement = match field.kind {
				Kind::ReadOnly | Kind::ReadOnlyJson => {
					anyhow::bail!("guard cannot rewrite a structural content field")
				},
				Kind::Text => Value::String(text),
				Kind::JsonText => {
					let _: Value = serde_json::from_str(&text)?;
					Value::String(text)
				},
				Kind::JsonValue => serde_json::from_str(&text)?,
			};
			anyhow::ensure!(
				body.pointer(&field.pointer).is_some(),
				"guard content address disappeared"
			);
			edits.push((&field.pointer, replacement));
		}
		for (pointer, replacement) in edits {
			*body
				.pointer_mut(pointer)
				.ok_or_else(|| anyhow::anyhow!("guard content address disappeared"))? = replacement;
		}
		Ok(())
	}
	fn field(&mut self, root: &Value, path: String, kind: Kind) -> anyhow::Result<()> {
		let Some(value) = root.pointer(&path) else {
			return Ok(());
		};
		if value.is_null() {
			return Ok(());
		}
		let text = if matches!(kind, Kind::JsonValue | Kind::ReadOnlyJson) {
			serde_json::to_string(value)?
		} else if matches!(kind, Kind::JsonText) {
			serde_json::to_string(&serde_json::from_str::<Value>(
				value
					.as_str()
					.ok_or_else(|| anyhow::anyhow!("tool arguments must be JSON text"))?,
			)?)?
		} else {
			value
				.as_str()
				.ok_or_else(|| anyhow::anyhow!("guard content must be text at {path}"))?
				.to_owned()
		};
		self.fields.push(Field {
			pointer: path,
			text,
			kind,
		});
		Ok(())
	}
}

/// Metadata does not become model text. Unknown output families are refused under a guard.
fn known(value: &Value, allowed: &[&str]) -> anyhow::Result<()> {
	let object = value
		.as_object()
		.ok_or_else(|| anyhow::anyhow!("guard requires an object"))?;
	anyhow::ensure!(
		object.keys().all(|key| allowed.contains(&key.as_str())),
		"unsupported guarded output field"
	);
	Ok(())
}
pub fn project(body: &Value, format: InputFormat) -> anyhow::Result<Projection> {
	let mut result = Projection { fields: Vec::new() };
	match format {
		InputFormat::Completions => {
			for (i, choice) in body
				.get("choices")
				.and_then(Value::as_array)
				.ok_or_else(|| anyhow::anyhow!("guard requires completion choices"))?
				.iter()
				.enumerate()
			{
				result.field(body, format!("/choices/{i}/logprobs"), Kind::ReadOnlyJson)?;
				let message = choice
					.get("message")
					.and_then(Value::as_object)
					.ok_or_else(|| anyhow::anyhow!("guard requires completion message"))?;
				let base = format!("/choices/{i}/message");
				for (key, value) in message {
					if value.is_null() {
						continue;
					}
					match key.as_str() {
						"content" | "refusal" | "reasoning_content" => {
							result.field(body, format!("{base}/{key}"), Kind::Text)?
						},
						"role" => {},
						"tool_calls" => {
							let tools = value
								.as_array()
								.ok_or_else(|| anyhow::anyhow!("invalid tool calls"))?;
							for (j, tool) in tools.iter().enumerate() {
								known(tool, &["id", "type", "function"])?;
								anyhow::ensure!(
									tool.get("type").and_then(Value::as_str) == Some("function"),
									"unsupported guarded tool type"
								);
								known(&tool["function"], &["name", "arguments"])?;
								result.field(
									body,
									format!("{base}/tool_calls/{j}/function/name"),
									Kind::ReadOnly,
								)?;
								result.field(
									body,
									format!("{base}/tool_calls/{j}/function/arguments"),
									Kind::JsonText,
								)?;
							}
						},
						"function_call" => {
							known(value, &["name", "arguments"])?;
							result.field(body, format!("{base}/function_call/name"), Kind::ReadOnly)?;
							result.field(
								body,
								format!("{base}/function_call/arguments"),
								Kind::JsonText,
							)?;
						},
						_ => anyhow::bail!("unsupported guarded completion message field {key}"),
					}
				}
			}
		},
		InputFormat::Messages => {
			for (i, block) in body
				.get("content")
				.and_then(Value::as_array)
				.ok_or_else(|| anyhow::anyhow!("guard requires message blocks"))?
				.iter()
				.enumerate()
			{
				let base = format!("/content/{i}");
				match block.get("type").and_then(Value::as_str) {
					Some("text") => {
						known(block, &["type", "text", "citations", "cache_control"])?;
						result.field(body, format!("{base}/text"), Kind::Text)?;
						result.field(body, format!("{base}/citations"), Kind::ReadOnlyJson)?;
					},
					Some("tool_use" | "server_tool_use") => {
						known(block, &["type", "id", "name", "input", "cache_control"])?;
						result.field(body, format!("{base}/name"), Kind::ReadOnly)?;
						result.field(body, format!("{base}/input"), Kind::JsonValue)?;
					},
					Some("thinking") => {
						known(block, &["type", "thinking", "signature"])?;
						result.field(body, format!("{base}/thinking"), Kind::ReadOnly)?;
					},
					// Signed/redacted or multimodal data cannot be safely inspected and rewritten.
					_ => anyhow::bail!("unsupported guarded message block"),
				}
			}
		},
		InputFormat::Responses => {
			for (i, item) in body
				.get("output")
				.and_then(Value::as_array)
				.ok_or_else(|| anyhow::anyhow!("guard requires response output"))?
				.iter()
				.enumerate()
			{
				let base = format!("/output/{i}");
				match item.get("type").and_then(Value::as_str) {
					Some("message") => {
						known(item, &["type", "id", "role", "status", "content", "phase"])?;
						for (j, part) in item
							.get("content")
							.and_then(Value::as_array)
							.ok_or_else(|| anyhow::anyhow!("guard requires message content"))?
							.iter()
							.enumerate()
						{
							known(
								part,
								&["type", "text", "refusal", "annotations", "logprobs"],
							)?;
							result.field(
								body,
								format!("{base}/content/{j}/annotations"),
								Kind::ReadOnlyJson,
							)?;
							result.field(
								body,
								format!("{base}/content/{j}/logprobs"),
								Kind::ReadOnlyJson,
							)?;
							let key = match part.get("type").and_then(Value::as_str) {
								Some("output_text") => "text",
								Some("refusal") => "refusal",
								_ => anyhow::bail!("unsupported guarded output content"),
							};
							result.field(body, format!("{base}/content/{j}/{key}"), Kind::Text)?;
						}
					},
					Some("function_call") => {
						known(
							item,
							&["type", "id", "call_id", "name", "arguments", "status"],
						)?;
						result.field(body, format!("{base}/name"), Kind::ReadOnly)?;
						result.field(body, format!("{base}/arguments"), Kind::JsonText)?;
					},
					Some("custom_tool_call") => {
						known(item, &["type", "id", "call_id", "name", "input", "status"])?;
						result.field(body, format!("{base}/name"), Kind::ReadOnly)?;
						result.field(body, format!("{base}/input"), Kind::Text)?;
					},
					_ => anyhow::bail!("unsupported guarded response output"),
				}
			}
		},
		_ => anyhow::bail!("content guards require an explicit supported text response format"),
	}
	Ok(result)
}

#[cfg(test)]
mod tests;
