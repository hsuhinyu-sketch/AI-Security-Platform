//! Bounded reverse-interaction wire contracts. These functions neither authorize
//! a parent operation nor negotiate a security grant; the Host supplies allowlists.
use serde_json::Value;

fn allowed(value: &Value, fields: &[&str]) -> bool {
	value
		.as_object()
		.is_some_and(|v| v.keys().all(|k| fields.contains(&k.as_str())))
}
fn bounded_text(value: &Value, max: usize) -> bool {
	value.as_str().is_some_and(|s| s.len() <= max)
}
fn text_content(content: &Value) -> bool {
	allowed(content, &["type", "text"])
		&& content["type"] == "text"
		&& bounded_text(&content["text"], 8192)
}

fn valid_schema(schema: &Value) -> bool {
	if !allowed(
		schema,
		&[
			"type",
			"properties",
			"required",
			"additionalProperties",
			"title",
			"description",
		],
	) || schema["type"] != "object"
		|| schema
			.get("additionalProperties")
			.is_some_and(|v| v != false)
	{
		return false;
	}
	let Some(properties) = schema["properties"].as_object() else {
		return false;
	};
	if properties.len() > 16 {
		return false;
	}
	if schema.get("required").is_some_and(|r| {
		!r.as_array().is_some_and(|a| {
			a.len() <= 16
				&& a
					.iter()
					.all(|s| s.as_str().is_some_and(|s| properties.contains_key(s)))
		})
	}) {
		return false;
	}
	properties.iter().all(|(key, p)| {
		!key.is_empty()
			&& key.len() <= 128
			&& allowed(
				p,
				&[
					"type",
					"title",
					"description",
					"enum",
					"enumNames",
					"minLength",
					"maxLength",
					"minimum",
					"maximum",
					"default",
				],
			) && matches!(
			p["type"].as_str(),
			Some("string" | "number" | "integer" | "boolean")
		) && p.get("enum").is_none_or(|e| {
			e.as_array()
				.is_some_and(|e| e.len() <= 64 && e.iter().all(|v| primitive(p, v)))
		}) && ["minLength", "maxLength"].iter().all(|k| {
			p.get(*k)
				.is_none_or(|v| v.as_u64().is_some_and(|n| n <= 8192))
		}) && ["minimum", "maximum"]
			.iter()
			.all(|k| p.get(*k).is_none_or(Value::is_number))
	})
}
fn primitive(schema: &Value, value: &Value) -> bool {
	match schema["type"].as_str() {
		Some("string") => value.as_str().is_some_and(|s| {
			s.len() <= 8192
				&& schema["minLength"]
					.as_u64()
					.is_none_or(|n| s.chars().count() as u64 >= n)
				&& schema["maxLength"]
					.as_u64()
					.is_none_or(|n| s.chars().count() as u64 <= n)
		}),
		Some("boolean") => value.is_boolean(),
		Some("number" | "integer") => value.as_f64().is_some_and(|n| {
			(schema["type"] != "integer" || value.is_i64() || value.is_u64())
				&& schema["minimum"].as_f64().is_none_or(|v| n >= v)
				&& schema["maximum"].as_f64().is_none_or(|v| n <= v)
		}),
		_ => false,
	}
}

pub fn valid_form_request(params: &Value, fields: &[String]) -> bool {
	allowed(params, &["mode", "message", "requestedSchema", "_meta"])
		&& params.get("mode").is_none_or(|v| v == "form")
		&& bounded_text(&params["message"], 8192)
		&& valid_schema(&params["requestedSchema"])
		&& params["requestedSchema"]["properties"]
			.as_object()
			.is_some_and(|p| p.keys().all(|key| fields.contains(key)))
}

pub fn valid_roots_request(params: &Value) -> bool {
	allowed(params, &["_meta"])
}

pub fn valid_sampling_response(result: &Value, models: &[String]) -> bool {
	allowed(result, &["role", "content", "model", "stopReason", "_meta"])
		&& result["role"] == "assistant"
		&& text_content(&result["content"])
		&& result["model"]
			.as_str()
			.is_some_and(|model| models.iter().any(|allowed| allowed == model))
		&& result
			.get("stopReason")
			.is_none_or(|s| matches!(s.as_str(), Some("endTurn" | "stopSequence" | "maxTokens")))
}

pub fn valid_form_response(result: &Value, schema: &Value) -> bool {
	allowed(result, &["action", "content", "_meta"])
		&& match result["action"].as_str() {
			Some("decline" | "cancel") => result.get("content").is_none(),
			Some("accept") => result["content"].as_object().is_some_and(|content| {
				content.iter().all(|(key, value)| {
					schema["properties"].get(key).is_some_and(|p| {
						primitive(p, value)
							&& p.get("enum").is_none_or(|values| {
								values
									.as_array()
									.is_some_and(|values| values.contains(value))
							})
					})
				}) && schema["required"].as_array().is_none_or(|required| {
					required
						.iter()
						.all(|key| key.as_str().is_some_and(|key| content.contains_key(key)))
				})
			}),
			_ => false,
		}
}

/// Filter only after the entire response has passed structural validation.
/// Task-owned roots omit client display names because a URI grant does not cover them.
pub fn filter_roots_response(result: &mut Value, roots: &[String], task_owned: bool) -> bool {
	if !allowed(result, &["roots", "_meta"])
		|| !result["roots"].as_array().is_some_and(|entries| {
			entries.len() <= 32
				&& entries.iter().all(|root| {
					allowed(root, &["uri", "name"])
						&& bounded_text(&root["uri"], 512)
						&& root.get("name").is_none_or(|name| bounded_text(name, 256))
				})
		}) {
		return false;
	}
	let entries = result["roots"].as_array_mut().expect("validated roots");
	entries.retain(|root| {
		root["uri"]
			.as_str()
			.is_some_and(|uri| roots.iter().any(|allowed| allowed == uri))
	});
	if task_owned {
		for root in entries {
			root.as_object_mut().expect("validated root").remove("name");
		}
	}
	true
}

#[cfg(test)]
#[path = "reverse/tests.rs"]
mod tests;
