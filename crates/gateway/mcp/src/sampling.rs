//! Explicitly bounded 2025-era Sampling compatibility, deprecated in MCP 2026-07-28.
//! Wire validation grants no model execution permission; the Host supplies the executor.
use gateway_protocol_core::model::{
	BoundTextGeneration, TextMessage, TextRequest, TextRole, TextStop,
};
use serde_json::{Value, json};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidSampling;

#[derive(Debug)]
pub struct Request {
	text: TextRequest,
	hints: Vec<String>,
	meta: Value,
}

fn allowed(value: &Value, fields: &[&str]) -> bool {
	value
		.as_object()
		.is_some_and(|v| v.keys().all(|k| fields.contains(&k.as_str())))
}
fn bounded_text(value: &Value, max: usize) -> bool {
	value.as_str().is_some_and(|s| s.len() <= max)
}

impl Request {
	pub fn validate(
		params: &Value,
		models: &[String],
		max_tokens: u64,
	) -> Result<(), InvalidSampling> {
		if !allowed(
			params,
			&[
				"messages",
				"modelPreferences",
				"maxTokens",
				"includeContext",
				"systemPrompt",
				"stopSequences",
				"_meta",
			],
		) || params.get("includeContext").is_some_and(|v| v != "none")
			|| !params["maxTokens"]
				.as_u64()
				.is_some_and(|n| n > 0 && n <= max_tokens)
			|| !params["messages"].as_array().is_some_and(|a| {
				!a.is_empty()
					&& a.len() <= 16
					&& a.iter().all(|m| {
						allowed(m, &["role", "content"])
							&& matches!(m["role"].as_str(), Some("user" | "assistant"))
							&& allowed(&m["content"], &["type", "text"])
							&& m["content"]["type"] == "text"
							&& bounded_text(&m["content"]["text"], 8192)
					})
			}) || !allowed(&params["modelPreferences"], &["hints"])
			|| !params["modelPreferences"]["hints"]
				.as_array()
				.is_some_and(|a| {
					!a.is_empty()
						&& a.len() <= 8
						&& a.iter().all(|m| {
							allowed(m, &["name"])
								&& m["name"]
									.as_str()
									.is_some_and(|m| models.iter().any(|x| x == m))
						})
				}) || params
			.get("systemPrompt")
			.is_some_and(|v| !bounded_text(v, 8192))
			|| params.get("stopSequences").is_some_and(|v| {
				!v.as_array()
					.is_some_and(|a| a.len() <= 16 && a.iter().all(|v| bounded_text(v, 256)))
			}) {
			return Err(InvalidSampling);
		}
		Ok(())
	}

	pub fn parse(
		params: &Value,
		models: &[String],
		max_tokens: u64,
	) -> Result<Self, InvalidSampling> {
		Self::validate(params, models, max_tokens)?;
		let mut messages = Vec::new();
		if let Some(system) = params.get("systemPrompt") {
			messages.push(TextMessage {
				role: TextRole::System,
				text: system.as_str().ok_or(InvalidSampling)?.into(),
			});
		}
		for message in params["messages"].as_array().ok_or(InvalidSampling)? {
			messages.push(TextMessage {
				role: if message["role"] == "user" {
					TextRole::User
				} else {
					TextRole::Assistant
				},
				text: message["content"]["text"]
					.as_str()
					.ok_or(InvalidSampling)?
					.into(),
			});
		}
		Ok(Self {
			text: TextRequest {
				messages,
				max_tokens: params["maxTokens"].as_u64().ok_or(InvalidSampling)?,
				stop: params
					.get("stopSequences")
					.map(|v| {
						v.as_array()
							.ok_or(InvalidSampling)?
							.iter()
							.map(|v| v.as_str().map(String::from).ok_or(InvalidSampling))
							.collect()
					})
					.transpose()?,
			},
			hints: params["modelPreferences"]["hints"]
				.as_array()
				.ok_or(InvalidSampling)?
				.iter()
				.map(|v| v["name"].as_str().map(String::from).ok_or(InvalidSampling))
				.collect::<Result<_, _>>()?,
			meta: params["_meta"].clone(),
		})
	}

	pub fn matches_model(&self, model: &str) -> bool {
		self.hints.iter().all(|hint| hint == model)
	}

	pub async fn generate<E: BoundTextGeneration + ?Sized>(
		&self,
		executor: &E,
	) -> Result<Value, E::Error> {
		let output = executor.generate(self.text.clone()).await?;
		Ok(json!({"role":"assistant", "model":output.model,
			"content":{"type":"text", "text":output.text},
			"stopReason":match output.stop { TextStop::EndTurn => "endTurn", TextStop::MaxTokens => "maxTokens" },
			"_meta":self.meta}))
	}
}

#[cfg(test)]
mod tests;
