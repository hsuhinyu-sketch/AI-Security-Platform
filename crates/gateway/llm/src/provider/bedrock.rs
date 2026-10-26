use super::ProviderFormat;
use arcstr::{self as strng, ArcStr as Strng};
use std::collections::HashMap;

#[derive(Debug, Clone, Copy)]
pub struct Endpoint<'a> {
	pub model: Option<&'a str>,
	pub region: &'a str,
}
impl Endpoint<'_> {
	pub fn is_anthropic_model(&self, request_model: Option<&str>) -> bool {
		let model = self
			.model
			.as_deref()
			.or(request_model)
			.unwrap_or_default()
			.to_ascii_lowercase();
		model.contains("anthropic.claude")
	}
	pub fn get_path_for_route(
		&self,
		route_type: Option<ProviderFormat>,
		streaming: bool,
		model: &str,
	) -> Strng {
		let model = self.model.as_deref().unwrap_or(model);
		const MODEL_SEGMENT: &percent_encoding::AsciiSet =
			&percent_encoding::CONTROLS.add(b'/').add(b'%');
		let model = percent_encoding::utf8_percent_encode(model, MODEL_SEGMENT);
		match route_type {
			Some(ProviderFormat::AnthropicTokenCount) => strng::format!("/model/{model}/count-tokens"),
			Some(ProviderFormat::Embeddings) => strng::format!("/model/{model}/invoke"),
			// Rerank uses the agent-runtime Rerank action (model goes in the body as an ARN).
			Some(ProviderFormat::Rerank) => strng::literal!("/rerank"),
			_ if streaming => strng::format!("/model/{model}/converse-stream"),
			_ => strng::format!("/model/{model}/converse"),
		}
	}
	pub fn get_host(&self, route_type: Option<ProviderFormat>) -> Strng {
		match route_type {
			Some(ProviderFormat::Rerank) => {
				strng::format!("bedrock-agent-runtime.{}.amazonaws.com", self.region)
			},
			_ => strng::format!("bedrock-runtime.{}.amazonaws.com", self.region),
		}
	}
}

pub fn supports_prompt_caching(model_id: &str) -> bool {
	let model_lower = model_id.to_lowercase();
	if model_lower.contains("anthropic.claude") {
		let excluded = ["claude-instant", "claude-v1", "claude-v2"];
		if excluded.iter().any(|pattern| model_lower.contains(pattern)) {
			return false;
		}
		return true;
	}
	if model_lower.contains("amazon.nova") {
		return true;
	}
	if model_lower.contains(":application-inference-profile/") {
		// If they are using inference profiles, the model name is obscured; we have no clue whether
		// It's supported or not.
		// Instead, we assume true; if users want to use models without support they can turn off caching manually.
		return true;
	}
	false
}

pub fn extract_flat_metadata(value: &serde_json::Value) -> HashMap<String, String> {
	let mut metadata = HashMap::new();

	if let serde_json::Value::Object(obj) = value {
		for (key, val) in obj {
			match val {
				serde_json::Value::String(s) => {
					metadata.insert(key.clone(), s.clone());
				},
				serde_json::Value::Number(n) => {
					metadata.insert(key.clone(), n.to_string());
				},
				serde_json::Value::Bool(b) => {
					metadata.insert(key.clone(), b.to_string());
				},
				_ => {}, // Skip nested objects, arrays, null
			}
		}
	}

	metadata
}

use std::hash::{Hash, Hasher};

/// Bedrock Converse `toolSpec.name` length limit.
pub const BEDROCK_TOOL_NAME_MAX_LEN: usize = 64;

/// Per-request mapping between client tool names and Bedrock-safe tool names.
#[derive(Debug, Clone, Default)]
pub struct BedrockToolNameMap {
	forward: HashMap<String, String>,
	reverse: HashMap<String, String>,
}

impl BedrockToolNameMap {
	pub fn is_empty(&self) -> bool {
		self.reverse.is_empty()
	}

	/// Return the Bedrock-safe name for `original`, registering a reverse mapping when sanitized.
	pub fn register(&mut self, original: &str) -> String {
		let original = if original.is_empty() {
			"tool".to_string()
		} else {
			original.to_string()
		};
		if let Some(mapped) = self.forward.get(&original) {
			return mapped.clone();
		}

		if is_valid_bedrock_tool_name(&original) && !self.forward.values().any(|used| used == &original)
		{
			self.forward.insert(original.clone(), original.clone());
			return original;
		}

		let sanitized = make_valid_bedrock_tool_name(&original, self.forward.values());
		self.forward.insert(original.clone(), sanitized.clone());
		if sanitized != original {
			self.reverse.insert(sanitized.clone(), original);
		}
		sanitized
	}

	/// Restore the client-facing tool name from a Bedrock response.
	pub fn restore(&self, sanitized: &str) -> String {
		self
			.reverse
			.get(sanitized)
			.cloned()
			.unwrap_or_else(|| sanitized.to_string())
	}
}

fn is_valid_bedrock_tool_name(name: &str) -> bool {
	!name.is_empty()
		&& name.len() <= BEDROCK_TOOL_NAME_MAX_LEN
		&& name
			.chars()
			.all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
}

fn sanitize_bedrock_tool_name_chars(name: &str) -> String {
	let mut out = String::with_capacity(name.len());
	for c in name.chars() {
		if c.is_ascii_alphanumeric() || c == '_' || c == '-' {
			out.push(c);
		} else {
			out.push('_');
		}
	}
	if out.is_empty() {
		"tool".to_string()
	} else {
		out
	}
}

fn make_valid_bedrock_tool_name<'a>(
	original: &str,
	used: impl Iterator<Item = &'a String> + Clone,
) -> String {
	let base = sanitize_bedrock_tool_name_chars(original);
	if base.len() <= BEDROCK_TOOL_NAME_MAX_LEN && !used.clone().any(|used| used == &base) {
		return base;
	}

	let mut hasher = std::collections::hash_map::DefaultHasher::new();
	original.hash(&mut hasher);
	let hash = format!("{:06x}", hasher.finish() & 0xFFFFFF);
	let prefix_len = BEDROCK_TOOL_NAME_MAX_LEN - 7;
	let prefix: String = base.chars().take(prefix_len).collect();
	let mut candidate = format!("{prefix}_{hash}");

	let mut counter = 0u32;
	while used.clone().any(|used| used == &candidate) {
		counter += 1;
		let suffix = format!("_{counter:x}");
		let trim = BEDROCK_TOOL_NAME_MAX_LEN.saturating_sub(suffix.len());
		candidate = format!(
			"{}{}",
			candidate.chars().take(trim).collect::<String>(),
			suffix
		);
	}
	candidate
}

pub fn restore_tool_name(map: Option<&BedrockToolNameMap>, name: &str) -> String {
	map
		.map(|m| m.restore(name))
		.unwrap_or_else(|| name.to_string())
}
