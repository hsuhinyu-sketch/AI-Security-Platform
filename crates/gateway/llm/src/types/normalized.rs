use std::time::Instant;

use arcstr::ArcStr as Strng;
use serde::Serialize;

/// Whether an upstream's reported `input_tokens` already includes cached tokens.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CacheTokenConvention {
	/// OpenAI-style: cached tokens are a subset of `input_tokens`
	#[default]
	InputIncludesCache,
	/// Anthropic-style: `input_tokens` is already fresh
	InputExcludesCache,
}

impl CacheTokenConvention {
	/// Placeholder used while request conversion lacks provider/native-format
	/// context. `process_request` replaces this with the classified convention.
	pub fn pending() -> Self {
		Self::InputIncludesCache
	}
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct LLMResponse {
	#[serde(skip_serializing_if = "Option::is_none")]
	pub input_tokens: Option<u64>,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub input_image_tokens: Option<u64>,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub input_text_tokens: Option<u64>,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub input_audio_tokens: Option<u64>,
	/// count_tokens contains the number of tokens in the request, when using the token counting endpoint
	/// These are not counted as 'input tokens' since they do not consume input tokens.
	#[serde(skip_serializing_if = "Option::is_none")]
	pub count_tokens: Option<u64>,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub output_tokens: Option<u64>,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub output_image_tokens: Option<u64>,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub output_text_tokens: Option<u64>,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub output_audio_tokens: Option<u64>,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub total_tokens: Option<u64>,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub reasoning_tokens: Option<u64>,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub cache_creation_input_tokens: Option<u64>,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub cached_input_tokens: Option<u64>,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub service_tier: Option<Strng>,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub provider_model: Option<Strng>,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub completion: Option<Vec<String>>,

	#[serde(skip)]
	// Time to get the first token. Only used for streaming.
	pub first_token: Option<Instant>,
}
