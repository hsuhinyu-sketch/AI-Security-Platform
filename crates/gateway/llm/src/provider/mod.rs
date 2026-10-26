//! Pure provider request descriptions. Outputs carry no execution authority.

#[cfg(feature = "protocol")]
pub mod anthropic;
#[cfg(feature = "protocol")]
pub mod azure;
#[cfg(feature = "protocol")]
pub mod copilot;
pub mod custom;
#[cfg(feature = "protocol")]
pub mod gemini;
#[cfg(feature = "protocol")]
pub mod openai;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ProviderFormat {
	Completions,
	Messages,
	Responses,
	Embeddings,
	AnthropicTokenCount,
	Realtime,
	Rerank,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum InputFormat {
	Completions,
	Messages,
	Responses,
	Embeddings,
	Realtime,
	CountTokens,
	Detect,
	Rerank,
}

impl InputFormat {
	pub fn supports_prompt_guard(&self) -> bool {
		match self {
			InputFormat::Completions => true,
			InputFormat::Messages => true,
			InputFormat::Responses => true,
			InputFormat::Realtime => false,
			InputFormat::Embeddings => false,
			InputFormat::CountTokens => false,
			InputFormat::Detect => false,
			InputFormat::Rerank => false,
		}
	}

	pub fn provider_format_preferences(&self) -> &'static [ProviderFormat] {
		use ProviderFormat::*;
		match self {
			InputFormat::Completions => &[Completions, Messages],
			InputFormat::Messages => &[Messages, Completions],
			InputFormat::Responses => &[Responses, Completions],
			InputFormat::Embeddings => &[Embeddings],
			InputFormat::Realtime => &[Realtime],
			InputFormat::CountTokens => &[AnthropicTokenCount],
			InputFormat::Detect => &[],
			InputFormat::Rerank => &[Rerank],
		}
	}
}

impl ProviderFormat {
	pub fn input_format(self) -> InputFormat {
		match self {
			Self::Completions => InputFormat::Completions,
			Self::Messages => InputFormat::Messages,
			Self::Responses => InputFormat::Responses,
			Self::Embeddings => InputFormat::Embeddings,
			Self::AnthropicTokenCount => InputFormat::CountTokens,
			Self::Realtime => InputFormat::Realtime,
			Self::Rerank => InputFormat::Rerank,
		}
	}
}

#[cfg(feature = "protocol")]
pub mod bedrock;
#[cfg(feature = "protocol")]
pub mod vertex;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RouteType {
	/// OpenAI /v1/chat/completions
	Completions,
	/// Anthropic /v1/messages
	Messages,
	/// OpenAI /v1/models
	Models,
	/// Send the request to the upstream LLM provider as-is
	Passthrough,
	/// Send the request to the upstream LLM provider as-is but attempt to extract information from it
	/// and apply a subset of policies (rate limit and telemetry; no guardrails).
	Detect,
	/// OpenAI /responses
	Responses,
	/// OpenAI /embeddings
	Embeddings,
	/// OpenAI /realtime (websockets)
	Realtime,
	/// Anthropic /v1/messages/count_tokens
	AnthropicTokenCount,
	/// Cohere /v2/rerank (document reranking)
	Rerank,
}

impl RouteType {
	pub fn provider_format(self) -> Option<ProviderFormat> {
		use ProviderFormat as F;
		match self {
			Self::Completions => Some(F::Completions),
			Self::Messages => Some(F::Messages),
			Self::Responses => Some(F::Responses),
			Self::Embeddings => Some(F::Embeddings),
			Self::AnthropicTokenCount => Some(F::AnthropicTokenCount),
			Self::Realtime => Some(F::Realtime),
			Self::Rerank => Some(F::Rerank),
			Self::Models | Self::Passthrough | Self::Detect => None,
		}
	}
}

#[cfg(feature = "protocol")]
pub mod adapter;

#[cfg(feature = "protocol")]
pub mod request;

#[cfg(feature = "protocol")]
pub mod endpoint;

impl ProviderFormat {
	pub fn route_type(self) -> RouteType {
		match self {
			Self::Completions => RouteType::Completions,
			Self::Messages => RouteType::Messages,
			Self::Responses => RouteType::Responses,
			Self::Embeddings => RouteType::Embeddings,
			Self::AnthropicTokenCount => RouteType::AnthropicTokenCount,
			Self::Realtime => RouteType::Realtime,
			Self::Rerank => RouteType::Rerank,
		}
	}
}

#[cfg(feature = "protocol")]
pub mod response;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(default)]
pub struct PromptCachingConfig {
	/// Add cache markers to system prompts when supported by the provider.
	#[serde(rename = "cacheSystem")]
	pub cache_system: bool,

	/// Add cache markers to chat messages when supported by the provider.
	#[serde(rename = "cacheMessages")]
	pub cache_messages: bool,

	/// Add cache markers to tool definitions when supported by the provider.
	#[serde(rename = "cacheTools")]
	pub cache_tools: bool,

	/// Minimum prompt size required before cache markers are added.
	#[serde(rename = "minTokens")]
	pub min_tokens: Option<usize>,

	/// Message offset used when choosing where to place cache markers.
	#[serde(rename = "cacheMessageOffset")]
	pub cache_message_offset: usize,
}

impl Default for PromptCachingConfig {
	fn default() -> Self {
		Self {
			cache_system: true,
			cache_messages: true,
			cache_tools: false,
			min_tokens: Some(1024),
			cache_message_offset: 0,
		}
	}
}
