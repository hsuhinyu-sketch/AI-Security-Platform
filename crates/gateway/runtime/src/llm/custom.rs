use platform_core::prelude::Strng;
use platform_core::strng;

use crate::llm::{InputFormat, RouteType};
use crate::*;

#[apply(schema!)]
#[cfg_attr(feature = "schema", schemars(rename = "CustomProvider"))]
pub struct Provider {
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub model: Option<Strng>,
	/// Provider identity for cost-catalog lookup and telemetry. Built-in named providers
	/// (cohere, mistral, ...) set this so their cost resolves under the right catalog key;
	/// a bare custom provider may set it to match a catalog entry. Falls back to "custom".
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub provider_override: Option<Strng>,
	pub formats: Vec<ProviderFormatConfig>,
}

impl Provider {
	pub fn supports(&self, format: ProviderFormat) -> bool {
		self
			.formats
			.iter()
			.any(|supported| supported.format == format)
	}

	pub fn native_format_for(&self, input_format: InputFormat) -> Option<ProviderFormat> {
		input_format
			.provider_format_preferences()
			.iter()
			.copied()
			.find(|format| self.supports(*format))
	}

	pub fn path_for(&self, format: ProviderFormat) -> Option<&str> {
		self
			.formats
			.iter()
			.find(|supported| supported.format == format)
			.and_then(|supported| supported.path.as_deref())
	}
}

impl super::Provider for Provider {
	const NAME: Strng = strng::literal!("custom");
}

#[apply(schema!)]
pub struct ProviderFormatConfig {
	#[serde(rename = "type")]
	pub format: ProviderFormat,
	pub path: Option<Strng>,
}

#[apply(schema!)]
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
