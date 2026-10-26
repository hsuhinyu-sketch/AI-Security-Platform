//! Provider protocol parameters and decisions. No credentials, policy or transport.
use super::{InputFormat, ProviderFormat, azure, bedrock, custom, vertex};
use crate::{CacheTokenConvention, WireError};

#[derive(Debug, Clone, Copy)]
pub struct Custom<'a> {
	pub model: Option<&'a str>,
	pub formats: &'a [custom::ProviderFormatConfig],
}

#[derive(Debug, Clone, Copy)]
pub enum Adapter<'a> {
	OpenAI(Option<&'a str>),
	Anthropic(Option<&'a str>),
	Gemini(Option<&'a str>),
	Copilot(Option<&'a str>),
	Azure(azure::Endpoint<'a>),
	Bedrock(bedrock::Endpoint<'a>),
	Vertex(vertex::Endpoint<'a>),
	Custom(Custom<'a>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestEncoding {
	OpenAI,
	Anthropic,
	OpenAIChat,
	Vertex,
	VertexAnthropic,
	VertexAnthropicCountTokens,
	Bedrock,
	BedrockCountTokens,
}

fn unsupported(message: impl Into<arcstr::ArcStr>) -> WireError {
	WireError::UnsupportedConversion(message.into())
}

impl Adapter<'_> {
	pub fn is_openai_compatible(&self) -> bool {
		matches!(self, Self::OpenAI(_) | Self::Copilot(_) | Self::Azure(_))
	}
	pub fn is_bedrock(&self) -> bool {
		matches!(self, Self::Bedrock(_))
	}
	pub fn is_vertex(&self) -> bool {
		matches!(self, Self::Vertex(_))
	}
	pub fn is_foundry_anthropic(&self, model: Option<&str>) -> bool {
		matches!(self, Self::Azure(p) if matches!(p.resource_type, azure::AzureResourceType::Foundry) && p.is_anthropic_model(model))
	}
	pub fn default_base_path(&self) -> Option<&'static str> {
		match self {
			Self::OpenAI(_) | Self::Copilot(_) | Self::Anthropic(_) => Some("/v1"),
			_ => None,
		}
	}
	pub fn override_model(&self) -> Option<&str> {
		match self {
			Self::OpenAI(model) | Self::Copilot(model) | Self::Anthropic(model) | Self::Gemini(model) => {
				*model
			},
			Self::Azure(p) => p.model,
			Self::Vertex(p) => p.model,
			Self::Bedrock(p) => p.model,
			Self::Custom(p) => p.model,
		}
	}
	pub fn supported_formats(&self, model: Option<&str>) -> Vec<ProviderFormat> {
		use ProviderFormat::*;
		match self {
			Self::OpenAI(_) => vec![Completions, Responses, Embeddings, Realtime, Rerank],
			Self::Copilot(_) => vec![Completions, Responses, Rerank],
			Self::Azure(_) => {
				let mut formats = vec![Completions, Responses, Embeddings, Rerank];
				if self.is_foundry_anthropic(model) {
					formats.extend([Messages, AnthropicTokenCount]);
				}
				formats
			},
			Self::Gemini(_) => vec![Completions, Embeddings],
			Self::Anthropic(_) => vec![Messages, AnthropicTokenCount],
			Self::Bedrock(p) => {
				let mut formats = vec![Completions, Messages, Responses, Embeddings, Rerank];
				if p.is_anthropic_model(model) {
					formats.push(AnthropicTokenCount);
				}
				formats
			},
			Self::Vertex(p) => {
				let mut formats = if p.is_anthropic_model(model) {
					vec![Messages, AnthropicTokenCount]
				} else {
					vec![Completions]
				};
				formats.extend([Embeddings, Rerank]);
				formats
			},
			Self::Custom(p) => p.formats.iter().map(|format| format.format).collect(),
		}
	}
	pub fn native_format_for(
		&self,
		input: InputFormat,
		model: Option<&str>,
	) -> Option<ProviderFormat> {
		if self.is_vertex() && input == InputFormat::Responses {
			return None;
		}
		let supported = self.supported_formats(model);
		custom::native_format_for(supported.iter().copied(), input)
	}
	pub fn cache_convention(
		&self,
		native: Option<ProviderFormat>,
		model: &str,
	) -> CacheTokenConvention {
		use CacheTokenConvention::*;
		match self {
			Self::Anthropic(_) | Self::Bedrock(_) => InputExcludesCache,
			Self::Vertex(p) if p.is_anthropic_model(Some(model)) => InputExcludesCache,
			Self::Custom(_)
				if matches!(
					native,
					Some(ProviderFormat::Messages | ProviderFormat::AnthropicTokenCount)
				) =>
			{
				InputExcludesCache
			},
			_ => InputIncludesCache,
		}
	}
	pub fn request_encoding(
		&self,
		input: InputFormat,
		native: Option<ProviderFormat>,
		model: &str,
	) -> Result<RequestEncoding, WireError> {
		use RequestEncoding as E;
		if input == InputFormat::CountTokens {
			return match self {
				Self::Anthropic(_) | Self::Custom(_) => Ok(E::Anthropic),
				Self::Bedrock(_) => Ok(E::BedrockCountTokens),
				Self::Vertex(_) => Ok(E::VertexAnthropicCountTokens),
				Self::Azure(_) if self.is_foundry_anthropic(Some(model)) => Ok(E::Anthropic),
				_ => Err(unsupported("count_tokens not supported for this provider")),
			};
		}
		Ok(match self {
			Self::Custom(_) => match (input, native) {
				(_, None) => E::OpenAI,
				(InputFormat::Completions, Some(ProviderFormat::Completions))
				| (InputFormat::Embeddings, Some(ProviderFormat::Embeddings))
				| (InputFormat::Rerank, Some(ProviderFormat::Rerank))
				| (InputFormat::Messages, Some(ProviderFormat::Completions))
				| (InputFormat::Responses, Some(ProviderFormat::Responses)) => E::OpenAI,
				(InputFormat::Completions | InputFormat::Messages, Some(ProviderFormat::Messages)) => {
					E::Anthropic
				},
				(InputFormat::Responses, Some(ProviderFormat::Completions)) => E::OpenAIChat,
				(InputFormat::CountTokens | InputFormat::Realtime, _) => {
					return Err(unsupported(
						"this request format does not use this codepath",
					));
				},
				(_, Some(format)) => {
					return Err(unsupported(format!(
						"unsupported custom native format {format:?}"
					)));
				},
			},
			Self::OpenAI(_) | Self::Copilot(_) => E::OpenAI,
			Self::Azure(_)
				if self.is_foundry_anthropic(Some(model))
					&& matches!(input, InputFormat::Messages | InputFormat::CountTokens) =>
			{
				E::Anthropic
			},
			Self::Azure(_) => E::OpenAI,
			Self::Vertex(p) if p.is_anthropic_model(Some(model)) => E::VertexAnthropic,
			Self::Vertex(_) => E::Vertex,
			Self::Gemini(_) if input == InputFormat::Responses => E::OpenAIChat,
			Self::Gemini(_) => E::OpenAI,
			Self::Anthropic(_) => E::Anthropic,
			Self::Bedrock(_) => E::Bedrock,
		})
	}
}
