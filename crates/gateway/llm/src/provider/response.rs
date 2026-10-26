//! Buffered and streaming codec selection, independent of Host telemetry/security hooks.
use super::{InputFormat as I, ProviderFormat as F, adapter::Adapter};
use crate::WireError;

#[derive(Debug, Clone, Copy)]
pub struct ResponseDetails<'a> {
	pub input_format: I,
	pub native_format: Option<F>,
	pub request_model: &'a str,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResponseEncoding {
	Completions,
	Messages,
	Responses,
	Detect,
	OpenAIToMessages,
	AnthropicToCompletions,
	OpenAIToResponses,
	BedrockToCompletions,
	BedrockToMessages,
	BedrockToResponses,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamEncoding {
	Completions,
	Messages,
	Responses,
	Detect,
	DetectBedrock,
	OpenAIToMessages,
	AnthropicToCompletions,
	OpenAIToResponses,
	BedrockToCompletions,
	BedrockToMessages,
	BedrockToResponses,
}
fn unsupported(message: impl Into<arcstr::ArcStr>) -> WireError {
	WireError::UnsupportedConversion(message.into())
}

impl Adapter<'_> {
	pub fn response_encoding(
		&self,
		request: ResponseDetails<'_>,
	) -> Result<ResponseEncoding, WireError> {
		use ResponseEncoding as E;
		let input = request.input_format;
		let native = request.native_format;
		let model = Some(request.request_model);
		Ok(match (self, input) {
			(_, I::Detect) => E::Detect,
			(Self::Custom(_), _) => match (input, native) {
				(I::Completions, Some(F::Completions)) => E::Completions,
				(I::Completions, Some(F::Messages)) => E::AnthropicToCompletions,
				(I::Messages, Some(F::Messages)) => E::Messages,
				(I::Messages, Some(F::Completions)) => E::OpenAIToMessages,
				(I::Responses, Some(F::Responses)) => E::Responses,
				(I::Responses, Some(F::Completions)) => E::OpenAIToResponses,
				_ => {
					return Err(unsupported(format!(
						"custom provider cannot translate {native:?} response to {input:?}"
					)));
				},
			},
			(provider, I::Completions)
				if provider.is_openai_compatible() || matches!(provider, Self::Gemini(_)) =>
			{
				E::Completions
			},
			(provider, I::Responses) if provider.is_openai_compatible() => E::Responses,
			(Self::Vertex(endpoint), I::Messages) if endpoint.is_anthropic_model(model) => E::Messages,
			(Self::Vertex(_), I::Messages) => E::OpenAIToMessages,
			(Self::Anthropic(_), I::Messages) => E::Messages,
			(Self::Azure(_), I::Messages) if self.is_foundry_anthropic(model) => E::Messages,
			(Self::Azure(_) | Self::OpenAI(_) | Self::Copilot(_) | Self::Gemini(_), I::Messages) => {
				E::OpenAIToMessages
			},
			(Self::Anthropic(_), I::Completions) => E::AnthropicToCompletions,
			(Self::Bedrock(_), I::Completions) => E::BedrockToCompletions,
			(Self::Bedrock(_), I::Messages) => E::BedrockToMessages,
			(Self::Bedrock(_), I::Responses) => E::BedrockToResponses,
			(Self::Vertex(endpoint), I::Completions) if endpoint.is_anthropic_model(model) => {
				E::AnthropicToCompletions
			},
			(Self::Vertex(_), I::Completions) => E::Completions,
			(Self::Gemini(_), I::Responses) => E::OpenAIToResponses,
			(_, I::Responses) => return Err(unsupported("this provider does not support Responses")),
			(_, I::Realtime) => return Err(unsupported("realtime does not use this codepath")),
			_ => return Err(unsupported("provider response format is not supported")),
		})
	}
	pub fn stream_encoding(&self, request: ResponseDetails<'_>) -> Result<StreamEncoding, WireError> {
		use StreamEncoding as E;
		let input = request.input_format;
		let native = request.native_format;
		let model = Some(request.request_model);
		Ok(match (self, input, native) {
			(Self::Custom(_), I::Completions, Some(F::Completions)) => E::Completions,
			(Self::Custom(_), I::Completions, Some(F::Messages)) => E::AnthropicToCompletions,
			(Self::Custom(_), I::Messages, Some(F::Messages)) => E::Messages,
			(Self::Custom(_), I::Messages, Some(F::Completions)) => E::OpenAIToMessages,
			(Self::Custom(_), I::Responses, Some(F::Responses)) => E::Responses,
			(Self::Custom(_), I::Responses, Some(F::Completions)) => E::OpenAIToResponses,
			(provider, I::Completions, _)
				if provider.is_openai_compatible() || matches!(provider, Self::Gemini(_)) =>
			{
				E::Completions
			},
			(Self::Vertex(endpoint), I::Completions, _) if endpoint.is_anthropic_model(model) => {
				E::AnthropicToCompletions
			},
			(Self::Vertex(_), I::Completions, _) => E::Completions,
			(Self::Bedrock(_), I::Detect, _) => E::DetectBedrock,
			(_, I::Detect, _) => E::Detect,
			(provider, I::Responses, _) if provider.is_openai_compatible() || provider.is_vertex() => {
				E::Responses
			},
			(Self::Gemini(_), I::Responses, _) => E::OpenAIToResponses,
			(Self::Vertex(endpoint), I::Messages, _) if endpoint.is_anthropic_model(model) => E::Messages,
			(Self::Vertex(_), I::Messages, _) => E::OpenAIToMessages,
			(Self::Anthropic(_), I::Messages, _) => E::Messages,
			(Self::Azure(_), I::Messages, _) if self.is_foundry_anthropic(model) => E::Messages,
			(provider, I::Messages, _)
				if provider.is_openai_compatible() || matches!(provider, Self::Gemini(_)) =>
			{
				E::OpenAIToMessages
			},
			(Self::Anthropic(_), I::Completions, _) => E::AnthropicToCompletions,
			(Self::Bedrock(_), I::Completions, _) => E::BedrockToCompletions,
			(Self::Bedrock(_), I::Messages, _) => E::BedrockToMessages,
			(Self::Bedrock(_), I::Responses, _) => E::BedrockToResponses,
			(_, I::Realtime, _) => return Err(unsupported("realtime does not use streaming codepath")),
			(_, I::Responses, _) => {
				return Err(unsupported(
					"this provider does not support Responses for streaming",
				));
			},
			(Self::Custom(_), input, native) => {
				return Err(unsupported(format!(
					"custom provider cannot translate {native:?} stream to {input:?}"
				)));
			},
			_ => return Err(unsupported("provider streaming format is not supported")),
		})
	}
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorEncoding {
	Passthrough,
	AnthropicToCompletions,
	OpenAIToMessages,
	GoogleToCompletions,
	GoogleToResponses,
	GoogleToMessages,
	Anthropic,
	Bedrock,
	BedrockToMessages,
}

impl Adapter<'_> {
	pub fn error_encoding(&self, request: ResponseDetails<'_>) -> Result<ErrorEncoding, WireError> {
		match (self, request.input_format, request.native_format) {
			(Self::Custom(_), I::Completions, Some(F::Completions))
			| (Self::Custom(_), I::Responses, Some(F::Completions | F::Responses))
			| (Self::Custom(_), I::Embeddings, Some(F::Embeddings)) => Ok(ErrorEncoding::Passthrough),
			(Self::Custom(_), I::Completions, Some(F::Messages)) => {
				Ok(ErrorEncoding::AnthropicToCompletions)
			},
			(Self::Custom(_), I::Messages, Some(F::Completions)) => Ok(ErrorEncoding::OpenAIToMessages),
			(Self::Custom(_), I::Messages, Some(F::Messages)) => Ok(ErrorEncoding::Passthrough),
			(provider, I::Completions | I::Responses | I::Embeddings, _)
				if provider.is_openai_compatible() =>
			{
				// Passthrough; nothing needed
				Ok(ErrorEncoding::Passthrough)
			},
			(Self::Gemini(_), I::Completions, _) => Ok(ErrorEncoding::GoogleToCompletions),
			(Self::Gemini(_), I::Responses, _) => Ok(ErrorEncoding::GoogleToResponses),
			(Self::Gemini(_), I::Embeddings, _) => {
				// Passthrough; Gemini embeddings endpoint already returns OpenAI-compatible errors.
				Ok(ErrorEncoding::Passthrough)
			},
			(Self::Vertex(p), I::Completions, _) => {
				if p.is_anthropic_model(Some(request.request_model)) {
					Ok(ErrorEncoding::Passthrough)
				} else {
					Ok(ErrorEncoding::GoogleToCompletions)
				}
			},
			(Self::Vertex(_), I::Embeddings, _) => {
				// Passthrough; Vertex embeddings endpoint already returns OpenAI-compatible errors.
				Ok(ErrorEncoding::Passthrough)
			},
			(provider, I::Messages, _) if provider.is_openai_compatible() => {
				Ok(ErrorEncoding::OpenAIToMessages)
			},
			(Self::Gemini(_), I::Messages, _) => Ok(ErrorEncoding::GoogleToMessages),
			(Self::Vertex(p), I::Messages, _) => {
				if p.is_anthropic_model(Some(request.request_model)) {
					Ok(ErrorEncoding::Passthrough)
				} else {
					Ok(ErrorEncoding::GoogleToMessages)
				}
			},
			(Self::Anthropic(_), I::Messages, _) => Ok(ErrorEncoding::Anthropic),
			(_, I::Detect, _) => {
				// Passthrough; nothing needed
				Ok(ErrorEncoding::Passthrough)
			},
			(Self::Anthropic(_), I::Completions, _) => Ok(ErrorEncoding::AnthropicToCompletions),
			(Self::Bedrock(_), I::Completions, _) => Ok(ErrorEncoding::Bedrock),
			(Self::Bedrock(_), I::Messages, _) => Ok(ErrorEncoding::BedrockToMessages),
			(Self::Bedrock(_), I::Responses, _) => Ok(ErrorEncoding::Bedrock),
			(Self::Bedrock(_), I::Embeddings, _) => Ok(ErrorEncoding::Bedrock),
			(Self::Custom(_), I::Rerank, Some(F::Rerank)) => Ok(ErrorEncoding::Passthrough),
			(provider, I::Rerank, _) if provider.is_openai_compatible() => Ok(ErrorEncoding::Passthrough),
			(Self::Bedrock(_), I::Rerank, _) => Ok(ErrorEncoding::Bedrock),
			(Self::Vertex(_), I::Rerank, _) => Ok(ErrorEncoding::GoogleToCompletions),
			(_, _, _) => Err(unsupported("this provider and format is not supported")),
		}
	}
}

/// Embeddings/rerank use a single normalized response shape, without chat translation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuxiliaryEncoding {
	Passthrough,
	Bedrock,
	Vertex,
}
impl Adapter<'_> {
	pub fn auxiliary_encoding(
		&self,
		input: I,
		model: Option<&str>,
	) -> Result<AuxiliaryEncoding, WireError> {
		use AuxiliaryEncoding as E;
		Ok(match (self, input) {
			(Self::Bedrock(_), I::Embeddings | I::Rerank) => E::Bedrock,
			(Self::Vertex(p), I::Embeddings) if !p.is_anthropic_model(model) => E::Vertex,
			(Self::Vertex(_), I::Rerank) => E::Vertex,
			(_, I::Embeddings | I::Rerank) => E::Passthrough,
			_ => return Err(unsupported("not an embeddings or rerank response")),
		})
	}
	pub fn supports_count_tokens_response(&self, model: Option<&str>) -> bool {
		match self {
			Self::Anthropic(_) | Self::Vertex(_) | Self::Bedrock(_) => true,
			Self::Azure(_) => self.is_foundry_anthropic(model),
			Self::Custom(p) => p.formats.iter().any(|f| f.format == F::AnthropicTokenCount),
			_ => false,
		}
	}
}
