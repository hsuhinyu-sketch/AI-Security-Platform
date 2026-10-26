//! Request encoding through protocol data converters supplied at the Host boundary.
//! Converters consume data only; this interface cannot authorize or send a model call.
use super::{
	InputFormat, ProviderFormat,
	adapter::{Adapter, RequestEncoding},
	bedrock::BedrockToolNameMap,
};
use crate::WireError;

pub struct EncodedRequest {
	pub body: Vec<u8>,
	pub tool_name_map: BedrockToolNameMap,
}
impl EncodedRequest {
	fn plain(body: Vec<u8>) -> Self {
		Self {
			body,
			tool_name_map: Default::default(),
		}
	}
}

pub trait RequestEncoder {
	type Error: From<WireError>;
	fn openai(&self) -> Result<Vec<u8>, Self::Error>;
	fn anthropic(&self) -> Result<Vec<u8>, Self::Error>;
	fn openai_chat(&self) -> Result<Vec<u8>, Self::Error>;
	fn vertex(&self) -> Result<Vec<u8>, Self::Error>;
	fn bedrock(&self) -> Result<EncodedRequest, Self::Error>;
	fn bedrock_count_tokens(&self) -> Result<Vec<u8>, Self::Error>;
}

impl Adapter<'_> {
	pub fn encode<E: RequestEncoder>(
		&self,
		input: InputFormat,
		native: Option<ProviderFormat>,
		model: &str,
		encoder: &E,
	) -> Result<EncodedRequest, E::Error> {
		let body = match self.request_encoding(input, native, model)? {
			RequestEncoding::OpenAI => encoder.openai()?,
			RequestEncoding::Anthropic => encoder.anthropic()?,
			RequestEncoding::OpenAIChat => encoder.openai_chat()?,
			RequestEncoding::Vertex => encoder.vertex()?,
			RequestEncoding::VertexAnthropic | RequestEncoding::VertexAnthropicCountTokens => {
				let body = encoder.anthropic()?;
				let Self::Vertex(endpoint) = self else {
					return Err(WireError::UnsupportedConversion("Vertex endpoint required".into()).into());
				};
				if input == InputFormat::CountTokens {
					endpoint.prepare_anthropic_count_tokens_body(body)?
				} else {
					endpoint.prepare_anthropic_message_body(body)?
				}
			},
			RequestEncoding::Bedrock => return encoder.bedrock(),
			RequestEncoding::BedrockCountTokens => encoder.bedrock_count_tokens()?,
		};
		Ok(EncodedRequest::plain(body))
	}
}
