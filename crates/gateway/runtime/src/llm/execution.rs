//! Request-local data bridge. Network, credentials and final execution remain Host-owned.
use super::{AIError, AIProvider, policy::PromptCachingConfig, types::RequestType};
use gateway_llm::provider::request::{EncodedRequest, RequestEncoder};

pub(super) struct Encoder<'a, R> {
	pub provider: &'a AIProvider,
	pub request: &'a R,
	pub headers: &'a http::HeaderMap,
	pub caching: Option<&'a PromptCachingConfig>,
}
impl<R: RequestType> RequestEncoder for Encoder<'_, R> {
	type Error = AIError;
	fn openai(&self) -> Result<Vec<u8>, AIError> {
		self.request.to_openai()
	}
	fn anthropic(&self) -> Result<Vec<u8>, AIError> {
		self.request.to_anthropic()
	}
	fn openai_chat(&self) -> Result<Vec<u8>, AIError> {
		self.request.to_openai_chat_completions()
	}
	fn vertex(&self) -> Result<Vec<u8>, AIError> {
		#[cfg(feature = "providers-gcp")]
		if let AIProvider::Vertex(provider) = self.provider {
			return self.request.to_vertex(provider);
		}
		Err(AIError::UnsupportedConversion(
			"Vertex endpoint required".into(),
		))
	}
	fn bedrock(&self) -> Result<EncodedRequest, AIError> {
		#[cfg(feature = "providers-aws")]
		if let AIProvider::Bedrock(provider) = self.provider {
			return self
				.request
				.to_bedrock(provider, Some(self.headers), self.caching);
		}
		Err(AIError::UnsupportedConversion(
			"Bedrock endpoint required".into(),
		))
	}
	fn bedrock_count_tokens(&self) -> Result<Vec<u8>, AIError> {
		self.request.to_bedrock_token_count(self.headers)
	}
}
