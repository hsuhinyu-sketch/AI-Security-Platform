pub use gateway_llm::types::embeddings::*;

use platform_core::prelude::Strng;
use platform_core::strng;

use crate::llm::types::RequestType;
use crate::llm::{AIError, InputFormat, LLMRequest, LLMRequestParams, SimpleChatCompletionMessage};

impl RequestType for Request {
	fn model(&mut self) -> &mut Option<String> {
		&mut self.model
	}

	fn prepend_prompts(&mut self, _prompts: Vec<SimpleChatCompletionMessage>) {
		// Ignored
	}

	fn append_prompts(&mut self, _prompts: Vec<SimpleChatCompletionMessage>) {
		// Ignored
	}

	fn to_llm_request(&self, provider: Strng, _tokenize: bool) -> Result<LLMRequest, AIError> {
		let model = strng::new(self.model.as_deref().unwrap_or_default());
		Ok(LLMRequest {
			// We never tokenize these, so always empty
			input_tokens: None,
			input_format: InputFormat::Embeddings,
			native_format: Some(crate::llm::custom::ProviderFormat::Embeddings),
			cache_convention: crate::llm::CacheTokenConvention::pending(),
			request_model: model,
			provider,
			streaming: false,
			params: LLMRequestParams {
				temperature: None,
				top_p: None,
				frequency_penalty: None,
				presence_penalty: None,
				seed: None,
				max_tokens: None,
				encoding_format: self.encoding_format.as_ref().map(|f| match f {
					typed::EncodingFormat::Base64 => strng::literal!("base64"),
					typed::EncodingFormat::Float => strng::literal!("float"),
				}),
				dimensions: self.dimensions.map(|d| d as u64),
			},
			prompt: Default::default(),
			provider_state: None,
		})
	}

	fn get_messages(&self) -> Vec<SimpleChatCompletionMessage> {
		unimplemented!("get_messages is used for prompt guard; prompt guard is disable for embeddings.")
	}

	fn set_messages(&mut self, _messages: Vec<SimpleChatCompletionMessage>) {
		unimplemented!("set_messages is used for prompt guard; prompt guard is disable for embeddings.")
	}

	fn to_openai(&self) -> Result<Vec<u8>, AIError> {
		serde_json::to_vec(&self).map_err(AIError::RequestMarshal)
	}

	fn to_bedrock(
		&self,
		provider: &crate::llm::bedrock::Provider,
		_headers: Option<&::http::HeaderMap>,
		_prompt_caching: Option<&crate::llm::policy::PromptCachingConfig>,
	) -> Result<crate::llm::conversion::bedrock::BedrockRequest, AIError> {
		Ok(crate::llm::conversion::bedrock::BedrockRequest {
			body: crate::llm::conversion::bedrock::from_embeddings::translate(self, provider)?,
			tool_name_map: Default::default(),
		})
	}

	fn to_vertex(&self, _provider: &crate::llm::vertex::Provider) -> Result<Vec<u8>, AIError> {
		crate::llm::conversion::vertex::from_embeddings::translate(self)
	}
}

impl crate::llm::types::ResponseType for Response {
	fn to_llm_response(&self, _include_completion_in_log: bool) -> crate::llm::LLMResponse {
		crate::llm::LLMResponse {
			input_tokens: Some(self.usage.prompt_tokens as u64),
			input_image_tokens: None,
			input_text_tokens: None,
			input_audio_tokens: None,
			total_tokens: Some(self.usage.total_tokens as u64),
			output_tokens: None,
			output_image_tokens: None,
			output_text_tokens: None,
			output_audio_tokens: None,
			service_tier: None,
			..Default::default()
		}
	}

	fn to_webhook_choices(&self) -> anyhow::Result<Vec<crate::llm::policy::webhook::ResponseChoice>> {
		anyhow::bail!("content guard unsupported for embeddings response")
	}

	fn set_webhook_choices(
		&mut self,
		_resp: Vec<crate::llm::policy::webhook::ResponseChoice>,
	) -> anyhow::Result<()> {
		anyhow::bail!("content rewrite unsupported for embeddings response")
	}

	fn serialize(&self) -> serde_json::Result<Vec<u8>> {
		serde_json::to_vec(self)
	}
}
