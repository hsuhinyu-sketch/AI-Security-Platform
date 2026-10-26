pub use gateway_llm::types::rerank::*;

use platform_core::prelude::Strng;
use platform_core::strng;

use crate::llm::types::RequestType;
use crate::llm::{AIError, InputFormat, LLMRequest, LLMRequestParams, SimpleChatCompletionMessage};

impl RequestType for Request {
	fn model(&mut self) -> &mut Option<String> {
		&mut self.model
	}

	fn prepend_prompts(&mut self, _prompts: Vec<SimpleChatCompletionMessage>) {}

	fn append_prompts(&mut self, _prompts: Vec<SimpleChatCompletionMessage>) {}

	fn to_llm_request(&self, provider: Strng, _tokenize: bool) -> Result<LLMRequest, AIError> {
		let model = strng::new(self.model.as_deref().unwrap_or_default());
		Ok(LLMRequest {
			input_tokens: None,
			input_format: InputFormat::Rerank,
			native_format: Some(crate::llm::custom::ProviderFormat::Rerank),
			cache_convention: crate::llm::CacheTokenConvention::pending(),
			request_model: model,
			provider,
			streaming: false,
			params: LLMRequestParams::default(),
			prompt: Default::default(),
			provider_state: None,
		})
	}

	fn get_messages(&self) -> Vec<SimpleChatCompletionMessage> {
		unimplemented!("get_messages is used for prompt guard; prompt guard is disabled for rerank.")
	}

	fn set_messages(&mut self, _messages: Vec<SimpleChatCompletionMessage>) {
		unimplemented!("set_messages is used for prompt guard; prompt guard is disabled for rerank.")
	}

	fn to_openai(&self) -> Result<Vec<u8>, AIError> {
		// Passthrough to Cohere-compatible backends (Cohere, Jina, vLLM, Azure Foundry).
		serde_json::to_vec(&self).map_err(AIError::RequestMarshal)
	}

	fn to_bedrock(
		&self,
		provider: &crate::llm::bedrock::Provider,
		_headers: Option<&::http::HeaderMap>,
		_prompt_caching: Option<&crate::llm::policy::PromptCachingConfig>,
	) -> Result<crate::llm::conversion::bedrock::BedrockRequest, AIError> {
		Ok(crate::llm::conversion::bedrock::BedrockRequest {
			body: crate::llm::conversion::bedrock::from_rerank::translate(self, provider)?,
			tool_name_map: Default::default(),
		})
	}

	fn to_vertex(&self, provider: &crate::llm::vertex::Provider) -> Result<Vec<u8>, AIError> {
		crate::llm::conversion::vertex::from_rerank::translate(self, provider)
	}
}

impl crate::llm::types::ResponseType for Response {
	fn to_llm_response(&self, _include_completion_in_log: bool) -> crate::llm::LLMResponse {
		// Cohere reports counts in `meta.tokens`; fall back to `billed_units.total_tokens`
		// (e.g. Voyage's usage normalized into meta).
		let input_tokens = self.meta.as_ref().and_then(|m| {
			m.tokens
				.as_ref()
				.and_then(|t| t.input_tokens)
				.map(|t| t as u64)
				.or_else(|| {
					m.billed_units
						.as_ref()
						.and_then(|b| b.total_tokens)
						.map(|t| t as u64)
				})
		});
		crate::llm::LLMResponse {
			input_tokens,
			total_tokens: input_tokens,
			..Default::default()
		}
	}

	fn to_webhook_choices(&self) -> anyhow::Result<Vec<crate::llm::policy::webhook::ResponseChoice>> {
		anyhow::bail!("content guard unsupported for rerank response")
	}

	fn set_webhook_choices(
		&mut self,
		_resp: Vec<crate::llm::policy::webhook::ResponseChoice>,
	) -> anyhow::Result<()> {
		anyhow::bail!("content rewrite unsupported for rerank response")
	}

	fn serialize(&self) -> serde_json::Result<Vec<u8>> {
		serde_json::to_vec(self)
	}
}
