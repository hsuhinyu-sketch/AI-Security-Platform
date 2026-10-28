#[cfg(feature = "gateway-llm")]
pub mod bedrock;
#[cfg(feature = "gateway-llm")]
pub mod completions;
#[cfg(feature = "gateway-llm")]
pub(crate) mod content_guard;
#[cfg(feature = "gateway-llm")]
pub mod count_tokens;
#[cfg(feature = "gateway-llm")]
pub mod detect;
#[cfg(feature = "gateway-llm")]
pub mod embeddings;
#[cfg(feature = "gateway-llm")]
pub mod messages;
#[cfg(feature = "gateway-llm")]
pub mod rerank;
#[cfg(feature = "gateway-llm")]
pub mod responses;
#[cfg(feature = "gateway-llm")]
pub mod vertex;

use platform_core::prelude::Strng;
#[cfg(feature = "gateway-llm")]
use platform_core::strng;
#[cfg(feature = "gateway-llm")]
use serde::Serialize;

use crate::apply;
#[cfg(feature = "gateway-llm")]
use crate::llm::{AIError, LLMRequest, LLMResponse};
use crate::serdes::schema;

/// ResponseType is an abstraction over provider/endpoint specific response formats that enables
/// uniform policy enforcement and observability
#[cfg(feature = "gateway-llm")]
pub trait ResponseType: Send + Sync {
	fn to_llm_response(&self, include_completion_in_log: bool) -> LLMResponse;
	fn to_webhook_choices(&self) -> anyhow::Result<Vec<crate::llm::policy::webhook::ResponseChoice>>;
	fn set_webhook_choices(
		&mut self,
		resp: Vec<crate::llm::policy::webhook::ResponseChoice>,
	) -> anyhow::Result<()>;
	fn serialize(&self) -> serde_json::Result<Vec<u8>>;
}

/// RequestType is an abstraction over provider/endpoint specific request formats that enables
/// uniform policy enforcement and observability
#[cfg(feature = "gateway-llm")]
pub trait RequestType: Send + Sync {
	#[cfg(feature = "security-pii")]
	fn pii_body(&self) -> Result<serde_json::Value, AIError> {
		Err(AIError::PiiInspection)
	}
	#[cfg(feature = "security-pii")]
	fn replace_pii_body(&mut self, _body: serde_json::Value) -> Result<(), AIError> {
		Err(AIError::PiiInspection)
	}
	fn supports_model(&self) -> bool {
		true
	}
	fn model(&mut self) -> &mut Option<String>;
	fn prepend_prompts(&mut self, prompts: Vec<SimpleChatCompletionMessage>);
	fn append_prompts(&mut self, prompts: Vec<SimpleChatCompletionMessage>);
	fn to_llm_request(&self, provider: Strng, tokenize: bool) -> Result<LLMRequest, AIError>;
	fn get_messages(&self) -> Vec<SimpleChatCompletionMessage>;
	fn set_messages(&mut self, messages: Vec<SimpleChatCompletionMessage>);

	fn to_openai(&self) -> Result<Vec<u8>, AIError> {
		Err(AIError::UnsupportedConversion(strng::literal!("openai")))
	}

	fn to_anthropic(&self) -> Result<Vec<u8>, AIError> {
		Err(AIError::UnsupportedConversion(strng::literal!("anthropic")))
	}

	fn to_bedrock(
		&self,
		_provider: &crate::llm::bedrock::Provider,
		_headers: Option<&::http::HeaderMap>,
		_prompt_caching: Option<&crate::llm::policy::PromptCachingConfig>,
	) -> Result<crate::llm::conversion::bedrock::BedrockRequest, AIError> {
		Err(AIError::UnsupportedConversion(strng::literal!("bedrock")))
	}

	fn to_bedrock_token_count(&self, _headers: &::http::HeaderMap) -> Result<Vec<u8>, AIError> {
		Err(AIError::UnsupportedConversion(strng::literal!(
			"bedrock token count"
		)))
	}

	fn to_openai_chat_completions(&self) -> Result<Vec<u8>, AIError> {
		Err(AIError::UnsupportedConversion(strng::literal!(
			"openai-compatible chat completions"
		)))
	}

	fn to_vertex(&self, _provider: &crate::llm::vertex::Provider) -> Result<Vec<u8>, AIError> {
		Err(AIError::UnsupportedConversion(strng::literal!("vertex")))
	}
}

/// SimpleChatCompletionMessage is a simplified chat message
#[apply(schema!)]
#[derive(Eq, PartialEq, cel::DynamicType)]
pub struct SimpleChatCompletionMessage {
	pub role: Strng,
	pub content: Strng,
}

#[cfg(feature = "gateway-llm")]
pub fn serialize_str<T: Serialize>(value: &T) -> Option<Strng> {
	serde_json::to_value(value).ok()?.as_str().map(Into::into)
}
