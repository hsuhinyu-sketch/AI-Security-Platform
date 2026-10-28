pub use gateway_llm::types::completions::*;

use itertools::Itertools;
use platform_core::strng;
use platform_core::strng::Strng;

use crate::llm;
use crate::llm::bedrock::Provider;
use crate::llm::policy::webhook::ResponseChoice;
use crate::llm::types::{ResponseType, SimpleChatCompletionMessage};
use crate::llm::{AIError, InputFormat, LLMRequest, LLMRequestParams, LLMResponse, conversion};

impl ResponseType for Response {
	fn to_llm_response(&self, include_completion_in_log: bool) -> LLMResponse {
		LLMResponse {
			input_tokens: self.usage.as_ref().map(|u| u.prompt_tokens as u64),
			input_image_tokens: None,
			input_text_tokens: None,
			input_audio_tokens: self.usage.as_ref().and_then(|u| {
				u.prompt_tokens_details
					.as_ref()
					.and_then(|d| d.audio_tokens)
			}),

			output_tokens: self.usage.as_ref().map(|u| u.completion_tokens as u64),
			output_image_tokens: None,
			output_text_tokens: None,
			output_audio_tokens: self.usage.as_ref().and_then(|u| {
				u.completion_tokens_details
					.as_ref()
					.and_then(|d| d.audio_tokens)
			}),

			total_tokens: self.usage.as_ref().map(|u| u.total_tokens as u64),
			count_tokens: None,

			reasoning_tokens: self.usage.as_ref().and_then(|u| {
				u.completion_tokens_details
					.as_ref()
					.and_then(|d| d.reasoning_tokens)
			}),
			cached_input_tokens: self.usage.as_ref().and_then(|u| {
				u.prompt_tokens_details
					.as_ref()
					.and_then(|d| d.cached_tokens)
			}),
			cache_creation_input_tokens: None,
			service_tier: self.service_tier.as_deref().map(Into::into),
			provider_model: Some(strng::new(&self.model)),
			completion: if include_completion_in_log {
				Some(
					self
						.choices
						.iter()
						.flat_map(|c| c.message.content.clone())
						.collect_vec(),
				)
			} else {
				None
			},
			first_token: Default::default(),
		}
	}

	fn set_webhook_choices(&mut self, choices: Vec<ResponseChoice>) -> anyhow::Result<()> {
		crate::llm::types::content_guard::replace(self, crate::llm::InputFormat::Completions, choices)
	}

	fn to_webhook_choices(&self) -> anyhow::Result<Vec<crate::llm::policy::webhook::ResponseChoice>> {
		crate::llm::types::content_guard::choices(self, crate::llm::InputFormat::Completions)
	}

	fn serialize(&self) -> serde_json::Result<Vec<u8>> {
		serde_json::to_vec(&self)
	}
}

impl super::RequestType for Request {
	#[cfg(feature = "security-pii")]
	fn pii_body(&self) -> Result<serde_json::Value, AIError> {
		serde_json::to_value(self).map_err(|_| AIError::PiiInspection)
	}
	#[cfg(feature = "security-pii")]
	fn replace_pii_body(&mut self, body: serde_json::Value) -> Result<(), AIError> {
		*self = serde_json::from_value(body).map_err(|_| AIError::PiiInspection)?;
		Ok(())
	}

	fn model(&mut self) -> &mut Option<String> {
		&mut self.model
	}
	fn prepend_prompts(&mut self, prompts: Vec<llm::types::SimpleChatCompletionMessage>) {
		self
			.messages
			.splice(..0, prompts.into_iter().map(convert_message));
	}

	fn append_prompts(&mut self, prompts: Vec<llm::types::SimpleChatCompletionMessage>) {
		self
			.messages
			.extend(prompts.into_iter().map(convert_message));
	}

	fn to_anthropic(&self) -> Result<Vec<u8>, AIError> {
		conversion::messages::from_completions::translate(self)
	}

	fn to_bedrock(
		&self,
		provider: &Provider,
		headers: Option<&::http::HeaderMap>,
		prompt_caching: Option<&crate::llm::policy::PromptCachingConfig>,
	) -> Result<crate::llm::conversion::bedrock::BedrockRequest, AIError> {
		conversion::bedrock::from_completions::translate(self, provider, headers, prompt_caching)
	}

	fn to_openai(&self) -> Result<Vec<u8>, AIError> {
		serde_json::to_vec(&self).map_err(AIError::RequestMarshal)
	}

	fn to_vertex(&self, provider: &crate::llm::vertex::Provider) -> Result<Vec<u8>, AIError> {
		if provider.is_anthropic_model(self.model.as_deref()) {
			let body = self.to_anthropic()?;
			provider.prepare_anthropic_message_body(body)
		} else {
			self.to_openai()
		}
	}

	fn to_llm_request(&self, provider: Strng, tokenize: bool) -> Result<LLMRequest, AIError> {
		let model = strng::new(self.model.as_deref().unwrap_or_default());
		let input_tokens = if tokenize {
			let messages = self.get_messages();
			let tokens = crate::llm::num_tokens_from_messages(&model, &messages)?;
			Some(tokens)
		} else {
			None
		};
		// Pass the original body through
		let llm = LLMRequest {
			input_tokens,
			input_format: InputFormat::Completions,
			native_format: Some(crate::llm::custom::ProviderFormat::Completions),
			cache_convention: crate::llm::CacheTokenConvention::pending(),
			request_model: model,
			provider,
			streaming: self.stream.unwrap_or_default(),
			params: LLMRequestParams {
				temperature: self.temperature.map(Into::into),
				top_p: self.top_p.map(Into::into),
				frequency_penalty: self.frequency_penalty.map(Into::into),
				presence_penalty: self.presence_penalty.map(Into::into),
				seed: self.seed,
				max_tokens: self
					.max_completion_tokens
					.or(self.max_tokens)
					.map(Into::into),
				encoding_format: None,
				dimensions: None,
			},
			prompt: Default::default(),
			provider_state: None,
		};
		Ok(llm)
	}

	fn get_messages(&self) -> Vec<SimpleChatCompletionMessage> {
		self
			.messages
			.iter()
			.map(|m| {
				let content = m
					.content
					.as_ref()
					.and_then(|c| match c {
						Content::Text(t) => Some(strng::new(t)),
						Content::Array(parts) if !parts.is_empty() => {
							let text = parts.iter().filter_map(|part| part.text.as_deref()).fold(
								String::new(),
								|mut acc, s| {
									if !acc.is_empty() {
										acc.push(' ');
									}
									acc.push_str(s);
									acc
								},
							);
							Some(strng::new(&text))
						},
						_ => None,
					})
					.unwrap_or_default();
				SimpleChatCompletionMessage {
					role: strng::new(&m.role),
					content,
				}
			})
			.collect()
	}

	fn set_messages(&mut self, messages: Vec<SimpleChatCompletionMessage>) {
		self.messages = messages.into_iter().map(convert_message).collect();
	}
}

fn convert_message(r: SimpleChatCompletionMessage) -> RequestMessage {
	RequestMessage {
		role: r.role.to_string(),
		name: None,
		content: Some(Content::Text(r.content.to_string())),
		tool_call_id: None,
		tool_calls: None,
		rest: Default::default(),
	}
}
