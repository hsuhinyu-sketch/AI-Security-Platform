pub use gateway_llm::types::messages::*;

use itertools::Itertools;
use platform_core::prelude::Strng;
use platform_core::strng;

use crate::llm::policy::webhook::ResponseChoice;
use crate::llm::types::{RequestType, ResponseType, SimpleChatCompletionMessage};
use crate::llm::{AIError, InputFormat, LLMRequest, LLMRequestParams, LLMResponse, conversion};

pub fn get_messages_helper(
	messages: &[RequestMessage],
	system: &Option<TextBlock>,
) -> Vec<SimpleChatCompletionMessage> {
	let mut out = Vec::new();
	if let Some(system) = system {
		let content = match system {
			TextBlock::Text(t) => strng::new(t),
			TextBlock::Array(parts) => {
				let text = parts
					.iter()
					.filter_map(|part| match part {
						TextPart::Text { text, .. } => Some(text.as_str()),
						_ => None,
					})
					.fold(String::new(), |mut acc, s| {
						if !acc.is_empty() {
							acc.push('\n');
						}
						acc.push_str(s);
						acc
					});
				strng::new(&text)
			},
		};
		if !content.is_empty() {
			out.push(SimpleChatCompletionMessage {
				role: strng::literal!("system"),
				content,
			});
		}
	}

	out.extend(messages.iter().map(|m| {
		let content = m
			.content
			.as_ref()
			.and_then(|c| match c {
				ContentBlock::Text(t) => Some(strng::new(t)),
				ContentBlock::Array(parts) if !parts.is_empty() => {
					let text = parts
						.iter()
						.filter_map(|part| match part {
							ContentPart::Text { text, .. } => Some(text.as_str()),
							_ => None,
						})
						.fold(String::new(), |mut acc, s| {
							if !acc.is_empty() {
								acc.push(' ');
							}
							acc.push_str(s);
							acc
						});
					Some(strng::new(&text))
				},
				_ => None,
			})
			.unwrap_or_default();
		SimpleChatCompletionMessage {
			role: strng::new(&m.role),
			content,
		}
	}));
	out
}

impl RequestType for Request {
	fn model(&mut self) -> &mut Option<String> {
		&mut self.model
	}

	fn prepend_prompts(&mut self, prompts: Vec<SimpleChatCompletionMessage>) {
		prepend_prompts_helper(&mut self.messages, &mut self.system, prompts);
	}

	fn append_prompts(&mut self, prompts: Vec<SimpleChatCompletionMessage>) {
		append_prompts_helper(&mut self.messages, &mut self.system, prompts);
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
			input_format: InputFormat::Messages,
			native_format: Some(crate::llm::custom::ProviderFormat::Messages),
			cache_convention: crate::llm::CacheTokenConvention::pending(),
			request_model: model,
			provider,
			streaming: self.stream.unwrap_or_default(),
			params: LLMRequestParams {
				temperature: self.temperature.map(Into::into),
				top_p: self.top_p.map(Into::into),
				frequency_penalty: None,
				presence_penalty: None,
				seed: None,
				max_tokens: self.max_tokens,
				encoding_format: None,
				dimensions: None,
			},
			prompt: Default::default(),
			provider_state: None,
		};
		Ok(llm)
	}

	fn get_messages(&self) -> Vec<SimpleChatCompletionMessage> {
		get_messages_helper(&self.messages, &self.system)
	}

	fn set_messages(&mut self, messages: Vec<SimpleChatCompletionMessage>) {
		let (system_prompts, message_prompts): (Vec<_>, Vec<_>) = messages
			.into_iter()
			.partition(|m| m.role.as_str() == "system");

		self.system = if system_prompts.is_empty() {
			None
		} else {
			Some(TextBlock::Array(
				system_prompts
					.into_iter()
					.map(|p| TextPart::Text {
						r#type: "text".to_string(),
						text: p.content.to_string(),
						rest: Default::default(),
					})
					.collect(),
			))
		};
		self.messages = message_prompts.into_iter().map(Into::into).collect();
	}

	fn to_openai(&self) -> Result<Vec<u8>, AIError> {
		conversion::completions::from_messages::translate(self)
	}

	fn to_anthropic(&self) -> Result<Vec<u8>, AIError> {
		serde_json::to_vec(&self).map_err(AIError::RequestMarshal)
	}

	fn to_bedrock(
		&self,
		provider: &crate::llm::bedrock::Provider,
		headers: Option<&::http::HeaderMap>,
		_prompt_caching: Option<&crate::llm::policy::PromptCachingConfig>,
	) -> Result<crate::llm::conversion::bedrock::BedrockRequest, AIError> {
		conversion::bedrock::from_messages::translate(self, provider, headers)
	}

	fn to_vertex(&self, provider: &crate::llm::vertex::Provider) -> Result<Vec<u8>, AIError> {
		if provider.is_anthropic_model(self.model.as_deref()) {
			let body = self.to_anthropic()?;
			provider.prepare_anthropic_message_body(body)
		} else {
			self.to_openai()
		}
	}
}

pub fn prepend_prompts_helper(
	messages: &mut Vec<RequestMessage>,
	system: &mut Option<TextBlock>,
	prompts: Vec<SimpleChatCompletionMessage>,
) {
	let (system_prompts, message_prompts): (Vec<_>, Vec<_>) = prompts
		.into_iter()
		.partition(|p| p.role.as_str() == "system");

	if !system_prompts.is_empty() {
		let mut items: Vec<TextPart> = match std::mem::take(system) {
			Some(TextBlock::Array(existing)) => existing,
			Some(TextBlock::Text(text)) => vec![TextPart::Text {
				r#type: "text".to_string(),
				text,
				rest: Default::default(),
			}],
			None => Vec::new(),
		};

		items.splice(
			0..0,
			system_prompts.into_iter().map(|p| TextPart::Text {
				r#type: "text".to_string(),
				text: p.content.to_string(),
				rest: Default::default(),
			}),
		);

		*system = Some(TextBlock::Array(items));
	}

	if !message_prompts.is_empty() {
		messages.splice(..0, message_prompts.into_iter().map(Into::into));
	}
}

pub fn append_prompts_helper(
	messages: &mut Vec<RequestMessage>,
	system: &mut Option<TextBlock>,
	prompts: Vec<SimpleChatCompletionMessage>,
) {
	let (system_prompts, message_prompts): (Vec<_>, Vec<_>) = prompts
		.into_iter()
		.partition(|p| p.role.as_str() == "system");

	if !system_prompts.is_empty() {
		let mut items: Vec<TextPart> = match std::mem::take(system) {
			Some(TextBlock::Text(text)) => vec![TextPart::Text {
				r#type: "text".to_string(),
				text,
				rest: Default::default(),
			}],
			Some(TextBlock::Array(existing)) => existing,
			None => Vec::new(),
		};

		items.extend(system_prompts.into_iter().map(|p| TextPart::Text {
			r#type: "text".to_string(),
			text: p.content.to_string(),
			rest: Default::default(),
		}));

		*system = Some(TextBlock::Array(items));
	}

	if !message_prompts.is_empty() {
		messages.extend(message_prompts.into_iter().map(Into::into));
	}
}

impl From<SimpleChatCompletionMessage> for RequestMessage {
	fn from(r: SimpleChatCompletionMessage) -> Self {
		RequestMessage {
			role: r.role.to_string(),
			content: Some(ContentBlock::Text(r.content.to_string())),
			rest: Default::default(),
		}
	}
}

impl ResponseType for Response {
	fn to_llm_response(&self, include_completion_in_log: bool) -> LLMResponse {
		LLMResponse {
			input_tokens: Some(self.usage.input_tokens),
			input_image_tokens: None,
			input_text_tokens: None,
			input_audio_tokens: self.input_audio_tokens,
			output_tokens: Some(self.usage.output_tokens),
			output_image_tokens: None,
			output_text_tokens: None,
			output_audio_tokens: self.output_audio_tokens,
			total_tokens: Some(self.usage.output_tokens + self.usage.input_tokens),
			provider_model: Some(strng::new(&self.model)),
			count_tokens: None,
			reasoning_tokens: None,
			cache_creation_input_tokens: self.usage.cache_creation_input_tokens,
			cached_input_tokens: self.usage.cache_read_input_tokens,
			service_tier: self.usage.service_tier.as_deref().map(Into::into),
			completion: if include_completion_in_log {
				Some(
					self
						.content
						.iter()
						.flat_map(|c| c.text.clone())
						.collect_vec(),
				)
			} else {
				None
			},
			first_token: Default::default(),
		}
	}

	fn set_webhook_choices(&mut self, choices: Vec<ResponseChoice>) -> anyhow::Result<()> {
		crate::llm::types::content_guard::replace(self, crate::llm::InputFormat::Messages, choices)
	}

	fn to_webhook_choices(&self) -> anyhow::Result<Vec<crate::llm::policy::webhook::ResponseChoice>> {
		crate::llm::types::content_guard::choices(self, crate::llm::InputFormat::Messages)
	}

	fn serialize(&self) -> serde_json::Result<Vec<u8>> {
		serde_json::to_vec(&self)
	}
}

pub mod typed {
	pub use gateway_llm::types::messages::typed::*;

	impl super::ResponseType for MessagesResponse {
		fn to_llm_response(&self, include_completion_in_log: bool) -> crate::llm::LLMResponse {
			crate::llm::LLMResponse {
				input_tokens: Some(self.usage.input_tokens as u64),
				input_image_tokens: None,
				input_text_tokens: None,
				input_audio_tokens: self.input_audio_tokens.map(|i| i as u64),
				output_tokens: Some(self.usage.output_tokens as u64),
				output_image_tokens: None,
				output_text_tokens: None,
				output_audio_tokens: self.output_audio_tokens.map(|i| i as u64),
				total_tokens: Some((self.usage.input_tokens + self.usage.output_tokens) as u64),
				reasoning_tokens: None,
				cache_creation_input_tokens: self.usage.cache_creation_input_tokens.map(|i| i as u64),
				cached_input_tokens: self.usage.cache_read_input_tokens.map(|i| i as u64),
				service_tier: self.usage.service_tier.as_deref().map(Into::into),
				provider_model: Some(platform_core::strng::new(&self.model)),
				count_tokens: None,
				completion: if include_completion_in_log {
					Some(
						self
							.content
							.iter()
							.filter_map(|c| match c {
								ContentBlock::Text(t) => Some(t.text.clone()),
								_ => None,
							})
							.collect(),
					)
				} else {
					None
				},
				first_token: Default::default(),
			}
		}

		fn set_webhook_choices(
			&mut self,
			choices: Vec<crate::llm::policy::webhook::ResponseChoice>,
		) -> anyhow::Result<()> {
			crate::llm::types::content_guard::replace(self, crate::llm::InputFormat::Messages, choices)
		}

		fn to_webhook_choices(
			&self,
		) -> anyhow::Result<Vec<crate::llm::policy::webhook::ResponseChoice>> {
			crate::llm::types::content_guard::choices(self, crate::llm::InputFormat::Messages)
		}

		fn serialize(&self) -> serde_json::Result<Vec<u8>> {
			serde_json::to_vec(&self)
		}
	}
}
