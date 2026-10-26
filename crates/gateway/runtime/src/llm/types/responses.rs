pub use gateway_llm::types::responses::*;

use serde_json::Value;

use self::typed::{
	EasyInputContent, EasyInputMessage, InputContent, InputItem, InputMessage, InputRole,
	InputTextContent, OutputItem, OutputMessageContent as Content, Role,
};
use super::*;
use crate::llm::{
	AIError, InputFormat, LLMRequest, LLMRequestParams, LLMResponse, RequestType, ResponseType,
	conversion,
};

pub struct ResponseBuilder {
	inner: gateway_llm::streaming::responses::ResponseBuilder,
}
impl ResponseBuilder {
	pub fn new(response_id: impl Into<String>, model: impl Into<String>) -> Self {
		let response_id = response_id.into();
		let model = model.into();
		let created_at = chrono::Utc::now().timestamp() as u64;
		Self {
			inner: gateway_llm::streaming::responses::ResponseBuilder::new_at(
				response_id,
				model,
				created_at,
			),
		}
	}
	pub fn response(
		&self,
		status: typed::Status,
		usage: Option<typed::ResponseUsage>,
		error: Option<typed::ErrorObject>,
		incomplete_details: Option<typed::IncompleteDetails>,
	) -> typed::Response {
		self
			.inner
			.response(status, usage, error, incomplete_details)
	}
}

impl From<SimpleChatCompletionMessage> for InputItem {
	fn from(msg: SimpleChatCompletionMessage) -> Self {
		match msg.role.as_str() {
			"assistant" => InputItem::EasyMessage(EasyInputMessage {
				r#type: Default::default(),
				role: Role::Assistant,
				content: EasyInputContent::Text(msg.content.to_string()),
				phase: None,
			}),
			"system" => InputItem::from(InputMessage {
				content: vec![InputContent::InputText(InputTextContent {
					text: msg.content.to_string(),
				})],
				role: InputRole::System,
				status: None,
			}),
			"developer" => InputItem::from(InputMessage {
				content: vec![InputContent::InputText(InputTextContent {
					text: msg.content.to_string(),
				})],
				role: InputRole::Developer,
				status: None,
			}),
			_ => InputItem::from(InputMessage {
				content: vec![InputContent::InputText(InputTextContent {
					text: msg.content.to_string(),
				})],
				role: InputRole::User,
				status: None,
			}),
		}
	}
}

trait RequestExt {
	fn take_input_as_items(&mut self) -> Vec<RawInputItem>;
}

impl RequestExt for Request {
	fn take_input_as_items(&mut self) -> Vec<RawInputItem> {
		match std::mem::replace(&mut self.input, RequestInput::Items(Vec::new())) {
			RequestInput::Text(text) => vec![RawInputItem::from_user_text(text)],
			RequestInput::Items(items) => items,
		}
	}
}

impl RequestType for Request {
	fn model(&mut self) -> &mut Option<String> {
		&mut self.model
	}

	fn prepend_prompts(&mut self, prompts: Vec<SimpleChatCompletionMessage>) {
		let mut items = self.take_input_as_items();
		let prepend_items: Vec<RawInputItem> = prompts
			.into_iter()
			.map(RawInputItem::from_simple_message)
			.collect();
		items.splice(0..0, prepend_items);
		self.input = RequestInput::Items(items);
	}

	fn append_prompts(&mut self, prompts: Vec<SimpleChatCompletionMessage>) {
		let mut items = self.take_input_as_items();
		items.extend(prompts.into_iter().map(RawInputItem::from_simple_message));
		self.input = RequestInput::Items(items);
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
		Ok(LLMRequest {
			input_tokens,
			input_format: InputFormat::Responses,
			native_format: Some(crate::llm::custom::ProviderFormat::Responses),
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
				max_tokens: self.max_output_tokens.map(Into::into),
				encoding_format: None,
				dimensions: None,
			},
			prompt: Default::default(),
			provider_state: None,
		})
	}

	fn get_messages(&self) -> Vec<SimpleChatCompletionMessage> {
		match &self.input {
			RequestInput::Text(text) => {
				vec![SimpleChatCompletionMessage {
					role: strng::literal!("user"),
					content: strng::new(text),
				}]
			},
			RequestInput::Items(items) => items
				.iter()
				.filter_map(RawInputItem::as_simple_message)
				.collect(),
		}
	}

	fn set_messages(&mut self, messages: Vec<SimpleChatCompletionMessage>) {
		self.input = RequestInput::Items(
			messages
				.into_iter()
				.map(RawInputItem::from_simple_message)
				.collect(),
		);
	}

	fn to_openai(&self) -> Result<Vec<u8>, AIError> {
		// Passthrough - just serialize
		serde_json::to_vec(&self).map_err(AIError::RequestMarshal)
	}

	fn to_openai_chat_completions(&self) -> Result<Vec<u8>, AIError> {
		conversion::openai_compat::from_responses::translate(self)
	}

	fn to_bedrock(
		&self,
		provider: &crate::llm::bedrock::Provider,
		headers: Option<&http::HeaderMap>,
		prompt_caching: Option<&crate::llm::policy::PromptCachingConfig>,
	) -> Result<crate::llm::conversion::bedrock::BedrockRequest, AIError> {
		conversion::bedrock::from_responses::translate(self, provider, headers, prompt_caching)
	}

	fn to_vertex(&self, _provider: &crate::llm::vertex::Provider) -> Result<Vec<u8>, AIError> {
		self.to_openai()
	}
}

impl ResponseType for Response {
	fn to_llm_response(&self, include_completion_in_log: bool) -> LLMResponse {
		LLMResponse {
			input_tokens: self.usage.as_ref().map(|u| u.input_tokens),
			input_image_tokens: None,
			input_text_tokens: None,
			input_audio_tokens: None,
			output_tokens: self.usage.as_ref().map(|u| u.output_tokens),
			// Note: responses supports image generation, but it does not report image generation as tokens.
			// Instead there is a cost based on the image parameters (https://platform.openai.com/docs/guides/image-generation#calculating-costs)
			// which we do not currently emit.
			output_image_tokens: None,
			output_text_tokens: None,
			output_audio_tokens: None,
			count_tokens: None,
			total_tokens: self
				.usage
				.as_ref()
				.map(|u| u.input_tokens + u.output_tokens),
			reasoning_tokens: self.usage.as_ref().and_then(|u| {
				u.output_tokens_details
					.as_ref()
					.and_then(|d| d.reasoning_tokens)
			}),
			cached_input_tokens: self.usage.as_ref().and_then(|u| {
				u.input_tokens_details
					.as_ref()
					.and_then(|d| d.cached_tokens)
			}),
			cache_creation_input_tokens: None,
			service_tier: self.service_tier.as_deref().map(Into::into),
			provider_model: Some(strng::new(&self.model)),
			completion: if include_completion_in_log {
				Some(
					self
						.output
						.iter()
						.filter_map(|o| match o {
							OutputItem::Message(msg) => Some(msg),
							_ => None,
						})
						.flat_map(|msg| {
							msg.content.iter().filter_map(|c| match c {
								Content::OutputText(t) => Some(t.text.clone()),
								_ => None,
							})
						})
						.collect(),
				)
			} else {
				None
			},
			first_token: Default::default(),
		}
	}

	fn to_webhook_choices(&self) -> anyhow::Result<Vec<crate::llm::policy::webhook::ResponseChoice>> {
		crate::llm::types::content_guard::choices(self, crate::llm::InputFormat::Responses)
	}

	fn set_webhook_choices(
		&mut self,
		choices: Vec<crate::llm::policy::webhook::ResponseChoice>,
	) -> anyhow::Result<()> {
		crate::llm::types::content_guard::replace(self, crate::llm::InputFormat::Responses, choices)
	}

	fn serialize(&self) -> serde_json::Result<Vec<u8>> {
		serde_json::to_vec(&self)
	}
}

trait RawInputItemExt {
	fn from_simple_message(msg: SimpleChatCompletionMessage) -> Self;
	fn as_simple_message(&self) -> Option<SimpleChatCompletionMessage>;
}
impl RawInputItemExt for RawInputItem {
	fn from_simple_message(msg: SimpleChatCompletionMessage) -> Self {
		Self::from_typed(InputItem::from(msg))
	}
	fn as_simple_message(&self) -> Option<SimpleChatCompletionMessage> {
		let role = self.as_value().get("role")?.as_str()?;
		let role = match role {
			"user" => strng::literal!("user"),
			"assistant" => strng::literal!("assistant"),
			"system" => strng::literal!("system"),
			"developer" => strng::literal!("developer"),
			_ => return None,
		};

		let content = match self.as_value().get("content")? {
			Value::String(text) => strng::new(text),
			Value::Array(parts) => {
				let text = parts
					.iter()
					.filter_map(|part| {
						let part_type = part.get("type")?.as_str()?;
						match part_type {
							"input_text" | "output_text" => part.get("text")?.as_str(),
							_ => None,
						}
					})
					.collect::<Vec<_>>()
					.join("\n");
				strng::new(&text)
			},
			_ => return None,
		};

		Some(SimpleChatCompletionMessage { role, content })
	}
}
