//! Buffered Converse normalization. Identity and timestamps are filled by the Host.
use crate::provider::bedrock::{BedrockToolNameMap, restore_tool_name};
use crate::{
	WireError,
	types::{bedrock, completions::typed::UsagePromptDetails, messages, responses},
};
pub struct ConverseResponseAdapter {
	pub model: String,
	pub stop_reason: bedrock::StopReason,
	usage: Option<bedrock::TokenUsage>,
	message: bedrock::Message,
}

impl ConverseResponseAdapter {
	pub fn from_response(resp: bedrock::ConverseResponse, model: &str) -> Result<Self, WireError> {
		let bedrock::ConverseResponse {
			output,
			stop_reason,
			usage,
			metrics: _,
			trace: _,
			additional_model_response_fields: _,
			performance_config: _,
		} = resp;

		let message = match output {
			Some(bedrock::ConverseOutput::Message(msg)) => msg,
			_ => return Err(WireError::IncompleteResponse),
		};

		Ok(Self {
			model: model.to_string(),
			stop_reason,
			usage,
			message,
		})
	}

	pub fn to_completions(
		&self,
		tool_name_map: Option<&BedrockToolNameMap>,
	) -> crate::types::completions::typed::Response {
		use crate::types::completions::typed as completions;
		let mut tool_calls: Vec<completions::MessageToolCalls> = Vec::new();
		let mut content = None;
		let mut reasoning_content = None;
		let mut reasoning_signature = None;
		for block in &self.message.content {
			match block {
				bedrock::ContentBlock::Text(text) => {
					// A message may contain multiple text blocks (e.g. text split around
					// citations); concatenate them into the single OpenAI `content` field.
					content.get_or_insert_with(String::new).push_str(text);
				},
				bedrock::ContentBlock::ReasoningContent(reasoning) => {
					// Extract text and signature from either format. The signature is forwarded so
					// downstream consumers can preserve thinking blocks across conversation turns;
					// empty signatures are excluded so callers can use Option::is_some() as the
					// "safe to replay" guard.
					let (text, signature) = match reasoning {
						bedrock::ReasoningContentBlock::Structured { reasoning_text } => (
							reasoning_text.text.clone(),
							reasoning_text.signature.clone(),
						),
						bedrock::ReasoningContentBlock::Simple { text } => (text.clone(), None),
					};
					reasoning_content = Some(text);
					if let Some(sig) = signature
						&& !sig.is_empty()
					{
						reasoning_signature = Some(sig);
					}
				},
				bedrock::ContentBlock::ToolUse(tu) => {
					let Some(args) = serde_json::to_string(&tu.input).ok() else {
						continue;
					};
					tool_calls.push(completions::MessageToolCalls::Function(
						completions::MessageToolCall {
							id: tu.tool_use_id.clone(),
							function: completions::FunctionCall {
								name: restore_tool_name(tool_name_map, &tu.name),
								arguments: args,
							},
						},
					));
				},
				bedrock::ContentBlock::Image(_)
				| bedrock::ContentBlock::ToolResult(_)
				| bedrock::ContentBlock::CachePoint(_) => {
					continue;
				},
			}
		}

		let message = completions::ResponseMessage {
			role: completions::Role::Assistant,
			content,
			tool_calls: if tool_calls.is_empty() {
				None
			} else {
				Some(tool_calls)
			},
			#[allow(deprecated)]
			function_call: None,
			refusal: None,
			audio: None,
			extra: None,
			reasoning_content,
			reasoning_signature,
		};

		let choice = completions::ChatChoice {
			index: 0,
			message,
			finish_reason: Some(crate::streaming::bedrock::translate_stop_reason(
				&self.stop_reason,
			)),
			logprobs: None,
		};

		let usage = self
			.usage
			.map(|token_usage| completions::Usage {
				prompt_tokens: token_usage.input_tokens as u32,
				completion_tokens: token_usage.output_tokens as u32,
				total_tokens: token_usage.total_tokens as u32,
				completion_tokens_details: None,

				cache_read_input_tokens: token_usage.cache_read_input_tokens.map(|i| i as u64),
				prompt_tokens_details: token_usage
					.cache_read_input_tokens
					.map(|i| UsagePromptDetails {
						cached_tokens: Some(i as u64),
						audio_tokens: None,
						rest: Default::default(),
					}),
				cache_creation_input_tokens: token_usage.cache_write_input_tokens.map(|i| i as u64),
			})
			.unwrap_or_default();

		completions::Response {
			id: String::new(),
			object: "chat.completion".to_string(),
			created: 0,
			model: self.model.clone(),
			choices: vec![choice],
			usage: Some(usage),
			service_tier: None,
			system_fingerprint: None,
		}
	}

	pub fn to_responses_typed(
		&self,
		tool_name_map: Option<&BedrockToolNameMap>,
		mut response: responses::typed::Response,
	) -> responses::typed::Response {
		use crate::types::responses::typed as responsest;

		// Convert Bedrock content blocks to Responses OutputItem
		let mut outputs: Vec<responsest::OutputItem> = Vec::new();

		// Group content by type for proper message construction
		let mut text_parts: Vec<responsest::OutputMessageContent> = Vec::new();
		let mut tool_calls: Vec<responsest::OutputItem> = Vec::new();

		for block in &self.message.content {
			match block {
				bedrock::ContentBlock::Text(text) => {
					text_parts.push(responsest::OutputMessageContent::OutputText(
						responsest::OutputTextContent {
							annotations: vec![],
							logprobs: None,
							text: text.clone(),
						},
					));
				},
				bedrock::ContentBlock::ReasoningContent(reasoning) => {
					let text = match reasoning {
						bedrock::ReasoningContentBlock::Structured { reasoning_text } => {
							reasoning_text.text.clone()
						},
						bedrock::ReasoningContentBlock::Simple { text } => text.clone(),
					};
					text_parts.push(responsest::OutputMessageContent::OutputText(
						responsest::OutputTextContent {
							annotations: vec![],
							logprobs: None,
							text,
						},
					));
				},
				bedrock::ContentBlock::ToolUse(tool_use) => {
					let arguments_str = serde_json::to_string(&tool_use.input).unwrap_or_default();
					tool_calls.push(responsest::OutputItem::FunctionCall(
						responsest::FunctionToolCall {
							arguments: arguments_str,
							call_id: tool_use.tool_use_id.clone(),
							namespace: None,
							name: restore_tool_name(tool_name_map, &tool_use.name),
							id: Some(tool_use.tool_use_id.clone()),
							status: Some(responsest::OutputStatus::Completed),
						},
					));
				},
				bedrock::ContentBlock::Image(_)
				| bedrock::ContentBlock::ToolResult(_)
				| bedrock::ContentBlock::CachePoint(_) => {
					// Skip these in responses (not part of output)
				},
			}
		}

		if !text_parts.is_empty() {
			outputs.push(responsest::OutputItem::Message(responsest::OutputMessage {
				id: String::new(),
				role: responsest::AssistantRole::Assistant,
				phase: None,
				content: text_parts,
				status: responsest::OutputStatus::Completed,
			}));
		}

		outputs.extend(tool_calls);

		let output = outputs;

		// Determine status from stop reason
		let status = match self.stop_reason {
			bedrock::StopReason::EndTurn | bedrock::StopReason::StopSequence => {
				responsest::Status::Completed
			},
			bedrock::StopReason::MaxTokens | bedrock::StopReason::ModelContextWindowExceeded => {
				responsest::Status::Incomplete
			},
			bedrock::StopReason::ToolUse => responsest::Status::Completed,
			bedrock::StopReason::ContentFiltered | bedrock::StopReason::GuardrailIntervened => {
				responsest::Status::Failed
			},
		};

		let incomplete_details = match self.stop_reason {
			bedrock::StopReason::MaxTokens | bedrock::StopReason::ModelContextWindowExceeded => {
				Some(responsest::IncompleteDetails {
					reason: "max_tokens".to_string(),
				})
			},
			_ => None,
		};

		let error = match self.stop_reason {
			bedrock::StopReason::ContentFiltered | bedrock::StopReason::GuardrailIntervened => {
				Some(responsest::ErrorObject {
					code: "content_filter".to_string(),
					message: "Content filtered by guardrails".to_string(),
				})
			},
			_ => None,
		};

		// Build usage
		let usage = self.usage.map(|u| responsest::ResponseUsage {
			input_tokens: u.input_tokens as u32,
			output_tokens: u.output_tokens as u32,
			total_tokens: (u.input_tokens + u.output_tokens) as u32,
			input_tokens_details: responsest::InputTokenDetails {
				cached_tokens: u.cache_read_input_tokens.unwrap_or(0) as u32,
			},
			output_tokens_details: responsest::OutputTokenDetails {
				reasoning_tokens: 0,
			},
		});

		response.status = status;
		response.usage = usage;
		response.error = error;
		response.incomplete_details = incomplete_details;
		response.output = output;
		response
	}

	pub fn to_anthropic(
		&self,
		tool_name_map: Option<&BedrockToolNameMap>,
	) -> Result<messages::typed::MessagesResponse, WireError> {
		use crate::types::messages::typed as messagest;
		let (content, usage) =
			super::anthropic_content_and_usage(&self.message, self.usage, tool_name_map);

		Ok(messagest::MessagesResponse {
			id: String::new(),
			r#type: "message".to_string(),
			role: messagest::Role::Assistant,
			content,
			model: self.model.clone(),
			stop_reason: Some(crate::streaming::bedrock::messages_stop_reason(
				self.stop_reason,
			)),
			stop_sequence: None,
			usage,
			input_audio_tokens: None,
			output_audio_tokens: None,
		})
	}
}
