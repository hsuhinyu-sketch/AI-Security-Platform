use crate::types;

pub fn parse_data_url(url: &str) -> Option<(&str, &str)> {
	let raw = url.strip_prefix("data:")?;
	let (meta, data) = raw.split_once(',')?;
	let (media_type, encoding) = meta.split_once(';')?;
	if !encoding.eq_ignore_ascii_case("base64") {
		return None;
	}
	Some((media_type, data))
}

pub fn extract_system_text(msg: &types::completions::typed::RequestMessage) -> Option<String> {
	fn normalize_text(text: &str) -> Option<String> {
		if text.trim().is_empty() {
			None
		} else {
			Some(text.to_string())
		}
	}

	match msg {
		types::completions::typed::RequestMessage::System(system) => match &system.content {
			types::completions::typed::RequestSystemMessageContent::Text(text) => normalize_text(text),
			types::completions::typed::RequestSystemMessageContent::Array(parts) => {
				let text = parts
					.iter()
					.map(|part| match part {
						types::completions::typed::RequestSystemMessageContentPart::Text(text) => {
							text.text.as_str()
						},
					})
					.filter(|text| !text.trim().is_empty())
					.collect::<Vec<_>>()
					.join("\n");
				normalize_text(&text)
			},
		},
		types::completions::typed::RequestMessage::Developer(developer) => match &developer.content {
			types::completions::typed::RequestDeveloperMessageContent::Text(text) => normalize_text(text),
			types::completions::typed::RequestDeveloperMessageContent::Array(parts) => {
				let text = parts
					.iter()
					.map(|part| match part {
						types::completions::typed::RequestDeveloperMessageContentPart::Text(text) => {
							text.text.as_str()
						},
					})
					.filter(|text| !text.trim().is_empty())
					.collect::<Vec<_>>()
					.join("\n");
				normalize_text(&text)
			},
		},
		_ => None,
	}
}

pub fn google_error_type(error: &types::completions::typed::GoogleError) -> &'static str {
	match error.status.as_deref() {
		Some("INVALID_ARGUMENT") | Some("FAILED_PRECONDITION") => "invalid_request_error",
		Some("NOT_FOUND") => "not_found_error",
		Some("PERMISSION_DENIED") | Some("UNAUTHENTICATED") => "authentication_error",
		Some("RESOURCE_EXHAUSTED") => "rate_limit_error",
		_ => "api_error",
	}
}

pub mod from_messages {
	use crate::{WireError, types};
	use arcstr as strng;
	use itertools::Itertools;
	use messages::{ToolResultContent, ToolResultContentPart};
	use types::completions::typed as completions;
	use types::messages::typed as messages;
	pub fn translate(req: &types::messages::Request) -> Result<Vec<u8>, WireError> {
		let typed =
			crate::types::convert::<_, messages::Request>(req).map_err(WireError::RequestMarshal)?;
		let xlated = translate_internal(typed);
		serde_json::to_vec(&xlated).map_err(WireError::RequestMarshal)
	}

	/// Convert an Anthropic image source JSON value into an OpenAI-compatible URL string.
	/// Base64 sources become `data:` URIs; URL sources pass through directly.
	fn anthropic_source_to_url(source: &serde_json::Value) -> Option<String> {
		let source_type = source.get("type")?.as_str()?;
		match source_type {
			"base64" => {
				let media_type = source.get("media_type")?.as_str()?;
				let data = source.get("data")?.as_str()?;
				Some(format!("data:{media_type};base64,{data}"))
			},
			"url" => {
				let url = source.get("url")?.as_str()?;
				Some(url.to_string())
			},
			_ => None,
		}
	}

	fn system_message_text(content: Vec<messages::ContentBlock>) -> Option<String> {
		let text = content
			.into_iter()
			.filter_map(|block| match block {
				messages::ContentBlock::Text(messages::ContentTextBlock { text, .. }) => Some(text),
				_ => None,
			})
			.collect::<Vec<_>>()
			.join("\n");

		(!text.is_empty()).then_some(text)
	}

	#[allow(deprecated)]
	fn translate_internal(req: messages::Request) -> completions::Request {
		let messages::Request {
			messages,
			system,
			model,
			max_tokens,
			stop_sequences,
			stream,
			temperature,
			top_p,
			top_k: _,
			tools,
			tool_choice,
			metadata,
			thinking,
			output_config,
		} = req;

		let adaptive_thinking_requested = thinking
			.as_ref()
			.is_some_and(|t| matches!(t, messages::ThinkingInput::Adaptive {}));
		let output_effort = output_config.as_ref().and_then(|cfg| cfg.effort);
		let reasoning_effort = if adaptive_thinking_requested {
			Some(match output_effort {
				Some(messages::ThinkingEffort::Low) => completions::ReasoningEffort::Low,
				Some(messages::ThinkingEffort::Medium) => completions::ReasoningEffort::Medium,
				Some(messages::ThinkingEffort::High) => completions::ReasoningEffort::High,
				Some(messages::ThinkingEffort::Xhigh | messages::ThinkingEffort::Max) => {
					completions::ReasoningEffort::Xhigh
				},
				// Anthropic adaptive thinking defaults to high effort when omitted.
				None => completions::ReasoningEffort::High,
			})
		} else {
			None
		};
		let response_format = output_config
			.as_ref()
			.and_then(|cfg| cfg.format.as_ref())
			.map(|format| match format {
				messages::OutputFormat::JsonSchema { schema } => completions::ResponseFormat::JsonSchema {
					json_schema: completions::ResponseFormatJsonSchema {
						description: None,
						name: "structured_output".to_string(),
						schema: schema.clone(),
						strict: None,
					},
				},
			});

		let mut msgs: Vec<completions::RequestMessage> = Vec::new();

		// Handle the system prompt (convert both string and block formats to string)
		if let Some(system) = system {
			let system_text = match system {
				messages::SystemPrompt::Text(text) => text,
				messages::SystemPrompt::Blocks(blocks) => blocks
					.into_iter()
					.map(|block| match block {
						messages::SystemContentBlock::Text { text, .. } => text,
					})
					.collect::<Vec<_>>()
					.join("\n"),
			};
			msgs.push(completions::RequestMessage::System(
				completions::RequestSystemMessage {
					content: completions::RequestSystemMessageContent::Text(system_text),
					name: None,
				},
			));
		}

		// Convert messages from Anthropic to universal format
		for msg in messages {
			match msg.role {
				messages::Role::User => {
					let mut parts: Vec<completions::RequestUserMessageContentPart> = Vec::new();

					for block in msg.content {
						match block {
							messages::ContentBlock::Text(messages::ContentTextBlock { text, .. }) => {
								parts.push(completions::RequestUserMessageContentPart::Text(
									completions::RequestMessageContentPartText { text },
								));
							},
							messages::ContentBlock::Image(messages::ContentImageBlock { source, .. }) => {
								if let Some(url) = anthropic_source_to_url(&source) {
									parts.push(completions::RequestUserMessageContentPart::ImageUrl(
										completions::RequestMessageContentPartImage {
											image_url: completions::ImageUrl { url, detail: None },
										},
									));
								}
							},
							messages::ContentBlock::ToolResult {
								tool_use_id,
								content,
								..
							} => {
								let tool_content = match content {
									ToolResultContent::Text(t) => completions::RequestToolMessageContent::Text(t),
									ToolResultContent::Array(arr) => completions::RequestToolMessageContent::Array(
										arr
											.into_iter()
											.filter_map(|p| match p {
												ToolResultContentPart::Text { text, .. } => {
													Some(completions::RequestToolMessageContentPart::Text(
														completions::RequestMessageContentPartText { text },
													))
												},
												_ => None,
											})
											.collect_vec(),
									),
								};
								msgs.push(completions::RequestMessage::Tool(
									completions::RequestToolMessage {
										content: tool_content,
										tool_call_id: tool_use_id,
									},
								));
							},
							messages::ContentBlock::ServerToolUse { .. }
							| messages::ContentBlock::ToolUse { .. } => {},
							_ => {},
						}
					}

					if !parts.is_empty() {
						msgs.push(completions::RequestMessage::User(
							completions::RequestUserMessage {
								content: completions::RequestUserMessageContent::Array(parts),
								name: None,
							},
						));
					}
				},
				messages::Role::Assistant => {
					let mut assistant_text = String::new();
					let mut tool_calls: Vec<completions::MessageToolCalls> = Vec::new();
					for block in msg.content {
						match block {
							messages::ContentBlock::Text(messages::ContentTextBlock { text, .. }) => {
								if !assistant_text.is_empty() {
									assistant_text.push('\n');
								}
								assistant_text.push_str(&text);
							},
							messages::ContentBlock::ToolUse {
								id, name, input, ..
							} => {
								tool_calls.push(completions::MessageToolCalls::Function(
									completions::MessageToolCall {
										id,
										function: completions::FunctionCall {
											name,
											arguments: serde_json::to_string(&input).unwrap_or_default(),
										},
									},
								));
							},
							messages::ContentBlock::Thinking { .. } => {
								// TODO
							},
							messages::ContentBlock::RedactedThinking { .. } => {
								// TODO
							},
							_ => {},
						}
					}
					if !assistant_text.is_empty() || !tool_calls.is_empty() {
						msgs.push(completions::RequestMessage::Assistant(
							completions::RequestAssistantMessage {
								content: if assistant_text.is_empty() {
									None
								} else {
									Some(completions::RequestAssistantMessageContent::Text(
										assistant_text,
									))
								},
								name: None,
								tool_calls: if tool_calls.is_empty() {
									None
								} else {
									Some(tool_calls)
								},
								refusal: None,
								audio: None,
								function_call: None,
								reasoning_content: None,
								reasoning_signature: None,
							},
						));
					}
				},
				messages::Role::System => {
					if let Some(text) = system_message_text(msg.content) {
						msgs.push(completions::RequestMessage::System(
							completions::RequestSystemMessage {
								content: completions::RequestSystemMessageContent::Text(text),
								name: None,
							},
						));
					}
				},
			}
		}

		let tools: Vec<completions::Tool> = tools
			.into_iter()
			.flat_map(|tools| tools.into_iter())
			.map(|tool| {
				completions::Tool::Function(completions::FunctionTool {
					function: completions::FunctionObject {
						name: tool.name,
						description: tool.description,
						parameters: Some(tool.input_schema),
						strict: None,
					},
				})
			})
			.collect_vec();

		// "Function tools with reasoning_effort are not supported for gpt-5.4
		let reasoning_effort = if !tools.is_empty() && model.starts_with("gpt-5.4") {
			None
		} else {
			reasoning_effort
		};

		let mut parallel_tool_calls = None;
		let tool_choice = tool_choice.map(|choice| match choice {
			messages::ToolChoice::Auto {
				disable_parallel_tool_use,
			} => {
				parallel_tool_calls = disable_parallel_tool_use.map(|d| !d);
				completions::ToolChoiceOption::Mode(completions::ToolChoiceOptions::Auto)
			},
			messages::ToolChoice::Any {
				disable_parallel_tool_use,
			} => {
				parallel_tool_calls = disable_parallel_tool_use.map(|d| !d);
				completions::ToolChoiceOption::Mode(completions::ToolChoiceOptions::Required)
			},
			messages::ToolChoice::Tool {
				name,
				disable_parallel_tool_use,
			} => {
				parallel_tool_calls = disable_parallel_tool_use.map(|d| !d);
				completions::ToolChoiceOption::Function(completions::NamedToolChoice {
					function: completions::FunctionName { name },
				})
			},
			messages::ToolChoice::None {} => {
				completions::ToolChoiceOption::Mode(completions::ToolChoiceOptions::None)
			},
		});

		// Preserve the common `user_id` field when mapping Messages -> OpenAI chat completions.
		// The rest of `messages.metadata` is handled only on provider-native Messages paths.
		// Forwarding it here breaks OpenAI-compatible backends because `metadata` requires `store=true`,
		// which agentgateway does not set on this path.
		let user_id = metadata
			.as_ref()
			.and_then(|m| m.fields.get("user_id").cloned());

		let stop = if stop_sequences.is_empty() {
			None
		} else {
			Some(completions::Stop::StringArray(stop_sequences))
		};

		completions::Request {
			model: Some(model),
			messages: msgs,
			stream: Some(stream),
			temperature,
			top_p,
			max_completion_tokens: Some(max_tokens as u32),
			max_tokens: None,
			stop,
			tools: if tools.is_empty() { None } else { Some(tools) },
			tool_choice,
			user: user_id,
			// Internal vendor extensions are only for completions-originated requests.
			// messages -> completions should emit OpenAI-compatible payloads only.
			vendor_extensions: completions::RequestVendorExtensions::default(),
			stream_options: if stream {
				Some(completions::StreamOptions {
					include_usage: Some(true),
					include_obfuscation: None,
				})
			} else {
				None
			},
			frequency_penalty: None,
			presence_penalty: None,
			seed: None,
			// Fields not applicable from Anthropic Messages
			store: None,
			reasoning_effort,
			metadata: None,
			logit_bias: None,
			logprobs: None,
			top_logprobs: None,
			n: None,
			modalities: None,
			prediction: None,
			audio: None,
			response_format,
			#[allow(deprecated)]
			function_call: None,
			#[allow(deprecated)]
			functions: None,
			service_tier: None,
			parallel_tool_calls,
			web_search_options: None,
		}
	}

	fn translate_response_internal(
		resp: completions::Response,
	) -> Result<messages::MessagesResponse, WireError> {
		let completions::Response {
			id,
			choices,
			model,
			usage,
			service_tier,
			..
		} = resp;
		// Anthropic only supports one choice
		let choice = choices.into_iter().next().ok_or_else(|| {
			WireError::InvalidResponse(strng::literal!("chat response missing choices"))
		})?;

		let mut content: Vec<messages::ContentBlock> = Vec::new();
		if let Some(text) = choice.message.content {
			content.push(messages::ContentBlock::Text(messages::ContentTextBlock {
				text,
				citations: None,
				cache_control: None,
			}));
		}
		if let Some(tool_calls) = choice.message.tool_calls {
			content.extend(tool_calls.into_iter().filter_map(|tc| match tc {
				completions::MessageToolCalls::Function(f) => {
					let input =
						serde_json::from_str::<serde_json::Value>(&f.function.arguments).unwrap_or_default();
					Some(messages::ContentBlock::ToolUse {
						id: f.id,
						name: f.function.name,
						input,
						cache_control: None,
					})
				},
				completions::MessageToolCalls::Custom(_) => None,
			}));
		}

		let stop_reason = choice
			.finish_reason
			.map(|r| match r {
				completions::FinishReason::Stop => messages::StopReason::EndTurn,
				completions::FinishReason::Length => messages::StopReason::MaxTokens,
				completions::FinishReason::ToolCalls => messages::StopReason::ToolUse,
				completions::FinishReason::ContentFilter => messages::StopReason::EndTurn,
				completions::FinishReason::FunctionCall => messages::StopReason::ToolUse,
			})
			.unwrap_or(messages::StopReason::EndTurn);

		Ok(messages::MessagesResponse {
			id,
			r#type: "message".to_string(),
			role: messages::Role::Assistant,
			model,
			stop_reason: Some(stop_reason),
			stop_sequence: None,
			usage: messages::Usage {
				input_tokens: usage
					.as_ref()
					.map(|u| u.prompt_tokens as usize)
					.unwrap_or(0),
				output_tokens: usage
					.as_ref()
					.map(|u| u.completion_tokens as usize)
					.unwrap_or(0),
				cache_creation_input_tokens: None,
				cache_read_input_tokens: None,
				service_tier,
			},
			input_audio_tokens: usage.as_ref().and_then(|u| {
				u.prompt_tokens_details
					.as_ref()
					.and_then(|d| d.audio_tokens)
					.map(|t| t as usize)
			}),
			output_audio_tokens: usage.as_ref().and_then(|u| {
				u.completion_tokens_details
					.as_ref()
					.and_then(|d| d.audio_tokens)
					.map(|t| t as usize)
			}),
			content,
		})
	}

	pub fn translate_response(bytes: &[u8]) -> Result<messages::MessagesResponse, WireError> {
		let resp =
			serde_json::from_slice::<completions::Response>(bytes).map_err(WireError::ResponseParsing)?;
		let anthropic = translate_response_internal(resp)?;
		Ok(anthropic)
	}
}
