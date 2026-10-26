pub mod from_completions {
	use crate::types::completions::typed::UsagePromptDetails;

	pub fn translate_response(resp: messages::MessagesResponse) -> completions::Response {
		// Convert Anthropic content blocks to OpenAI message content
		let mut tool_calls: Vec<completions::MessageToolCalls> = Vec::new();
		let mut content = None;
		let mut reasoning_content = None;
		for block in resp.content {
			match block {
				messages::ContentBlock::Text(messages::ContentTextBlock { text, .. }) => {
					// A message may contain multiple text blocks (e.g. text split around
					// citations); concatenate them into the single OpenAI `content` field.
					content.get_or_insert_with(String::new).push_str(&text)
				},
				messages::ContentBlock::ToolUse {
					id, name, input, ..
				}
				| messages::ContentBlock::ServerToolUse {
					id, name, input, ..
				} => {
					let Some(args) = serde_json::to_string(&input).ok() else {
						continue;
					};
					tool_calls.push(completions::MessageToolCalls::Function(
						completions::MessageToolCall {
							id: id.clone(),
							function: completions::FunctionCall {
								name: name.clone(),
								arguments: args,
							},
						},
					));
				},
				messages::ContentBlock::ToolResult { .. } => {
					// Should be on the request path, not the response path
					continue;
				},
				// For now we ignore Redacted and signature think through a better approach as this may be needed
				messages::ContentBlock::Thinking { thinking, .. } => {
					reasoning_content = Some(thinking);
				},
				messages::ContentBlock::RedactedThinking { .. } => {},

				// not currently supported
				messages::ContentBlock::Image { .. } => continue,
				messages::ContentBlock::Document(_) => continue,
				messages::ContentBlock::SearchResult(_) => continue,
				messages::ContentBlock::WebSearchToolResult { .. } => continue,
				messages::ContentBlock::Unknown => continue,
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
			reasoning_content,
			reasoning_signature: None,
			extra: None,
		};
		let finish_reason = resp
			.stop_reason
			.as_ref()
			.map(crate::streaming::messages::translate_stop_reason);
		// Only one choice for anthropic
		let choice = completions::ChatChoice {
			index: 0,
			message,
			finish_reason,
			logprobs: None,
		};

		let choices = vec![choice];
		// Convert usage from Anthropic format to OpenAI format
		let usage = completions::Usage {
			prompt_tokens: resp.usage.input_tokens as u32,
			completion_tokens: resp.usage.output_tokens as u32,
			total_tokens: (resp.usage.input_tokens + resp.usage.output_tokens) as u32,
			cache_read_input_tokens: resp.usage.cache_read_input_tokens.map(|i| i as u64),
			prompt_tokens_details: resp
				.usage
				.cache_read_input_tokens
				.map(|i| UsagePromptDetails {
					cached_tokens: Some(i as u64),
					audio_tokens: None,
					rest: Default::default(),
				}),
			cache_creation_input_tokens: resp.usage.cache_creation_input_tokens.map(|i| i as u64),

			completion_tokens_details: None,
		};

		completions::Response {
			id: resp.id,
			object: "chat.completion".to_string(),
			// No date in anthropic response so just call it "now"
			created: 0,
			model: resp.model,
			choices,
			usage: Some(usage),
			service_tier: resp.usage.service_tier,
			system_fingerprint: None,
		}
	}

	use crate::conversion::completions::{extract_system_text, parse_data_url};
	use crate::{WireError, types};
	use std::collections::HashMap;
	use types::completions::typed as completions;
	use types::messages::typed as messages;
	fn user_content_to_messages(
		content: &completions::RequestUserMessageContent,
	) -> Vec<messages::ContentBlock> {
		let mut out = Vec::new();
		match content {
			completions::RequestUserMessageContent::Text(text) => {
				if !text.trim().is_empty() {
					out.push(messages::ContentBlock::Text(messages::ContentTextBlock {
						text: text.clone(),
						citations: None,
						cache_control: None,
					}));
				}
			},
			completions::RequestUserMessageContent::Array(parts) => {
				for part in parts {
					match part {
						completions::RequestUserMessageContentPart::Text(text) => {
							if !text.text.trim().is_empty() {
								out.push(messages::ContentBlock::Text(messages::ContentTextBlock {
									text: text.text.clone(),
									citations: None,
									cache_control: None,
								}));
							}
						},
						completions::RequestUserMessageContentPart::ImageUrl(image) => {
							let source = if let Some((media_type, data)) = parse_data_url(&image.image_url.url) {
								serde_json::json!({
									"type": "base64",
									"media_type": media_type,
									"data": data
								})
							} else {
								serde_json::json!({
									"type": "url",
									"url": image.image_url.url
								})
							};
							out.push(messages::ContentBlock::Image(messages::ContentImageBlock {
								source,
								cache_control: None,
							}));
						},
						completions::RequestUserMessageContentPart::InputAudio(_)
						| completions::RequestUserMessageContentPart::File(_) => {},
					}
				}
			},
		}
		out
	}

	fn assistant_content_to_messages(
		msg: &completions::RequestAssistantMessage,
	) -> Vec<messages::ContentBlock> {
		let mut out = Vec::new();
		if let Some(content) = &msg.content {
			match content {
				completions::RequestAssistantMessageContent::Text(text) => {
					if !text.trim().is_empty() {
						out.push(messages::ContentBlock::Text(messages::ContentTextBlock {
							text: text.clone(),
							citations: None,
							cache_control: None,
						}));
					}
				},
				completions::RequestAssistantMessageContent::Array(parts) => {
					for part in parts {
						match part {
							completions::RequestAssistantMessageContentPart::Text(text) => {
								if !text.text.trim().is_empty() {
									out.push(messages::ContentBlock::Text(messages::ContentTextBlock {
										text: text.text.clone(),
										citations: None,
										cache_control: None,
									}));
								}
							},
							completions::RequestAssistantMessageContentPart::Refusal(refusal) => {
								if !refusal.refusal.trim().is_empty() {
									out.push(messages::ContentBlock::Text(messages::ContentTextBlock {
										text: refusal.refusal.clone(),
										citations: None,
										cache_control: None,
									}));
								}
							},
						}
					}
				},
			}
		}
		if let Some(refusal) = &msg.refusal
			&& !refusal.trim().is_empty()
		{
			out.push(messages::ContentBlock::Text(messages::ContentTextBlock {
				text: refusal.clone(),
				citations: None,
				cache_control: None,
			}));
		}
		if let Some(tool_calls) = &msg.tool_calls {
			for tool_call in tool_calls {
				match tool_call {
					completions::MessageToolCalls::Function(call) => {
						let input = serde_json::from_str::<serde_json::Value>(&call.function.arguments)
							.unwrap_or_else(|_| serde_json::Value::String(call.function.arguments.clone()));
						out.push(messages::ContentBlock::ToolUse {
							id: call.id.clone(),
							name: call.function.name.clone(),
							input,
							cache_control: None,
						});
					},
					completions::MessageToolCalls::Custom(call) => {
						let input = serde_json::from_str::<serde_json::Value>(&call.custom_tool.input)
							.unwrap_or_else(|_| serde_json::Value::String(call.custom_tool.input.clone()));
						out.push(messages::ContentBlock::ToolUse {
							id: call.id.clone(),
							name: call.custom_tool.name.clone(),
							input,
							cache_control: None,
						});
					},
				}
			}
		}
		out
	}

	fn tool_content_to_messages(
		content: &completions::RequestToolMessageContent,
	) -> messages::ToolResultContent {
		match content {
			completions::RequestToolMessageContent::Text(text) => {
				messages::ToolResultContent::Text(text.clone())
			},
			completions::RequestToolMessageContent::Array(parts) => {
				let parts = parts
					.iter()
					.map(|part| match part {
						completions::RequestToolMessageContentPart::Text(text) => {
							messages::ToolResultContentPart::Text {
								text: text.text.clone(),
								citations: None,
								cache_control: None,
							}
						},
					})
					.collect();
				messages::ToolResultContent::Array(parts)
			},
		}
	}

	pub fn translate(req: &types::completions::Request) -> Result<Vec<u8>, WireError> {
		let typed =
			crate::types::convert::<_, completions::Request>(req).map_err(WireError::RequestMarshal)?;
		let model_id = typed.model.clone().unwrap_or_default();
		let xlated = translate_internal(typed, model_id);
		serde_json::to_vec(&xlated).map_err(WireError::RequestMarshal)
	}

	fn translate_internal(req: completions::Request, model_id: String) -> messages::Request {
		let max_tokens = req.max_tokens();
		let stop_sequences = req.stop_sequence();
		// Anthropic has all system prompts in a single field. Join them
		let system = req
			.messages
			.iter()
			.filter_map(extract_system_text)
			.collect::<Vec<String>>()
			.join("\n");

		// Convert messages to Anthropic format
		let messages = req
			.messages
			.iter()
			.filter_map(|msg| {
				let (role, content) = match msg {
					completions::RequestMessage::System(_) | completions::RequestMessage::Developer(_) => {
						return None;
					},
					completions::RequestMessage::User(user) => (
						messages::Role::User,
						user_content_to_messages(&user.content),
					),
					completions::RequestMessage::Assistant(assistant) => (
						messages::Role::Assistant,
						assistant_content_to_messages(assistant),
					),
					completions::RequestMessage::Tool(tool) => (
						messages::Role::User,
						vec![messages::ContentBlock::ToolResult {
							tool_use_id: tool.tool_call_id.clone(),
							content: tool_content_to_messages(&tool.content),
							cache_control: None,
							is_error: None,
						}],
					),
					completions::RequestMessage::Function(function) => {
						let mut blocks = Vec::new();
						if let Some(text) = &function.content
							&& !text.trim().is_empty()
						{
							blocks.push(messages::ContentBlock::Text(messages::ContentTextBlock {
								text: text.clone(),
								citations: None,
								cache_control: None,
							}));
						}
						(messages::Role::User, blocks)
					},
				};
				if content.is_empty() {
					None
				} else {
					Some(messages::Message { role, content })
				}
			})
			.collect();

		let tools = if let Some(tools) = req.tools {
			let mapped_tools: Vec<_> = tools
				.iter()
				.filter_map(|tool| match tool {
					completions::Tool::Function(function_tool) => Some(messages::Tool {
						name: function_tool.function.name.clone(),
						description: function_tool.function.description.clone(),
						input_schema: function_tool
							.function
							.parameters
							.clone()
							.unwrap_or_default(),
						cache_control: None,
					}),
					_ => None,
				})
				.collect();
			Some(mapped_tools)
		} else {
			None
		};
		let metadata = req.user.map(|user| messages::Metadata {
			fields: HashMap::from([("user_id".to_string(), user)]),
		});

		let disable_parallel_tool_use = req.parallel_tool_calls.map(|p| !p);
		let has_tools = tools.as_ref().is_some_and(|tools| !tools.is_empty());
		let tool_choice = match req.tool_choice {
			Some(completions::ToolChoiceOption::Function(completions::NamedToolChoice { function })) => {
				Some(messages::ToolChoice::Tool {
					name: function.name,
					disable_parallel_tool_use,
				})
			},
			Some(completions::ToolChoiceOption::Mode(completions::ToolChoiceOptions::Auto)) => {
				Some(messages::ToolChoice::Auto {
					disable_parallel_tool_use,
				})
			},
			Some(completions::ToolChoiceOption::Mode(completions::ToolChoiceOptions::Required)) => {
				Some(messages::ToolChoice::Any {
					disable_parallel_tool_use,
				})
			},
			Some(completions::ToolChoiceOption::Mode(completions::ToolChoiceOptions::None)) => {
				Some(messages::ToolChoice::None {})
			},
			None if disable_parallel_tool_use.is_some() && has_tools => {
				Some(messages::ToolChoice::Auto {
					disable_parallel_tool_use,
				})
			},
			_ => None,
		};
		let explicit_thinking_budget = req.vendor_extensions.thinking_budget_tokens;
		let thinking = if let Some(budget_tokens) = explicit_thinking_budget {
			Some(messages::ThinkingInput::Enabled { budget_tokens })
		} else {
			req
				.reasoning_effort
				.as_ref()
				.and_then(reasoning_effort_to_enabled_budget)
				.map(|budget_tokens| messages::ThinkingInput::Enabled { budget_tokens })
		};

		let response_format = match req.response_format {
			Some(completions::ResponseFormat::JsonSchema { json_schema }) => {
				Some(messages::OutputFormat::JsonSchema {
					schema: json_schema.schema,
				})
			},
			Some(completions::ResponseFormat::JsonObject) => Some(messages::OutputFormat::JsonSchema {
				schema: serde_json::json!({
					"type": "object",
					"additionalProperties": true
				}),
			}),
			Some(completions::ResponseFormat::Text) | None => None,
		};
		let output_config = if response_format.is_some() {
			Some(messages::OutputConfig {
				effort: None,
				format: response_format,
			})
		} else {
			None
		};
		messages::Request {
			messages,
			system: if system.is_empty() {
				None
			} else {
				Some(messages::SystemPrompt::Text(system))
			},
			model: model_id,
			max_tokens,
			stop_sequences,
			stream: req.stream.unwrap_or(false),
			temperature: req.temperature,
			top_p: req.top_p,
			top_k: None, // OpenAI doesn't have top_k
			tools,
			tool_choice,
			metadata,
			thinking,
			output_config,
		}
	}

	fn reasoning_effort_to_enabled_budget(effort: &completions::ReasoningEffort) -> Option<u64> {
		match effort {
			completions::ReasoningEffort::None => None,
			completions::ReasoningEffort::Minimal | completions::ReasoningEffort::Low => Some(1024),
			completions::ReasoningEffort::Medium => Some(2048),
			completions::ReasoningEffort::High | completions::ReasoningEffort::Xhigh => Some(4096),
		}
	}
}
