//! Pure Converse request builders. Ambient beta policy remains a Host input.
use crate::provider::bedrock::BedrockToolNameMap;
use crate::provider::request::EncodedRequest as BedrockRequest;
#[derive(Debug, Clone, Copy)]
pub struct ConverseOptions<'a> {
	pub guardrail_identifier: Option<&'a str>,
	pub guardrail_version: Option<&'a str>,
	pub allowed_beta_headers: &'a [String],
}
pub use crate::provider::PromptCachingConfig;

mod helpers {
	pub use crate::provider::bedrock::{extract_flat_metadata, supports_prompt_caching};
	use crate::{WireError as AIError, types::bedrock};
	use std::collections::HashMap;
	pub fn create_cache_point() -> bedrock::CachePointBlock {
		bedrock::CachePointBlock {
			r#type: bedrock::CachePointType::Default,
		}
	}
	pub fn estimate_system_tokens(system: &[bedrock::SystemContentBlock]) -> usize {
		let word_count: usize = system
			.iter()
			.filter_map(|block| match block {
				bedrock::SystemContentBlock::Text { text } => Some(text.split_whitespace().count()),
				bedrock::SystemContentBlock::CachePoint { .. } => None,
			})
			.sum();
		(word_count * 13) / 10
	}
	pub fn insert_message_cache_point(messages: &mut [bedrock::Message], offset: usize) {
		// Strategy: Cache everything BEFORE the last message (not including it)
		// This caches the conversation history but not the current turn's input
		//
		// Example:
		//   [User: "Hello", Assistant: "Hi", User: "How are you?"]
		//   Cache point goes after "Hi" (before current "How are you?")
		//
		// This way:
		//   - Conversation history: cached (cheap reads on subsequent turns)
		//   - Current input: full price (it's new each turn anyway)
		//
		// The `offset` parameter shifts the cache point further back:
		//   offset 0 → second-to-last message (default)
		//   offset N → N additional messages back from default, clamped to bounds

		let len = messages.len();

		// If we have 0-1 messages, no point caching (nothing to reuse yet)
		if len < 2 {
			return;
		}

		// Clamp so the index never goes below 0
		let target_idx = (len - 2).saturating_sub(offset);
		messages[target_idx]
			.content
			.push(bedrock::ContentBlock::CachePoint(create_cache_point()));
	}
	pub fn extract_metadata_from_headers(
		headers: Option<&http::HeaderMap>,
	) -> Option<HashMap<String, String>> {
		const BEDROCK_METADATA_HEADER: &str = "x-bedrock-metadata";

		let header_value = headers?.get(BEDROCK_METADATA_HEADER)?;
		let json_str = header_value.to_str().ok()?;
		let json = serde_json::from_str::<serde_json::Value>(json_str).ok()?;
		Some(extract_flat_metadata(&json))
	}
	pub fn extract_beta_headers_with_allowed(
		headers: &http::HeaderMap,
		allowed_beta_headers: &[String],
	) -> Result<Option<Vec<serde_json::Value>>, AIError> {
		let mut beta_features = Vec::new();

		// Collect all anthropic-beta header values
		for value in headers.get_all("anthropic-beta") {
			let header_str = value
				.to_str()
				.map_err(|_| AIError::MissingField("Invalid anthropic-beta header value".into()))?;

			// Handle comma-separated values within a single header
			for feature in header_str.split(',') {
				let trimmed = feature.trim();
				if allowed_beta_headers
					.iter()
					.any(|feature| feature == trimmed)
				{
					// Add each beta feature as a string value in the array
					beta_features.push(serde_json::Value::String(trimmed.to_string()));
				}
			}
		}

		if beta_features.is_empty() {
			Ok(None)
		} else {
			Ok(Some(beta_features))
		}
	}
	pub fn push_or_merge_message(messages: &mut Vec<bedrock::Message>, msg: bedrock::Message) {
		if let Some(last) = messages.last_mut()
			&& last.role == msg.role
		{
			last.content.extend(msg.content);
		} else {
			messages.push(msg);
		}
	}
}

pub mod from_completions {
	use super::helpers;
	use crate::conversion::completions::{extract_system_text, parse_data_url};
	use crate::types as json;
	use crate::types::bedrock;
	use crate::{WireError as AIError, types};
	use itertools::Itertools;
	use types::completions::typed as completions;
	fn text_blocks_from_user_content(
		content: &completions::RequestUserMessageContent,
	) -> Vec<bedrock::ContentBlock> {
		let mut out = Vec::new();
		match content {
			completions::RequestUserMessageContent::Text(text) => {
				if !text.trim().is_empty() {
					out.push(bedrock::ContentBlock::Text(text.clone()));
				}
			},
			completions::RequestUserMessageContent::Array(parts) => {
				for part in parts {
					match part {
						completions::RequestUserMessageContentPart::Text(text) => {
							if !text.text.trim().is_empty() {
								out.push(bedrock::ContentBlock::Text(text.text.clone()));
							}
						},
						completions::RequestUserMessageContentPart::ImageUrl(image) => {
							if let Some((media_type, data)) = parse_data_url(&image.image_url.url) {
								let format = media_type
									.strip_prefix("image/")
									.unwrap_or(media_type)
									.to_string();
								out.push(bedrock::ContentBlock::Image(bedrock::ImageBlock {
									format,
									source: bedrock::ImageSource {
										bytes: data.to_string(),
									},
								}));
							}
						},
						completions::RequestUserMessageContentPart::InputAudio(_)
						| completions::RequestUserMessageContentPart::File(_) => {},
					}
				}
			},
		}
		out
	}

	fn assistant_content_to_bedrock(
		msg: &completions::RequestAssistantMessage,
		tool_name_map: &mut super::BedrockToolNameMap,
	) -> Vec<bedrock::ContentBlock> {
		let mut content = Vec::new();
		// Replay a previously-emitted thinking block first. Anthropic (via Bedrock Converse) requires
		// the reasoningContent block to precede the text/toolUse blocks of the same assistant turn,
		// and to carry the original cryptographic signature so Bedrock can validate it. Only replay
		// when a non-empty signature is present — Bedrock rejects an unsigned thinking block.
		if let Some(signature) = msg.reasoning_signature.as_deref().filter(|s| !s.is_empty()) {
			content.push(bedrock::ContentBlock::ReasoningContent(
				bedrock::ReasoningContentBlock::Structured {
					reasoning_text: bedrock::ReasoningText {
						text: msg.reasoning_content.clone().unwrap_or_default(),
						signature: Some(signature.to_string()),
					},
				},
			));
		}
		if let Some(content_field) = &msg.content {
			match content_field {
				completions::RequestAssistantMessageContent::Text(text) => {
					if !text.trim().is_empty() {
						content.push(bedrock::ContentBlock::Text(text.to_string()));
					}
				},
				completions::RequestAssistantMessageContent::Array(parts) => {
					for part in parts {
						match part {
							completions::RequestAssistantMessageContentPart::Text(text) => {
								if !text.text.trim().is_empty() {
									content.push(bedrock::ContentBlock::Text(text.text.clone()));
								}
							},
							completions::RequestAssistantMessageContentPart::Refusal(refusal) => {
								if !refusal.refusal.trim().is_empty() {
									content.push(bedrock::ContentBlock::Text(refusal.refusal.clone()));
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
			content.push(bedrock::ContentBlock::Text(refusal.clone()));
		}

		if let Some(tool_calls) = &msg.tool_calls {
			for call in tool_calls {
				match call {
					completions::MessageToolCalls::Function(call) => {
						let input = serde_json::from_str::<serde_json::Value>(&call.function.arguments)
							.unwrap_or_else(|_| serde_json::Value::String(call.function.arguments.clone()));
						content.push(bedrock::ContentBlock::ToolUse(bedrock::ToolUseBlock {
							tool_use_id: call.id.clone(),
							name: tool_name_map.register(&call.function.name),
							input,
						}));
					},
					completions::MessageToolCalls::Custom(call) => {
						let input = serde_json::from_str::<serde_json::Value>(&call.custom_tool.input)
							.unwrap_or_else(|_| serde_json::Value::String(call.custom_tool.input.clone()));
						content.push(bedrock::ContentBlock::ToolUse(bedrock::ToolUseBlock {
							tool_use_id: call.id.clone(),
							name: tool_name_map.register(&call.custom_tool.name),
							input,
						}));
					},
				}
			}
		}
		content
	}

	fn tool_content_to_bedrock(msg: &completions::RequestToolMessage) -> Vec<bedrock::ContentBlock> {
		let content = match &msg.content {
			completions::RequestToolMessageContent::Text(text) => {
				vec![bedrock::ToolResultContentBlock::Text(text.to_string())]
			},
			completions::RequestToolMessageContent::Array(parts) => parts
				.iter()
				.map(|part| match part {
					completions::RequestToolMessageContentPart::Text(text) => {
						bedrock::ToolResultContentBlock::Text(text.text.clone())
					},
				})
				.collect(),
		};
		if content.is_empty() {
			return Vec::new();
		}
		vec![bedrock::ContentBlock::ToolResult(
			bedrock::ToolResultBlock {
				tool_use_id: msg.tool_call_id.clone(),
				content,
				// OpenAI tool messages do not carry explicit success/error status.
				// Keep this unset rather than asserting success.
				status: None,
			},
		)]
	}

	/// translate an OpenAI completions request to a Bedrock converse  request
	pub fn translate(
		req: &types::completions::Request,
		provider: &super::ConverseOptions<'_>,
		headers: Option<&http::HeaderMap>,
		prompt_caching: Option<&super::PromptCachingConfig>,
	) -> Result<super::BedrockRequest, AIError> {
		let typed = json::convert::<_, completions::Request>(req).map_err(AIError::RequestParsing)?;
		let model_id = typed.model.clone().unwrap_or_default();
		let (xlated, tool_name_map) =
			translate_internal(typed, model_id, provider, headers, prompt_caching);
		let body = serde_json::to_vec(&xlated).map_err(AIError::RequestMarshal)?;
		Ok(super::BedrockRequest {
			body,
			tool_name_map,
		})
	}

	fn translate_internal(
		req: completions::Request,
		model_id: String,
		provider: &super::ConverseOptions<'_>,
		headers: Option<&http::HeaderMap>,
		prompt_caching: Option<&super::PromptCachingConfig>,
	) -> (bedrock::ConverseRequest, super::BedrockToolNameMap) {
		let mut tool_name_map = super::BedrockToolNameMap::default();
		for tool in req.tools.iter().flatten() {
			if let completions::Tool::Function(function_tool) = tool {
				tool_name_map.register(&function_tool.function.name);
			}
		}
		if let Some(completions::ToolChoiceOption::Function(completions::NamedToolChoice {
			function,
		})) = &req.tool_choice
		{
			tool_name_map.register(&function.name);
		}
		for msg in &req.messages {
			let completions::RequestMessage::Assistant(assistant) = msg else {
				continue;
			};
			for call in assistant
				.tool_calls
				.iter()
				.flat_map(|tool_calls| tool_calls.iter())
			{
				match call {
					completions::MessageToolCalls::Function(call) => {
						tool_name_map.register(&call.function.name);
					},
					completions::MessageToolCalls::Custom(call) => {
						tool_name_map.register(&call.custom_tool.name);
					},
				};
			}
		}
		// Extract and join system prompts from completions format
		let system_text = req
			.messages
			.iter()
			.filter_map(extract_system_text)
			.collect::<Vec<String>>()
			.join("\n");

		let inference_config = bedrock::InferenceConfiguration {
			max_tokens: req.max_tokens(),
			temperature: req.temperature,
			top_p: req.top_p,
			// Map Anthropic-style vendor extension to Bedrock topK when provided
			top_k: req.vendor_extensions.top_k,
			stop_sequences: req.stop_sequence(),
		};

		let tool_choice = match req.tool_choice {
			Some(completions::ToolChoiceOption::Function(completions::NamedToolChoice { function })) => {
				Some(bedrock::ToolChoice::Tool {
					name: tool_name_map.register(&function.name),
				})
			},
			Some(completions::ToolChoiceOption::Mode(completions::ToolChoiceOptions::Auto)) => {
				Some(bedrock::ToolChoice::Auto)
			},
			Some(completions::ToolChoiceOption::Mode(completions::ToolChoiceOptions::Required)) => {
				Some(bedrock::ToolChoice::Any)
			},
			Some(completions::ToolChoiceOption::Mode(completions::ToolChoiceOptions::None)) => None,
			_ => None,
		};
		let tools = req.tools.map(|tools| {
			tools
				.into_iter()
				.filter_map(|tool| match tool {
					completions::Tool::Function(function_tool) => {
						let tool_spec = bedrock::ToolSpecification {
							name: tool_name_map.register(&function_tool.function.name),
							description: function_tool.function.description,
							input_schema: function_tool
								.function
								.parameters
								.map(bedrock::ToolInputSchema::Json),
						};

						Some(bedrock::Tool::ToolSpec(tool_spec))
					},
					_ => None,
				})
				.collect_vec()
		});
		let tool_config = tools.map(|tools| bedrock::ToolConfiguration { tools, tool_choice });

		let messages = req
			.messages
			.iter()
			.filter_map(|msg| match msg {
				completions::RequestMessage::System(_) | completions::RequestMessage::Developer(_) => None,
				completions::RequestMessage::User(user) => {
					let content = text_blocks_from_user_content(&user.content);
					if content.is_empty() {
						None
					} else {
						Some(bedrock::Message {
							role: bedrock::Role::User,
							content,
						})
					}
				},
				completions::RequestMessage::Assistant(assistant) => {
					let content = assistant_content_to_bedrock(assistant, &mut tool_name_map);
					if content.is_empty() {
						None
					} else {
						Some(bedrock::Message {
							role: bedrock::Role::Assistant,
							content,
						})
					}
				},
				completions::RequestMessage::Tool(tool_result) => {
					let content = tool_content_to_bedrock(tool_result);
					if content.is_empty() {
						None
					} else {
						Some(bedrock::Message {
							role: bedrock::Role::User,
							content,
						})
					}
				},
				completions::RequestMessage::Function(function) => function
					.content
					.as_ref()
					.filter(|s| !s.trim().is_empty())
					.map(|s| bedrock::Message {
						role: bedrock::Role::User,
						content: vec![bedrock::ContentBlock::Text(s.clone())],
					}),
			})
			.fold(Vec::new(), |mut msgs, msg| {
				helpers::push_or_merge_message(&mut msgs, msg);
				msgs
			});

		// Build guardrail configuration if specified
		let guardrail_config = if let (Some(identifier), Some(version)) =
			(&provider.guardrail_identifier, &provider.guardrail_version)
		{
			Some(bedrock::GuardrailConfiguration {
				guardrail_identifier: identifier.to_string(),
				guardrail_version: version.to_string(),
				trace: Some("enabled".to_string()),
			})
		} else {
			None
		};

		// x-bedrock-metadata is an explicit Bedrock requestMetadata escape hatch. Forward it
		// unchanged so Bedrock, not the gateway, rejects operator-supplied invalid values.
		let metadata = super::helpers::extract_metadata_from_headers(headers).unwrap_or_default();
		let metadata = if metadata.is_empty() {
			None
		} else {
			Some(metadata)
		};

		let explicit_thinking_budget = req.vendor_extensions.thinking_budget_tokens;
		let enabled_thinking_budget = explicit_thinking_budget.or_else(|| {
			req
				.reasoning_effort
				.as_ref()
				.and_then(reasoning_effort_to_enabled_budget)
		});

		let additional_model_request_fields = enabled_thinking_budget.map(|budget| {
			serde_json::json!({
				"thinking": {
					"type": "enabled",
					"budget_tokens": budget
				}
			})
		});
		let output_config = req
			.response_format
			.as_ref()
			.and_then(completions_response_format_to_bedrock_output_config);

		let supports_caching = helpers::supports_prompt_caching(&model_id);
		let system_content = if system_text.is_empty() {
			None
		} else {
			let mut system_blocks = vec![bedrock::SystemContentBlock::Text { text: system_text }];

			if let Some(caching) = prompt_caching
				&& caching.cache_system
				&& supports_caching
			{
				let meets_minimum = if let Some(min_tokens) = caching.min_tokens {
					helpers::estimate_system_tokens(&system_blocks) >= min_tokens
				} else {
					true
				};
				if meets_minimum {
					system_blocks.push(bedrock::SystemContentBlock::CachePoint {
						cache_point: helpers::create_cache_point(),
					});
				}
			}
			Some(system_blocks)
		};

		let mut bedrock_request = bedrock::ConverseRequest {
			model_id,
			messages,
			system: system_content,
			inference_config: Some(inference_config),
			output_config,
			tool_config,
			guardrail_config,
			additional_model_request_fields,
			prompt_variables: None,
			additional_model_response_field_paths: None,
			request_metadata: metadata,
			performance_config: None,
		};
		if let Some(caching) = prompt_caching {
			if caching.cache_messages && supports_caching {
				helpers::insert_message_cache_point(
					&mut bedrock_request.messages,
					caching.cache_message_offset,
				);
			}
			if caching.cache_tools
				&& supports_caching
				&& let Some(ref mut tool_config) = bedrock_request.tool_config
				&& !tool_config.tools.is_empty()
			{
				tool_config
					.tools
					.push(bedrock::Tool::CachePoint(helpers::create_cache_point()));
			}
		}

		(bedrock_request, tool_name_map)
	}

	fn reasoning_effort_to_enabled_budget(effort: &completions::ReasoningEffort) -> Option<u64> {
		match effort {
			completions::ReasoningEffort::None => None,
			completions::ReasoningEffort::Minimal | completions::ReasoningEffort::Low => Some(1024),
			completions::ReasoningEffort::Medium => Some(2048),
			completions::ReasoningEffort::High | completions::ReasoningEffort::Xhigh => Some(4096),
		}
	}

	fn completions_response_format_to_bedrock_output_config(
		response_format: &completions::ResponseFormat,
	) -> Option<bedrock::OutputConfig> {
		let (name, description, schema) = match response_format {
			completions::ResponseFormat::Text => return None,
			completions::ResponseFormat::JsonObject => (
				None,
				None,
				std::borrow::Cow::Owned(
					serde_json::json!({ "type": "object", "additionalProperties": true }),
				),
			),
			completions::ResponseFormat::JsonSchema { json_schema } => (
				Some(json_schema.name.clone()),
				json_schema.description.clone(),
				std::borrow::Cow::Borrowed(&json_schema.schema),
			),
		};

		let Ok(schema_json) = serde_json::to_string(schema.as_ref()) else {
			return None;
		};

		Some(bedrock::OutputConfig {
			text_format: Some(bedrock::OutputFormat {
				r#type: bedrock::OutputFormatType::JsonSchema,
				structure: bedrock::OutputFormatStructure {
					json_schema: bedrock::JsonSchemaDefinition {
						schema: schema_json,
						name,
						description,
					},
				},
			}),
		})
	}
}

pub mod from_messages {
	use super::helpers;
	use crate::types as json;
	use crate::types::bedrock;
	use crate::{WireError as AIError, types};
	use arcstr as strng;
	use types::messages::typed as messages;
	pub fn translate(
		req: &types::messages::Request,
		provider: &super::ConverseOptions<'_>,
		headers: Option<&http::HeaderMap>,
	) -> Result<super::BedrockRequest, AIError> {
		let typed = json::convert::<_, messages::Request>(req).map_err(AIError::RequestParsing)?;
		let (xlated, tool_name_map) = translate_internal(typed, provider, headers)?;
		let body = serde_json::to_vec(&xlated).map_err(AIError::RequestMarshal)?;
		Ok(super::BedrockRequest {
			body,
			tool_name_map,
		})
	}

	fn translate_internal(
		req: messages::Request,
		provider: &super::ConverseOptions<'_>,
		headers: Option<&http::HeaderMap>,
	) -> Result<(bedrock::ConverseRequest, super::BedrockToolNameMap), AIError> {
		let mut tool_name_map = super::BedrockToolNameMap::default();
		for tool in req.tools.iter().flatten() {
			tool_name_map.register(&tool.name);
		}
		if let Some(messages::ToolChoice::Tool { name, .. }) = &req.tool_choice {
			tool_name_map.register(name);
		}
		for msg in &req.messages {
			for block in &msg.content {
				if let messages::ContentBlock::ToolUse { name, .. } = block {
					tool_name_map.register(name);
				}
			}
		}
		let mut cache_points_used = 0;
		// Converse placement note (AWS docs):
		// - Anthropic-specific params are sent via additionalModelRequestFields for Converse:
		//   https://docs.aws.amazon.com/bedrock/latest/userguide/conversation-inference-call.html
		//   https://docs.aws.amazon.com/bedrock/latest/APIReference/API_runtime_Converse.html
		// - Adaptive thinking knob is thinking.type = "adaptive":
		//   https://docs.aws.amazon.com/bedrock/latest/userguide/claude-messages-adaptive-thinking.html
		// - Effort knob is output_config.effort in Anthropic request shape:
		//   https://docs.aws.amazon.com/bedrock/latest/userguide/model-parameters-anthropic-claude-messages-request-response.html
		let requested_thinking = req.thinking.as_ref();
		let requested_output_config = req.output_config.as_ref();
		let output_config = requested_output_config
			.and_then(|cfg| cfg.format.as_ref())
			.and_then(messages_output_format_to_bedrock_output_config);
		let requested_output_config_json = requested_output_config.and_then(|cfg| {
			let mut output_config = serde_json::Map::new();
			if let Some(effort) = cfg.effort {
				output_config.insert("effort".to_string(), serde_json::json!(effort));
			}
			if output_config.is_empty() {
				// Preserve an explicitly empty output_config when present in the input request.
				if cfg.format.is_none() {
					Some(serde_json::Value::Object(output_config))
				} else {
					None
				}
			} else {
				Some(serde_json::Value::Object(output_config))
			}
		});

		// Bedrock applies strict inference/tool-choice constraints only to explicit extended thinking.
		let thinking_enabled = requested_thinking
			.is_some_and(|thinking| matches!(thinking, messages::ThinkingInput::Enabled { .. }));

		// Prepare typed tools before messages so definitions keep priority if a previous tool-use
		// name would otherwise collide. Cache points are inserted later in their original order.
		let pending_tool_config = if let Some(tools) = req.tools {
			let mut bedrock_tools = Vec::with_capacity(tools.len());
			for tool in tools {
				bedrock_tools.push((
					bedrock::Tool::ToolSpec(bedrock::ToolSpecification {
						name: tool_name_map.register(&tool.name),
						description: tool.description,
						input_schema: Some(bedrock::ToolInputSchema::Json(tool.input_schema)),
					}),
					tool.cache_control.is_some(),
				));
			}

			if bedrock_tools.is_empty() {
				None
			} else {
				let tool_choice = match req.tool_choice {
					Some(messages::ToolChoice::Auto { .. }) => {
						if thinking_enabled {
							Some(bedrock::ToolChoice::Any)
						} else {
							Some(bedrock::ToolChoice::Auto)
						}
					},
					Some(messages::ToolChoice::Any { .. }) => Some(bedrock::ToolChoice::Any),
					Some(messages::ToolChoice::Tool { name, .. }) => {
						if thinking_enabled {
							Some(bedrock::ToolChoice::Any)
						} else {
							Some(bedrock::ToolChoice::Tool {
								name: tool_name_map.register(&name),
							})
						}
					},
					Some(messages::ToolChoice::None {}) | None => {
						if thinking_enabled {
							Some(bedrock::ToolChoice::Any)
						} else {
							None
						}
					},
				};

				Some((bedrock_tools, tool_choice))
			}
		} else {
			None
		};

		// Convert system prompt to Bedrock format with cache point insertion
		// Note: Anthropic MessagesRequest.system is Option<SystemPrompt>, Bedrock wants Option<Vec<SystemContentBlock>>
		let mut system_content = req.system.as_ref().map(|sys| {
			let mut result = Vec::new();
			match sys {
				messages::SystemPrompt::Text(text) => {
					result.push(bedrock::SystemContentBlock::Text { text: text.clone() });
				},
				messages::SystemPrompt::Blocks(blocks) => {
					// Convert Anthropic system blocks to Bedrock system blocks with cache points
					for block in blocks {
						match block {
							messages::SystemContentBlock::Text {
								text,
								cache_control,
							} => {
								result.push(bedrock::SystemContentBlock::Text { text: text.clone() });
								// Insert cache point if this block has cache_control
								if cache_control.is_some() && cache_points_used < 4 {
									result.push(bedrock::SystemContentBlock::CachePoint {
										cache_point: helpers::create_cache_point(),
									});
									cache_points_used += 1;
								}
							},
						}
					}
				},
			}
			result
		});

		// Convert typed Anthropic messages to Bedrock messages
		let mut messages = Vec::new();
		for msg in req.messages {
			let role = match msg.role {
				messages::Role::Assistant => bedrock::Role::Assistant,
				messages::Role::User => bedrock::Role::User,
				messages::Role::System => {
					for block in msg.content {
						if let messages::ContentBlock::Text(messages::ContentTextBlock {
							text,
							cache_control,
							..
						}) = block
						{
							let system_content = system_content.get_or_insert_with(Vec::new);
							system_content.push(bedrock::SystemContentBlock::Text { text });
							if cache_control.is_some() && cache_points_used < 4 {
								system_content.push(bedrock::SystemContentBlock::CachePoint {
									cache_point: helpers::create_cache_point(),
								});
								cache_points_used += 1;
							}
						}
					}
					continue;
				},
			};

			// Convert ContentBlocks from Anthropic → Bedrock, inserting cache points
			let mut content = Vec::with_capacity(msg.content.len() * 2);
			for block in msg.content {
				let (bedrock_block, has_cache_control) = match block {
					messages::ContentBlock::Text(messages::ContentTextBlock {
						text,
						cache_control,
						..
					}) => (bedrock::ContentBlock::Text(text), cache_control.is_some()),
					messages::ContentBlock::Image(messages::ContentImageBlock {
						source,
						cache_control,
					}) => {
						if let Some(media_type) = source.get("media_type").and_then(|v| v.as_str())
							&& let Some(data) = source.get("data").and_then(|v| v.as_str())
						{
							let format = media_type
								.strip_prefix("image/")
								.unwrap_or(media_type)
								.to_string();
							(
								bedrock::ContentBlock::Image(bedrock::ImageBlock {
									format,
									source: bedrock::ImageSource {
										bytes: data.to_string(),
									},
								}),
								cache_control.is_some(),
							)
						} else {
							return Err(AIError::UnsupportedConversion(strng::literal!(
								"bedrock image source must be base64 (media_type + data); URL image sources are unsupported"
							)));
						}
					},
					messages::ContentBlock::ToolUse {
						id,
						name,
						input,
						cache_control,
					} => (
						bedrock::ContentBlock::ToolUse(bedrock::ToolUseBlock {
							tool_use_id: id,
							name: tool_name_map.register(&name),
							input,
						}),
						cache_control.is_some(),
					),
					messages::ContentBlock::ToolResult {
						tool_use_id,
						content: tool_content,
						is_error,
						cache_control,
					} => {
						let bedrock_content = match tool_content {
							messages::ToolResultContent::Text(text) => {
								vec![bedrock::ToolResultContentBlock::Text(text)]
							},
							messages::ToolResultContent::Array(parts) => parts
								.into_iter()
								.filter_map(|part| match part {
									messages::ToolResultContentPart::Text { text, .. } => {
										Some(bedrock::ToolResultContentBlock::Text(text))
									},
									messages::ToolResultContentPart::Image { source, .. } => {
										if let Some(media_type) = source.get("media_type").and_then(|v| v.as_str())
											&& let Some(data) = source.get("data").and_then(|v| v.as_str())
										{
											let format = media_type
												.strip_prefix("image/")
												.unwrap_or(media_type)
												.to_string();
											Some(bedrock::ToolResultContentBlock::Image(
												bedrock::ImageBlock {
													format,
													source: bedrock::ImageSource {
														bytes: data.to_string(),
													},
												},
											))
										} else {
											None
										}
									},
									_ => None,
								})
								.collect(),
						};

						let status = is_error.map(|is_err| match is_err {
							true => bedrock::ToolResultStatus::Error,
							false => bedrock::ToolResultStatus::Success,
						});

						(
							bedrock::ContentBlock::ToolResult(bedrock::ToolResultBlock {
								tool_use_id,
								content: bedrock_content,
								status,
							}),
							cache_control.is_some(),
						)
					},
					messages::ContentBlock::Thinking {
						thinking,
						signature,
					} => (
						bedrock::ContentBlock::ReasoningContent(bedrock::ReasoningContentBlock::Structured {
							reasoning_text: bedrock::ReasoningText {
								text: thinking,
								signature: Some(signature),
							},
						}),
						false,
					),
					messages::ContentBlock::WebSearchToolResult { .. } => continue,
					messages::ContentBlock::RedactedThinking { .. } => continue,
					messages::ContentBlock::Document(_) => continue,
					messages::ContentBlock::SearchResult(_) => continue,
					messages::ContentBlock::ServerToolUse { .. } => continue,
					messages::ContentBlock::Unknown => continue,
				};

				content.push(bedrock_block);

				if has_cache_control && cache_points_used < 4 {
					content.push(bedrock::ContentBlock::CachePoint(
						helpers::create_cache_point(),
					));
					cache_points_used += 1;
				}
			}

			messages.push(bedrock::Message { role, content });
		}

		// Build inference config from typed fields
		let inference_config = bedrock::InferenceConfiguration {
			max_tokens: req.max_tokens,
			// Extended thinking requires temperature/top_p/top_k to be unset.
			temperature: if thinking_enabled {
				None
			} else {
				req.temperature
			},
			top_p: if thinking_enabled { None } else { req.top_p },
			top_k: if thinking_enabled { None } else { req.top_k },
			stop_sequences: req.stop_sequences,
		};

		let tool_config = pending_tool_config.map(|(tools, tool_choice)| {
			let mut bedrock_tools = Vec::with_capacity(tools.len() * 2);
			for (tool, has_cache_control) in tools {
				bedrock_tools.push(tool);
				if has_cache_control && cache_points_used < 4 {
					bedrock_tools.push(bedrock::Tool::CachePoint(helpers::create_cache_point()));
					cache_points_used += 1;
				}
			}
			bedrock::ToolConfiguration {
				tools: bedrock_tools,
				tool_choice,
			}
		});

		// Build Anthropic model-specific fields under Converse's additionalModelRequestFields.
		let mut additional_fields = requested_thinking.map(|thinking| {
			let thinking_json = match thinking {
				messages::ThinkingInput::Enabled { budget_tokens } => serde_json::json!({
					"type": "enabled",
					"budget_tokens": budget_tokens
				}),
				messages::ThinkingInput::Disabled {} => serde_json::json!({
					"type": "disabled"
				}),
				messages::ThinkingInput::Adaptive {} => serde_json::json!({
					"type": "adaptive"
				}),
			};
			serde_json::json!({ "thinking": thinking_json })
		});
		let mut upsert_additional_field = |key: &str, value: serde_json::Value| {
			let fields =
				additional_fields.get_or_insert_with(|| serde_json::Value::Object(serde_json::Map::new()));
			fields
				.as_object_mut()
				.expect("additional model request fields must be a JSON object")
				.insert(key.to_string(), value);
		};

		// Preserve explicit output_config in Anthropic's model-specific envelope.
		if let Some(output_config) = requested_output_config_json {
			upsert_additional_field("output_config", output_config);
		}

		// Extract beta headers from HTTP headers if provided
		let beta_headers = headers.and_then(|h| {
			helpers::extract_beta_headers_with_allowed(h, provider.allowed_beta_headers)
				.ok()
				.flatten()
		});

		if let Some(beta_array) = beta_headers {
			// Add beta headers to additionalModelRequestFields.
			upsert_additional_field("anthropic_beta", serde_json::Value::Array(beta_array));
		}

		// Build guardrail configuration if provider has it configured
		let guardrail_config = if let (Some(identifier), Some(version)) =
			(&provider.guardrail_identifier, &provider.guardrail_version)
		{
			Some(bedrock::GuardrailConfiguration {
				guardrail_identifier: identifier.to_string(),
				guardrail_version: version.to_string(),
				trace: Some("enabled".to_string()),
			})
		} else {
			None
		};

		if let Some(metadata) = req.metadata.map(|m| m.fields)
			&& !metadata.is_empty()
		{
			// Anthropic metadata is opaque to Bedrock requestMetadata validation. Preserve it
			// in the Anthropic model request envelope instead of dropping provider-specific data.
			upsert_additional_field("metadata", serde_json::json!(metadata));
		}

		// x-bedrock-metadata is an explicit Bedrock requestMetadata escape hatch. Forward it
		// unchanged so Bedrock, not the gateway, rejects operator-supplied invalid values.
		let metadata = helpers::extract_metadata_from_headers(headers).unwrap_or_default();
		let metadata = if metadata.is_empty() {
			None
		} else {
			Some(metadata)
		};

		Ok((
			bedrock::ConverseRequest {
				model_id: req.model,
				messages,
				system: system_content,
				inference_config: Some(inference_config),
				output_config,
				tool_config,
				guardrail_config,
				additional_model_request_fields: additional_fields,
				prompt_variables: None,
				additional_model_response_field_paths: None,
				request_metadata: metadata,
				performance_config: None,
			},
			tool_name_map,
		))
	}

	fn messages_output_format_to_bedrock_output_config(
		format: &messages::OutputFormat,
	) -> Option<bedrock::OutputConfig> {
		let schema = match format {
			messages::OutputFormat::JsonSchema { schema } => schema,
		};
		let Ok(schema_json) = serde_json::to_string(schema) else {
			return None;
		};

		Some(bedrock::OutputConfig {
			text_format: Some(bedrock::OutputFormat {
				r#type: bedrock::OutputFormatType::JsonSchema,
				structure: bedrock::OutputFormatStructure {
					json_schema: bedrock::JsonSchemaDefinition {
						schema: schema_json,
						name: None,
						description: None,
					},
				},
			}),
		})
	}
}

pub mod from_responses {
	use super::helpers;
	use crate::types as json;
	use crate::types::bedrock;
	use crate::{WireError as AIError, types};
	use helpers::*;
	use types::responses::typed as responses;
	pub fn translate(
		req: &types::responses::Request,
		provider: &super::ConverseOptions<'_>,
		headers: Option<&http::HeaderMap>,
		prompt_caching: Option<&super::PromptCachingConfig>,
	) -> Result<super::BedrockRequest, AIError> {
		let typed =
			json::convert::<_, responses::CreateResponse>(req).map_err(AIError::RequestMarshal)?;
		let explicit_thinking_budget = extract_responses_thinking_budget_tokens(req);
		let model_id = typed.model.clone().unwrap_or_default();
		let (xlated, tool_name_map) = translate_internal(
			typed,
			explicit_thinking_budget,
			model_id,
			provider,
			headers,
			prompt_caching,
		);
		let body = serde_json::to_vec(&xlated).map_err(AIError::RequestMarshal)?;
		Ok(super::BedrockRequest {
			body,
			tool_name_map,
		})
	}

	fn translate_internal(
		req: responses::CreateResponse,
		explicit_thinking_budget: Option<u64>,
		model_id: String,
		provider: &super::ConverseOptions<'_>,
		headers: Option<&http::HeaderMap>,
		prompt_caching: Option<&super::PromptCachingConfig>,
	) -> (bedrock::ConverseRequest, super::BedrockToolNameMap) {
		use responses::{
			CustomToolCallOutput, CustomToolCallOutputOutput, EasyInputContent, FunctionCallOutput,
			InputContent, InputItem, InputMessage, InputParam, InputRole, InputTextContent, Item,
			MessageItem, OutputMessageContent, Role as ResponsesRole,
		};

		let mut tool_name_map = super::BedrockToolNameMap::default();
		for tool in req.tools.iter().flatten() {
			if let responses::Tool::Function(func) = tool {
				tool_name_map.register(&func.name);
			}
		}
		if let Some(responses::ToolChoiceParam::Function(responses::ToolChoiceFunction { name })) =
			&req.tool_choice
		{
			tool_name_map.register(name);
		}
		if let responses::InputParam::Items(items) = &req.input {
			for item in items {
				match item {
					responses::InputItem::Item(responses::Item::FunctionCall(call)) => {
						tool_name_map.register(&call.name);
					},
					responses::InputItem::Item(responses::Item::CustomToolCall(call)) => {
						tool_name_map.register(&call.name);
					},
					_ => {},
				}
			}
		}

		// Convert tools from typed Responses API format to Bedrock format before messages so
		// definitions keep priority if a previous tool-use name would otherwise collide.
		let (tools, tool_choice) = if let Some(response_tools) = &req.tools {
			let bedrock_tools: Vec<bedrock::Tool> = response_tools
				.iter()
				.filter_map(|tool_def| {
					use responses::Tool;
					match tool_def {
						Tool::Function(func) => Some(bedrock::Tool::ToolSpec(bedrock::ToolSpecification {
							name: tool_name_map.register(&func.name),
							description: func.description.clone(),
							input_schema: Some(bedrock::ToolInputSchema::Json(
								func.parameters.clone().unwrap_or_default(),
							)),
						})),
						_ => None,
					}
				})
				.collect();

			let bedrock_tool_choice = req.tool_choice.as_ref().and_then(|tc| {
				use responses::{ToolChoiceFunction, ToolChoiceOptions, ToolChoiceParam};
				match tc {
					ToolChoiceParam::Mode(ToolChoiceOptions::Auto) => Some(bedrock::ToolChoice::Auto),
					ToolChoiceParam::Mode(ToolChoiceOptions::Required) => Some(bedrock::ToolChoice::Any),
					ToolChoiceParam::Mode(ToolChoiceOptions::None) => None,
					ToolChoiceParam::Function(ToolChoiceFunction { name }) => {
						Some(bedrock::ToolChoice::Tool {
							name: tool_name_map.register(name),
						})
					},
					ToolChoiceParam::Hosted(_) => None,
					ToolChoiceParam::AllowedTools(_)
					| ToolChoiceParam::Mcp(_)
					| ToolChoiceParam::Custom(_)
					| ToolChoiceParam::ApplyPatch
					| ToolChoiceParam::Shell => None,
				}
			});

			(bedrock_tools, bedrock_tool_choice)
		} else {
			(vec![], None)
		};

		let supports_caching = req.model.as_deref().is_some_and(supports_prompt_caching);

		// Convert input to Bedrock messages and system content
		let mut messages: Vec<bedrock::Message> = Vec::new();
		let mut system_blocks: Vec<bedrock::SystemContentBlock> = Vec::new();

		// Convert Input format to items
		let items = match &req.input {
			InputParam::Text(text) => vec![InputItem::from(InputMessage {
				content: vec![InputContent::InputText(InputTextContent {
					text: text.clone(),
				})],
				role: InputRole::User,
				status: None,
			})],
			InputParam::Items(items) => items.clone(),
		};

		let input_parts_to_blocks = |parts: &[InputContent]| {
			let mut blocks = Vec::new();

			for part in parts {
				match part {
					InputContent::InputText(input_text) => {
						blocks.push(bedrock::ContentBlock::Text(input_text.text.clone()));
					},
					InputContent::InputImage(_) => {
						// Image support requires fetching URLs or resolving file_ids

						continue;
					},
					InputContent::InputFile(_) => {
						continue;
					},
				}
			}

			blocks
		};

		// Process each input item
		for item in items {
			match item {
				InputItem::EasyMessage(msg) => {
					let role = match msg.role {
						ResponsesRole::User => bedrock::Role::User,
						ResponsesRole::Assistant => bedrock::Role::Assistant,
						ResponsesRole::System | ResponsesRole::Developer => {
							let text = match &msg.content {
								EasyInputContent::Text(text) => text.clone(),
								EasyInputContent::ContentList(parts) => parts
									.iter()
									.filter_map(|part| match part {
										InputContent::InputText(input_text) => Some(input_text.text.clone()),
										_ => None,
									})
									.collect::<Vec<_>>()
									.join("\n"),
							};
							system_blocks.push(bedrock::SystemContentBlock::Text { text });
							continue;
						},
					};

					let content = match &msg.content {
						EasyInputContent::Text(text) => {
							vec![bedrock::ContentBlock::Text(text.clone())]
						},
						EasyInputContent::ContentList(parts) => input_parts_to_blocks(parts),
					};

					helpers::push_or_merge_message(&mut messages, bedrock::Message { role, content });
				},
				InputItem::Item(Item::Message(MessageItem::Input(msg))) => {
					let role = match msg.role {
						InputRole::User => bedrock::Role::User,
						InputRole::System | InputRole::Developer => {
							let text = msg
								.content
								.iter()
								.filter_map(|part| match part {
									InputContent::InputText(input_text) => Some(input_text.text.clone()),
									_ => None,
								})
								.collect::<Vec<_>>()
								.join("\n");
							system_blocks.push(bedrock::SystemContentBlock::Text { text });
							continue;
						},
					};

					let content = input_parts_to_blocks(&msg.content);
					helpers::push_or_merge_message(&mut messages, bedrock::Message { role, content });
				},
				InputItem::Item(Item::Message(MessageItem::Output(msg))) => {
					let content = msg
						.content
						.iter()
						.filter_map(|part| match part {
							OutputMessageContent::OutputText(output_text) => {
								Some(bedrock::ContentBlock::Text(output_text.text.clone()))
							},
							_ => None,
						})
						.collect::<Vec<_>>();
					if !content.is_empty() {
						helpers::push_or_merge_message(
							&mut messages,
							bedrock::Message {
								role: bedrock::Role::Assistant,
								content,
							},
						);
					}
				},
				InputItem::Item(Item::FunctionCall(call)) => {
					let Ok(input) = serde_json::from_str::<serde_json::Value>(&call.arguments) else {
						continue;
					};

					helpers::push_or_merge_message(
						&mut messages,
						bedrock::Message {
							role: bedrock::Role::Assistant,
							content: vec![bedrock::ContentBlock::ToolUse(bedrock::ToolUseBlock {
								tool_use_id: call.call_id,
								name: tool_name_map.register(&call.name),
								input,
							})],
						},
					);
				},
				InputItem::Item(Item::FunctionCallOutput(output)) => {
					let output_text = match output.output {
						FunctionCallOutput::Text(text) => text,
						FunctionCallOutput::Content(parts) => parts
							.iter()
							.filter_map(|part| match part {
								InputContent::InputText(input_text) => Some(input_text.text.clone()),
								_ => None,
							})
							.collect::<Vec<_>>()
							.join("\n"),
					};

					helpers::push_or_merge_message(
						&mut messages,
						bedrock::Message {
							role: bedrock::Role::User,
							content: vec![bedrock::ContentBlock::ToolResult(
								bedrock::ToolResultBlock {
									tool_use_id: output.call_id,
									content: vec![bedrock::ToolResultContentBlock::Text(output_text)],
									// Responses tool outputs do not carry explicit success/error metadata.
									// Leave Bedrock status unset instead of assuming success.
									status: None,
								},
							)],
						},
					);
				},
				InputItem::Item(Item::CustomToolCall(call)) => {
					helpers::push_or_merge_message(
						&mut messages,
						bedrock::Message {
							role: bedrock::Role::Assistant,
							content: vec![bedrock::ContentBlock::ToolUse(bedrock::ToolUseBlock {
								tool_use_id: call.call_id,
								name: tool_name_map.register(&call.name),
								input: serde_json::json!({ "input": call.input }),
							})],
						},
					);
				},
				InputItem::Item(Item::CustomToolCallOutput(CustomToolCallOutput {
					call_id,
					output,
					..
				})) => {
					let output_text = match output {
						CustomToolCallOutputOutput::Text(text) => text,
						CustomToolCallOutputOutput::List(parts) => parts
							.iter()
							.filter_map(|part| match part {
								InputContent::InputText(input_text) => Some(input_text.text.clone()),
								_ => None,
							})
							.collect::<Vec<_>>()
							.join("\n"),
					};

					helpers::push_or_merge_message(
						&mut messages,
						bedrock::Message {
							role: bedrock::Role::User,
							content: vec![bedrock::ContentBlock::ToolResult(
								bedrock::ToolResultBlock {
									tool_use_id: call_id,
									content: vec![bedrock::ToolResultContentBlock::Text(output_text)],
									// Responses tool outputs do not carry explicit success/error metadata.
									// Leave Bedrock status unset instead of assuming success.
									status: None,
								},
							)],
						},
					);
				},
				_ => {},
			}
		}

		let mut system_content = if system_blocks.is_empty() {
			None
		} else {
			Some(system_blocks)
		};

		// Add instructions field to system content if present
		if let Some(instructions) = &req.instructions {
			let instructions_block = bedrock::SystemContentBlock::Text {
				text: instructions.clone(),
			};
			if let Some(ref mut system) = system_content {
				system.insert(0, instructions_block);
			} else {
				system_content = Some(vec![instructions_block]);
			}
		}

		// Apply system prompt caching if configured
		if let Some(caching) = prompt_caching
			&& caching.cache_system
			&& supports_caching
			&& let Some(ref mut system) = system_content
		{
			let meets_minimum = if let Some(min_tokens) = caching.min_tokens {
				estimate_system_tokens(system) >= min_tokens
			} else {
				true
			};
			if meets_minimum {
				system.push(bedrock::SystemContentBlock::CachePoint {
					cache_point: create_cache_point(),
				});
			}
		}

		let inference_config = bedrock::InferenceConfiguration {
			max_tokens: req.max_output_tokens.unwrap_or(4096) as usize,
			temperature: req.temperature,
			top_p: req.top_p,
			top_k: None,
			stop_sequences: vec![],
		};
		let output_config = req
			.text
			.as_ref()
			.and_then(responses_text_format_to_bedrock_output_config);
		let enabled_thinking_budget = explicit_thinking_budget.or_else(|| {
			req
				.reasoning
				.as_ref()
				.and_then(|r| r.effort.as_ref())
				.and_then(responses_reasoning_effort_to_enabled_budget)
		});
		let additional_model_request_fields = enabled_thinking_budget.map(|budget| {
			serde_json::json!({
				"thinking": {
					"type": "enabled",
					"budget_tokens": budget
				}
			})
		});

		let tool_config = if !tools.is_empty() {
			Some(bedrock::ToolConfiguration { tools, tool_choice })
		} else {
			None
		};

		let guardrail_config = if let (Some(identifier), Some(version)) =
			(&provider.guardrail_identifier, &provider.guardrail_version)
		{
			Some(bedrock::GuardrailConfiguration {
				guardrail_identifier: identifier.to_string(),
				guardrail_version: version.to_string(),
				trace: Some("enabled".to_string()),
			})
		} else {
			None
		};

		// x-bedrock-metadata is an explicit Bedrock requestMetadata escape hatch. Forward it
		// unchanged so Bedrock, not the gateway, rejects operator-supplied invalid values.
		let metadata = extract_metadata_from_headers(headers).unwrap_or_default();
		let metadata = if metadata.is_empty() {
			None
		} else {
			Some(metadata)
		};

		let mut bedrock_request = bedrock::ConverseRequest {
			model_id,
			messages,
			system: system_content,
			inference_config: Some(inference_config),
			output_config,
			tool_config,
			guardrail_config,
			additional_model_request_fields,
			prompt_variables: None,
			additional_model_response_field_paths: None,
			request_metadata: metadata,
			performance_config: None,
		};

		// Apply user message and tool caching
		if let Some(caching) = prompt_caching {
			if caching.cache_messages && supports_caching {
				insert_message_cache_point(&mut bedrock_request.messages, caching.cache_message_offset);
			}
			if caching.cache_tools
				&& supports_caching
				&& let Some(ref mut tool_config) = bedrock_request.tool_config
				&& !tool_config.tools.is_empty()
			{
				tool_config
					.tools
					.push(bedrock::Tool::CachePoint(create_cache_point()));
			}
		}

		(bedrock_request, tool_name_map)
	}

	fn extract_responses_thinking_budget_tokens(req: &types::responses::Request) -> Option<u64> {
		req
			.vendor_extensions
			.as_ref()
			.and_then(|v| v.thinking_budget_tokens)
	}

	fn responses_reasoning_effort_to_enabled_budget(
		effort: &responses::ReasoningEffort,
	) -> Option<u64> {
		match effort {
			responses::ReasoningEffort::None => None,
			responses::ReasoningEffort::Minimal | responses::ReasoningEffort::Low => Some(1024),
			responses::ReasoningEffort::Medium => Some(2048),
			responses::ReasoningEffort::High | responses::ReasoningEffort::Xhigh => Some(4096),
		}
	}

	fn responses_text_format_to_bedrock_output_config(
		text: &responses::ResponseTextParam,
	) -> Option<bedrock::OutputConfig> {
		let (name, description, schema) = match &text.format {
			responses::TextResponseFormatConfiguration::Text => return None,
			responses::TextResponseFormatConfiguration::JsonObject => (
				None,
				None,
				std::borrow::Cow::Owned(
					serde_json::json!({ "type": "object", "additionalProperties": true }),
				),
			),
			responses::TextResponseFormatConfiguration::JsonSchema(json_schema) => (
				Some(json_schema.name.clone()),
				json_schema.description.clone(),
				std::borrow::Cow::Borrowed(&json_schema.schema),
			),
		};

		let Ok(schema_json) = serde_json::to_string(schema.as_ref()) else {
			return None;
		};

		Some(bedrock::OutputConfig {
			text_format: Some(bedrock::OutputFormat {
				r#type: bedrock::OutputFormatType::JsonSchema,
				structure: bedrock::OutputFormatStructure {
					json_schema: bedrock::JsonSchemaDefinition {
						schema: schema_json,
						name,
						description,
					},
				},
			}),
		})
	}
}

pub mod from_anthropic_token_count {

	use crate::{WireError as AIError, types};

	pub fn translate(
		req: &types::count_tokens::Request,
		headers: &http::HeaderMap,
	) -> Result<Vec<u8>, AIError> {
		use base64::Engine;
		let anthropic_version = headers
			.get("anthropic-version")
			.and_then(|v| v.to_str().ok())
			.unwrap_or("2023-06-01");

		let body = serde_json::to_vec(req).map_err(AIError::RequestMarshal)?;
		let mut body: serde_json::Map<String, serde_json::Value> =
			serde_json::from_slice(&body).map_err(AIError::RequestMarshal)?;

		// Remove the model field because its in the URL path not the body
		body.remove("model");

		// AWS Bedrock's count-tokens endpoint wraps InvokeModel, which requires a valid
		// Anthropic Messages API request. The `max_tokens` parameter is required by Anthropic's API.
		// We set it to 1 (the minimum valid value) since token counting doesn't generate output.
		body
			.entry("max_tokens")
			.or_insert(serde_json::Value::Number(1.into()));
		body
			.entry("anthropic_version")
			.or_insert(serde_json::Value::String(anthropic_version.into()));

		let body_json = serde_json::to_vec(&body).map_err(AIError::RequestMarshal)?;
		let body_b64 = base64::engine::general_purpose::STANDARD.encode(&body_json);

		let xlated = types::bedrock::CountTokensRequest {
			input: types::bedrock::CountTokensInputInvokeModel {
				invoke_model: types::bedrock::InvokeModelBody { body: body_b64 },
			},
		};
		serde_json::to_vec(&xlated).map_err(AIError::RequestMarshal)
	}
}
