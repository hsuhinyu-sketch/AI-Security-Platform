pub mod from_responses {
	use crate::types::completions::typed as completions;
	use crate::types::responses::typed as responses;
	pub fn translate_internal(
		req: responses::CreateResponse,
	) -> (completions::Request, Option<responses::ToolChoiceParam>) {
		use responses::{
			EasyInputContent, InputContent, InputItem, InputMessage, InputParam, InputRole,
			InputTextContent, Item, MessageItem, OutputMessageContent, Role as ResponsesRole,
			TextResponseFormatConfiguration,
		};

		let mut messages: Vec<completions::RequestMessage> = Vec::new();

		if let Some(instructions) = &req.instructions {
			messages.push(completions::RequestMessage::Developer(
				completions::RequestDeveloperMessage {
					content: completions::RequestDeveloperMessageContent::Text(instructions.clone()),
					name: None,
				},
			));
		}

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

		for item in items {
			match item {
				InputItem::EasyMessage(msg) => match msg.role {
					ResponsesRole::User => {
						let text = match &msg.content {
							EasyInputContent::Text(text) => text.clone(),
							EasyInputContent::ContentList(parts) => parts
								.iter()
								.filter_map(|p| match p {
									InputContent::InputText(t) => Some(t.text.as_str()),
									_ => None,
								})
								.collect::<Vec<_>>()
								.join("\n"),
						};
						messages.push(completions::RequestMessage::User(
							completions::RequestUserMessage {
								content: completions::RequestUserMessageContent::Text(text),
								name: None,
							},
						));
					},
					ResponsesRole::Assistant => {
						let text = match &msg.content {
							EasyInputContent::Text(text) => text.clone(),
							EasyInputContent::ContentList(parts) => parts
								.iter()
								.filter_map(|p| match p {
									InputContent::InputText(t) => Some(t.text.as_str()),
									_ => None,
								})
								.collect::<Vec<_>>()
								.join("\n"),
						};
						messages.push(completions::RequestMessage::Assistant(
							completions::RequestAssistantMessage {
								content: Some(completions::RequestAssistantMessageContent::Text(text)),
								..Default::default()
							},
						));
					},
					ResponsesRole::System | ResponsesRole::Developer => {
						let text = match &msg.content {
							EasyInputContent::Text(text) => text.clone(),
							EasyInputContent::ContentList(parts) => parts
								.iter()
								.filter_map(|p| match p {
									InputContent::InputText(t) => Some(t.text.as_str()),
									_ => None,
								})
								.collect::<Vec<_>>()
								.join("\n"),
						};
						messages.push(completions::RequestMessage::Developer(
							completions::RequestDeveloperMessage {
								content: completions::RequestDeveloperMessageContent::Text(text),
								name: None,
							},
						));
					},
				},
				InputItem::ItemReference(_) => continue,
				InputItem::Item(item) => match item {
					Item::Message(msg_item) => match msg_item {
						MessageItem::Input(msg) => {
							let text_parts: Vec<String> = msg
								.content
								.iter()
								.filter_map(|c| match c {
									InputContent::InputText(t) => Some(t.text.clone()),
									_ => None,
								})
								.collect();
							let text = text_parts.join("\n");

							match msg.role {
								InputRole::User => {
									messages.push(completions::RequestMessage::User(
										completions::RequestUserMessage {
											content: completions::RequestUserMessageContent::Text(text),
											name: None,
										},
									));
								},
								InputRole::System => {
									messages.push(completions::RequestMessage::System(
										completions::RequestSystemMessage {
											content: completions::RequestSystemMessageContent::Text(text),
											name: None,
										},
									));
								},
								InputRole::Developer => {
									messages.push(completions::RequestMessage::Developer(
										completions::RequestDeveloperMessage {
											content: completions::RequestDeveloperMessageContent::Text(text),
											name: None,
										},
									));
								},
							}
						},
						MessageItem::Output(msg) => {
							let text = msg
								.content
								.iter()
								.filter_map(|c| match c {
									OutputMessageContent::OutputText(t) => Some(t.text.clone()),
									_ => None,
								})
								.collect::<Vec<_>>()
								.join("\n");

							messages.push(completions::RequestMessage::Assistant(
								completions::RequestAssistantMessage {
									content: if text.is_empty() {
										None
									} else {
										Some(completions::RequestAssistantMessageContent::Text(text))
									},
									..Default::default()
								},
							));
						},
					},
					Item::FunctionCall(call) => {
						messages.push(completions::RequestMessage::Assistant(
							completions::RequestAssistantMessage {
								tool_calls: Some(vec![completions::MessageToolCalls::Function(
									completions::MessageToolCall {
										id: call.call_id.clone(),
										function: completions::FunctionCall {
											name: call.name.clone(),
											arguments: call.arguments.clone(),
										},
									},
								)]),
								..Default::default()
							},
						));
					},
					Item::FunctionCallOutput(output) => {
						let output_text = match output.output {
							responses::FunctionCallOutput::Text(text) => text,
							responses::FunctionCallOutput::Content(parts) => parts
								.iter()
								.filter_map(|part| match part {
									InputContent::InputText(t) => Some(t.text.clone()),
									_ => None,
								})
								.collect::<Vec<_>>()
								.join("\n"),
						};
						messages.push(completions::RequestMessage::Tool(
							completions::RequestToolMessage {
								content: completions::RequestToolMessageContent::Text(output_text),
								tool_call_id: output.call_id,
							},
						));
					},
					Item::CustomToolCall(call) => {
						let arguments = serde_json::to_string(&call.input).unwrap_or_else(|_| "{}".to_string());
						messages.push(completions::RequestMessage::Assistant(
							completions::RequestAssistantMessage {
								tool_calls: Some(vec![completions::MessageToolCalls::Function(
									completions::MessageToolCall {
										id: call.id.clone(),
										function: completions::FunctionCall {
											name: call.name.clone(),
											arguments,
										},
									},
								)]),
								..Default::default()
							},
						));
					},
					Item::CustomToolCallOutput(output) => {
						let text = match &output.output {
							responses::CustomToolCallOutputOutput::Text(t) => t.clone(),
							_ => continue,
						};
						messages.push(completions::RequestMessage::Tool(
							completions::RequestToolMessage {
								content: completions::RequestToolMessageContent::Text(text),
								tool_call_id: output.id.clone().unwrap_or_default(),
							},
						));
					},
					_ => continue,
				},
			}
		}

		let tools: Option<Vec<completions::Tool>> = req.tools.as_ref().map(|tools| {
			tools
				.iter()
				.filter_map(|tool| match tool {
					responses::Tool::Function(func) => {
						Some(completions::Tool::Function(completions::FunctionTool {
							function: completions::FunctionObject {
								name: func.name.clone(),
								description: func.description.clone(),
								parameters: func.parameters.clone(),
								strict: func.strict,
							},
						}))
					},
					_ => None,
				})
				.collect()
		});

		let mut unsupported_tool_choice = None;
		let tool_choice = req.tool_choice.as_ref().and_then(|tc| {
			use responses::{ToolChoiceFunction, ToolChoiceOptions, ToolChoiceParam};
			match tc {
				ToolChoiceParam::Mode(ToolChoiceOptions::Auto) => Some(
					completions::ToolChoiceOption::Mode(completions::ToolChoiceOptions::Auto),
				),
				ToolChoiceParam::Mode(ToolChoiceOptions::Required) => Some(
					completions::ToolChoiceOption::Mode(completions::ToolChoiceOptions::Required),
				),
				ToolChoiceParam::Mode(ToolChoiceOptions::None) => Some(
					completions::ToolChoiceOption::Mode(completions::ToolChoiceOptions::None),
				),
				ToolChoiceParam::Function(ToolChoiceFunction { name }) => Some(
					completions::ToolChoiceOption::Function(completions::NamedToolChoice {
						function: completions::FunctionName { name: name.clone() },
					}),
				),
				ToolChoiceParam::Hosted(_)
				| ToolChoiceParam::AllowedTools(_)
				| ToolChoiceParam::Mcp(_)
				| ToolChoiceParam::Custom(_)
				| ToolChoiceParam::ApplyPatch
				| ToolChoiceParam::Shell => {
					unsupported_tool_choice = Some(tc.clone());
					None
				},
			}
		});

		let reasoning_effort = req.reasoning.as_ref().and_then(|r| {
			r.effort.as_ref().and_then(|e| match e {
				responses::ReasoningEffort::Minimal => Some(completions::ReasoningEffort::Minimal),
				responses::ReasoningEffort::Low => Some(completions::ReasoningEffort::Low),
				responses::ReasoningEffort::Medium => Some(completions::ReasoningEffort::Medium),
				responses::ReasoningEffort::High => Some(completions::ReasoningEffort::High),
				responses::ReasoningEffort::Xhigh => Some(completions::ReasoningEffort::Xhigh),
				responses::ReasoningEffort::None => None,
			})
		});

		let response_format = req.text.as_ref().and_then(|text| match &text.format {
			TextResponseFormatConfiguration::JsonSchema(json_schema) => {
				Some(completions::ResponseFormat::JsonSchema {
					json_schema: completions::ResponseFormatJsonSchema {
						description: json_schema.description.clone(),
						name: json_schema.name.clone(),
						schema: json_schema.schema.clone(),
						strict: json_schema.strict,
					},
				})
			},
			TextResponseFormatConfiguration::JsonObject => Some(completions::ResponseFormat::JsonObject),
			TextResponseFormatConfiguration::Text => None,
		});

		let stream = req.stream.unwrap_or(false);
		let stream_options = if stream {
			Some(completions::StreamOptions {
				include_usage: Some(true),
				include_obfuscation: None,
			})
		} else {
			None
		};

		#[allow(deprecated)]
		let request = completions::Request {
			messages,
			tools,
			tool_choice,
			stream_options,
			reasoning_effort,
			response_format,
			stream: Some(stream),
			model: req.model.clone(),
			temperature: req.temperature,
			top_p: req.top_p,
			max_completion_tokens: req.max_output_tokens,
			parallel_tool_calls: req.parallel_tool_calls,
			vendor_extensions: completions::RequestVendorExtensions::default(),
			max_tokens: None,
			stop: None,
			user: None,
			frequency_penalty: None,
			presence_penalty: None,
			seed: None,
			store: None,
			metadata: None,
			logit_bias: None,
			logprobs: None,
			top_logprobs: None,
			n: None,
			modalities: None,
			prediction: None,
			audio: None,
			function_call: None,
			functions: None,
			service_tier: None,
			web_search_options: None,
		};
		(request, unsupported_tool_choice)
	}
}

pub mod to_responses {
	use crate::streaming::responses::usage_output_tokens;
	use crate::types::{completions::typed as completions, responses::typed as responses};

	pub fn translate_response(
		resp: completions::Response,
		mut response: responses::Response,
	) -> responses::Response {
		let choice = resp.choices.into_iter().next();

		let mut outputs: Vec<responses::OutputItem> = Vec::new();
		let mut text_parts: Vec<responses::OutputMessageContent> = Vec::new();
		let mut tool_calls: Vec<responses::OutputItem> = Vec::new();

		if let Some(choice) = &choice {
			if let Some(content) = &choice.message.content {
				text_parts.push(responses::OutputMessageContent::OutputText(
					responses::OutputTextContent {
						annotations: vec![],
						logprobs: None,
						text: content.clone(),
					},
				));
			}

			if let Some(tcs) = &choice.message.tool_calls {
				for tc in tcs {
					match tc {
						completions::MessageToolCalls::Function(f) => {
							tool_calls.push(responses::OutputItem::FunctionCall(
								responses::FunctionToolCall {
									arguments: f.function.arguments.clone(),
									call_id: f.id.clone(),
									name: f.function.name.clone(),
									id: Some(f.id.clone()),
									status: Some(responses::OutputStatus::Completed),
									namespace: None,
								},
							));
						},
						completions::MessageToolCalls::Custom(_) => {},
					}
				}
			}
		}

		if !text_parts.is_empty() {
			outputs.push(responses::OutputItem::Message(responses::OutputMessage {
				id: String::new(),
				role: responses::AssistantRole::Assistant,
				phase: None,
				content: text_parts,
				status: responses::OutputStatus::Completed,
			}));
		}
		outputs.extend(tool_calls);

		let finish_reason = choice.as_ref().and_then(|c| c.finish_reason.as_ref());

		let status = match finish_reason {
			Some(completions::FinishReason::Stop) | None => responses::Status::Completed,
			Some(completions::FinishReason::Length) => responses::Status::Incomplete,
			Some(completions::FinishReason::ToolCalls)
			| Some(completions::FinishReason::FunctionCall) => responses::Status::Completed,
			Some(completions::FinishReason::ContentFilter) => responses::Status::Failed,
		};

		let incomplete_details = match finish_reason {
			Some(completions::FinishReason::Length) => Some(responses::IncompleteDetails {
				reason: "max_tokens".to_string(),
			}),
			_ => None,
		};

		let error = match finish_reason {
			Some(completions::FinishReason::ContentFilter) => Some(responses::ErrorObject {
				code: "content_filter".to_string(),
				message: "Content filtered".to_string(),
			}),
			_ => None,
		};

		let usage = resp.usage.map(|u| responses::ResponseUsage {
			input_tokens: u.prompt_tokens,
			output_tokens: usage_output_tokens(&u),
			total_tokens: u.total_tokens,
			input_tokens_details: responses::InputTokenDetails {
				cached_tokens: u
					.prompt_tokens_details
					.as_ref()
					.and_then(|d| d.cached_tokens)
					.unwrap_or(0) as u32,
			},
			output_tokens_details: responses::OutputTokenDetails {
				reasoning_tokens: u
					.completion_tokens_details
					.as_ref()
					.and_then(|d| d.reasoning_tokens)
					.unwrap_or(0) as u32,
			},
		});

		response.status = status;
		response.usage = usage;
		response.error = error;
		response.incomplete_details = incomplete_details;
		response.output = outputs;
		response
	}
}
