//! Decoded Converse → Responses transitions, with explicit identities and time.
use crate::provider::bedrock::{BedrockToolNameMap, restore_tool_name};
use crate::streaming::responses::ResponseBuilder;
use crate::types::{bedrock, responses::typed as responses};
use responses::{
	AssistantRole, ErrorObject, FunctionToolCall, IncompleteDetails, InputTokenDetails,
	OutputContent, OutputItem, OutputMessage, OutputStatus, OutputTextContent, OutputTokenDetails,
	ResponseContentPartAddedEvent, ResponseContentPartDoneEvent,
	ResponseFunctionCallArgumentsDeltaEvent, ResponseFunctionCallArgumentsDoneEvent,
	ResponseOutputItemAddedEvent, ResponseOutputItemDoneEvent, ResponseStreamEvent,
	ResponseTextDeltaEvent, ResponseUsage,
};
use std::collections::{HashMap, HashSet};

pub struct ResponsesState {
	seen_blocks: HashSet<i32>,
	pending_stop_reason: Option<bedrock::StopReason>,
	pending_usage: Option<bedrock::TokenUsage>,
	tool_calls: HashMap<i32, (String, String, String, u32)>,
	next_output_index: u32,
	sequence_number: u64,
	response_builder: ResponseBuilder,
	message_item_id: String,
	tool_name_map: Option<BedrockToolNameMap>,
}
impl ResponsesState {
	pub fn new(
		response_id: String,
		message_item_id: String,
		model: String,
		created_at: u64,
		tool_name_map: Option<BedrockToolNameMap>,
	) -> Self {
		Self {
			seen_blocks: HashSet::new(),
			pending_stop_reason: None,
			pending_usage: None,
			tool_calls: HashMap::new(),
			next_output_index: 1,
			sequence_number: 0,
			response_builder: ResponseBuilder::new_at(response_id, model, created_at),
			message_item_id,
			tool_name_map,
		}
	}
	pub fn push(
		&mut self,
		event: bedrock::ConverseStreamOutput,
		event_identity: &str,
	) -> Vec<(&'static str, ResponseStreamEvent)> {
		let make_output_part = |text: String| {
			OutputContent::OutputText(OutputTextContent {
				annotations: Vec::new(),
				logprobs: None,
				text,
			})
		};
		match event {
			bedrock::ConverseStreamOutput::MessageStart(_start) => {
				let mut events: Vec<(&'static str, ResponseStreamEvent)> = Vec::new();

				self.sequence_number += 1;
				let created_event = self.response_builder.created_event(self.sequence_number);
				events.push(("event", created_event));

				self.sequence_number += 1;
				let item_added_event =
					ResponseStreamEvent::ResponseOutputItemAdded(ResponseOutputItemAddedEvent {
						sequence_number: self.sequence_number,
						output_index: 0,
						item: OutputItem::Message(OutputMessage {
							content: Vec::new(),
							id: self.message_item_id.clone(),
							role: AssistantRole::Assistant,
							phase: None,
							status: OutputStatus::InProgress,
						}),
					});
				events.push(("event", item_added_event));

				events
			},
			bedrock::ConverseStreamOutput::ContentBlockStart(start) => {
				self.seen_blocks.insert(start.content_block_index);

				match start.start {
					Some(bedrock::ContentBlockStart::ToolUse(tu)) => {
						let tool_call_item_id = event_identity.to_string();
						let output_index = self.next_output_index;
						self.next_output_index += 1;
						let restored_name = restore_tool_name(self.tool_name_map.as_ref(), &tu.name);
						self.tool_calls.insert(
							start.content_block_index,
							(
								tool_call_item_id.clone(),
								restored_name.clone(),
								String::new(),
								output_index,
							),
						);

						self.sequence_number += 1;
						let item_added_event =
							ResponseStreamEvent::ResponseOutputItemAdded(ResponseOutputItemAddedEvent {
								sequence_number: self.sequence_number,
								output_index,
								item: OutputItem::FunctionCall(FunctionToolCall {
									arguments: String::new(),
									call_id: tool_call_item_id.clone(),
									namespace: None,
									name: restored_name,
									id: Some(tool_call_item_id),
									status: Some(OutputStatus::InProgress),
								}),
							});

						vec![("event", item_added_event)]
					},
					_ => {
						self.sequence_number += 1;
						let part_added_event =
							ResponseStreamEvent::ResponseContentPartAdded(ResponseContentPartAddedEvent {
								sequence_number: self.sequence_number,
								item_id: self.message_item_id.clone(),
								output_index: 0,
								content_index: 0,
								part: make_output_part(String::new()),
							});

						vec![("event", part_added_event)]
					},
				}
			},
			bedrock::ConverseStreamOutput::ContentBlockDelta(delta) => {
				let mut out: Vec<(&'static str, ResponseStreamEvent)> = Vec::new();

				if let Some(d) = delta.delta {
					match d {
						bedrock::ContentBlockDelta::Text(text) => {
							self.sequence_number += 1;
							let delta_event =
								ResponseStreamEvent::ResponseOutputTextDelta(ResponseTextDeltaEvent {
									sequence_number: self.sequence_number,
									item_id: self.message_item_id.clone(),
									output_index: 0,
									content_index: 0,
									delta: text,
									logprobs: None,
								});
							out.push(("event", delta_event));
						},
						bedrock::ContentBlockDelta::ReasoningContent(rc) => match rc {
							bedrock::ReasoningContentBlockDelta::Text(t) => {
								self.sequence_number += 1;
								let delta_event =
									ResponseStreamEvent::ResponseOutputTextDelta(ResponseTextDeltaEvent {
										sequence_number: self.sequence_number,
										item_id: self.message_item_id.clone(),
										output_index: 0,
										content_index: 0,
										delta: t,
										logprobs: None,
									});
								out.push(("event", delta_event));
							},
							bedrock::ReasoningContentBlockDelta::RedactedContent(_) => {
								self.sequence_number += 1;
								let delta_event =
									ResponseStreamEvent::ResponseOutputTextDelta(ResponseTextDeltaEvent {
										sequence_number: self.sequence_number,
										item_id: self.message_item_id.clone(),
										output_index: 0,
										content_index: 0,
										delta: "[REDACTED]".to_string(),
										logprobs: None,
									});
								out.push(("event", delta_event));
							},
							_ => {},
						},
						bedrock::ContentBlockDelta::ToolUse(tu) => {
							if let Some((item_id, _name, buffer, output_index)) =
								self.tool_calls.get_mut(&delta.content_block_index)
							{
								buffer.push_str(&tu.input);

								self.sequence_number += 1;
								let delta_event = ResponseStreamEvent::ResponseFunctionCallArgumentsDelta(
									ResponseFunctionCallArgumentsDeltaEvent {
										sequence_number: self.sequence_number,
										item_id: item_id.clone(),
										output_index: *output_index,
										delta: tu.input,
									},
								);
								out.push(("event", delta_event));
							}
						},
					}
				}

				out
			},
			bedrock::ConverseStreamOutput::ContentBlockStop(stop) => {
				let mut events: Vec<(&'static str, ResponseStreamEvent)> = Vec::new();
				let was_tracked = self.seen_blocks.remove(&stop.content_block_index);

				if let Some((item_id, name, buffer, output_index)) =
					self.tool_calls.remove(&stop.content_block_index)
				{
					self.sequence_number += 1;
					let args_done_event = ResponseStreamEvent::ResponseFunctionCallArgumentsDone(
						ResponseFunctionCallArgumentsDoneEvent {
							name: Some(name.clone()),
							sequence_number: self.sequence_number,
							item_id: item_id.clone(),
							output_index,
							arguments: buffer.clone(),
						},
					);
					events.push(("event", args_done_event));

					self.sequence_number += 1;
					let item_done_event =
						ResponseStreamEvent::ResponseOutputItemDone(ResponseOutputItemDoneEvent {
							sequence_number: self.sequence_number,
							output_index,
							item: OutputItem::FunctionCall(FunctionToolCall {
								arguments: buffer,
								call_id: item_id.clone(),
								namespace: None,
								name,
								id: Some(item_id),
								status: Some(OutputStatus::Completed),
							}),
						});
					events.push(("event", item_done_event));
				} else if was_tracked {
					self.sequence_number += 1;
					let part_done_event =
						ResponseStreamEvent::ResponseContentPartDone(ResponseContentPartDoneEvent {
							sequence_number: self.sequence_number,
							item_id: self.message_item_id.clone(),
							output_index: 0,
							content_index: 0,
							part: make_output_part(String::new()),
						});
					events.push(("event", part_done_event));
				}

				events
			},
			bedrock::ConverseStreamOutput::MessageStop(stop) => {
				self.pending_stop_reason = Some(stop.stop_reason);
				vec![]
			},
			bedrock::ConverseStreamOutput::Metadata(meta) => {
				if let Some(usage) = meta.usage {
					self.pending_usage = Some(usage);
				}

				let mut out: Vec<(&'static str, ResponseStreamEvent)> = Vec::new();

				self.sequence_number += 1;
				let message_done_event =
					ResponseStreamEvent::ResponseOutputItemDone(ResponseOutputItemDoneEvent {
						sequence_number: self.sequence_number,
						output_index: 0,
						item: OutputItem::Message(OutputMessage {
							content: Vec::new(),
							id: self.message_item_id.clone(),
							role: AssistantRole::Assistant,
							phase: None,
							status: OutputStatus::Completed,
						}),
					});
				out.push(("event", message_done_event));

				let stop = self.pending_stop_reason.take();
				let usage_data = self.pending_usage.take();

				let usage_obj = usage_data.map(|u| ResponseUsage {
					input_tokens: u.input_tokens as u32,
					output_tokens: u.output_tokens as u32,
					total_tokens: (u.input_tokens + u.output_tokens) as u32,
					input_tokens_details: InputTokenDetails {
						cached_tokens: u.cache_read_input_tokens.unwrap_or(0) as u32,
					},
					output_tokens_details: OutputTokenDetails {
						reasoning_tokens: 0,
					},
				});

				self.sequence_number += 1;
				let done_event = match stop {
					Some(bedrock::StopReason::EndTurn) | Some(bedrock::StopReason::StopSequence) | None => {
						self
							.response_builder
							.completed_event(self.sequence_number, usage_obj)
					},
					Some(bedrock::StopReason::MaxTokens)
					| Some(bedrock::StopReason::ModelContextWindowExceeded) => {
						self.response_builder.incomplete_event(
							self.sequence_number,
							usage_obj,
							IncompleteDetails {
								reason: "max_tokens".to_string(),
							},
						)
					},
					Some(bedrock::StopReason::ContentFiltered)
					| Some(bedrock::StopReason::GuardrailIntervened) => self.response_builder.failed_event(
						self.sequence_number,
						usage_obj,
						ErrorObject {
							code: "content_filter".to_string(),
							message: "Content filtered by guardrails".to_string(),
						},
					),
					Some(bedrock::StopReason::ToolUse) => self
						.response_builder
						.completed_event(self.sequence_number, usage_obj),
				};

				out.push(("event", done_event));
				out
			},
		}
	}
}
