//! Completions chunks to Messages events; protocol data only.
use crate::types::{completions::typed as completions, messages::typed as messages};
use serde_json::Value;
use std::collections::{HashMap, HashSet};

#[derive(Debug)]
pub enum Observation {
	ProviderModel(String),
	FirstToken,
	Usage(completions::Usage),
}
pub struct Step {
	pub events: Vec<(&'static str, messages::MessagesStreamEvent)>,
	pub observations: Vec<Observation>,
}
#[derive(Debug)]
struct PendingToolCall {
	id: Option<String>,
	name: Option<String>,
	pending_json: String,
}

#[derive(Debug, Default)]
pub struct State {
	sent_message_start: bool,
	sent_message_stop: bool,
	sent_first_token: bool,
	next_block_index: usize,
	text_block_index: Option<usize>,
	tool_block_indices: HashMap<u32, usize>,
	open_tool_blocks: HashSet<u32>,
	pending_tool_calls: HashMap<u32, PendingToolCall>,
	pending_stop_reason: Option<messages::StopReason>,
	pending_usage: Option<completions::Usage>,
}

fn push_event(
	events: &mut Vec<(&'static str, messages::MessagesStreamEvent)>,
	event: messages::MessagesStreamEvent,
) {
	let name = event.event_name();
	events.push((name, event));
}

fn close_text_block(
	state: &mut State,
	events: &mut Vec<(&'static str, messages::MessagesStreamEvent)>,
) {
	if let Some(index) = state.text_block_index.take() {
		push_event(
			events,
			messages::MessagesStreamEvent::ContentBlockStop { index },
		);
	}
}

fn close_all_tool_blocks(
	state: &mut State,
	events: &mut Vec<(&'static str, messages::MessagesStreamEvent)>,
) {
	let mut blocks: Vec<(u32, usize)> = state
		.open_tool_blocks
		.iter()
		.filter_map(|tool_index| {
			state
				.tool_block_indices
				.get(tool_index)
				.map(|index| (*tool_index, *index))
		})
		.collect();
	blocks.sort_by_key(|(_, index)| *index);
	for (tool_index, index) in blocks {
		push_event(
			events,
			messages::MessagesStreamEvent::ContentBlockStop { index },
		);
		state.open_tool_blocks.remove(&tool_index);
	}
}

fn open_text_block(
	state: &mut State,
	events: &mut Vec<(&'static str, messages::MessagesStreamEvent)>,
) -> usize {
	if let Some(index) = state.text_block_index {
		return index;
	}
	close_all_tool_blocks(state, events);
	let index = state.next_block_index;
	state.next_block_index += 1;
	state.text_block_index = Some(index);
	push_event(
		events,
		messages::MessagesStreamEvent::ContentBlockStart {
			index,
			content_block: messages::ContentBlock::Text(messages::ContentTextBlock {
				text: "".to_string(),
				citations: None,
				cache_control: None,
			}),
		},
	);
	index
}

fn open_tool_block(
	state: &mut State,
	events: &mut Vec<(&'static str, messages::MessagesStreamEvent)>,
	tool_index: u32,
	id: String,
	name: String,
) -> usize {
	close_text_block(state, events);
	let index = *state
		.tool_block_indices
		.entry(tool_index)
		.or_insert_with(|| {
			let idx = state.next_block_index;
			state.next_block_index += 1;
			idx
		});

	// Keep each tool-use block open across interleaved deltas to avoid
	// emitting duplicate start events for the same block index.
	if state.open_tool_blocks.insert(tool_index) {
		push_event(
			events,
			messages::MessagesStreamEvent::ContentBlockStart {
				index,
				content_block: messages::ContentBlock::ToolUse {
					id,
					name,
					input: Value::Object(serde_json::Map::new()),
					cache_control: None,
				},
			},
		);
	}
	index
}

fn maybe_set_first_token(state: &mut State, observations: &mut Vec<Observation>) {
	if state.sent_first_token {
		return;
	}
	state.sent_first_token = true;
	observations.push(Observation::FirstToken);
}

fn flush_message_end(
	state: &mut State,
	events: &mut Vec<(&'static str, messages::MessagesStreamEvent)>,
	observations: &mut Vec<Observation>,
	force: bool,
) {
	if state.sent_message_stop {
		return;
	}
	let stop_reason = match state.pending_stop_reason.take() {
		Some(stop_reason) => stop_reason,
		None if force => messages::StopReason::EndTurn,
		None => return,
	};
	let usage = match state.pending_usage.take() {
		Some(usage) => Some(usage),
		None if force => None,
		None => {
			state.pending_stop_reason = Some(stop_reason);
			return;
		},
	};

	close_text_block(state, events);
	close_all_tool_blocks(state, events);

	let (input_tokens, output_tokens) = usage
		.as_ref()
		.map(|u| (u.prompt_tokens as usize, u.completion_tokens as usize))
		.unwrap_or((0, 0));

	push_event(
		events,
		messages::MessagesStreamEvent::MessageDelta {
			delta: messages::MessageDelta {
				stop_reason: Some(stop_reason),
				stop_sequence: None,
			},
			usage: messages::MessageDeltaUsage {
				input_tokens: Some(input_tokens),
				output_tokens: Some(output_tokens),
				cache_creation_input_tokens: None,
				cache_read_input_tokens: None,
			},
		},
	);
	push_event(events, messages::MessagesStreamEvent::MessageStop);
	state.sent_message_stop = true;

	if let Some(usage) = usage {
		observations.push(Observation::Usage(usage));
	}
}
impl State {
	pub fn push(&mut self, chunk: completions::StreamResponse) -> Step {
		self.apply(Some(chunk))
	}
	pub fn finish(&mut self) -> Step {
		self.apply(None)
	}
	fn apply(&mut self, chunk: Option<completions::StreamResponse>) -> Step {
		let state = self;
		let mut observations = Vec::new();
		let mut events: Vec<(&'static str, messages::MessagesStreamEvent)> = Vec::new();
		match chunk {
			None => {
				flush_message_end(state, &mut events, &mut observations, true);
				return Step {
					events,
					observations,
				};
			},

			Some(f) => {
				if !state.sent_message_start {
					state.sent_message_start = true;
					push_event(
						&mut events,
						messages::MessagesStreamEvent::MessageStart {
							message: messages::MessagesResponse {
								id: f.id.clone(),
								r#type: "message".to_string(),
								role: messages::Role::Assistant,
								content: vec![],
								model: f.model.clone(),
								stop_reason: None,
								stop_sequence: None,
								usage: messages::Usage {
									input_tokens: 0,
									output_tokens: 0,
									cache_creation_input_tokens: None,
									cache_read_input_tokens: None,
									service_tier: None,
								},
								input_audio_tokens: None,
								output_audio_tokens: None,
							},
						},
					);

					observations.push(Observation::ProviderModel(f.model.clone()));
				}

				if let Some(usage) = f.usage {
					state.pending_usage = Some(usage);
				}

				if let Some(choice) = f.choices.first() {
					if let Some(content) = choice.delta.content.as_deref().filter(|s| !s.is_empty()) {
						let index = open_text_block(state, &mut events);
						maybe_set_first_token(state, &mut observations);
						push_event(
							&mut events,
							messages::MessagesStreamEvent::ContentBlockDelta {
								index,
								delta: messages::ContentBlockDelta::TextDelta {
									text: content.to_string(),
								},
							},
						);
					}

					if let Some(tool_calls) = &choice.delta.tool_calls {
						for tool_call in tool_calls {
							let tool_index = tool_call.index;
							let (should_open, id, name, pending_json) = {
								let entry = state
									.pending_tool_calls
									.entry(tool_index)
									.or_insert(PendingToolCall {
										id: None,
										name: None,
										pending_json: String::new(),
									});
								if let Some(id) = &tool_call.id {
									entry.id = Some(id.clone());
								}
								if let Some(function) = &tool_call.function {
									if let Some(name) = &function.name {
										entry.name = Some(name.clone());
									}
									if let Some(args) = &function.arguments {
										entry.pending_json.push_str(args);
									}
								}

								let should_open = entry.name.is_some();
								let id = entry.id.clone();
								let name = entry.name.clone();
								let pending_json = if should_open && !entry.pending_json.is_empty() {
									Some(std::mem::take(&mut entry.pending_json))
								} else {
									None
								};
								(should_open, id, name, pending_json)
							};

							if should_open {
								let id = id.unwrap_or_else(|| format!("tool_call_{tool_index}"));
								let name = name.unwrap_or_default();
								let index = open_tool_block(state, &mut events, tool_index, id, name);

								if let Some(pending_json) = pending_json {
									maybe_set_first_token(state, &mut observations);
									let delta = messages::ContentBlockDelta::InputJsonDelta {
										partial_json: pending_json,
									};
									push_event(
										&mut events,
										messages::MessagesStreamEvent::ContentBlockDelta { index, delta },
									);
								}
							}
						}
					}

					if let Some(finish_reason) = &choice.finish_reason {
						let stop_reason = match finish_reason {
							completions::FinishReason::Stop => messages::StopReason::EndTurn,
							completions::FinishReason::Length => messages::StopReason::MaxTokens,
							completions::FinishReason::ToolCalls => messages::StopReason::ToolUse,
							completions::FinishReason::ContentFilter => messages::StopReason::Refusal,
							completions::FinishReason::FunctionCall => messages::StopReason::ToolUse,
						};
						state.pending_stop_reason = Some(stop_reason);
					}
				}

				if state.pending_stop_reason.is_some() && state.pending_usage.is_some() {
					flush_message_end(state, &mut events, &mut observations, false);
				}
			},
		}
		Step {
			events,
			observations,
		}
	}
}
