//! Messages events to Completions chunks; clocks and log mutation stay in Host.
use crate::types::{completions::typed as completions, messages::typed as messages};
use completions::UsagePromptDetails;
use std::collections::HashMap;
#[derive(Debug)]
pub enum Observation {
	Start {
		model: String,
		usage: messages::Usage,
	},
	FirstToken,
	Usage(messages::MessageDeltaUsage),
}
pub struct Step {
	pub event: Option<completions::StreamResponse>,
	pub observations: Vec<Observation>,
}
#[derive(Default)]
pub struct State {
	message_id: Option<String>,
	model: String,
	service_tier: Option<String>,
	created: u32,
	saw_token: bool,
	next_tool_index: u32,
	tool_index_map: HashMap<usize, u32>,
}
impl State {
	pub fn new(created: u32) -> Self {
		Self {
			created,
			..Default::default()
		}
	}
	pub fn push(&mut self, f: messages::MessagesStreamEvent) -> Step {
		let Self {
			message_id,
			model,
			service_tier,
			created,
			saw_token,
			next_tool_index,
			tool_index_map,
		} = self;
		let mut observations = Vec::new();
		let mk = |choices: Vec<completions::ChatChoiceStream>, usage: Option<completions::Usage>| {
			Some(completions::StreamResponse {
				id: message_id.clone().unwrap_or_else(|| "unknown".to_string()),
				model: model.clone(),
				object: "chat.completion.chunk".to_string(),
				system_fingerprint: None,
				service_tier: service_tier.clone(),
				created: *created,
				choices,
				usage,
			})
		};
		// ignore errors... what else can we do?

		// Extract info we need
		let event = match f {
			messages::MessagesStreamEvent::MessageStart { message } => {
				*message_id = Some(message.id);
				*model = message.model.clone();
				*service_tier = message.usage.service_tier.clone();
				observations.push(Observation::Start {
					model: message.model.clone(),
					usage: message.usage.clone(),
				});
				// no need to respond with anything yet
				None
			},

			messages::MessagesStreamEvent::ContentBlockStart {
				index,
				content_block,
			} => match content_block {
				messages::ContentBlock::ToolUse { id, name, .. }
				| messages::ContentBlock::ServerToolUse { id, name, .. } => {
					let tool_index = *next_tool_index;
					*next_tool_index += 1;
					tool_index_map.insert(index, tool_index);

					let choice = completions::ChatChoiceStream {
						index: 0,
						logprobs: None,
						delta: completions::StreamResponseDelta {
							tool_calls: Some(vec![completions::ChatCompletionMessageToolCallChunk {
								index: tool_index,
								id: Some(id),
								r#type: Some(completions::FunctionType::Function),
								function: Some(completions::FunctionCallStream {
									name: Some(name),
									arguments: None,
								}),
							}]),
							..Default::default()
						},
						finish_reason: None,
					};
					mk(vec![choice], None)
				},
				_ => None,
			},
			messages::MessagesStreamEvent::ContentBlockDelta { delta, index } => {
				if !*saw_token {
					*saw_token = true;
					observations.push(Observation::FirstToken);
				}
				let mut dr = completions::StreamResponseDelta::default();
				let mut emit_chunk = true;
				match delta {
					messages::ContentBlockDelta::TextDelta { text } => {
						dr.content = Some(text);
					},
					messages::ContentBlockDelta::ThinkingDelta { thinking } => {
						dr.reasoning_content = Some(thinking)
					},
					messages::ContentBlockDelta::InputJsonDelta { partial_json } => {
						if let Some(&tool_index) = tool_index_map.get(&index) {
							dr.tool_calls = Some(vec![completions::ChatCompletionMessageToolCallChunk {
								index: tool_index,
								id: None,
								r#type: None,
								function: Some(completions::FunctionCallStream {
									name: None,
									arguments: Some(partial_json),
								}),
							}]);
						} else {
							emit_chunk = false;
						}
					},
					messages::ContentBlockDelta::SignatureDelta { .. }
					| messages::ContentBlockDelta::CitationsDelta { .. } => {
						emit_chunk = false;
					},
				};
				if emit_chunk {
					let choice = completions::ChatChoiceStream {
						index: 0,
						logprobs: None,
						delta: dr,
						finish_reason: None,
					};
					mk(vec![choice], None)
				} else {
					None
				}
			},
			messages::MessagesStreamEvent::MessageDelta { usage, delta } => {
				let finish_reason = delta.stop_reason.as_ref().map(translate_stop_reason);
				observations.push(Observation::Usage(usage.clone()));
				let choices = finish_reason.map_or_else(Vec::new, |finish_reason| {
					vec![completions::ChatChoiceStream {
						index: 0,
						logprobs: None,
						delta: completions::StreamResponseDelta::default(),
						finish_reason: Some(finish_reason),
					}]
				});
				mk(
					choices,
					Some(completions::Usage {
						prompt_tokens: usage.input_tokens.unwrap_or_default() as u32,
						completion_tokens: usage.output_tokens.unwrap_or_default() as u32,

						total_tokens: (usage.input_tokens.unwrap_or_default()
							+ usage.output_tokens.unwrap_or_default()) as u32,

						cache_read_input_tokens: usage.cache_read_input_tokens.map(|i| i as u64),
						prompt_tokens_details: usage.cache_read_input_tokens.map(|i| UsagePromptDetails {
							cached_tokens: Some(i as u64),
							audio_tokens: None,
							rest: Default::default(),
						}),
						cache_creation_input_tokens: usage.cache_creation_input_tokens.map(|i| i as u64),

						completion_tokens_details: None,
					}),
				)
			},
			messages::MessagesStreamEvent::ContentBlockStop { index } => {
				tool_index_map.remove(&index);
				None
			},
			messages::MessagesStreamEvent::MessageStop => None,
			messages::MessagesStreamEvent::Ping => None,
		};
		Step {
			event,
			observations,
		}
	}
}
pub fn translate_stop_reason(resp: &messages::StopReason) -> completions::FinishReason {
	match resp {
		messages::StopReason::EndTurn => completions::FinishReason::Stop,
		messages::StopReason::MaxTokens => completions::FinishReason::Length,
		messages::StopReason::StopSequence => completions::FinishReason::Stop,
		messages::StopReason::ToolUse => completions::FinishReason::ToolCalls,
		messages::StopReason::Refusal => completions::FinishReason::ContentFilter,
		messages::StopReason::PauseTurn => completions::FinishReason::Stop,
		messages::StopReason::ModelContextWindowExceeded => completions::FinishReason::Length,
	}
}
