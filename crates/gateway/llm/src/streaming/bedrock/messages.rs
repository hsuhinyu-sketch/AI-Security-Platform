//! Decoded Converse → Messages transitions; identities are supplied by the Host.
use crate::provider::bedrock::{BedrockToolNameMap, restore_tool_name};
use crate::types::{bedrock, messages::typed as messages};
use std::collections::HashSet;
pub struct MessagesState {
	model: String,
	tool_name_map: Option<BedrockToolNameMap>,
	seen_blocks: HashSet<i32>,
	pending_stop_reason: Option<bedrock::StopReason>,
	pending_usage: Option<bedrock::TokenUsage>,
}
impl MessagesState {
	pub fn new(model: &str, tool_name_map: Option<BedrockToolNameMap>) -> Self {
		Self {
			model: model.into(),
			tool_name_map,
			seen_blocks: HashSet::new(),
			pending_stop_reason: None,
			pending_usage: None,
		}
	}
	pub fn push(
		&mut self,
		event: bedrock::ConverseStreamOutput,
		event_identity: &str,
	) -> Vec<(&'static str, serde_json::Value)> {
		match event {
			bedrock::ConverseStreamOutput::MessageStart(_start) => {
				let event = messages::MessagesStreamEvent::MessageStart {
					message: messages::MessagesResponse {
						id: event_identity.to_string(),
						r#type: "message".to_string(),
						role: messages::Role::Assistant,
						content: vec![],
						model: self.model.to_string(),
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
				};
				let (event_name, event_data) = event.into_sse_tuple();
				vec![(event_name, serde_json::to_value(event_data).unwrap())]
			},
			bedrock::ConverseStreamOutput::ContentBlockStart(start) => {
				self.seen_blocks.insert(start.content_block_index);
				let content_block = match start.start {
					Some(bedrock::ContentBlockStart::ToolUse(s)) => messages::ContentBlock::ToolUse {
						id: s.tool_use_id,
						name: restore_tool_name(self.tool_name_map.as_ref(), &s.name),
						input: serde_json::json!({}),
						cache_control: None,
					},
					Some(bedrock::ContentBlockStart::ReasoningContent) => messages::ContentBlock::Thinking {
						thinking: String::new(),
						signature: String::new(),
					},
					_ => messages::ContentBlock::Text(messages::ContentTextBlock {
						text: String::new(),
						citations: None,
						cache_control: None,
					}),
				};

				let event = messages::MessagesStreamEvent::ContentBlockStart {
					index: start.content_block_index as usize,
					content_block,
				};
				let (event_name, event_data) = event.into_sse_tuple();
				vec![(event_name, serde_json::to_value(event_data).unwrap())]
			},
			bedrock::ConverseStreamOutput::ContentBlockDelta(delta) => {
				let mut out = Vec::new();

				// Synthesize ContentStart for first text/thinking delta on this index
				let first_for_index = !self.seen_blocks.contains(&delta.content_block_index);
				if first_for_index {
					self.seen_blocks.insert(delta.content_block_index);

					if let Some(ref d) = delta.delta {
						let content_block = match d {
							bedrock::ContentBlockDelta::Text(_) => {
								Some(messages::ContentBlock::Text(messages::ContentTextBlock {
									text: String::new(),
									citations: None,
									cache_control: None,
								}))
							},
							bedrock::ContentBlockDelta::ReasoningContent(_) => {
								Some(messages::ContentBlock::Thinking {
									thinking: String::new(),
									signature: String::new(),
								})
							},
							bedrock::ContentBlockDelta::ToolUse(_) => None,
						};

						if let Some(cb) = content_block {
							let event = messages::MessagesStreamEvent::ContentBlockStart {
								index: delta.content_block_index as usize,
								content_block: cb,
							};
							let (event_name, event_data) = event.into_sse_tuple();
							out.push((event_name, serde_json::to_value(event_data).unwrap()));
						}
					}
				}

				if let Some(d) = delta.delta {
					let anthropic_delta = match d {
						bedrock::ContentBlockDelta::Text(text) => {
							messages::ContentBlockDelta::TextDelta { text }
						},
						bedrock::ContentBlockDelta::ReasoningContent(rc) => rc.into_anthropic_delta(),
						bedrock::ContentBlockDelta::ToolUse(tu) => {
							messages::ContentBlockDelta::InputJsonDelta {
								partial_json: tu.input,
							}
						},
					};

					let event = messages::MessagesStreamEvent::ContentBlockDelta {
						index: delta.content_block_index as usize,
						delta: anthropic_delta,
					};
					let (event_name, event_data) = event.into_sse_tuple();
					out.push((event_name, serde_json::to_value(event_data).unwrap()));
				}

				out
			},
			bedrock::ConverseStreamOutput::ContentBlockStop(stop) => {
				self.seen_blocks.remove(&stop.content_block_index);
				let event = messages::MessagesStreamEvent::ContentBlockStop {
					index: stop.content_block_index as usize,
				};
				let (event_name, event_data) = event.into_sse_tuple();
				vec![(event_name, serde_json::to_value(event_data).unwrap())]
			},
			bedrock::ConverseStreamOutput::MessageStop(stop) => {
				self.pending_stop_reason = Some(stop.stop_reason);
				vec![]
			},
			bedrock::ConverseStreamOutput::Metadata(meta) => {
				if let Some(usage) = meta.usage {
					self.pending_usage = Some(usage);
				}

				let mut out = Vec::new();
				let stop = self.pending_stop_reason.take();
				let usage = self.pending_usage.take();

				if let (Some(stop_reason), Some(usage_data)) = (stop, usage) {
					let event = messages::MessagesStreamEvent::MessageDelta {
						delta: messages::MessageDelta {
							stop_reason: Some(super::messages_stop_reason(stop_reason)),
							stop_sequence: None,
						},
						usage: super::to_anthropic_message_delta_usage(usage_data),
					};
					let (event_name, event_data) = event.into_sse_tuple();
					out.push((event_name, serde_json::to_value(event_data).unwrap()));
				}

				let event = messages::MessagesStreamEvent::MessageStop;
				let (event_name, event_data) = event.into_sse_tuple();
				out.push((event_name, serde_json::to_value(event_data).unwrap()));

				out
			},
		}
	}
}
