//! Decoded Bedrock protocol values only; transport and statistics remain external.
pub mod messages;
pub mod responses;
use crate::types::{bedrock, messages::typed as messagest};

pub fn to_anthropic_message_delta_usage(
	usage: bedrock::TokenUsage,
) -> messagest::MessageDeltaUsage {
	messagest::MessageDeltaUsage {
		input_tokens: Some(usage.input_tokens),
		output_tokens: Some(usage.output_tokens),
		cache_creation_input_tokens: usage.cache_write_input_tokens,
		cache_read_input_tokens: usage.cache_read_input_tokens,
	}
}

use crate::types::completions::typed::{self as completions, UsagePromptDetails};
use std::collections::HashSet;

/// Data observations applied by the Host before event mapping, preserving its clock/log order.
pub enum Observation {
	FirstDelta,
	Usage(bedrock::TokenUsage),
}

pub struct CompletionsState {
	tool_calls: HashSet<i32>,
	model: String,
	message_id: String,
	created: u32,
}
impl CompletionsState {
	pub fn new(model: &str, message_id: &str, created: u32) -> Self {
		Self {
			tool_calls: HashSet::new(),
			model: model.to_string(),
			message_id: message_id.to_string(),
			created,
		}
	}
	pub fn observation(event: &bedrock::ConverseStreamOutput) -> Option<Observation> {
		match event {
			bedrock::ConverseStreamOutput::ContentBlockDelta(_) => Some(Observation::FirstDelta),
			bedrock::ConverseStreamOutput::Metadata(m) => m.usage.map(Observation::Usage),
			_ => None,
		}
	}
	/// Tool start names have already been restored by the request-local Host map.
	pub fn push(
		&mut self,
		res: bedrock::ConverseStreamOutput,
	) -> Option<completions::StreamResponse> {
		let Self {
			tool_calls,
			model,
			message_id,
			created,
		} = self;
		let mk = |choices: Vec<completions::ChatChoiceStream>, usage: Option<completions::Usage>| {
			Some(completions::StreamResponse {
				id: message_id.to_string(),
				model: model.to_string(),
				object: "chat.completion.chunk".to_string(),
				system_fingerprint: None,
				service_tier: None,
				created: *created,
				choices,
				usage,
			})
		};
		match res {
			bedrock::ConverseStreamOutput::ContentBlockStart(start) => {
				// Track tool call starts for streaming
				if let Some(bedrock::ContentBlockStart::ToolUse(tu)) = start.start {
					tool_calls.insert(start.content_block_index);
					// Emit the start of a tool call
					let d = completions::StreamResponseDelta {
						tool_calls: Some(vec![completions::ChatCompletionMessageToolCallChunk {
							index: start.content_block_index as u32,
							id: Some(tu.tool_use_id),
							r#type: Some(completions::FunctionType::Function),
							function: Some(completions::FunctionCallStream {
								name: Some(tu.name),
								arguments: None,
							}),
						}]),
						..Default::default()
					};
					let choice = completions::ChatChoiceStream {
						index: 0,
						logprobs: None,
						delta: d,
						finish_reason: None,
					};
					mk(vec![choice], None)
				} else {
					// Text/reasoning starts don't need events in Universal format
					None
				}
			},
			bedrock::ConverseStreamOutput::ContentBlockDelta(d) => {
				let delta = d.delta.map(|delta| {
					let mut dr = completions::StreamResponseDelta::default();
					match delta {
						bedrock::ContentBlockDelta::ReasoningContent(
							bedrock::ReasoningContentBlockDelta::Text(t),
						) => {
							dr.reasoning_content = Some(t);
						},
						bedrock::ContentBlockDelta::ReasoningContent(
							bedrock::ReasoningContentBlockDelta::RedactedContent(_),
						) => {
							dr.reasoning_content = Some("[REDACTED]".to_string());
						},
						bedrock::ContentBlockDelta::ReasoningContent(
							bedrock::ReasoningContentBlockDelta::Signature(sig),
						) => {
							// Forward the cryptographic signature so a replayed thinking block can be
							// validated by Bedrock on the next turn. Bedrock emits a single Signature
							// delta per reasoning block as the terminal piece, so a later overwrite
							// here would be a protocol change, not normal multi-chunk accumulation.
							dr.reasoning_signature = Some(sig);
						},
						bedrock::ContentBlockDelta::ReasoningContent(_) => {},
						bedrock::ContentBlockDelta::Text(t) => {
							dr.content = Some(t);
						},
						bedrock::ContentBlockDelta::ToolUse(tu) => {
							// Only membership is needed; arguments are forwarded, never retained.
							if tool_calls.contains(&d.content_block_index) {
								dr.tool_calls = Some(vec![completions::ChatCompletionMessageToolCallChunk {
									index: d.content_block_index as u32,
									id: None, // Only sent in the first chunk
									r#type: None,
									function: Some(completions::FunctionCallStream {
										name: None,
										arguments: Some(tu.input),
									}),
								}]);
							}
						},
					};
					dr
				});

				if let Some(delta) = delta {
					let choice = completions::ChatChoiceStream {
						index: 0,
						logprobs: None,
						delta,
						finish_reason: None,
					};
					mk(vec![choice], None)
				} else {
					None
				}
			},
			bedrock::ConverseStreamOutput::ContentBlockStop(stop) => {
				// Clean up tool call tracking for this content block
				tool_calls.remove(&stop.content_block_index);
				None
			},
			bedrock::ConverseStreamOutput::MessageStart(start) => {
				// Just send a blob with the role
				let choice = completions::ChatChoiceStream {
					index: 0,
					logprobs: None,
					delta: completions::StreamResponseDelta {
						role: Some(match start.role {
							bedrock::Role::Assistant => completions::Role::Assistant,
							bedrock::Role::User => completions::Role::User,
						}),
						..Default::default()
					},
					finish_reason: None,
				};
				mk(vec![choice], None)
			},
			bedrock::ConverseStreamOutput::MessageStop(stop) => {
				let finish_reason = Some(translate_stop_reason(&stop.stop_reason));

				// Just send a blob with the finish reason
				let choice = completions::ChatChoiceStream {
					index: 0,
					logprobs: None,
					delta: completions::StreamResponseDelta::default(),
					finish_reason,
				};
				mk(vec![choice], None)
			},
			bedrock::ConverseStreamOutput::Metadata(metadata) => {
				if let Some(usage) = metadata.usage {
					mk(
						vec![],
						Some(completions::Usage {
							prompt_tokens: usage.input_tokens as u32,
							completion_tokens: usage.output_tokens as u32,
							total_tokens: usage.total_tokens as u32,
							cache_read_input_tokens: usage.cache_read_input_tokens.map(|i| i as u64),
							cache_creation_input_tokens: usage.cache_write_input_tokens.map(|i| i as u64),
							prompt_tokens_details: usage.cache_read_input_tokens.map(|i| UsagePromptDetails {
								cached_tokens: Some(i as u64),
								audio_tokens: None,
								rest: Default::default(),
							}),
							// TODO: can we get reasoning tokens?
							completion_tokens_details: None,
						}),
					)
				} else {
					None
				}
			},
		}
	}
}
pub fn translate_stop_reason(resp: &bedrock::StopReason) -> completions::FinishReason {
	match resp {
		bedrock::StopReason::EndTurn => completions::FinishReason::Stop,
		bedrock::StopReason::MaxTokens => completions::FinishReason::Length,
		bedrock::StopReason::StopSequence => completions::FinishReason::Stop,
		bedrock::StopReason::ContentFiltered => completions::FinishReason::ContentFilter,
		bedrock::StopReason::GuardrailIntervened => completions::FinishReason::ContentFilter,
		bedrock::StopReason::ToolUse => completions::FinishReason::ToolCalls,
		bedrock::StopReason::ModelContextWindowExceeded => completions::FinishReason::Length,
	}
}

pub fn messages_stop_reason(stop_reason: bedrock::StopReason) -> messagest::StopReason {
	match stop_reason {
		bedrock::StopReason::EndTurn => messagest::StopReason::EndTurn,
		bedrock::StopReason::MaxTokens => messagest::StopReason::MaxTokens,
		bedrock::StopReason::ModelContextWindowExceeded => {
			messagest::StopReason::ModelContextWindowExceeded
		},
		bedrock::StopReason::StopSequence => messagest::StopReason::StopSequence,
		bedrock::StopReason::ToolUse => messagest::StopReason::ToolUse,
		bedrock::StopReason::ContentFiltered | bedrock::StopReason::GuardrailIntervened => {
			messagest::StopReason::Refusal
		},
	}
}
