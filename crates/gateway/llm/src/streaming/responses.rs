//! Responses event construction and terminal state transitions.
//! IDs and timestamps are explicit inputs; this module has no clock or RNG.
use crate::types::{completions::typed as completions, responses::typed};
use std::collections::HashMap;
use typed::{
	AssistantRole, ErrorObject, FunctionToolCall, IncompleteDetails, InputTokenDetails,
	OutputContent, OutputItem, OutputMessage, OutputStatus, OutputTextContent, OutputTokenDetails,
	ResponseContentPartDoneEvent, ResponseFunctionCallArgumentsDoneEvent,
	ResponseOutputItemDoneEvent, ResponseStreamEvent, ResponseUsage,
};
pub struct ResponseBuilder {
	response_id: String,
	model: String,
	created_at: u64,
}

impl ResponseBuilder {
	pub fn new_at(response_id: impl Into<String>, model: impl Into<String>, created_at: u64) -> Self {
		Self {
			response_id: response_id.into(),
			model: model.into(),
			created_at,
		}
	}

	pub fn response(
		&self,
		status: typed::Status,
		usage: Option<typed::ResponseUsage>,
		error: Option<typed::ErrorObject>,
		incomplete_details: Option<typed::IncompleteDetails>,
	) -> typed::Response {
		typed::Response {
			background: None,
			billing: None,
			conversation: None,
			created_at: self.created_at,
			completed_at: None,
			error,
			id: self.response_id.clone(),
			incomplete_details,
			instructions: None,
			max_output_tokens: None,
			metadata: None,
			model: self.model.clone(),
			object: "response".to_string(),
			output: Vec::new(),
			parallel_tool_calls: None,
			previous_response_id: None,
			prompt: None,
			prompt_cache_key: None,
			prompt_cache_retention: None,
			reasoning: None,
			safety_identifier: None,
			service_tier: None,
			status,
			temperature: None,
			text: None,
			tool_choice: None,
			tools: None,
			top_logprobs: None,
			top_p: None,
			truncation: None,
			usage,
		}
	}

	pub fn created_event(&self, sequence_number: u64) -> typed::ResponseStreamEvent {
		typed::ResponseStreamEvent::ResponseCreated(typed::ResponseCreatedEvent {
			sequence_number,
			response: self.response(typed::Status::InProgress, None, None, None),
		})
	}

	pub fn completed_event(
		&self,
		sequence_number: u64,
		usage: Option<typed::ResponseUsage>,
	) -> typed::ResponseStreamEvent {
		typed::ResponseStreamEvent::ResponseCompleted(typed::ResponseCompletedEvent {
			sequence_number,
			response: self.response(typed::Status::Completed, usage, None, None),
		})
	}

	pub fn incomplete_event(
		&self,
		sequence_number: u64,
		usage: Option<typed::ResponseUsage>,
		incomplete_details: typed::IncompleteDetails,
	) -> typed::ResponseStreamEvent {
		typed::ResponseStreamEvent::ResponseIncomplete(typed::ResponseIncompleteEvent {
			sequence_number,
			response: self.response(
				typed::Status::Incomplete,
				usage,
				None,
				Some(incomplete_details),
			),
		})
	}

	pub fn failed_event(
		&self,
		sequence_number: u64,
		usage: Option<typed::ResponseUsage>,
		error: typed::ErrorObject,
	) -> typed::ResponseStreamEvent {
		typed::ResponseStreamEvent::ResponseFailed(typed::ResponseFailedEvent {
			sequence_number,
			response: self.response(typed::Status::Failed, usage, Some(error), None),
		})
	}
}

pub fn usage_output_tokens(usage: &completions::Usage) -> u32 {
	if usage.completion_tokens == 0 && usage.total_tokens > 0 {
		return usage.total_tokens.saturating_sub(usage.prompt_tokens);
	}
	usage.completion_tokens
}

/// Close per-stream tool/content items and drain the explicit tool accumulator.
pub fn close_items(
	events: &mut Vec<(&'static str, ResponseStreamEvent)>,
	sequence_number: &mut u64,
	tool_calls: &mut HashMap<u32, (String, String, String, u32)>,
	message_item_id: &str,
	sent_content_part: bool,
) {
	let mut sorted_tools: Vec<_> = tool_calls.drain().collect();
	sorted_tools.sort_by_key(|(_, (_, _, _, output_index))| *output_index);

	for (_, (item_id, name, buffer, output_index)) in sorted_tools {
		*sequence_number += 1;
		events.push((
			"event",
			ResponseStreamEvent::ResponseFunctionCallArgumentsDone(
				ResponseFunctionCallArgumentsDoneEvent {
					sequence_number: *sequence_number,
					output_index,
					name: Some(name.clone()),
					item_id: item_id.clone(),
					arguments: buffer.clone(),
				},
			),
		));

		*sequence_number += 1;
		events.push((
			"event",
			ResponseStreamEvent::ResponseOutputItemDone(ResponseOutputItemDoneEvent {
				sequence_number: *sequence_number,
				output_index,
				item: OutputItem::FunctionCall(FunctionToolCall {
					arguments: buffer,
					call_id: item_id.clone(),
					namespace: None,
					name,
					id: Some(item_id),
					status: Some(OutputStatus::Completed),
				}),
			}),
		));
	}

	if sent_content_part {
		*sequence_number += 1;
		events.push((
			"event",
			ResponseStreamEvent::ResponseContentPartDone(ResponseContentPartDoneEvent {
				sequence_number: *sequence_number,
				item_id: message_item_id.to_string(),
				output_index: 0,
				content_index: 0,
				part: OutputContent::OutputText(OutputTextContent {
					annotations: Vec::new(),
					logprobs: None,
					text: String::new(),
				}),
			}),
		));
	}

	*sequence_number += 1;
	events.push((
		"event",
		ResponseStreamEvent::ResponseOutputItemDone(ResponseOutputItemDoneEvent {
			sequence_number: *sequence_number,
			output_index: 0,
			item: OutputItem::Message(OutputMessage {
				content: Vec::new(),
				id: message_item_id.to_string(),
				role: AssistantRole::Assistant,
				phase: None,
				status: OutputStatus::Completed,
			}),
		}),
	));
}
/// Normalize the original usage fields before Host captures its terminal timestamp.
pub fn normalize_usage(usage: Option<completions::Usage>) -> Option<ResponseUsage> {
	usage.map(|u| ResponseUsage {
		input_tokens: u.prompt_tokens,
		output_tokens: usage_output_tokens(&u),
		total_tokens: u.total_tokens,
		input_tokens_details: InputTokenDetails {
			cached_tokens: u
				.prompt_tokens_details
				.as_ref()
				.and_then(|d| d.cached_tokens)
				.unwrap_or(0) as u32,
		},
		output_tokens_details: OutputTokenDetails {
			reasoning_tokens: u
				.completion_tokens_details
				.as_ref()
				.and_then(|d| d.reasoning_tokens)
				.unwrap_or(0) as u32,
		},
	})
}

/// Consume the pending finish reason and usage into the original terminal event.
pub fn terminal_event(
	builder: &ResponseBuilder,
	sequence_number: &mut u64,
	stop_reason: Option<completions::FinishReason>,
	usage_obj: Option<ResponseUsage>,
) -> ResponseStreamEvent {
	*sequence_number += 1;
	let done_event = match stop_reason {
		Some(completions::FinishReason::Stop)
		| Some(completions::FinishReason::ToolCalls)
		| Some(completions::FinishReason::FunctionCall)
		| None => builder.completed_event(*sequence_number, usage_obj),
		Some(completions::FinishReason::Length) => builder.incomplete_event(
			*sequence_number,
			usage_obj,
			IncompleteDetails {
				reason: "max_tokens".to_string(),
			},
		),
		Some(completions::FinishReason::ContentFilter) => builder.failed_event(
			*sequence_number,
			usage_obj,
			ErrorObject {
				code: "content_filter".to_string(),
				message: "Content filtered".to_string(),
			},
		),
	};

	done_event
}
