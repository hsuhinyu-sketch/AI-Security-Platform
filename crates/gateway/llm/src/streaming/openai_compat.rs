//! OpenAI-compatible Responses stream transitions. No transport or execution state.
use super::responses::ResponseBuilder;
use crate::types::{completions::typed as completions, responses::typed as responses};
use responses::{
	AssistantRole, FunctionToolCall, OutputContent, OutputItem, OutputMessage, OutputStatus,
	OutputTextContent, ResponseContentPartAddedEvent, ResponseFunctionCallArgumentsDeltaEvent,
	ResponseOutputItemAddedEvent, ResponseStreamEvent, ResponseTextDeltaEvent,
};
use std::collections::HashMap;

pub enum Observation<'a> {
	FirstDelta,
	Provider {
		model: &'a str,
		service_tier: Option<&'a str>,
	},
	Usage(&'a completions::Usage),
}
/// Supplies request-local metadata and receives observations at protocol-defined positions.
/// This interface contains no authorization, network or configuration capability.
pub trait Observer {
	fn created_at(&mut self) -> u64;
	fn tool_id(&mut self) -> String;
	fn observe(&mut self, observation: Observation<'_>);
}
pub struct State {
	saw_token: bool,
	sent_created: bool,
	sent_content_part: bool,
	flushed: bool,
	sequence_number: u64,
	response_id: String,
	message_item_id: String,
	model: String,
	next_output_index: u32,
	tool_calls: HashMap<u32, (String, String, String, u32)>,
	pending_stop_reason: Option<completions::FinishReason>,
	pending_usage: Option<completions::Usage>,
}
impl State {
	pub fn new(response_id: String, message_item_id: String) -> Self {
		Self {
			saw_token: false,
			sent_created: false,
			sent_content_part: false,
			flushed: false,
			sequence_number: 0,
			response_id,
			message_item_id,
			model: String::new(),
			next_output_index: 1,
			tool_calls: HashMap::new(),
			pending_stop_reason: None,
			pending_usage: None,
		}
	}
	pub fn push(
		&mut self,
		chunk: completions::StreamResponse,
		observer: &mut impl Observer,
	) -> Vec<(&'static str, ResponseStreamEvent)> {
		let mut events = Vec::new();

		if !self.sent_created {
			self.sent_created = true;
			self.model = chunk.model.clone();

			let response_builder = ResponseBuilder::new_at(
				self.response_id.clone(),
				chunk.model.clone(),
				observer.created_at(),
			);

			self.sequence_number += 1;
			events.push((
				"event",
				response_builder.created_event(self.sequence_number),
			));

			self.sequence_number += 1;
			events.push((
				"event",
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
				}),
			));

			observer.observe(Observation::Provider {
				model: &chunk.model,
				service_tier: chunk.service_tier.as_deref(),
			});
		}

		if let Some(usage) = chunk.usage {
			observer.observe(Observation::Usage(&usage));
			self.pending_usage = Some(usage);
		}

		if let Some(choice) = chunk.choices.first() {
			if let Some(content) = &choice.delta.content {
				if !self.sent_content_part {
					self.sent_content_part = true;
					self.sequence_number += 1;
					events.push((
						"event",
						ResponseStreamEvent::ResponseContentPartAdded(ResponseContentPartAddedEvent {
							sequence_number: self.sequence_number,
							item_id: self.message_item_id.clone(),
							output_index: 0,
							content_index: 0,
							part: OutputContent::OutputText(OutputTextContent {
								text: String::new(),
								annotations: Vec::new(),
								logprobs: None,
							}),
						}),
					));
				}

				if !self.saw_token {
					self.saw_token = true;
					observer.observe(Observation::FirstDelta);
				}

				self.sequence_number += 1;
				events.push((
					"event",
					ResponseStreamEvent::ResponseOutputTextDelta(ResponseTextDeltaEvent {
						sequence_number: self.sequence_number,
						item_id: self.message_item_id.clone(),
						output_index: 0,
						content_index: 0,
						delta: content.clone(),
						logprobs: None,
					}),
				));
			}

			if let Some(tcs) = &choice.delta.tool_calls {
				for tc in tcs {
					let tool_index = tc.index;

					let is_new = !self.tool_calls.contains_key(&tool_index);

					let entry = self.tool_calls.entry(tool_index).or_insert_with(|| {
						let item_id = observer.tool_id();
						let output_index = self.next_output_index;
						self.next_output_index += 1;
						(item_id, String::new(), String::new(), output_index)
					});

					if let Some(function) = &tc.function {
						if let Some(name) = &function.name {
							entry.1 = name.clone();
						}
						if let Some(args) = &function.arguments {
							entry.2.push_str(args);
						}
					}

					if is_new {
						if !self.saw_token {
							self.saw_token = true;
							observer.observe(Observation::FirstDelta);
						}

						self.sequence_number += 1;
						events.push((
							"event",
							ResponseStreamEvent::ResponseOutputItemAdded(ResponseOutputItemAddedEvent {
								sequence_number: self.sequence_number,
								output_index: entry.3,
								item: OutputItem::FunctionCall(FunctionToolCall {
									arguments: String::new(),
									call_id: entry.0.clone(),
									namespace: None,
									name: entry.1.clone(),
									id: Some(entry.0.clone()),
									status: Some(OutputStatus::InProgress),
								}),
							}),
						));
					}

					if let Some(function) = &tc.function
						&& let Some(args) = &function.arguments
						&& !args.is_empty()
					{
						self.sequence_number += 1;
						events.push((
							"event",
							ResponseStreamEvent::ResponseFunctionCallArgumentsDelta(
								ResponseFunctionCallArgumentsDeltaEvent {
									sequence_number: self.sequence_number,
									item_id: entry.0.clone(),
									output_index: entry.3,
									delta: args.clone(),
								},
							),
						));
					}
				}
			}

			if let Some(reason) = &choice.finish_reason {
				self.pending_stop_reason = Some(*reason);
			}
		}

		if !self.flushed && self.pending_stop_reason.is_some() && self.pending_usage.is_some() {
			self.flushed = true;
			self.flush_end(&mut events, observer);
		}

		events
	}
	pub fn finish(
		&mut self,
		observer: &mut impl Observer,
	) -> Vec<(&'static str, ResponseStreamEvent)> {
		let mut events = Vec::new();
		if !self.flushed {
			self.flushed = true;
			self.flush_end(&mut events, observer);
		}
		events
	}
	fn flush_end(
		&mut self,
		events: &mut Vec<(&'static str, ResponseStreamEvent)>,
		observer: &mut impl Observer,
	) {
		let stop_reason = self.pending_stop_reason.take();
		let usage = self.pending_usage.take();
		super::responses::close_items(
			events,
			&mut self.sequence_number,
			&mut self.tool_calls,
			&self.message_item_id,
			self.sent_content_part,
		);
		if let Some(ref usage) = usage {
			observer.observe(Observation::Usage(usage));
		}

		let usage_obj = super::responses::normalize_usage(usage);

		let response_builder = ResponseBuilder::new_at(
			self.response_id.to_string(),
			self.model.to_string(),
			observer.created_at(),
		);
		let done_event = super::responses::terminal_event(
			&response_builder,
			&mut self.sequence_number,
			stop_reason,
			usage_obj,
		);
		events.push(("event", done_event));
	}
}
