use std::time::Instant;

use bytes::Bytes;
use platform_core::strng;

use crate::http::Body;
use crate::llm::types::messages::typed as messages;
use crate::llm::{AIError, AmendOnDrop};
use crate::parse;

pub fn translate_anthropic_error(
	bytes: &Bytes,
	status: ::http::StatusCode,
) -> Result<Bytes, AIError> {
	gateway_llm::conversion::errors::normalize_anthropic(bytes, status)
		.map_err(|error| super::response_error(bytes, error))
}

/// Translate a Google error response into an Anthropic Messages error response.
pub fn translate_google_error(bytes: &Bytes) -> Result<Bytes, AIError> {
	gateway_llm::conversion::errors::google_to_anthropic(bytes)
		.map_err(|error| super::response_error(bytes, error))
}

pub mod from_completions {
	use std::time::Instant;

	use bytes::Bytes;
	use platform_core::strng;

	use crate::http::Body;
	use crate::llm::types::ResponseType;
	use crate::llm::types::completions::typed as completions;
	use crate::llm::types::messages::typed as messages;
	use crate::llm::{AIError, AmendOnDrop, logged_response_parsing, types};
	use crate::{json, parse};

	/// translate an OpenAI completions request to an anthropic messages request
	pub fn translate(req: &types::completions::Request) -> Result<Vec<u8>, AIError> {
		gateway_llm::conversion::messages::from_completions::translate(req).map_err(Into::into)
	}

	pub fn translate_response(bytes: &Bytes) -> Result<Box<dyn ResponseType>, AIError> {
		let resp = serde_json::from_slice::<messages::MessagesResponse>(bytes)
			.map_err(logged_response_parsing(bytes))?;
		let openai = translate_response_internal(resp);
		let passthrough = json::convert::<_, types::completions::Response>(&openai)
			.map_err(AIError::ResponseParsing)?;
		Ok(Box::new(passthrough))
	}

	fn translate_response_internal(resp: messages::MessagesResponse) -> completions::Response {
		let mut response =
			gateway_llm::conversion::messages::from_completions::translate_response(resp);
		response.created = chrono::Utc::now().timestamp() as u32;
		response
	}

	pub fn translate_error(bytes: &Bytes) -> Result<Bytes, AIError> {
		gateway_llm::conversion::errors::anthropic_to_openai(bytes)
			.map_err(|error| super::super::response_error(bytes, error))
	}

	pub fn translate_stream(b: Body, buffer_limit: usize, log: AmendOnDrop) -> Body {
		use gateway_llm::streaming::messages::{Observation, State};
		let created = chrono::Utc::now().timestamp() as u32;
		let mut state = State::new(created);
		parse::sse::json_transform::<messages::MessagesStreamEvent, completions::StreamResponse>(
			b,
			buffer_limit,
			move |event| {
				let event = event.ok()?;
				let step = state.push(event);
				for observation in step.observations {
					match observation {
						Observation::Start { model, usage } => log.non_atomic_mutate(|r| {
							r.response.output_tokens = Some(usage.output_tokens as u64);
							r.response.input_tokens = Some(usage.input_tokens as u64);
							r.response.cached_input_tokens = usage.cache_read_input_tokens.map(|i| i as u64);
							r.response.cache_creation_input_tokens =
								usage.cache_creation_input_tokens.map(|i| i as u64);
							r.response.service_tier = usage.service_tier.as_deref().map(Into::into);
							r.response.provider_model = Some(strng::new(&model));
						}),
						Observation::FirstToken => {
							log.non_atomic_mutate(|r| r.response.first_token = Some(Instant::now()))
						},
						Observation::Usage(usage) => log.non_atomic_mutate(|r| {
							if let Some(crt) = usage.cache_read_input_tokens {
								r.response.cached_input_tokens = Some(crt as u64);
							}
							if let Some(cwt) = usage.cache_creation_input_tokens {
								r.response.cache_creation_input_tokens = Some(cwt as u64);
							}
							if let Some(o) = usage.output_tokens {
								r.response.output_tokens = Some(o as u64);
							}
							if let Some(inp) = r.response.input_tokens
								&& let Some(o) = r.response.output_tokens
							{
								r.response.total_tokens = Some(inp + o);
							}
						}),
					}
				}
				step.event
			},
		)
	}
}

pub fn passthrough_stream(
	b: Body,
	buffer_limit: usize,
	log: AmendOnDrop,
	include_completion_in_log: bool,
) -> Body {
	let mut saw_token = false;
	let mut completion = include_completion_in_log.then(String::new);
	// https://platform.claude.com/docs/en/build-with-claude/streaming
	parse::sse::json_passthrough::<messages::MessagesStreamEvent>(b, buffer_limit, move |f| {
		// ignore errors... what else can we do?
		let Some(Ok(f)) = f else {
			// Stream ended ([DONE]): flush completion if not already set via MessageDelta
			if f.is_none() {
				log.non_atomic_mutate(|r| {
					if let Some(c) = completion.take() {
						r.response.completion = Some(vec![c]);
					}
				});
			}
			return;
		};

		// Extract info we need
		match f {
			messages::MessagesStreamEvent::MessageStart { message } => {
				log.non_atomic_mutate(|r| {
					r.response.output_tokens = Some(message.usage.output_tokens as u64);
					r.response.input_tokens = Some(message.usage.input_tokens as u64);
					r.response.cached_input_tokens = message.usage.cache_read_input_tokens.map(|i| i as u64);
					r.response.cache_creation_input_tokens =
						message.usage.cache_creation_input_tokens.map(|i| i as u64);
					r.response.service_tier = message.usage.service_tier.as_deref().map(Into::into);
					r.response.provider_model = Some(strng::new(&message.model))
				});
			},
			messages::MessagesStreamEvent::ContentBlockDelta { delta, .. } => {
				if !saw_token {
					saw_token = true;
					log.non_atomic_mutate(|r| {
						r.response.first_token = Some(Instant::now());
					});
				}
				if let Some(c) = completion.as_mut()
					&& let messages::ContentBlockDelta::TextDelta { text } = &delta
				{
					c.push_str(text);
				}
			},
			messages::MessagesStreamEvent::MessageDelta { usage, delta: _ } => {
				log.non_atomic_mutate(|r| {
					if let Some(o) = usage.output_tokens {
						r.response.output_tokens = Some(o as u64);
					}
					if let Some(crt) = usage.cache_read_input_tokens {
						r.response.cached_input_tokens = Some(crt as u64);
					}
					if let Some(cwt) = usage.cache_creation_input_tokens {
						r.response.cache_creation_input_tokens = Some(cwt as u64);
					}
					if let Some(inp) = r.response.input_tokens
						&& let Some(o) = r.response.output_tokens
					{
						r.response.total_tokens = Some(inp + o)
					}
					if let Some(c) = completion.take() {
						r.response.completion = Some(vec![c]);
					}
				});
			},
			messages::MessagesStreamEvent::ContentBlockStart { .. }
			| messages::MessagesStreamEvent::ContentBlockStop { .. }
			| messages::MessagesStreamEvent::MessageStop
			| messages::MessagesStreamEvent::Ping => {},
		}
	})
}
