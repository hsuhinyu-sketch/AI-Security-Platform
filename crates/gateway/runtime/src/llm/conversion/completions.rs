use std::time::Instant;

use bytes::Bytes;
use platform_core::strng;
use tracing::debug;

use crate::http::Response;
use crate::llm::{AmendOnDrop, types};
use crate::{llm, parse};

pub fn translate_google_error(bytes: &Bytes) -> Result<Bytes, llm::AIError> {
	gateway_llm::conversion::errors::google_to_openai(bytes)
		.map_err(|error| super::response_error(bytes, error))
}

pub mod from_messages {
	use std::time::Instant;

	use bytes::Bytes;
	use platform_core::strng;
	use types::completions::typed as completions;
	use types::messages::typed as messages;

	use crate::llm::types::ResponseType;
	use crate::llm::{AIError, AmendOnDrop, logged_response_parsing, types};
	use crate::parse::sse::SseJsonEvent;

	/// translate an Anthropic messages to an OpenAI completions request
	pub fn translate(req: &types::messages::Request) -> Result<Vec<u8>, AIError> {
		gateway_llm::conversion::completions::from_messages::translate(req).map_err(Into::into)
	}

	pub fn translate_response(bytes: &Bytes) -> Result<Box<dyn ResponseType>, AIError> {
		let anthropic = gateway_llm::conversion::completions::from_messages::translate_response(bytes)
			.map_err(|error| match error {
				gateway_llm::WireError::ResponseParsing(error) => logged_response_parsing(bytes)(error),
				error => error.into(),
			})?;
		Ok(Box::new(anthropic))
	}

	pub fn translate_stream(
		b: crate::http::Body,
		buffer_limit: usize,
		log: AmendOnDrop,
	) -> crate::http::Body {
		use gateway_llm::streaming::completions::{Observation, State};
		let mut state = State::default();
		crate::parse::sse::json_transform_multi::<
			completions::StreamResponse,
			messages::MessagesStreamEvent,
			_,
		>(b, buffer_limit, move |evt| {
			let step = match evt {
				SseJsonEvent::Done => state.finish(),
				SseJsonEvent::Data(Ok(chunk)) => {
					if let Some(usage) = &chunk.usage {
						record_usage(&log, usage);
					}
					state.push(chunk)
				},
				SseJsonEvent::Data(Err(e)) => {
					tracing::warn!(
						"Failed to parse OpenAI stream response during translation: {}",
						e
					);
					return vec![];
				},
			};
			for observation in step.observations {
				match observation {
					Observation::ProviderModel(model) => {
						log.non_atomic_mutate(|r| r.response.provider_model = Some(strng::new(&model)))
					},
					Observation::FirstToken => {
						log.non_atomic_mutate(|r| r.response.first_token = Some(Instant::now()))
					},
					Observation::Usage(usage) => record_usage(&log, &usage),
				}
			}
			step.events
		})
	}

	fn record_usage(log: &AmendOnDrop, usage: &completions::Usage) {
		log.non_atomic_mutate(|r| {
			r.response.input_tokens = Some(usage.prompt_tokens as u64);
			r.response.output_tokens = Some(usage.completion_tokens as u64);
			r.response.total_tokens = Some(usage.total_tokens as u64);
		});
	}

	pub fn translate_error(bytes: &Bytes, status: ::http::StatusCode) -> Result<Bytes, AIError> {
		gateway_llm::conversion::errors::openai_to_anthropic(bytes, status)
			.map_err(|error| super::super::response_error(bytes, error))
	}
}

pub fn passthrough_stream(
	mut log: AmendOnDrop,
	include_completion_in_log: bool,
	resp: Response,
) -> Response {
	let mut completion = include_completion_in_log.then(String::new);
	let buffer_limit = crate::http::response_buffer_limit(&resp);
	resp.map(|b| {
		let mut seen_provider = false;
		let mut saw_token = false;
		parse::sse::json_passthrough::<types::completions::typed::StreamResponse>(
			b,
			buffer_limit,
			move |f| {
				match f {
					Some(Ok(f)) => {
						if let Some(c) = completion.as_mut()
							&& let Some(delta) = f.choices.first().and_then(|c| c.delta.content.as_deref())
						{
							c.push_str(delta);
						}
						if !saw_token {
							saw_token = true;
							log.non_atomic_mutate(|r| {
								r.response.first_token = Some(Instant::now());
							});
						}
						if !seen_provider {
							seen_provider = true;
							log.non_atomic_mutate(|r| {
								r.response.provider_model = Some(strng::new(&f.model));
								r.response.service_tier = f.service_tier.as_deref().map(Into::into);
							});
						}
						if let Some(u) = f.usage {
							log.non_atomic_mutate(|r| {
								r.response.input_tokens = Some(u.prompt_tokens as u64);
								r.response.input_audio_tokens = u
									.prompt_tokens_details
									.as_ref()
									.and_then(|d| d.audio_tokens);
								r.response.output_tokens = Some(u.completion_tokens as u64);
								r.response.output_audio_tokens = u
									.completion_tokens_details
									.as_ref()
									.and_then(|d| d.audio_tokens);
								r.response.total_tokens = Some(u.total_tokens as u64);
								r.response.cached_input_tokens = u
									.prompt_tokens_details
									.as_ref()
									.and_then(|d| d.cached_tokens);
								r.response.cache_creation_input_tokens = u.cache_creation_input_tokens;
								r.response.reasoning_tokens = u
									.completion_tokens_details
									.as_ref()
									.and_then(|d| d.reasoning_tokens);
								if let Some(c) = completion.take() {
									r.response.completion = Some(vec![c]);
								}
							});

							log.report_rate_limit();
						}
					},
					Some(Err(e)) => {
						debug!("failed to parse streaming response: {e}");
					},
					None => {
						// We are done, try to set completion if we haven't already
						// This is useful in case we never see "usage"
						log.non_atomic_mutate(|r| {
							if let Some(c) = completion.take() {
								r.response.completion = Some(vec![c]);
							}
						});
					},
				}
			},
		)
	})
}
