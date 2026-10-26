pub mod from_responses {
	use types::completions::typed as completions;
	use types::responses::typed as responses;

	use crate::json;
	use crate::llm::{AIError, types};

	/// Translate an OpenAI Responses request into an OpenAI-compatible chat completions request.
	pub fn translate(req: &types::responses::Request) -> Result<Vec<u8>, AIError> {
		let typed =
			json::convert::<_, responses::CreateResponse>(req).map_err(AIError::RequestMarshal)?;
		let xlated = translate_internal(typed);
		serde_json::to_vec(&xlated).map_err(AIError::RequestMarshal)
	}

	fn translate_internal(req: responses::CreateResponse) -> completions::Request {
		let (request, unsupported) =
			gateway_llm::conversion::openai_compat::from_responses::translate_internal(req);
		if let Some(tc) = unsupported {
			tracing::warn!(
				"Unsupported tool choice for OpenAI-compatible chat completions: {:?}",
				tc
			);
		}
		request
	}
}

pub mod to_responses {
	use std::time::Instant;

	use bytes::Bytes;
	use platform_core::strng;
	use rand::RngExt;
	use types::completions::typed as completions;
	use types::responses::typed as responses;

	use crate::http::Body;
	use crate::llm::types::ResponseType;
	use crate::llm::{AIError, AmendOnDrop, logged_response_parsing, types};
	use crate::parse::sse::SseJsonEvent;
	use crate::{json, parse};

	/// Translate an OpenAI-compatible chat completions response into an OpenAI Responses response.
	pub fn translate_response(bytes: &Bytes, model: &str) -> Result<Box<dyn ResponseType>, AIError> {
		let resp = serde_json::from_slice::<completions::Response>(bytes)
			.map_err(logged_response_parsing(bytes))?;
		let typed = translate_response_internal(resp, model);
		let mut passthrough =
			json::convert::<_, types::responses::Response>(&typed).map_err(AIError::ResponseParsing)?;
		passthrough.rest = serde_json::Value::Object(serde_json::Map::new());
		if let Some(usage) = passthrough.usage.as_mut() {
			usage.rest = serde_json::Value::Object(serde_json::Map::new());
		}
		Ok(Box::new(passthrough))
	}

	fn translate_response_internal(resp: completions::Response, model: &str) -> responses::Response {
		let response_id = format!("resp_{:016x}", rand::rng().random::<u64>());
		let builder = types::responses::ResponseBuilder::new(response_id, model.to_string());
		let mut out = gateway_llm::conversion::openai_compat::to_responses::translate_response(
			resp,
			builder.response(responses::Status::InProgress, None, None, None),
		);
		for item in &mut out.output {
			if let responses::OutputItem::Message(message) = item {
				message.id = format!("msg_{:016x}", rand::rng().random::<u64>());
			}
		}
		out
	}

	pub fn translate_stream(b: Body, buffer_limit: usize, log: AmendOnDrop) -> Body {
		let response_id = format!("resp_{:016x}", rand::rng().random::<u64>());
		let message_item_id = format!("msg_{:016x}", rand::rng().random::<u64>());
		let mut state = gateway_llm::streaming::openai_compat::State::new(response_id, message_item_id);
		let mut observer = HostObserver(log);
		parse::sse::json_transform_multi::<completions::StreamResponse, responses::ResponseStreamEvent, _>(
			b,
			buffer_limit,
			move |evt| match evt {
				SseJsonEvent::Done => state.finish(&mut observer),
				SseJsonEvent::Data(Ok(chunk)) => state.push(chunk, &mut observer),
				SseJsonEvent::Data(Err(e)) => {
					tracing::warn!(
						"Failed to parse OpenAI-compatible stream response during translation: {}",
						e
					);
					Vec::new()
				},
			},
		)
	}
	struct HostObserver(AmendOnDrop);
	impl gateway_llm::streaming::openai_compat::Observer for HostObserver {
		fn created_at(&mut self) -> u64 {
			chrono::Utc::now().timestamp() as u64
		}
		fn tool_id(&mut self) -> String {
			format!("call_{:016x}", rand::rng().random::<u64>())
		}
		fn observe(&mut self, observation: gateway_llm::streaming::openai_compat::Observation<'_>) {
			use gateway_llm::streaming::openai_compat::Observation;
			match observation {
				Observation::FirstDelta => self
					.0
					.non_atomic_mutate(|r| r.response.first_token = Some(Instant::now())),
				Observation::Usage(usage) => record_usage(&self.0, usage),
				Observation::Provider {
					model,
					service_tier,
				} => self.0.non_atomic_mutate(|r| {
					r.response.provider_model = Some(strng::new(model));
					if let Some(tier) = service_tier {
						r.response.service_tier = Some(strng::new(tier));
					}
				}),
			}
		}
	}

	use gateway_llm::streaming::responses::usage_output_tokens;

	fn record_usage(log: &AmendOnDrop, u: &completions::Usage) {
		log.non_atomic_mutate(|r| {
			r.response.input_tokens = Some(u.prompt_tokens as u64);
			r.response.output_tokens = Some(usage_output_tokens(u) as u64);
			r.response.total_tokens = Some(u.total_tokens as u64);
			r.response.cached_input_tokens = u
				.prompt_tokens_details
				.as_ref()
				.and_then(|d| d.cached_tokens);
			r.response.reasoning_tokens = u
				.completion_tokens_details
				.as_ref()
				.and_then(|d| d.reasoning_tokens);
		});
	}
}
