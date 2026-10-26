#[cfg(feature = "providers-aws")]
mod streaming;

use rand::RngExt;
use tracing::trace;

use crate::http::Response;
use crate::llm::AIError;
use crate::llm::types::{bedrock, messages, responses};

use gateway_llm::provider::bedrock::restore_tool_name;
// Preserve the former Runtime path for downstream source compatibility.
#[allow(unused_imports)]
pub use gateway_llm::provider::bedrock::BEDROCK_TOOL_NAME_MAX_LEN;
pub use gateway_llm::provider::bedrock::BedrockToolNameMap;

pub use gateway_llm::provider::request::EncodedRequest as BedrockRequest;

fn request_options(
	provider: &crate::llm::bedrock::Provider,
	beta: bool,
) -> gateway_llm::conversion::bedrock::request::ConverseOptions<'_> {
	gateway_llm::conversion::bedrock::request::ConverseOptions {
		guardrail_identifier: provider.guardrail_identifier.as_deref(),
		guardrail_version: provider.guardrail_version.as_deref(),
		allowed_beta_headers: if beta {
			&helpers::ALLOWED_BETA_HEADERS
		} else {
			&[]
		},
	}
}

pub(crate) fn invalid_request_error(bytes: &bytes::Bytes) -> Result<bytes::Bytes, AIError> {
	gateway_llm::conversion::errors::bedrock_to_openai(bytes)
		.map_err(|error| super::response_error(bytes, error))
}

pub mod from_rerank {
	use crate::llm::bedrock::Provider;
	use crate::llm::types::ResponseType;
	use crate::llm::{AIError, logged_response_parsing, types};

	pub fn translate(req: &types::rerank::Request, provider: &Provider) -> Result<Vec<u8>, AIError> {
		gateway_llm::conversion::bedrock::from_rerank::translate(
			req,
			provider.model.as_deref(),
			provider.region.as_str(),
		)
		.map_err(Into::into)
	}

	/// Bedrock returns only `index` + `relevanceScore`; it does not echo document text.
	pub fn translate_response(bytes: &[u8]) -> Result<Box<dyn ResponseType>, AIError> {
		let resp: types::bedrock::RerankResponse =
			serde_json::from_slice(bytes).map_err(logged_response_parsing(bytes))?;
		Ok(Box::new(
			gateway_llm::conversion::bedrock::from_rerank::translate_response(resp),
		))
	}
}

pub mod from_embeddings {
	use crate::llm::bedrock::Provider;
	use crate::llm::types::ResponseType;
	use crate::llm::{AIError, logged_response_parsing, types};

	pub fn translate(
		req: &types::embeddings::Request,
		provider: &Provider,
	) -> Result<Vec<u8>, AIError> {
		gateway_llm::conversion::bedrock::from_embeddings::translate(req, provider.model.as_deref())
			.map_err(Into::into)
	}

	pub fn translate_response(
		bytes: &[u8],
		headers: &http::HeaderMap,
		model: &str,
	) -> Result<Box<dyn ResponseType>, AIError> {
		if model.contains("cohere") {
			let resp: types::bedrock::CohereEmbeddingResponse =
				serde_json::from_slice(bytes).map_err(logged_response_parsing(bytes))?;

			// Cohere doesn't include token counts in the JSON body;
			// Bedrock surfaces them via response headers instead.
			let prompt_tokens = headers
				.get("x-amzn-bedrock-input-token-count")
				.and_then(|v| v.to_str().ok())
				.and_then(|v| v.parse::<u64>().ok())
				.unwrap_or(0);

			Ok(Box::new(
				gateway_llm::conversion::bedrock::from_embeddings::from_cohere_response(
					resp,
					model,
					prompt_tokens,
				)
				.map_err(AIError::from)?,
			))
		} else {
			let resp: types::bedrock::AmazonTitanV2EmbeddingResponse =
				serde_json::from_slice(bytes).map_err(logged_response_parsing(bytes))?;
			Ok(Box::new(
				gateway_llm::conversion::bedrock::from_embeddings::from_titan_response(resp, model)
					.map_err(AIError::from)?,
			))
		}
	}
}

pub mod from_completions {
	use std::time::Instant;

	use bytes::Bytes;
	use types::bedrock;

	use crate::http::Body;
	use crate::llm::bedrock::Provider;
	use crate::llm::types::ResponseType;
	use crate::llm::{AIError, AmendOnDrop, logged_response_parsing, types};
	use crate::{json, parse};

	pub fn translate(
		req: &types::completions::Request,
		provider: &Provider,
		headers: Option<&http::HeaderMap>,
		prompt_caching: Option<&crate::llm::policy::PromptCachingConfig>,
	) -> Result<super::BedrockRequest, AIError> {
		gateway_llm::conversion::bedrock::request::from_completions::translate(
			req,
			&super::request_options(provider, false),
			headers,
			prompt_caching,
		)
		.map_err(Into::into)
	}

	pub fn translate_response(
		bytes: &Bytes,
		model: &str,
		tool_name_map: Option<&super::BedrockToolNameMap>,
	) -> Result<Box<dyn ResponseType>, AIError> {
		let resp = serde_json::from_slice::<bedrock::ConverseResponse>(bytes)
			.map_err(logged_response_parsing(bytes))?;
		let openai = translate_response_internal(resp, model, tool_name_map)?;
		let passthrough = json::convert::<_, types::completions::Response>(&openai)
			.map_err(AIError::ResponseParsing)?;
		Ok(Box::new(passthrough))
	}

	fn translate_response_internal(
		resp: bedrock::ConverseResponse,
		model: &str,
		tool_name_map: Option<&super::BedrockToolNameMap>,
	) -> Result<types::completions::typed::Response, AIError> {
		let adapter = super::ConverseResponseAdapter::from_response(resp, model)?;
		Ok(adapter.to_completions(tool_name_map))
	}

	#[cfg(feature = "providers-aws")]
	pub fn translate_stream(
		b: Body,
		buffer_limit: usize,
		log: AmendOnDrop,
		model: &str,
		message_id: &str,
		tool_name_map: Option<super::BedrockToolNameMap>,
	) -> Body {
		// This is static for all chunks!
		let created = chrono::Utc::now().timestamp() as u32;
		let mut saw_token = false;
		use gateway_llm::streaming::bedrock::{CompletionsState, Observation};
		let mut state = CompletionsState::new(model, message_id, created);
		let done = Some(parse::encode_sse_event("", Bytes::from_static(b"[DONE]")));
		super::streaming::translate(b, buffer_limit, done, move |mut res| {
			match CompletionsState::observation(&res) {
				Some(Observation::FirstDelta) if !saw_token => {
					saw_token = true;
					log.non_atomic_mutate(|r| {
						r.response.first_token = Some(Instant::now());
					});
				},
				Some(Observation::Usage(usage)) => {
					log.non_atomic_mutate(|r| {
						r.response.output_tokens = Some(usage.output_tokens as u64);
						r.response.input_tokens = Some(usage.input_tokens as u64);
						r.response.total_tokens = Some(usage.total_tokens as u64);
						r.response.cached_input_tokens = usage.cache_read_input_tokens.map(|i| i as u64);
						r.response.cache_creation_input_tokens =
							usage.cache_write_input_tokens.map(|i| i as u64);
					});
				},
				_ => {},
			}
			if let bedrock::ConverseStreamOutput::ContentBlockDelta(bedrock::ContentBlockDeltaEvent {
				delta: Some(bedrock::ContentBlockDelta::ReasoningContent(other)),
				..
			}) = &res
			{
				match other {
					bedrock::ReasoningContentBlockDelta::Text(_)
					| bedrock::ReasoningContentBlockDelta::RedactedContent(_)
					| bedrock::ReasoningContentBlockDelta::Signature(_) => {},
					other => tracing::debug!(?other, "unhandled Bedrock reasoning content delta variant"),
				}
			}
			if let bedrock::ConverseStreamOutput::ContentBlockStart(start) = &mut res {
				if let Some(bedrock::ContentBlockStart::ToolUse(tu)) = &mut start.start {
					tu.name = super::restore_tool_name(tool_name_map.as_ref(), &tu.name);
				}
			}
			state
				.push(res)
				.map(|event| ("", event))
				.into_iter()
				.collect()
		})
	}
}

pub mod from_messages {
	use std::time::Instant;

	use bytes::Bytes;
	use types::bedrock;

	use super::helpers;
	use crate::http::Body;
	use crate::json;
	use crate::llm::bedrock::Provider;
	use crate::llm::types::ResponseType;
	use crate::llm::{AIError, AmendOnDrop, logged_response_parsing, types};

	/// translate an Anthropic messages request to a Bedrock converse request
	pub fn translate(
		req: &types::messages::Request,
		provider: &Provider,
		headers: Option<&http::HeaderMap>,
	) -> Result<super::BedrockRequest, AIError> {
		gateway_llm::conversion::bedrock::request::from_messages::translate(
			req,
			&super::request_options(provider, true),
			headers,
		)
		.map_err(Into::into)
	}

	pub fn translate_response(
		bytes: &Bytes,
		model: &str,
		tool_name_map: Option<&super::BedrockToolNameMap>,
	) -> Result<Box<dyn ResponseType>, AIError> {
		let resp = serde_json::from_slice::<bedrock::ConverseResponse>(bytes)
			.map_err(logged_response_parsing(bytes))?;
		let openai = translate_response_internal(resp, model, tool_name_map)?;
		let passthrough =
			json::convert::<_, types::messages::Response>(&openai).map_err(AIError::ResponseParsing)?;
		Ok(Box::new(passthrough))
	}

	fn translate_response_internal(
		resp: bedrock::ConverseResponse,
		model: &str,
		tool_name_map: Option<&super::BedrockToolNameMap>,
	) -> Result<types::messages::typed::MessagesResponse, AIError> {
		let adapter = super::ConverseResponseAdapter::from_response(resp, model)?;
		adapter.to_anthropic(tool_name_map)
	}

	pub fn translate_error(bytes: &Bytes) -> Result<Bytes, AIError> {
		gateway_llm::conversion::errors::bedrock_to_anthropic(bytes)
			.map_err(|error| super::super::response_error(bytes, error))
	}

	#[cfg(feature = "providers-aws")]
	pub fn translate_stream(
		b: Body,
		buffer_limit: usize,
		log: AmendOnDrop,
		model: &str,
		_message_id: &str,
		include_completion_in_log: bool,
		tool_name_map: Option<super::BedrockToolNameMap>,
	) -> Body {
		let mut saw_token = false;
		let mut completion = include_completion_in_log.then(String::new);
		let mut state =
			gateway_llm::streaming::bedrock::messages::MessagesState::new(model, tool_name_map);
		super::streaming::translate(b, buffer_limit, None, move |event| {
			match &event {
				bedrock::ConverseStreamOutput::ContentBlockDelta(delta) => {
					if let Some(d) = &delta.delta {
						if !saw_token {
							saw_token = true;
							log.non_atomic_mutate(|r| r.response.first_token = Some(Instant::now()));
						}
						if let bedrock::ContentBlockDelta::Text(text) = d
							&& let Some(c) = completion.as_mut()
						{
							c.push_str(text);
						}
					}
				},
				bedrock::ConverseStreamOutput::Metadata(meta) => {
					if let Some(usage) = meta.usage {
						log.non_atomic_mutate(|r| {
							r.response.output_tokens = Some(usage.output_tokens as u64);
							r.response.input_tokens = Some(usage.input_tokens as u64);
							r.response.total_tokens = Some(usage.total_tokens as u64);
							r.response.cached_input_tokens = usage.cache_read_input_tokens.map(|i| i as u64);
							r.response.cache_creation_input_tokens =
								usage.cache_write_input_tokens.map(|i| i as u64);
							if let Some(c) = completion.take() {
								r.response.completion = Some(vec![c]);
							}
						});
					}
				},
				_ => {},
			}
			let identity = if matches!(event, bedrock::ConverseStreamOutput::MessageStart(_)) {
				helpers::generate_anthropic_message_id()
			} else {
				String::new()
			};
			state.push(event, &identity)
		})
	}

	#[cfg(test)]
	#[test]
	fn bedrock_usage_matches_original_golden() {
		let cases: Vec<serde_json::Value> = serde_json::from_str(include_str!(
			"../../../../llm/tests/fixtures/bedrock-usage-golden.json"
		))
		.unwrap();
		assert_eq!(cases.len(), 6);
		for c in cases {
			let usage = serde_json::from_value(c["input"].clone()).unwrap();
			assert_eq!(
				serde_json::to_value(
					gateway_llm::streaming::bedrock::to_anthropic_message_delta_usage(usage)
				)
				.unwrap(),
				c["expected"]
			);
		}
	}
}

pub mod from_responses {
	use std::time::Instant;

	use bytes::Bytes;
	use rand::RngExt;
	use types::bedrock;

	use crate::http::Body;
	use crate::json;
	use crate::llm::bedrock::Provider;
	use crate::llm::types::ResponseType;
	use crate::llm::{AIError, AmendOnDrop, logged_response_parsing, types};

	/// translate an OpenAI responses request to a Bedrock converse request
	pub fn translate(
		req: &types::responses::Request,
		provider: &Provider,
		headers: Option<&http::HeaderMap>,
		prompt_caching: Option<&crate::llm::policy::PromptCachingConfig>,
	) -> Result<super::BedrockRequest, AIError> {
		gateway_llm::conversion::bedrock::request::from_responses::translate(
			req,
			&super::request_options(provider, false),
			headers,
			prompt_caching,
		)
		.map_err(Into::into)
	}

	pub fn translate_response(
		bytes: &Bytes,
		model: &str,
		tool_name_map: Option<&super::BedrockToolNameMap>,
	) -> Result<Box<dyn ResponseType>, AIError> {
		let resp = serde_json::from_slice::<bedrock::ConverseResponse>(bytes)
			.map_err(logged_response_parsing(bytes))?;
		let adapter = super::ConverseResponseAdapter::from_response(resp, model)?;
		let typed = adapter.to_responses_typed(tool_name_map);
		let mut passthrough =
			json::convert::<_, types::responses::Response>(&typed).map_err(AIError::ResponseParsing)?;
		passthrough.rest = serde_json::Value::Object(serde_json::Map::new());
		if let Some(usage) = passthrough.usage.as_mut() {
			usage.rest = serde_json::Value::Object(serde_json::Map::new());
		}
		if matches!(adapter.0.stop_reason, bedrock::StopReason::ToolUse) {
			passthrough.status = "requires_action".to_string();
		}
		Ok(Box::new(passthrough))
	}

	#[cfg(feature = "providers-aws")]
	pub fn translate_stream(
		b: Body,
		buffer_limit: usize,
		log: AmendOnDrop,
		model: &str,
		_message_id: &str,
		tool_name_map: Option<super::BedrockToolNameMap>,
	) -> Body {
		let mut saw_token = false;
		let response_id = format!("resp_{:016x}", rand::rng().random::<u64>());
		let message_item_id = format!("msg_{:016x}", rand::rng().random::<u64>());
		let model = model.to_string();
		let created_at = chrono::Utc::now().timestamp() as u64;
		let mut state = gateway_llm::streaming::bedrock::responses::ResponsesState::new(
			response_id,
			message_item_id,
			model,
			created_at,
			tool_name_map,
		);
		super::streaming::translate(b, buffer_limit, None, move |event| {
			match &event {
				bedrock::ConverseStreamOutput::ContentBlockDelta(_) => {
					if !saw_token {
						saw_token = true;
						log.non_atomic_mutate(|r| r.response.first_token = Some(Instant::now()));
					}
				},
				bedrock::ConverseStreamOutput::Metadata(meta) => {
					if let Some(usage) = meta.usage {
						log.non_atomic_mutate(|r| {
							r.response.output_tokens = Some(usage.output_tokens as u64);
							r.response.input_tokens = Some(usage.input_tokens as u64);
							r.response.total_tokens = Some(usage.total_tokens as u64);
							r.response.cached_input_tokens = usage.cache_read_input_tokens.map(|i| i as u64);
							r.response.cache_creation_input_tokens =
								usage.cache_write_input_tokens.map(|i| i as u64);
						});
					}
				},
				_ => {},
			}
			let identity = if matches!(&event,bedrock::ConverseStreamOutput::ContentBlockStart(start) if matches!(start.start,Some(bedrock::ContentBlockStart::ToolUse(_))))
			{
				format!("call_{:016x}", rand::rng().random::<u64>())
			} else {
				String::new()
			};
			state.push(event, &identity)
		})
	}
}

pub mod from_anthropic_token_count {
	pub fn translate(
		req: &crate::llm::types::count_tokens::Request,
		headers: &http::HeaderMap,
	) -> Result<Vec<u8>, crate::llm::AIError> {
		gateway_llm::conversion::bedrock::request::from_anthropic_token_count::translate(req, headers)
			.map_err(Into::into)
	}
}

mod helpers {

	use std::sync::LazyLock;

	// From https://docs.aws.amazon.com/bedrock/latest/userguide/model-parameters-anthropic-claude-messages-request-response.html
	const DEFAULT_ALLOWED_BETA_HEADERS: &[&str] = &[
		"computer-use-2025-01-24",
		"token-efficient-tools-2025-02-19",
		"interleaved-thinking-2025-05-14",
		"output-128k-2025-02-19",
		"dev-full-thinking-2025-05-14",
		"context-1m-2025-08-07",
		"context-management-2025-06-27",
		"effort-2025-11-24",
		"tool-search-tool-2025-10-19",
		"tool-examples-2025-10-29",
	];
	const ALLOWED_BETA_HEADERS_ENV: &str = "AGENTGATEWAY_BEDROCK_ANTHROPIC_BETA_HEADERS";
	const DEFAULT_SENTINEL: &str = "default";

	pub(super) static ALLOWED_BETA_HEADERS: LazyLock<Vec<String>> = LazyLock::new(|| {
		let default_allowed_beta_headers = || {
			DEFAULT_ALLOWED_BETA_HEADERS
				.iter()
				.map(|feature| feature.to_string())
				.collect::<Vec<_>>()
		};
		let Ok(env) = std::env::var(ALLOWED_BETA_HEADERS_ENV) else {
			return default_allowed_beta_headers();
		};

		env
			.split(',')
			.map(str::trim)
			.filter(|feature| !feature.is_empty())
			.flat_map(|feature| {
				if feature == DEFAULT_SENTINEL {
					default_allowed_beta_headers()
				} else {
					vec![feature.to_string()]
				}
			})
			.collect()
	});
	#[cfg(test)]
	pub use gateway_llm::provider::bedrock::{extract_flat_metadata, supports_prompt_caching};
	pub fn generate_anthropic_message_id() -> String {
		let timestamp = chrono::Utc::now().timestamp_millis();
		let random: u32 = rand::random();
		format!("msg_{:x}{:08x}", timestamp, random)
	}
}

struct ConverseResponseAdapter(gateway_llm::conversion::bedrock::response::ConverseResponseAdapter);
impl ConverseResponseAdapter {
	fn from_response(resp: bedrock::ConverseResponse, model: &str) -> Result<Self, AIError> {
		if let Some(trace) = resp.trace.as_ref()
			&& let Some(guardrail_trace) = &trace.guardrail
		{
			trace!("Bedrock guardrail trace: {:?}", guardrail_trace);
		}
		gateway_llm::conversion::bedrock::response::ConverseResponseAdapter::from_response(resp, model)
			.map(Self)
			.map_err(Into::into)
	}
	fn to_completions(
		&self,
		map: Option<&BedrockToolNameMap>,
	) -> crate::llm::types::completions::typed::Response {
		let mut response = self.0.to_completions(map);
		response.id = format!("bedrock-{}", chrono::Utc::now().timestamp_millis());
		response.created = chrono::Utc::now().timestamp() as u32;
		response
	}
	fn to_responses_typed(&self, map: Option<&BedrockToolNameMap>) -> responses::typed::Response {
		let response_id = format!("resp_{:016x}", rand::rng().random::<u64>());
		let builder =
			crate::llm::types::responses::ResponseBuilder::new(response_id, self.0.model.clone());
		let mut response = self.0.to_responses_typed(
			map,
			builder.response(responses::typed::Status::InProgress, None, None, None),
		);
		for output in &mut response.output {
			if let responses::typed::OutputItem::Message(message) = output {
				message.id = format!("msg_{:016x}", rand::rng().random::<u64>());
			}
		}
		response
	}
	fn to_anthropic(
		&self,
		map: Option<&BedrockToolNameMap>,
	) -> Result<messages::typed::MessagesResponse, AIError> {
		let mut response = self.0.to_anthropic(map)?;
		response.id = helpers::generate_anthropic_message_id();
		Ok(response)
	}
}

pub fn message_id(resp: &Response) -> String {
	resp
		.headers()
		.get(crate::http::x_headers::X_AMZN_REQUESTID)
		.and_then(|s| s.to_str().ok().map(|s| s.to_owned()))
		.unwrap_or_else(|| format!("{:016x}", rand::rng().random::<u64>()))
}

#[cfg(test)]
mod provider_parameter_tests {
	#[test]
	fn original_cache_and_metadata_contracts() {
		let cases: Vec<serde_json::Value> = serde_json::from_str(include_str!(
			"../../../../llm/tests/fixtures/provider-b-golden.json"
		))
		.unwrap();
		let mut count = 0;
		for c in cases {
			let actual = match c["family"].as_str() {
				Some("bedrock-cache") => serde_json::json!(super::helpers::supports_prompt_caching(
					c["model"].as_str().unwrap()
				)),
				Some("bedrock-metadata") => {
					serde_json::json!(super::helpers::extract_flat_metadata(&c["value"]))
				},
				_ => continue,
			};
			count += 1;
			assert_eq!(actual, c["expected"], "{c}");
		}
		assert_eq!(count, 15);
	}
}

#[cfg(test)]
#[path = "bedrock_contract_tests.rs"]
mod bedrock_contract_tests;
