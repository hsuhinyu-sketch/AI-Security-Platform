use super::*;
use crate::http::Body;
use crate::telemetry::log::AsyncLog;
use http_body_util::BodyExt;
use serde_json::{Value, json};

#[path = "../../../llm/tests/streaming_support/mod.rs"]
mod support;

async fn observe(case: &Value) -> Value {
	let input = case["input"].as_str().unwrap().as_bytes();
	let mut offset = 0;
	let chunks: Vec<_> = case["chunkSizes"]
		.as_array()
		.unwrap()
		.iter()
		.map(|n| {
			let end = offset + n.as_u64().unwrap() as usize;
			let chunk = Bytes::copy_from_slice(&input[offset..end]);
			offset = end;
			Ok::<_, std::io::Error>(chunk)
		})
		.collect();
	assert_eq!(offset, input.len());
	let body = Body::from_stream(futures_util::stream::iter(chunks));
	let stored: AsyncLog<LLMInfo> = Default::default();
	stored.store(Some(LLMInfo::new(
		LLMRequest {
			input_tokens: None,
			input_format: InputFormat::Completions,
			native_format: None,
			cache_convention: CacheTokenConvention::pending(),
			request_model: "fixture".into(),
			provider: "fixture".into(),
			streaming: true,
			params: Default::default(),
			prompt: None,
			provider_state: None,
		},
		Default::default(),
	)));
	let log = AmendOnDrop {
		log: stored.clone(),
		pol: None,
		req: None,
		catalog: None,
	};
	let limit = case["bufferLimit"].as_u64().unwrap() as usize;
	let mut output = match case["kind"].as_str().unwrap() {
		"chat-messages" => conversion::completions::from_messages::translate_stream(body, limit, log),
		"messages-chat" => conversion::messages::from_completions::translate_stream(body, limit, log),
		"chat-responses" => conversion::openai_compat::to_responses::translate_stream(body, limit, log),
		kind => panic!("unknown streaming case {kind}"),
	};
	let mut frames = Vec::new();
	let mut error = None;
	while let Some(frame) = output.frame().await {
		match frame {
			Ok(frame) => {
				if let Ok(data) = frame.into_data() {
					frames.push(String::from_utf8(data.to_vec()).unwrap());
				}
			},
			Err(e) => {
				error = Some(e.to_string());
				break;
			},
		}
	}
	drop(output);
	let response = stored.take().unwrap().response;
	let frames = support::normalize_frames(frames);
	json!({"events":support::event_values(&frames),"frames":frames,"error":error,
		"stats":{"input":response.input_tokens,"output":response.output_tokens,"total":response.total_tokens,
		"cached":response.cached_input_tokens,"cacheWrite":response.cache_creation_input_tokens,
		"reasoning":response.reasoning_tokens,"model":response.provider_model,"tier":response.service_tier,
		"firstToken":response.first_token.is_some()}})
}

#[tokio::test]
async fn runtime_streaming_matches_frozen_golden() {
	let fixture = support::fixture();
	assert_eq!(fixture["cases"].as_array().unwrap().len(), 78);
	for case in fixture["cases"].as_array().unwrap() {
		assert_eq!(
			observe(case).await,
			case["expected"],
			"{} {}",
			case["kind"],
			case["name"]
		);
	}
}
