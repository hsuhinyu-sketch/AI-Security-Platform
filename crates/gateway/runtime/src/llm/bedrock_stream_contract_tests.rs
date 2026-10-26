use super::*;
use crate::http::Body;
use crate::telemetry::log::AsyncLog;
use http_body_util::BodyExt;
use serde_json::{Value, json};

#[allow(dead_code)]
#[path = "../../../llm/tests/streaming_support/mod.rs"]
mod support;

async fn observe(case: &Value) -> Value {
	let mut encoded = bytes::BytesMut::new();
	let mut decoded = Vec::new();
	for event in case["events"].as_array().unwrap() {
		let message = message(event);
		decoded.push(
			match types::bedrock::deserialize_stream_output(message.clone()) {
				Ok(e) => json!({"ok":format!("{e:?}")}),
				Err(e) => json!({"error":e.to_string()}),
			},
		);
		aws_smithy_eventstream::frame::write_message_to(&message, &mut encoded).unwrap();
	}
	match case["damage"].as_str() {
		Some("truncated") => {
			encoded.truncate(encoded.len() - 3);
		},
		Some("crc") => {
			let n = encoded.len();
			encoded[n - 1] ^= 1;
		},
		_ => {},
	}
	let size = case["chunkSize"].as_u64().unwrap() as usize;
	let size = if size == 0 {
		encoded.len().max(1)
	} else {
		size
	};
	let mut chunks: Vec<Result<Bytes, std::io::Error>> = encoded
		.chunks(size)
		.map(|b| Ok(Bytes::copy_from_slice(b)))
		.collect();
	if case["damage"] == "io-error" {
		chunks.push(Err(std::io::Error::other("original upstream failure")));
	}
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
	let mut map = conversion::bedrock::BedrockToolNameMap::default();
	map.register("danger.tool");
	let mut output = match case["direction"].as_str().unwrap() {
		"chat" => conversion::bedrock::from_completions::translate_stream(
			body,
			limit,
			log,
			"fixture",
			"fixed-message",
			Some(map),
		),
		"messages" => conversion::bedrock::from_messages::translate_stream(
			body,
			limit,
			log,
			"fixture",
			"fixed-message",
			false,
			Some(map),
		),
		_ => unreachable!(),
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
	let mut ids = std::collections::BTreeMap::new();
	for event in support::event_values(&frames) {
		if event["event"] == "message_start" {
			let id = event["data"]["message"]["id"].as_str().unwrap();
			let suffix = id.strip_prefix("msg_").unwrap();
			assert!(suffix.len() >= 9 && suffix.bytes().all(|b| b.is_ascii_hexdigit()));
			let next = ids.len();
			ids
				.entry(id.to_string())
				.or_insert_with(|| format!("msg_fixture_{next}"));
		}
	}
	let frames: Vec<String> = frames
		.into_iter()
		.map(|mut f| {
			for (id, replacement) in &ids {
				f = f.replace(&format!("\"{id}\""), &format!("\"{replacement}\""));
			}
			f
		})
		.collect();
	json!({"decoded":decoded,"events":support::event_values(&frames),"frames":frames,"error":error,
		"stats":{"input":response.input_tokens,"output":response.output_tokens,"total":response.total_tokens,
		"cached":response.cached_input_tokens,"cacheWrite":response.cache_creation_input_tokens,
		"reasoning":response.reasoning_tokens,"model":response.provider_model,"tier":response.service_tier,
		"firstToken":response.first_token.is_some()}})
}

pub(super) fn message(event: &Value) -> crate::parse::aws_sse::Message {
	use aws_smithy_types::event_stream::{Header, HeaderValue, Message};
	let mut m = Message::new(Bytes::from(event["payload"].as_str().unwrap().to_string()));
	if let Some(t) = event["type"].as_str() {
		m = m.add_header(Header::new(
			":event-type",
			HeaderValue::String(t.to_string().into()),
		));
	}
	if let Some(t) = event["exception"].as_str() {
		m = m
			.add_header(Header::new(
				":message-type",
				HeaderValue::String("exception".into()),
			))
			.add_header(Header::new(
				":exception-type",
				HeaderValue::String(t.to_string().into()),
			));
	}
	m
}

#[tokio::test]
async fn bedrock_streams_preserve_golden_except_explicit_error_contract_changes() {
	let fixture: Value = serde_json::from_str(include_str!(
		"../../../llm/tests/fixtures/bedrock-streaming-golden.json"
	))
	.unwrap();
	assert_eq!(fixture["cases"].as_array().unwrap().len(), 71);
	for case in fixture["cases"].as_array().unwrap() {
		let actual = observe(case).await;
		match case["name"].as_str().unwrap() {
			// These historical snapshots captured the bug. Keep their bytes frozen,
			// but assert the explicitly revised failure/extension contract here.
			"unknown-event" | "unknown-delta" | "unknown-reasoning" | "malformed" | "missing-header"
			| "exception" => {
				assert_eq!(actual["decoded"], case["expected"]["decoded"]);
				assert_eq!(actual["stats"], case["expected"]["stats"]);
				if case["name"] == "unknown-event" {
					assert!(actual["error"].is_null());
					if case["direction"] == "chat" {
						assert_eq!(actual["frames"], serde_json::json!(["data: [DONE]\n\n"]));
					} else {
						assert_eq!(actual["frames"], serde_json::json!([]));
					}
				} else {
					assert_eq!(
						actual["error"],
						if case["name"] == "exception" {
							"Bedrock upstream streaming failure"
						} else {
							"invalid Bedrock stream event"
						}
					);
					assert_eq!(actual["frames"], serde_json::json!([]));
					assert_eq!(actual["events"], serde_json::json!([]));
				}
			},
			_ => assert_eq!(
				actual, case["expected"],
				"{} {}",
				case["direction"], case["name"]
			),
		}
	}
}
