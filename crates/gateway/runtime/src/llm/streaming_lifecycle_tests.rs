use super::*;
use futures_util::StreamExt;
use http_body_util::BodyExt;
use serde_json::json;
use std::sync::atomic::{AtomicUsize, Ordering};

fn request(input_tokens: Option<u64>) -> LLMRequest {
	LLMRequest {
		input_tokens,
		input_format: InputFormat::Completions,
		native_format: None,
		cache_convention: CacheTokenConvention::pending(),
		request_model: "fixture".into(),
		provider: "fixture".into(),
		streaming: true,
		params: Default::default(),
		prompt: None,
		provider_state: None,
	}
}
fn limiter() -> http::localratelimit::RateLimit {
	serde_json::from_value(
		json!({"maxTokens":100,"tokensPerFill":1,"fillInterval":"1h","type":"tokens"}),
	)
	.unwrap()
}
fn policies(limit: &http::localratelimit::RateLimit) -> LLMResponsePolicies {
	LLMResponsePolicies {
		streaming_limits: Default::default(),
		local_rate_limit: vec![limit.clone()],
		remote_rate_limit: None,
		request_traceparent: None,
		prompt_guard: vec![],
		streaming_prompt_guard_enabled: false,
	}
}
// Probe only this test's private bucket through its real public debit/refund API.
// A wrong remaining balance fails before refund; no production read/test interface is added.
fn assert_available(limit: &http::localratelimit::RateLimit, n: u64) {
	assert!(limit.check_llm_request(&request(Some(n + 1))).is_err());
	assert!(limit.check_llm_request(&request(Some(n))).is_ok());
	limit.amend_tokens(-(n as i64));
}
struct DropProbe(Arc<AtomicUsize>);
impl Drop for DropProbe {
	fn drop(&mut self) {
		self.0.fetch_add(1, Ordering::SeqCst);
	}
}
#[cfg(feature = "providers-aws")]
fn wire(t: &str, payload: serde_json::Value) -> Bytes {
	let message = super::bedrock_stream_contract_tests::message(
		&json!({"type":t,"payload":serde_json::to_string(&payload).unwrap()}),
	);
	let mut b = bytes::BytesMut::new();
	aws_smithy_eventstream::frame::write_message_to(&message, &mut b).unwrap();
	b.freeze()
}

#[tokio::test]
#[cfg(feature = "providers-aws")]
async fn s6_stream_clock_usage_and_accounting_follow_real_eof_error_and_drop() {
	for end in ["eof", "error", "consumer-drop"] {
		let limit = limiter();
		let log: AsyncLog<LLMInfo> = Default::default();
		log.store(Some(LLMInfo::new(request(None), Default::default())));
		let logger = AmendOnDrop::with_catalog(log.clone(), policies(&limit), None, None);
		let mut chunks = vec![
			Ok(wire("messageStart", json!({"role":"assistant"}))),
			Ok(wire(
				"contentBlockDelta",
				json!({"contentBlockIndex":0,"delta":{"text":"first"}}),
			)),
			Ok(wire(
				"metadata",
				json!({"usage":{"inputTokens":17,"outputTokens":5,"totalTokens":22,"cacheReadInputTokens":3,"cacheWriteInputTokens":4}}),
			)),
		];
		if end == "error" {
			chunks.push(Err(std::io::Error::other("accounting source failure")));
		} else {
			chunks.push(Ok(wire(
				"contentBlockDelta",
				json!({"contentBlockIndex":0,"delta":{"text":"second"}}),
			)));
		}
		let polls = Arc::new(AtomicUsize::new(0));
		let drops = Arc::new(AtomicUsize::new(0));
		let probe = DropProbe(drops.clone());
		let source_polls = polls.clone();
		let source = futures_util::stream::iter(chunks).map(move |item| {
			let _keep = &probe;
			source_polls.fetch_add(1, Ordering::SeqCst);
			item
		});
		let mut body = conversion::bedrock::from_completions::translate_stream(
			Body::from_stream(source),
			4096,
			logger,
			"fixture",
			"fixed-id",
			None,
		);
		assert!(log.load_clone().unwrap().response.first_token.is_none());
		assert_available(&limit, 100);
		assert!(body.frame().await.unwrap().is_ok());
		assert!(log.load_clone().unwrap().response.first_token.is_none());
		let before = std::time::Instant::now();
		assert!(body.frame().await.unwrap().is_ok());
		let after = std::time::Instant::now();
		let first = log.load_clone().unwrap().response.first_token.unwrap();
		assert!(first >= before && first <= after);
		assert!(body.frame().await.unwrap().is_ok());
		let info = log.load_clone().unwrap();
		assert_eq!(info.response.first_token, Some(first));
		assert_eq!(
			(
				info.response.input_tokens,
				info.response.output_tokens,
				info.response.total_tokens,
				info.response.cached_input_tokens,
				info.response.cache_creation_input_tokens
			),
			(Some(17), Some(5), Some(22), Some(3), Some(4))
		);
		assert_available(&limit, 100);
		assert_eq!(polls.load(Ordering::SeqCst), 3);
		match end {
			"consumer-drop" => {},
			"error" => {
				assert!(body.frame().await.unwrap().is_err());
				assert!(body.frame().await.is_none());
				assert_available(&limit, 78);
			},
			_ => {
				assert!(body.frame().await.unwrap().is_ok());
				assert_eq!(log.load_clone().unwrap().response.first_token, Some(first));
				let done = body.frame().await.unwrap().unwrap().into_data().unwrap();
				assert_eq!(done, "data: [DONE]\n\n");
				// The Bedrock Host bridge drops the translated source before emitting DONE.
				assert_available(&limit, 78);
				assert!(body.frame().await.is_none());
			},
		}
		drop(body);
		assert_eq!(drops.load(Ordering::SeqCst), 1);
		assert_available(&limit, 78);
		assert_eq!(
			polls.load(Ordering::SeqCst),
			if end == "consumer-drop" { 3 } else { 4 }
		);
	}
}

#[test]
fn s6_explicit_accounting_then_drop_commits_exactly_once() {
	let limit = limiter();
	let log: AsyncLog<LLMInfo> = Default::default();
	let mut info = LLMInfo::new(request(Some(10)), Default::default());
	info.response.input_tokens = Some(17);
	info.response.output_tokens = Some(5);
	log.store(Some(info));
	assert!(limit.check_llm_request(&request(Some(10))).is_ok());
	assert_available(&limit, 90);
	let mut logger = AmendOnDrop::with_catalog(log, policies(&limit), None, None);
	logger.report_rate_limit();
	assert_available(&limit, 78);
	logger.report_rate_limit();
	assert_available(&limit, 78);
	drop(logger);
	assert_available(&limit, 78);
}

#[cfg(feature = "providers-aws")]
fn bedrock_stream(direction: &str, body: Body, logger: AmendOnDrop) -> Body {
	match direction {
		"chat" => conversion::bedrock::from_completions::translate_stream(
			body, 4096, logger, "fixture", "fixed-id", None,
		),
		"messages" => conversion::bedrock::from_messages::translate_stream(
			body, 4096, logger, "fixture", "fixed-id", false, None,
		),
		"responses" => conversion::bedrock::from_responses::translate_stream(
			body, 4096, logger, "fixture", "fixed-id", None,
		),
		_ => unreachable!(),
	}
}
#[cfg(feature = "providers-aws")]
fn exception() -> Bytes {
	let message = super::bedrock_stream_contract_tests::message(
		&json!({"exception":"modelStreamErrorException","payload":"{\"message\":\"private-provider-detail\"}"}),
	);
	let mut b = bytes::BytesMut::new();
	aws_smithy_eventstream::frame::write_message_to(&message, &mut b).unwrap();
	b.freeze()
}
#[cfg(feature = "providers-aws")]
async fn assert_bedrock_terminal_failure(direction: &str, failure: Bytes, coalesced: bool) {
	let limit = limiter();
	let log: AsyncLog<LLMInfo> = Default::default();
	let mut info = LLMInfo::new(request(None), Default::default());
	// Already observed usage must survive failure and be settled once.
	info.response.input_tokens = Some(17);
	info.response.output_tokens = Some(5);
	log.store(Some(info));
	let logger = AmendOnDrop::with_catalog(log.clone(), policies(&limit), None, None);
	let polls = Arc::new(AtomicUsize::new(0));
	let drops = Arc::new(AtomicUsize::new(0));
	let probe = DropProbe(drops.clone());
	let source_polls = polls.clone();
	let chunks = vec![
		failure,
		wire(
			"contentBlockDelta",
			json!({"contentBlockIndex":0,"delta":{"text":"must-not-disclose"}}),
		),
		wire("messageStop", json!({"stopReason":"end_turn"})),
		wire(
			"metadata",
			json!({"usage":{"inputTokens":99,"outputTokens":99,"totalTokens":198}}),
		),
	];
	let chunks = if coalesced {
		vec![Bytes::from(chunks.concat())]
	} else {
		chunks
	};
	let source = futures_util::stream::iter(chunks).map(move |chunk| {
		let _keep = &probe;
		source_polls.fetch_add(1, Ordering::SeqCst);
		Ok::<_, std::io::Error>(chunk)
	});
	let mut body = bedrock_stream(direction, Body::from_stream(source), logger);
	let error =
		body.frame().await.unwrap().expect_err(
			"provider failure must terminate the stream instead of becoming successful output",
		);
	assert!(!error.to_string().contains("private-provider-detail"));
	assert_eq!(
		drops.load(Ordering::SeqCst),
		1,
		"source must be released before consumer Drop"
	);
	assert_eq!(polls.load(Ordering::SeqCst), 1);
	assert_available(&limit, 78);
	for _ in 0..3 {
		assert!(body.frame().await.is_none());
	}
	assert_eq!(polls.load(Ordering::SeqCst), 1);
	let info = log.load_clone().unwrap();
	assert_eq!(
		(info.response.input_tokens, info.response.output_tokens),
		(Some(17), Some(5))
	);
	drop(body);
	assert_eq!(drops.load(Ordering::SeqCst), 1);
	assert_available(&limit, 78);
}
#[tokio::test]
#[cfg(feature = "providers-aws")]
async fn bedrock_terminal_chat() {
	exercise_terminal_cases("chat").await;
}
#[tokio::test]
#[cfg(feature = "providers-aws")]
async fn bedrock_terminal_messages() {
	exercise_terminal_cases("messages").await;
}
#[tokio::test]
#[cfg(feature = "providers-aws")]
async fn bedrock_terminal_responses() {
	exercise_terminal_cases("responses").await;
}

#[cfg(feature = "providers-aws")]
fn encode_message(message: crate::parse::aws_sse::Message) -> Bytes {
	let mut buffer = bytes::BytesMut::new();
	aws_smithy_eventstream::frame::write_message_to(&message, &mut buffer).unwrap();
	buffer.freeze()
}
#[cfg(feature = "providers-aws")]
async fn exercise_terminal_cases(direction: &str) {
	use aws_smithy_types::event_stream::{Header, HeaderValue, Message};
	let raw = |event: serde_json::Value| {
		encode_message(super::bedrock_stream_contract_tests::message(&event))
	};
	let failures = vec![
		exception(),
		encode_message(
			Message::new(Bytes::new())
				.add_header(Header::new(
					":message-type",
					HeaderValue::String("error".into()),
				))
				.add_header(Header::new(
					":error-message",
					HeaderValue::String("private-provider-detail".into()),
				)),
		),
		raw(json!({"type":"contentBlockDelta","payload":"{"})),
		raw(json!({"payload":"{}"})),
		raw(
			json!({"type":"contentBlockDelta","payload":"{\"contentBlockIndex\":0,\"delta\":{\"future\":{}}}"}),
		),
		encode_message(
			Message::new(Bytes::new()).add_header(Header::new(":event-type", HeaderValue::Int32(1))),
		),
		encode_message(
			Message::new(Bytes::new())
				.add_header(Header::new(
					":event-type",
					HeaderValue::String("future".into()),
				))
				.add_header(Header::new(
					":event-type",
					HeaderValue::String("messageStop".into()),
				)),
		),
	];
	for failure in failures {
		for coalesced in [false, true] {
			assert_bedrock_terminal_failure(direction, failure.clone(), coalesced).await;
		}
	}
}

#[tokio::test]
#[cfg(feature = "providers-aws")]
async fn bedrock_normal_stream_accepts_unknown_extensions_and_preserves_usage() {
	for direction in ["chat", "messages", "responses"] {
		for chunk_size in [0, 1, 73] {
			let limit = limiter();
			let log: AsyncLog<LLMInfo> = Default::default();
			log.store(Some(LLMInfo::new(request(None), Default::default())));
			let chunks = [
				wire("futureExtension", json!({"future":true})),
				wire("messageStart", json!({"role":"assistant"})),
				wire(
					"contentBlockDelta",
					json!({"contentBlockIndex":0,"delta":{"text":"kept"}}),
				),
				wire("futureExtension", json!({"future":true})),
				wire("messageStop", json!({"stopReason":"end_turn"})),
				wire(
					"metadata",
					json!({"usage":{"inputTokens":17,"outputTokens":5,"totalTokens":22}}),
				),
				wire("futureExtension", json!({"future":true})),
			];
			let bytes = chunks.concat();
			let chunks: Vec<_> = bytes
				.chunks(if chunk_size == 0 {
					bytes.len()
				} else {
					chunk_size
				})
				.map(|b| Ok::<_, std::io::Error>(Bytes::copy_from_slice(b)))
				.collect();
			let mut body = bedrock_stream(
				direction,
				Body::from_stream(futures_util::stream::iter(chunks)),
				AmendOnDrop::with_catalog(log.clone(), policies(&limit), None, None),
			);
			let mut output = String::new();
			while let Some(frame) = body.frame().await {
				output.push_str(std::str::from_utf8(&frame.unwrap().into_data().unwrap()).unwrap());
			}
			for _ in 0..3 {
				assert!(body.frame().await.is_none());
			}
			assert!(output.contains("kept"));
			assert!(!output.contains("futureExtension"));
			let terminal = match direction {
				"chat" => "data: [DONE]",
				"messages" => "event: message_stop",
				_ => "\"type\":\"response.completed\"",
			};
			assert_eq!(output.matches(terminal).count(), 1, "{direction}: {output}");
			let info = log.load_clone().unwrap();
			assert_eq!(
				(
					info.response.input_tokens,
					info.response.output_tokens,
					info.response.total_tokens
				),
				(Some(17), Some(5), Some(22))
			);
			assert!(info.response.first_token.is_some());
			assert_available(&limit, 78);
			drop(body);
			assert_available(&limit, 78);
		}
	}
}

#[tokio::test]
#[cfg(feature = "providers-aws")]
async fn bedrock_partial_stream_failure_and_early_drop_release_source() {
	for direction in ["chat", "messages", "responses"] {
		for end in ["exception", "io-error", "consumer-drop"] {
			let log: AsyncLog<LLMInfo> = Default::default();
			log.store(Some(LLMInfo::new(request(None), Default::default())));
			let polls = Arc::new(AtomicUsize::new(0));
			let drops = Arc::new(AtomicUsize::new(0));
			let probe = DropProbe(drops.clone());
			let source_polls = polls.clone();
			let chunks = vec![
				Ok(wire("messageStart", json!({"role":"assistant"}))),
				Ok(wire(
					"contentBlockDelta",
					json!({"contentBlockIndex":0,"delta":{"text":"allowed-prefix"}}),
				)),
				if end == "io-error" {
					Err(std::io::Error::new(
						std::io::ErrorKind::ConnectionReset,
						"original provider I/O failure",
					))
				} else {
					Ok(exception())
				},
				Ok(wire(
					"contentBlockDelta",
					json!({"contentBlockIndex":0,"delta":{"text":"must-not-disclose"}}),
				)),
			];
			let source = futures_util::stream::iter(chunks).map(move |item| {
				let _keep = &probe;
				source_polls.fetch_add(1, Ordering::SeqCst);
				item
			});
			let logger = AmendOnDrop {
				log,
				pol: None,
				req: None,
				catalog: None,
			};
			let mut body = bedrock_stream(direction, Body::from_stream(source), logger);
			assert_eq!(polls.load(Ordering::SeqCst), 0);
			assert!(body.frame().await.unwrap().is_ok());
			let prefix = body.frame().await.unwrap().unwrap().into_data().unwrap();
			assert!(
				std::str::from_utf8(&prefix)
					.unwrap()
					.contains("allowed-prefix")
			);
			assert_eq!(polls.load(Ordering::SeqCst), 2);
			if end != "consumer-drop" {
				let error = body.frame().await.unwrap().unwrap_err();
				if end == "io-error" {
					assert!(format!("{error:?}").contains("ConnectionReset"));
					assert!(error.to_string().contains("original provider I/O failure"));
				}
				assert_eq!(drops.load(Ordering::SeqCst), 1);
				for _ in 0..3 {
					assert!(body.frame().await.is_none());
				}
			}
			drop(body);
			assert_eq!(drops.load(Ordering::SeqCst), 1);
			assert_eq!(
				polls.load(Ordering::SeqCst),
				if end == "consumer-drop" { 2 } else { 3 }
			);
		}
	}
}

#[tokio::test]
#[cfg(feature = "providers-aws")]
async fn bedrock_usage_observed_before_failure_is_settled_once() {
	let limit = limiter();
	let log: AsyncLog<LLMInfo> = Default::default();
	log.store(Some(LLMInfo::new(request(None), Default::default())));
	let chunks = vec![
		Ok::<_, std::io::Error>(wire(
			"metadata",
			json!({"usage":{"inputTokens":17,"outputTokens":5,"totalTokens":22,"cacheReadInputTokens":3,"cacheWriteInputTokens":4}}),
		)),
		Ok(exception()),
	];
	let mut body = bedrock_stream(
		"chat",
		Body::from_stream(futures_util::stream::iter(chunks)),
		AmendOnDrop::with_catalog(log.clone(), policies(&limit), None, None),
	);
	assert!(body.frame().await.unwrap().is_ok());
	assert_available(&limit, 100);
	assert!(body.frame().await.unwrap().is_err());
	assert!(body.frame().await.is_none());
	let info = log.load_clone().unwrap();
	assert_eq!(
		(
			info.response.input_tokens,
			info.response.output_tokens,
			info.response.cached_input_tokens,
			info.response.cache_creation_input_tokens
		),
		(Some(17), Some(5), Some(3), Some(4))
	);
	assert_available(&limit, 78);
	drop(body);
	assert_available(&limit, 78);
}

fn host_client() -> PolicyClient {
	let config = Arc::new(crate::config::parse_config("{}".into(), None).unwrap());
	let stores = crate::store::Stores::default();
	let mut registry = prometheus_client::registry::Registry::default();
	let metrics = Arc::new(crate::telemetry::metrics::Metrics::new(
		&mut registry,
		config.metrics.excluded_metrics.clone(),
	));
	let client = crate::client::Client::new(
		&config.dns,
		None,
		config.backend.clone(),
		Some(metrics.clone()),
	);
	PolicyClient::new(Arc::new(crate::RuntimeContext {
		cfg: config,
		stores,
		upstream: client,
		metrics,
		admin: None,
		ca: None,
		guardrails: None,
		vehicle_state: Default::default(),
		circuit_breakers: None,
	}))
}
#[cfg(feature = "providers-aws")]
async fn memory_default_limit(kind: &str) {
	let provider =
		AIProvider::Bedrock(serde_json::from_value(json!({"region":"us-east-1"})).unwrap());
	let log: AsyncLog<LLMInfo> = Default::default();
	let chunks=match kind {
		"blocks"=>(0..129).map(|index|wire("contentBlockStart",json!({"contentBlockIndex":index,"start":{"toolUse":{"toolUseId":format!("tool-{index}"),"name":"lookup"}}}))).collect::<Vec<_>>(),
		"arguments"=>{
			let mut chunks=vec![wire("contentBlockStart",json!({"contentBlockIndex":0,"start":{"toolUse":{"toolUseId":"t","name":"lookup"}}}))];
			let delta=wire("contentBlockDelta",json!({"contentBlockIndex":0,"delta":{"toolUse":{"input":"a".repeat(32*1024)}}}));
			chunks.extend(std::iter::repeat_n(delta,33));chunks
		},
		_=>{
			let delta=wire("contentBlockDelta",json!({"contentBlockIndex":0,"delta":{"text":"a".repeat(64*1024)}}));
			std::iter::repeat_n(delta,129).collect()
		},
	};
	let source = Body::from_stream(futures_util::stream::iter(
		chunks.into_iter().map(Ok::<_, std::io::Error>),
	));
	let mut output = provider
		.process_streaming(
			host_client(),
			request(None),
			Default::default(),
			None,
			log,
			false,
			None,
			Response::new(source),
		)
		.unwrap()
		.into_body();
	let mut failed = false;
	while let Some(frame) = output.frame().await {
		if frame.is_err() {
			failed = true;
			break;
		}
	}
	assert!(
		failed,
		"{kind} grew beyond the default resource budget without an error"
	);
	assert!(output.frame().await.is_none());
}
#[tokio::test]
#[cfg(feature = "providers-aws")]
async fn memory_default_blocks_are_bounded() {
	memory_default_limit("blocks").await;
}
#[tokio::test]
#[cfg(feature = "providers-aws")]
async fn memory_default_tool_arguments_are_bounded() {
	memory_default_limit("arguments").await;
}
#[tokio::test]
#[cfg(feature = "providers-aws")]
async fn memory_default_decompressed_stream_bytes_are_bounded() {
	memory_default_limit("bytes").await;
}

#[tokio::test]
async fn memory_usage_survives_limits_and_drop_in_all_chat_conversions() {
	use crate::llm::policy::streaming_limits::StreamingLimits;
	for format in [
		InputFormat::Completions,
		InputFormat::Messages,
		InputFormat::Responses,
	] {
		for end in ["limit", "consumer-drop"] {
			let provider = AIProvider::Gemini(serde_json::from_value(json!({})).unwrap());
			let limit = limiter();
			let log: AsyncLog<LLMInfo> = Default::default();
			let mut policies = policies(&limit);
			policies.streaming_limits = serde_json::from_value::<StreamingLimits>(
				json!({"maxResponseBytes":8192,"maxToolArgumentBytes":4,"maxTrackedBlocks":1}),
			)
			.unwrap();
			let polls = Arc::new(AtomicUsize::new(0));
			let drops = Arc::new(AtomicUsize::new(0));
			let source_polls = polls.clone();
			let probe = DropProbe(drops.clone());
			let usage = json!({"id":"r","object":"chat.completion.chunk","model":"fixture","created":0,"choices":[],"usage":{"prompt_tokens":17,"completion_tokens":5,"total_tokens":22}});
			let tool = |args: &str| json!({"id":"r","object":"chat.completion.chunk","model":"fixture","created":0,"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"id":"t","type":"function","function":{"name":"lookup","arguments":args}}]}}]});
			let chunks = [usage, tool("abcd"), tool("must-not-disclose")]
				.into_iter()
				.map(|v| Bytes::from(format!("data: {v}\n\n")))
				.collect::<Vec<_>>();
			let source = futures_util::stream::iter(chunks).map(move |chunk| {
				let _keep = &probe;
				source_polls.fetch_add(1, Ordering::SeqCst);
				Ok::<_, std::io::Error>(chunk)
			});
			let mut req = request(None);
			req.input_format = format;
			let mut body = provider
				.process_streaming(
					host_client(),
					req,
					policies,
					None,
					log.clone(),
					false,
					None,
					Response::new(Body::from_stream(source)),
				)
				.unwrap()
				.into_body();
			assert!(body.frame().await.unwrap().is_ok());
			let info = log.load_clone().unwrap();
			assert_eq!(
				(info.response.input_tokens, info.response.output_tokens),
				(Some(17), Some(5)),
				"{format:?} lost received Usage before terminal processing"
			);
			if end == "limit" {
				assert!(body.frame().await.unwrap().is_ok());
				assert!(
					body
						.frame()
						.await
						.unwrap()
						.unwrap_err()
						.to_string()
						.contains("tool argument limit")
				);
				assert_eq!(drops.load(Ordering::SeqCst), 1);
				assert_available(&limit, 78);
				for _ in 0..3 {
					assert!(body.frame().await.is_none());
				}
			}
			drop(body);
			assert_eq!(drops.load(Ordering::SeqCst), 1);
			assert_available(&limit, 78);
			assert_eq!(
				polls.load(Ordering::SeqCst),
				if end == "limit" { 3 } else { 1 }
			);
		}
	}
}

#[tokio::test]
async fn memory_counts_expanded_gzip_bytes_in_the_real_host_path() {
	use tokio::io::AsyncReadExt;
	let raw = format!(
		"data: {}\n\n",
		json!({"id":"r","model":"fixture","choices":[]})
	)
	.repeat(100);
	let mut compressor =
		async_compression::tokio::bufread::GzipEncoder::new(tokio::io::BufReader::new(raw.as_bytes()));
	let mut compressed = Vec::new();
	compressor.read_to_end(&mut compressed).await.unwrap();
	assert!(compressed.len() < 512);
	assert!(raw.len() > 512);
	let provider = AIProvider::OpenAI(serde_json::from_value(json!({})).unwrap());
	let mut policies = LLMResponsePolicies::default();
	policies.streaming_limits.max_response_bytes = 512.try_into().unwrap();
	let mut response = Response::new(Body::from(compressed));
	response
		.headers_mut()
		.insert(header::CONTENT_ENCODING, "gzip".parse().unwrap());
	let mut body = provider
		.process_streaming(
			host_client(),
			request(None),
			policies,
			None,
			Default::default(),
			false,
			None,
			response,
		)
		.unwrap()
		.into_body();
	let mut rejected = false;
	while let Some(frame) = body.frame().await {
		if let Err(error) = frame {
			assert!(error.to_string().contains("response byte limit"));
			rejected = true;
			break;
		}
	}
	assert!(rejected);
	assert!(body.frame().await.is_none());
}
