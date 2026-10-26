use super::*;
use http_body_util::BodyExt;
use serde_json::json;
use std::{
	collections::VecDeque,
	sync::{
		Arc, Mutex,
		atomic::{AtomicUsize, Ordering},
	},
	task::Waker,
};

fn limits(bytes: usize, args: usize, blocks: usize) -> StreamingLimits {
	serde_json::from_value(
		json!({"maxResponseBytes":bytes,"maxToolArgumentBytes":args,"maxTrackedBlocks":blocks}),
	)
	.unwrap()
}
struct Source {
	frames: VecDeque<Result<Frame<Bytes>, io::Error>>,
	polls: Arc<AtomicUsize>,
	drops: Arc<AtomicUsize>,
	pending: Option<Arc<Mutex<Option<Waker>>>>,
}
impl Drop for Source {
	fn drop(&mut self) {
		self.drops.fetch_add(1, Ordering::SeqCst);
	}
}
impl http_body::Body for Source {
	type Data = Bytes;
	type Error = io::Error;
	fn poll_frame(
		mut self: Pin<&mut Self>,
		cx: &mut Context<'_>,
	) -> Poll<Option<Result<Frame<Bytes>, io::Error>>> {
		self.polls.fetch_add(1, Ordering::SeqCst);
		if self.frames.is_empty()
			&& let Some(pending) = &self.pending
		{
			*pending.lock().unwrap() = Some(cx.waker().clone());
			return Poll::Pending;
		}
		Poll::Ready(self.frames.pop_front())
	}
}
fn source(
	frames: Vec<Result<Frame<Bytes>, io::Error>>,
	pending: Option<Arc<Mutex<Option<Waker>>>>,
) -> (Body, Arc<AtomicUsize>, Arc<AtomicUsize>) {
	let polls = Arc::new(AtomicUsize::new(0));
	let drops = Arc::new(AtomicUsize::new(0));
	(
		Body::new(Source {
			frames: frames.into(),
			polls: polls.clone(),
			drops: drops.clone(),
			pending,
		}),
		polls,
		drops,
	)
}
fn event(value: Value) -> Bytes {
	Bytes::from(format!("data: {}\n\n", value))
}
fn slot(format: &str, index: i64, args: &str) -> Bytes {
	let value = match format {
		"aws" => json!({"contentBlockIndex":index,"delta":{"toolUse":{"input":args}}}),
		"chat" => {
			json!({"choices":[{"index":0,"delta":{"tool_calls":[{"index":index,"function":{"arguments":args}}]}}]})
		},
		"messages" => {
			json!({"type":"content_block_delta","index":index,"delta":{"type":"input_json_delta","partial_json":args}})
		},
		_ => json!({"type":"response.function_call_arguments.delta","output_index":index,"delta":args}),
	};
	if format != "aws" {
		return event(value);
	}
	#[cfg(not(feature = "providers-aws"))]
	panic!("AWS fixture requires providers-aws");
	#[cfg(feature = "providers-aws")]
	{
		use aws_smithy_types::event_stream::{Header, HeaderValue, Message};
		let message =
			Message::new(Bytes::from(serde_json::to_vec(&value).unwrap())).add_header(Header::new(
				":event-type",
				HeaderValue::String("contentBlockDelta".into()),
			));
		let mut encoded = BytesMut::new();
		aws_smithy_eventstream::frame::write_message_to(&message, &mut encoded).unwrap();
		encoded.freeze()
	}
}
#[tokio::test]
async fn memory_limits_preserve_chunk_bytes_trailers_and_exact_total_boundary() {
	let bytes = Bytes::from(": heartbeat\n\ndata: {}\nid: original\nretry: 17\n\n".repeat(300));
	for split in [1, bytes.len()] {
		let mut frames: Vec<_> = bytes
			.chunks(split)
			.map(|b| Ok(Frame::data(Bytes::copy_from_slice(b))))
			.collect();
		let mut trailers = ::http::HeaderMap::new();
		trailers.insert("x-end", "original".parse().unwrap());
		frames.push(Ok(Frame::trailers(trailers.clone())));
		let (body, polls, drops) = source(frames, None);
		let mut body = limited(body, 64, false, limits(bytes.len(), 4, 1));
		assert_eq!(polls.load(Ordering::SeqCst), 0);
		let mut output = Vec::new();
		let mut got_trailers = false;
		while let Some(frame) = body.frame().await {
			let frame = frame.unwrap();
			if let Some(data) = frame.data_ref() {
				output.extend_from_slice(data);
			} else {
				assert_eq!(frame.into_trailers().unwrap(), trailers);
				got_trailers = true;
			}
		}
		assert_eq!(output, bytes);
		assert!(got_trailers);
		assert_eq!(drops.load(Ordering::SeqCst), 1);
		let final_polls = polls.load(Ordering::SeqCst);
		for _ in 0..3 {
			assert!(body.frame().await.is_none());
		}
		assert_eq!(polls.load(Ordering::SeqCst), final_polls);
	}
	let (body, polls, drops) = source(vec![Ok(Frame::data(bytes.clone()))], None);
	let mut body = limited(body, 64, false, limits(bytes.len() - 1, 4, 1));
	assert!(
		body
			.frame()
			.await
			.unwrap()
			.unwrap_err()
			.to_string()
			.contains("response byte limit")
	);
	assert_eq!(drops.load(Ordering::SeqCst), 1);
	assert_eq!(polls.load(Ordering::SeqCst), 1);
	assert!(body.frame().await.is_none());
}
#[tokio::test]
async fn memory_limits_stop_all_wire_families_at_argument_and_block_boundaries() {
	for format in ["aws", "chat", "messages", "responses"] {
		if format == "aws" && !cfg!(feature = "providers-aws") {
			continue;
		}
		for block_overflow in [false, true] {
			let first = slot(format, 0, "éé");
			let second = slot(
				format,
				if block_overflow { 1 } else { 0 },
				if block_overflow { "" } else { "x" },
			);
			let (body, polls, drops) = source(
				vec![
					Ok(Frame::data(first.clone())),
					Ok(Frame::data(second)),
					Ok(Frame::data(event(json!({"mustNotRead":true})))),
				],
				None,
			);
			let mut body = limited(body, 4096, format == "aws", limits(8192, 4, 1));
			assert_eq!(
				body.frame().await.unwrap().unwrap().into_data().unwrap(),
				first
			);
			let error = body.frame().await.unwrap().unwrap_err();
			assert!(
				error.to_string().contains(if block_overflow {
					"tracked block limit"
				} else {
					"tool argument limit"
				}),
				"{format}: {error}"
			);
			assert_eq!(drops.load(Ordering::SeqCst), 1);
			assert_eq!(polls.load(Ordering::SeqCst), 2);
			for _ in 0..3 {
				assert!(body.frame().await.is_none());
			}
			assert_eq!(polls.load(Ordering::SeqCst), 2);
		}
	}
}
#[tokio::test]
async fn memory_limits_keep_lifetime_slots_and_do_not_double_charge_response_snapshots() {
	let frames = vec![
		slot("responses", 0, "abcd"),
		event(
			json!({"type":"response.function_call_arguments.done","output_index":0,"arguments":"abcd"}),
		),
		event(json!({"type":"response.output_item.done","output_index":0,"item":{"arguments":"abcd"}})),
		slot("responses", 1, ""),
	];
	let (body, _, drops) = source(
		frames.into_iter().map(|b| Ok(Frame::data(b))).collect(),
		None,
	);
	let mut body = limited(body, 4096, false, limits(8192, 4, 1));
	for _ in 0..3 {
		assert!(body.frame().await.unwrap().is_ok());
	}
	assert!(
		body
			.frame()
			.await
			.unwrap()
			.unwrap_err()
			.to_string()
			.contains("tracked block limit")
	);
	assert_eq!(drops.load(Ordering::SeqCst), 1);
	assert!(body.frame().await.is_none());
}
#[derive(Default)]
struct Wakes(AtomicUsize);
impl std::task::Wake for Wakes {
	fn wake(self: Arc<Self>) {
		self.0.fetch_add(1, Ordering::SeqCst);
	}
}
#[tokio::test]
async fn memory_limits_forward_pending_wakers_and_release_on_error_or_drop() {
	use http_body::Body as _;
	let registered = Arc::new(Mutex::new(None));
	let wakes = Arc::new(Wakes::default());
	let waker = Waker::from(wakes.clone());
	let mut cx = Context::from_waker(&waker);
	let (body, polls, drops) = source(vec![], Some(registered.clone()));
	let mut body = limited(body, 64, false, limits(128, 4, 1));
	assert!(Pin::new(&mut body).poll_frame(&mut cx).is_pending());
	registered.lock().unwrap().take().unwrap().wake();
	assert_eq!(wakes.0.load(Ordering::SeqCst), 1);
	drop(body);
	assert_eq!(drops.load(Ordering::SeqCst), 1);
	assert_eq!(polls.load(Ordering::SeqCst), 1);
	let (body, polls, drops) = source(
		vec![Err(io::Error::new(
			io::ErrorKind::ConnectionReset,
			"original source error",
		))],
		None,
	);
	let mut body = terminal(limited(body, 64, false, limits(128, 4, 1)));
	let error = body.frame().await.unwrap().unwrap_err();
	assert!(format!("{error:?}").contains("ConnectionReset"));
	assert!(error.to_string().contains("original source error"));
	assert!(body.frame().await.is_none());
	assert_eq!(polls.load(Ordering::SeqCst), 1);
	assert_eq!(drops.load(Ordering::SeqCst), 1);
}
#[test]
fn memory_limits_configuration_is_finite_and_policy_layers_cannot_relax_it() {
	assert_eq!(
		serde_json::from_value::<StreamingLimits>(json!({})).unwrap(),
		StreamingLimits::default()
	);
	for field in [
		"maxResponseBytes",
		"maxToolArgumentBytes",
		"maxTrackedBlocks",
	] {
		assert!(
			serde_json::from_value::<StreamingLimits>(Value::Object(serde_json::Map::from_iter([(
				field.to_owned(),
				json!(0)
			)])))
			.is_err()
		);
	}
	let route = Arc::new(crate::store::LLMRequestPolicies {
		llm: Some(Arc::new(crate::llm::Policy {
			streaming_limits: Some(limits(200, 8, 2)),
			..Default::default()
		})),
		..Default::default()
	});
	let backend = Arc::new(crate::llm::Policy {
		streaming_limits: Some(limits(100, 16, 1)),
		..Default::default()
	});
	let merged = route.merge_backend_policies(Some(backend));
	assert_eq!(
		merged.llm.as_ref().unwrap().streaming_limits,
		Some(limits(100, 8, 1))
	);
	assert!(merged.requires_structured_adapter());
}
#[tokio::test]
async fn memory_limits_are_per_response_under_concurrent_consumption() {
	let run = |cap| async move {
		let bytes = slot("chat", 0, "abcd");
		let (body, _, drops) = source(vec![Ok(Frame::data(bytes))], None);
		let mut body = limited(body, 4096, false, limits(8192, cap, 1));
		let rejected = body.frame().await.unwrap().is_err();
		assert!(body.frame().await.is_none());
		assert_eq!(drops.load(Ordering::SeqCst), 1);
		rejected
	};
	let (a, b) = tokio::join!(run(3), run(4));
	assert!(a);
	assert!(!b);
}

#[tokio::test]
async fn memory_config_normalization_preserves_ai_system_shape_and_intersects_limits() {
	use crate::types::{
		agent::{BackendTrafficPolicy, ListenerTarget},
		local::NormalizedLocalConfig,
	};
	let config = crate::config::parse_config("{}".into(), None).unwrap();
	let resources = crate::resource_manager::ResourceFetcher::files_only();
	let target = ListenerTarget {
		gateway_name: "gateway".into(),
		gateway_namespace: "default".into(),
		listener_name: None,
		port: None,
	};
	let yaml = "aiSystems:\n- name: edge\n  llm:\n    policies:\n      streamingLimits:\n        maxResponseBytes: 4096\n        maxToolArgumentBytes: 16\n        maxTrackedBlocks: 2\n    models:\n    - name: local\n      provider: openai\n      streamingLimits:\n        maxResponseBytes: 8192\n        maxToolArgumentBytes: 8\n        maxTrackedBlocks: 4\n";
	let normalized = NormalizedLocalConfig::from(&config, &resources, target.clone(), yaml)
		.await
		.unwrap();
	let find = |normalized: &NormalizedLocalConfig| {
		normalized
			.backends
			.iter()
			.flat_map(|b| b.inline_policies.iter())
			.find_map(|policy| match policy {
				BackendTrafficPolicy::AI(policy) if policy.streaming_limits.is_some() => {
					Some(policy.clone())
				},
				_ => None,
			})
			.unwrap()
	};
	let first = find(&normalized);
	assert_eq!(first.streaming_limits, Some(limits(4096, 8, 2)));
	let next = NormalizedLocalConfig::from(
		&config,
		&resources,
		target.clone(),
		&yaml.replace("maxToolArgumentBytes: 8", "maxToolArgumentBytes: 4"),
	)
	.await
	.unwrap();
	assert_eq!(find(&next).streaming_limits, Some(limits(4096, 4, 2)));
	assert_eq!(first.streaming_limits, Some(limits(4096, 8, 2)));
	assert!(
		NormalizedLocalConfig::from(
			&config,
			&resources,
			target,
			&yaml.replace("maxToolArgumentBytes: 8", "maxToolArgumentBytes: 0")
		)
		.await
		.is_err()
	);
	assert_eq!(first.streaming_limits, Some(limits(4096, 8, 2)));
}
#[tokio::test]
async fn memory_limits_cover_terminal_response_snapshots_and_content_indices() {
	for value in [
		json!({"type":"response.completed","response":{"output":[{"type":"function_call","arguments":"too-large"}]}}),
		json!({"type":"response.content_part.added","output_index":0,"content_index":1}),
		json!({"type":"message_start","message":{"content":[{"type":"tool_use","input":{"key":"too-large"}}]}}),
	] {
		let (body, _, drops) = source(vec![Ok(Frame::data(event(value)))], None);
		let mut body = limited(body, 4096, false, limits(8192, 4, 1));
		assert!(body.frame().await.unwrap().is_err());
		assert_eq!(drops.load(Ordering::SeqCst), 1);
		assert!(body.frame().await.is_none());
	}
}

#[tokio::test]
async fn memory_tiny_valid_byte_limit_rejects_without_codec_constructor_panic() {
	let settings = serde_json::from_value::<StreamingLimits>(json!({"maxResponseBytes":1})).unwrap();
	let (body, polls, drops) = source(vec![Ok(Frame::data(Bytes::from_static(b"xx")))], None);
	let mut body = limited(body, 4096, false, settings);
	assert!(
		body
			.frame()
			.await
			.unwrap()
			.unwrap_err()
			.to_string()
			.contains("response byte limit")
	);
	assert!(body.frame().await.is_none());
	assert_eq!(polls.load(Ordering::SeqCst), 1);
	assert_eq!(drops.load(Ordering::SeqCst), 1);
}

#[cfg(not(feature = "providers-aws"))]
#[tokio::test]
async fn unavailable_aws_framing_fails_closed_without_polling_source() {
	for strict in [false, true] {
		let (body, polls, drops) = source(
			vec![Ok(Frame::data(Bytes::from_static(b"must not forward")))],
			None,
		);
		let mut body = if strict {
			super::super::streaming_wire::validated(body, 4096, true)
		} else {
			limited(body, 4096, true, StreamingLimits::default())
		};
		assert_eq!(polls.load(Ordering::SeqCst), 0);
		assert_eq!(drops.load(Ordering::SeqCst), 1);
		assert!(
			body
				.frame()
				.await
				.unwrap()
				.unwrap_err()
				.to_string()
				.contains("not compiled")
		);
		assert!(body.frame().await.is_none());
		assert_eq!(polls.load(Ordering::SeqCst), 0);
	}
}
