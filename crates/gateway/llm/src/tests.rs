use super::*;
use futures_util::{StreamExt, TryStreamExt};
use http_body::Frame;
use http_body_util::{BodyExt, Full, StreamBody};
use std::sync::{
	Arc, Mutex,
	atomic::{AtomicBool, Ordering},
};

struct PatternGuard(Arc<Mutex<Vec<String>>>);
#[async_trait::async_trait]
impl StreamingEvaluator for PatternGuard {
	fn failure_mode(&self) -> FailureMode {
		FailureMode::FailClosed
	}
	async fn evaluate(&mut self, window: &str) -> anyhow::Result<Option<StreamingGuardrailOutcome>> {
		self.0.lock().unwrap().push(window.to_owned());
		Ok(
			window
				.contains("secret")
				.then(|| StreamingGuardrailOutcome::Blocked(Bytes::from_static(b"blocked"))),
		)
	}
}
struct OnDrop(Arc<AtomicBool>);
impl Drop for OnDrop {
	fn drop(&mut self) {
		self.0.store(true, Ordering::Release);
	}
}
fn delta(text: &str) -> Bytes {
	Bytes::from(format!(
		"data: {}\n\n",
		serde_json::json!({"choices":[{"delta":{"content":text}}]})
	))
}

#[tokio::test]
async fn unsupported_stream_content_is_blocked_before_disclosure_and_drops_upstream() {
	use serde_json::json;
	for value in [
		json!({"choices":[{"delta":{"analysis":"secret"}}]}),
		json!({"choices":[{"delta":{"content":"safe","transcript":"secret"}}]}),
		json!({"choices":[{"message":{"role":"assistant","reasoning":"secret"}}]}),
		json!({"choices":[{"delta":{"model":"secret"}}]}),
		json!({"choices":[{"analysis":"secret","delta":{}}]}),
		json!({"choices":[{"delta":{"tool_calls":[{"function":{"analysis":"secret"}}]}}]}),
		json!({"type":"content_block_delta","delta":{"type":"text_delta","analysis":"secret"}}),
		json!({"type":"response.output_item.done","item":{"type":"message","content":[{"type":"output_text","text":"safe","transcript":"secret"}]}}),
		json!({"choices":[{"delta":{"type":"audio","text":"safe"}}]}),
		json!({"choices":[],"usage":{"audio":{"data":"secret"}}}),
	] {
		let dropped = Arc::new(AtomicBool::new(false));
		let lease = OnDrop(dropped.clone());
		let source = futures_util::stream::iter([Ok::<_, std::io::Error>(Frame::data(Bytes::from(
			format!("data: {value}\n\n"),
		)))])
		.chain(futures_util::stream::pending())
		.map(move |item| {
			let _keep = &lease;
			item
		});
		let body = GuardedSseBody::with_threshold(StreamBody::new(source), vec![], 4096, None::<()>, 1);
		// An unsupported event must terminate even if the upstream never produces EOF.
		let output = tokio::time::timeout(std::time::Duration::from_secs(1), body.collect())
			.await
			.unwrap()
			.unwrap()
			.to_bytes();
		let output = String::from_utf8(output.to_vec()).unwrap();
		assert!(
			output.contains("guardrail_intervention"),
			"{value}: {output}"
		);
		assert!(!output.contains("secret"), "{value}: {output}");
		assert!(dropped.load(Ordering::Acquire));
	}
}

#[tokio::test]
async fn known_content_formats_keep_metadata_out_of_adjacent_text() {
	use serde_json::json;
	let cases = [
		vec![
			json!({"id":"ignored","model":"ignored","object":"chat.completion.chunk","usage":{"output_tokens":1},"obfuscation":"ignored","choices":[{"index":0,"delta":{"role":"assistant","content":"sec"},"finish_reason":null}]}),
			json!({"choices":[{"delta":{"content":"ret"}}]}),
		],
		vec![
			json!({"type":"message_start","message":{"type":"message","id":"ignored","model":"ignored","role":"assistant","content":[],"usage":{"input_tokens":1}}}),
			json!({"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"sec"}}),
			json!({"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"ret"}}),
		],
		vec![
			json!({"type":"response.created","sequence_number":0,"response":{"id":"ignored","model":"ignored","output":[],"instructions":"ignored","usage":null}}),
			json!({"type":"response.output_text.delta","item_id":"ignored","output_index":0,"content_index":0,"delta":"sec"}),
			json!({"type":"response.output_text.delta","item_id":"ignored","output_index":0,"content_index":0,"delta":"ret"}),
		],
	];
	for events in cases {
		let wire = events
			.iter()
			.map(|event| format!("data: {event}\n\n"))
			.collect::<String>();
		for (wire, expected) in [
			(wire.clone(), "secret"),
			(
				wire
					.replace("\"sec\"", "\"sa\"")
					.replace("\"ret\"", "\"fe\""),
				"safe",
			),
		] {
			let windows = Arc::new(Mutex::new(Vec::new()));
			let body = GuardedSseBody::new(
				Full::new(Bytes::from(wire)),
				vec![Box::new(PatternGuard(windows.clone()))],
				4096,
				None::<()>,
			);
			let output = body.collect().await.unwrap().to_bytes();
			assert_eq!(
				String::from_utf8_lossy(&output).contains("guardrail_intervention"),
				expected == "secret"
			);
			assert_eq!(*windows.lock().unwrap(), vec![expected]);
		}
	}
}

#[tokio::test]
async fn initial_tool_inputs_and_partial_arguments_are_inspected() {
	use serde_json::json;
	for events in [
		vec![
			json!({"choices":[{"delta":{"tool_calls":[{"id":"call","type":"function","index":0,"function":{"name":"echo","arguments":"{\"query\":\"sec"}}]}}]}),
			json!({"choices":[{"delta":{"tool_calls":[{"index":0,"function":{"arguments":"ret\"}"}}]}}]}),
		],
		vec![
			json!({"type":"content_block_start","index":0,"content_block":{"type":"tool_use","id":"call","name":"echo","input":{"query":"secret"}}}),
		],
		vec![
			json!({"type":"content_block_start","index":0,"content_block":{"type":"tool_use","id":"call","name":"echo","input":{}}}),
			json!({"type":"content_block_delta","index":0,"delta":{"type":"input_json_delta","partial_json":"{\"query\":\"sec"}}),
			json!({"type":"content_block_delta","index":0,"delta":{"type":"input_json_delta","partial_json":"ret\"}"}}),
		],
		vec![
			json!({"type":"response.output_item.done","item":{"type":"function_call","id":"call","call_id":"call","name":"echo","arguments":"{\"query\":\"secret\"}","status":"completed"}}),
		],
	] {
		let windows = Arc::new(Mutex::new(Vec::new()));
		let wire = events
			.iter()
			.map(|event| format!("data: {event}\n\n"))
			.collect::<String>();
		let body = GuardedSseBody::new(
			Full::new(Bytes::from(wire)),
			vec![Box::new(PatternGuard(windows.clone()))],
			4096,
			None::<()>,
		);
		let output = body.collect().await.unwrap().to_bytes();
		assert!(String::from_utf8_lossy(&output).contains("guardrail_intervention"));
		assert!(
			windows
				.lock()
				.unwrap()
				.iter()
				.any(|text| text.contains("secret"))
		);
	}
}

#[tokio::test]
async fn existing_successful_conversion_frames_remain_valid_guarded_output() {
	let fixtures: serde_json::Value =
		serde_json::from_str(include_str!("../tests/fixtures/streaming-golden.json")).unwrap();
	let mut checked = 0;
	for case in fixtures["cases"].as_array().unwrap() {
		if !case["expected"]["error"].is_null() {
			continue;
		}
		let wire = case["expected"]["frames"]
			.as_array()
			.unwrap()
			.iter()
			.map(|frame| frame.as_str().unwrap())
			.collect::<String>();
		let windows = Arc::new(Mutex::new(Vec::new()));
		let body = GuardedSseBody::new(
			Full::new(Bytes::from(wire)),
			vec![Box::new(PatternGuard(windows))],
			64 * 1024,
			None::<()>,
		);
		let output = body.collect().await.unwrap().to_bytes();
		assert!(
			!String::from_utf8_lossy(&output).contains("guardrail_intervention"),
			"{} / {}: {}",
			case["kind"],
			case["name"],
			String::from_utf8_lossy(&output)
		);
		checked += 1;
	}
	assert!(checked > 0);
}

#[tokio::test]
async fn ancillary_content_is_checked_without_splitting_main_text_patterns() {
	use serde_json::json;
	for (events, expected_block) in [
		(
			vec![
				json!({"choices":[{"delta":{"content":"sec"},"logprobs":{"content":[{"token":"ignored"}]}}]}),
				json!({"choices":[{"delta":{"content":"ret"}}]}),
			],
			true,
		),
		(
			vec![
				json!({"choices":[{"delta":{"content":"safe"},"logprobs":{"content":[{"token":"secret"}]}}]}),
			],
			true,
		),
		(
			vec![
				json!({"type":"response.content_part.done","part":{"type":"output_text","text":"safe","annotations":[{"text":"secret"}]}}),
			],
			true,
		),
		(
			vec![
				json!({"type":"content_block_delta","index":0,"delta":{"type":"citations_delta","citations":[{"cited_text":"secret"}]}}),
			],
			true,
		),
		(
			vec![
				json!({"choices":[{"delta":{"content":"safe"},"logprobs":{"content":[{"token":"safe"}]}}]}),
			],
			false,
		),
	] {
		let windows = Arc::new(Mutex::new(Vec::new()));
		let wire = events
			.iter()
			.map(|event| format!("data: {event}\n\n"))
			.collect::<String>();
		let body = GuardedSseBody::new(
			Full::new(Bytes::from(wire)),
			vec![Box::new(PatternGuard(windows.clone()))],
			4096,
			None::<()>,
		);
		let output = body.collect().await.unwrap().to_bytes();
		let output = String::from_utf8_lossy(&output);
		assert_eq!(
			output.contains("guardrail_intervention"),
			expected_block,
			"{events:?}: {output}"
		);
		if expected_block {
			assert!(!output.contains("secret"));
		}
		assert!(!windows.lock().unwrap().is_empty());
	}
}

#[tokio::test]
async fn ancillary_evaluation_does_not_replace_the_main_text_overlap() {
	use serde_json::json;
	let windows = Arc::new(Mutex::new(Vec::new()));
	let events = [
		json!({"choices":[{"delta":{"content":"sec"},"logprobs":{"content":[{"token":"metadata"}]}}]}),
		json!({"choices":[{"delta":{"content":"ret"}}]}),
	];
	let source =
		futures_util::stream::iter(events.map(|event| {
			Ok::<_, std::io::Error>(Frame::data(Bytes::from(format!("data: {event}\n\n"))))
		}));
	let body = GuardedSseBody::with_threshold(
		StreamBody::new(source),
		vec![Box::new(PatternGuard(windows.clone()))],
		4096,
		None::<()>,
		1,
	);
	let output = body.collect().await.unwrap().to_bytes();
	let output = String::from_utf8_lossy(&output);
	assert!(output.contains("guardrail_intervention"));
	assert!(!output.contains("ret"));
	let windows = windows.lock().unwrap();
	assert_eq!(windows[0], "sec");
	assert!(windows[1].contains("metadata"));
	assert_eq!(windows[2], "secret");
}

#[tokio::test]
async fn cross_window_block_discards_pending_frames_and_releases_upstream() {
	let windows = Arc::new(Mutex::new(Vec::new()));
	let dropped = Arc::new(AtomicBool::new(false));
	let lease = OnDrop(dropped.clone());
	let chunks = futures_util::stream::iter([
		Ok::<_, std::io::Error>(delta(&format!("{}sec", "a".repeat(1021)))),
		Ok(delta(&format!("ret{}", "x".repeat(1021)))),
	])
	.chain(futures_util::stream::pending())
	.map(move |item| {
		let _keep = &lease;
		item
	});
	let body = GuardedSseBody::new(
		StreamBody::new(chunks.map_ok(Frame::data)),
		vec![Box::new(PatternGuard(windows.clone()))],
		4096,
		None::<()>,
	);
	let output = body.collect().await.unwrap().to_bytes();
	let output = String::from_utf8(output.to_vec()).unwrap();
	assert!(output.contains("sec"));
	assert!(!output.contains("retxxx"));
	assert!(output.contains("guardrail_intervention"));
	assert!(windows.lock().unwrap()[1].contains("secret"));
	assert!(dropped.load(Ordering::Acquire));
}

#[tokio::test]
async fn truncated_event_is_not_disclosed_as_valid_output() {
	let body = GuardedSseBody::new(
		Full::new(Bytes::from_static(
			b"data: {\"choices\":[{\"delta\":{\"content\":\"secret\"}}]}",
		)),
		vec![],
		4096,
		None::<()>,
	);
	let output = body.collect().await.unwrap().to_bytes();
	let output = String::from_utf8(output.to_vec()).unwrap();
	assert!(output.contains("guardrail_intervention"));
	assert!(!output.contains("secret"));
}

struct PendingGuard {
	started: Arc<AtomicBool>,
	dropped: Arc<AtomicBool>,
}
#[async_trait::async_trait]
impl StreamingEvaluator for PendingGuard {
	async fn evaluate(&mut self, _: &str) -> anyhow::Result<Option<StreamingGuardrailOutcome>> {
		let lease = OnDrop(self.dropped.clone());
		self.started.store(true, Ordering::SeqCst);
		std::future::pending::<()>().await;
		drop(lease);
		Ok(None)
	}
}

#[tokio::test]
async fn s6_guard_evaluation_is_backpressured_and_drop_cancels_inline_future() {
	let polls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
	let dropped = Arc::new(AtomicBool::new(false));
	let evaluation_dropped = Arc::new(AtomicBool::new(false));
	let started = Arc::new(AtomicBool::new(false));
	let lease = OnDrop(dropped.clone());
	let source_polls = polls.clone();
	let stream = futures_util::stream::repeat_with(move || {
		let _keep = &lease;
		source_polls.fetch_add(1, Ordering::SeqCst);
		Ok::<_, std::io::Error>(Frame::data(delta("one")))
	});
	let mut body = GuardedSseBody::with_threshold(
		StreamBody::new(stream),
		vec![Box::new(PendingGuard {
			started: started.clone(),
			dropped: evaluation_dropped.clone(),
		})],
		4096,
		None::<()>,
		1,
	);
	assert_eq!(polls.load(Ordering::SeqCst), 0);
	assert!(futures_util::poll!(body.frame()).is_pending());
	assert!(started.load(Ordering::SeqCst));
	assert_eq!(polls.load(Ordering::SeqCst), 1);
	for _ in 0..8 {
		tokio::task::yield_now().await;
	}
	assert_eq!(polls.load(Ordering::SeqCst), 1);
	drop(body);
	assert!(dropped.load(Ordering::SeqCst));
	assert!(evaluation_dropped.load(Ordering::SeqCst));
}

struct FailingGuard(FailureMode);
#[async_trait::async_trait]
impl StreamingEvaluator for FailingGuard {
	fn failure_mode(&self) -> FailureMode {
		self.0
	}
	async fn evaluate(&mut self, _: &str) -> anyhow::Result<Option<StreamingGuardrailOutcome>> {
		anyhow::bail!("fixture evaluator unavailable")
	}
}

#[tokio::test]
async fn s6_guard_policy_failure_modes_and_logger_release_are_explicit() {
	for mode in [FailureMode::FailClosed, FailureMode::FailOpen] {
		let released = Arc::new(AtomicBool::new(false));
		let mut body = GuardedSseBody::with_threshold(
			Full::new(delta("guarded")),
			vec![Box::new(FailingGuard(mode))],
			4096,
			Some(OnDrop(released.clone())),
			1,
		);
		let frame = body.frame().await.unwrap().unwrap().into_data().unwrap();
		if mode == FailureMode::FailClosed {
			assert!(!String::from_utf8_lossy(&frame).contains("guarded"));
			assert!(String::from_utf8_lossy(&frame).contains("guardrail_intervention"));
		} else {
			assert!(String::from_utf8_lossy(&frame).contains("guarded"));
		}
		assert!(!released.load(Ordering::SeqCst));
		drop(body);
		assert!(released.load(Ordering::SeqCst));
	}
}
