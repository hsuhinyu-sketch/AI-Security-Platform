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
