//! Host policy clients are assembled here; the SSE state machine lives in gateway-llm.
use super::{
	FailureMode, ResponseGuard, ResponseGuardKind, StreamingEvaluator, StreamingGuardrailOutcome,
};
use crate::llm::policy::PromptGuard;
use crate::proxy::httpproxy::PolicyClient;
use ::http::HeaderMap;
pub use gateway_llm::{
	DEFAULT_EVAL_THRESHOLD, GuardedSseBody, OVERLAP_BYTES, evaluate_window, tail_chars,
};

// ---------------------------------------------------------------------------
// Factory
// ---------------------------------------------------------------------------

/// Construct a boxed `StreamingEvaluator` for the given `ResponseGuard`.
pub fn make_evaluator(
	guard: &ResponseGuard,
	client: PolicyClient,
	http_headers: HeaderMap,
) -> Box<dyn StreamingEvaluator> {
	Box::new(ResponseGuardEvaluator {
		guard: guard.clone(),
		client,
		http_headers,
	})
}

struct ResponseGuardEvaluator {
	guard: ResponseGuard,
	client: PolicyClient,
	http_headers: HeaderMap,
}

#[async_trait::async_trait]
impl StreamingEvaluator for ResponseGuardEvaluator {
	fn failure_mode(&self) -> FailureMode {
		match &self.guard.kind {
			ResponseGuardKind::Webhook(wh) => wh.failure_mode,
			_ => FailureMode::FailClosed,
		}
	}

	async fn evaluate(&mut self, window: &str) -> anyhow::Result<Option<StreamingGuardrailOutcome>> {
		PromptGuard::evaluate_streaming_response_window(
			&self.guard,
			window,
			&self.client,
			&self.http_headers,
		)
		.await
	}
}
