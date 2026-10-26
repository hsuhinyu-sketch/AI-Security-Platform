//! Default `protocol` selects codecs, providers, routing and streaming.
//! With default features disabled, only shared config, observation and pricing values remain.
//! This data-only selection supplies no model execution or authorization.
//!
//! LLM protocol data, conversion, pricing, provider descriptors and streaming guards.
//!
//! `GuardedSseBody` implements **windowed guardrail evaluation**:
//!
//! 1. Incoming SSE byte frames are held (not forwarded) while text deltas are
//!    accumulated into a pending batch.
//! 2. When the batch reaches `eval_threshold` bytes of text (or the stream ends),
//!    all `StreamingEvaluator`s are run against a window consisting of an
//!    *overlap tail* from previously evaluated text plus the pending batch. The
//!    overlap ensures patterns spanning a batch boundary are still seen
//!    contiguously by at least one evaluation.
//! 3. **Pass** → the held frames are flushed to the client and buffering resumes.
//!    **Block** → the held (never-forwarded) frames are discarded and a synthetic
//!    SSE error event is emitted. Content flushed by earlier passing windows
//!    cannot be retracted — an accepted accuracy/latency tradeoff.
//!
//! This is not 100% accurate: a guard that needs full-response context, or a
//! pattern spanning more than the overlap window, can be missed.

pub mod catalog;
#[cfg(feature = "protocol")]
pub mod content;
#[cfg(feature = "protocol")]
pub mod conversion;
pub mod error;
pub mod provider;
#[cfg(feature = "protocol")]
pub mod routing;
#[cfg(feature = "protocol")]
pub mod streaming;
pub mod types;

pub use error::WireError;
pub use types::{CacheTokenConvention, LLMResponse};

use bytes::Bytes;

#[cfg(feature = "protocol")]
mod guard;
#[cfg(feature = "protocol")]
pub use guard::{
	DEFAULT_EVAL_THRESHOLD, GuardedSseBody, OVERLAP_BYTES, evaluate_window, tail_chars,
};

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "schema", schemars(rename = "WebhookFailureMode"))]
#[derive(Default, Copy, PartialEq, Eq)]
pub enum FailureMode {
	/// Reject the request when the webhook guardrail is unavailable (default).
	#[default]
	#[serde(rename = "failClosed")]
	FailClosed,
	/// Allow the request through when the webhook guardrail is unavailable.
	#[serde(rename = "failOpen")]
	FailOpen,
}

#[async_trait::async_trait]
pub trait StreamingEvaluator: Send {
	/// Evaluate a text window. Returns `Some(Blocked)` if the content should be blocked.
	async fn evaluate(&mut self, window: &str) -> anyhow::Result<Option<StreamingGuardrailOutcome>>;

	/// Returns the failure mode to apply when `evaluate` returns an error.
	/// Guard types without an explicit `failure_mode` field default to `FailOpen`.
	fn failure_mode(&self) -> FailureMode {
		FailureMode::FailOpen
	}
}

/// Outcome returned by a `StreamingEvaluator`.
pub enum StreamingGuardrailOutcome {
	/// Content was blocked; include the rejection body to encode for the stream.
	Blocked(Bytes),
}

#[cfg(all(test, feature = "protocol"))]
mod tests;
