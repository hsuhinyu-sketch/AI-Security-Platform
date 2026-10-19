//! Streaming guardrail infrastructure: `GuardedSseBody` and per-guardrail evaluators.
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

use std::collections::VecDeque;
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

use ::http::HeaderMap;
use bytes::Bytes;
use http_body::Frame;
use pin_project_lite::pin_project;
use tokio_sse_codec::{Event, Frame as SseFrame, SseDecoder};
use tokio_util::codec::Decoder;
use tracing::warn;

use super::{
	FailureMode, ResponseGuard, ResponseGuardKind, StreamingEvaluator, StreamingGuardrailOutcome,
};
use crate::llm::policy::PromptGuard;
use crate::proxy::httpproxy::PolicyClient;

/// Text bytes accumulated before triggering a guardrail evaluation.
/// Larger values reduce guardrail API calls but increase time-to-first-byte
/// and the amount of content discarded on a mid-stream block.
pub const DEFAULT_EVAL_THRESHOLD: usize = 1024;

/// Tail bytes of previously evaluated text prepended to each new window so
/// patterns spanning a batch boundary are still seen contiguously.
pub const OVERLAP_BYTES: usize = 256;

/// Return the last `max_bytes` of `s`, respecting UTF-8 char boundaries.
pub fn tail_chars(s: &str, max_bytes: usize) -> &str {
	if s.len() <= max_bytes {
		return s;
	}
	let mut start = s.len() - max_bytes;
	while !s.is_char_boundary(start) {
		start += 1;
	}
	&s[start..]
}

/// Run all evaluators against a window. Returns the rejection body if any evaluator blocked.
pub async fn evaluate_window(
	evaluators: &mut [Box<dyn StreamingEvaluator>],
	window: &str,
) -> Option<Bytes> {
	for ev in evaluators.iter_mut() {
		match ev.evaluate(window).await {
			Ok(Some(StreamingGuardrailOutcome::Blocked(body))) => {
				tracing::debug!("streaming guardrail blocked response window");
				return Some(body);
			},
			Ok(None) => {},
			Err(e) => match ev.failure_mode() {
				FailureMode::FailClosed => {
					warn!("streaming guardrail error, failing closed: {e}");
					return Some(Bytes::from_static(b"Content blocked by guardrail policy"));
				},
				FailureMode::FailOpen => {
					warn!("streaming guardrail error, failing open: {e}");
				},
			},
		}
	}
	None
}

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

// ---------------------------------------------------------------------------
// GuardedSseBody
// ---------------------------------------------------------------------------

/// Synthetic SSE error event sent to the client when a guardrail blocks content.
///
/// Encoded as a single `data: {...}\n\n` SSE frame.
fn guardrail_blocked_sse_bytes(body: Bytes) -> Bytes {
	let message = String::from_utf8_lossy(&body);
	let event = serde_json::json!({
		"error": {
			"type": "guardrail_blocked",
			"code": "guardrail_intervention",
			"message": message,
		}
	});
	Bytes::from(format!("data: {event}\n\n"))
}

type EvalFuture =
	Pin<Box<dyn Future<Output = (Vec<Box<dyn StreamingEvaluator>>, Option<Bytes>)> + Send + 'static>>;

/// Internal state machine for `GuardedSseBody`.
enum GuardedBodyState {
	/// Reading from upstream, holding frames until the eval threshold is reached.
	Buffering,
	/// Evaluating the current window asynchronously. `eof` records whether the
	/// upstream is already exhausted (this is the final evaluation).
	Evaluating { fut: EvalFuture, eof: bool },
	/// Yield held frames in order, then return to `Buffering` (or `Done` if `eof`).
	Flushing { queue: VecDeque<Bytes>, eof: bool },
	/// Send the synthetic error event then close.
	Blocked(Bytes),
	/// Done – no more frames.
	Done,
}

pin_project! {
	// An `http_body::Body` wrapper that implements windowed guardrail evaluation.
	pub struct GuardedSseBody {
		#[pin]
		inner: Option<crate::http::Body>,
		evaluators: Vec<Box<dyn StreamingEvaluator>>,
		eval_threshold: usize,
		buffer_limit: usize,
		held_frames: Vec<Bytes>,
		held_bytes: usize,
		pending_text: String,
		overlap_tail: String,
		sse_decoder: SseDecoder<Bytes>,
		decode_buffer: bytes::BytesMut,
		state: GuardedBodyState,
		// Owns the rate-limit logger; dropped only when this body is fully consumed,
		// so telemetry is recorded at the correct time.
		logger: Option<crate::llm::AmendOnDrop>,
	}
}

impl GuardedSseBody {
	/// Create a new `GuardedSseBody` with the default evaluation threshold.
	///
	/// * `inner` – the upstream SSE body.
	/// * `evaluators` – one evaluator per configured response guard.
	/// * `buffer_limit` – max bytes of held frames; reaching it forces an evaluation.
	/// * `logger` – rate-limit logger that must outlive the streaming response.
	// We do actually return Self; just wrapped in an http_body::Body. The annotation silences a false positive from clippy about that.
	#[allow(clippy::new_ret_no_self)]
	pub fn new(
		inner: crate::http::Body,
		evaluators: Vec<Box<dyn StreamingEvaluator>>,
		buffer_limit: usize,
		logger: Option<crate::llm::AmendOnDrop>,
	) -> crate::http::Body {
		Self::with_threshold(
			inner,
			evaluators,
			buffer_limit,
			logger,
			DEFAULT_EVAL_THRESHOLD,
		)
	}

	/// Like [`GuardedSseBody::new`] but with an explicit evaluation threshold.
	pub fn with_threshold(
		inner: crate::http::Body,
		evaluators: Vec<Box<dyn StreamingEvaluator>>,
		buffer_limit: usize,
		logger: Option<crate::llm::AmendOnDrop>,
		eval_threshold: usize,
	) -> crate::http::Body {
		let buffer_limit = buffer_limit.clamp(1024, 4 * 1024 * 1024);
		crate::http::Body::new(Self {
			inner: Some(inner),
			evaluators,
			eval_threshold: eval_threshold.clamp(1, buffer_limit),
			buffer_limit,
			held_frames: Vec::new(),
			held_bytes: 0,
			pending_text: String::new(),
			overlap_tail: String::new(),
			sse_decoder: SseDecoder::with_max_size(buffer_limit),
			decode_buffer: bytes::BytesMut::new(),
			state: GuardedBodyState::Buffering,
			logger,
		})
	}

	/// Extract text delta from a parsed SSE frame if present.
	fn extract_text_delta(frame: &SseFrame<Bytes>) -> Result<Option<String>, ()> {
		let SseFrame::Event(Event { data, .. }) = frame else {
			return Ok(None);
		};
		if data.as_ref() == b"[DONE]" {
			return Ok(None);
		}
		let value: serde_json::Value = serde_json::from_slice(data).map_err(|_| ())?;
		if !value.is_object() {
			return Err(());
		}
		// Inspect content fields in every choice, initial block and final response copy.
		// Telemetry/obfuscation must not be interleaved between consecutive text deltas:
		// that would hide a pattern split across otherwise adjacent fragments.
		fn collect(value: &serde_json::Value, text: &mut String, content: bool) {
			match value {
				serde_json::Value::String(s) if content => text.push_str(s),
				serde_json::Value::Array(values) => values.iter().for_each(|v| collect(v, text, content)),
				serde_json::Value::Object(values) => {
					for (key, value) in values {
						let content = matches!(
							key.as_str(),
							"text"
								| "content"
								| "delta"
								| "arguments"
								| "partial_json"
								| "thinking"
								| "reasoning_content"
								| "refusal"
								| "data"
						);
						collect(value, text, content);
					}
				},
				_ => {},
			}
		}
		let mut text = String::new();
		fn uninspectable(value: &serde_json::Value) -> bool {
			match value {
				serde_json::Value::Array(a) => a.iter().any(uninspectable),
				serde_json::Value::Object(o) => o.iter().any(|(k, v)| {
					(k == "type"
						&& v
							.as_str()
							.is_some_and(|s| s.contains("audio") || s.contains("image")))
						|| (matches!(k.as_str(), "audio" | "image_url" | "b64_json") && !v.is_null())
						|| uninspectable(v)
				}),
				_ => false,
			}
		}
		if uninspectable(&value) {
			return Err(());
		}
		collect(&value, &mut text, false);
		Ok((!text.is_empty()).then_some(text))
	}

	fn encode_frame(frame: SseFrame<Bytes>) -> Option<Bytes> {
		let SseFrame::Event(event) = frame else {
			return None;
		};
		Some(crate::parse::encode_sse_event(
			if event.name == "message" {
				""
			} else {
				&event.name
			},
			event.data,
		))
	}
}

impl http_body::Body for GuardedSseBody {
	type Data = Bytes;
	type Error = crate::http::Error;

	fn poll_frame(
		self: Pin<&mut Self>,
		cx: &mut Context<'_>,
	) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
		let mut this = self.project();
		let mut steps = 0;

		loop {
			// An always-ready source of comments/empty chunks must not monopolize a
			// Tokio worker and prevent outer deadlines or cancellation from polling.
			if steps == 64 {
				cx.waker().wake_by_ref();
				return Poll::Pending;
			}
			steps += 1;
			match this.state {
				// -----------------------------------------------------------------
				// Flushing: yield held frames one at a time.
				// -----------------------------------------------------------------
				GuardedBodyState::Flushing { queue, eof } => {
					if let Some(frame) = queue.pop_front() {
						return Poll::Ready(Some(Ok(Frame::data(frame))));
					} else if *eof {
						*this.state = GuardedBodyState::Done;
						return Poll::Ready(None);
					} else {
						*this.state = GuardedBodyState::Buffering;
					}
				},
				// -----------------------------------------------------------------
				// Blocked: yield synthetic error event, then done.
				// -----------------------------------------------------------------
				GuardedBodyState::Blocked(body) => {
					this.inner.as_mut().set(None);
					this.decode_buffer.clear();
					this.pending_text.clear();
					let body = std::mem::take(body);
					*this.state = GuardedBodyState::Done;
					return Poll::Ready(Some(Ok(Frame::data(guardrail_blocked_sse_bytes(body)))));
				},
				// -----------------------------------------------------------------
				// Done: stream exhausted.
				// -----------------------------------------------------------------
				GuardedBodyState::Done => {
					this.inner.as_mut().set(None);
					return Poll::Ready(None);
				},
				// -----------------------------------------------------------------
				// Evaluating: poll the guardrail future for the current window.
				// -----------------------------------------------------------------
				GuardedBodyState::Evaluating { fut, eof } => match fut.as_mut().poll(cx) {
					Poll::Pending => return Poll::Pending,
					Poll::Ready((evaluators, blocked_body)) => {
						*this.evaluators = evaluators;
						if let Some(body) = blocked_body {
							this.held_frames.clear();
							*this.held_bytes = 0;
							*this.state = GuardedBodyState::Blocked(body);
						} else {
							let queue: VecDeque<Bytes> = this.held_frames.drain(..).collect();
							*this.held_bytes = 0;
							*this.state = GuardedBodyState::Flushing { queue, eof: *eof };
						}
					},
				},
				// -----------------------------------------------------------------
				// Buffering: read from upstream, holding frames until threshold.
				// -----------------------------------------------------------------
				GuardedBodyState::Buffering => {
					match this
						.inner
						.as_mut()
						.as_pin_mut()
						.expect("active upstream")
						.poll_frame(cx)
					{
						Poll::Pending => return Poll::Pending,
						Poll::Ready(Some(Err(e))) => {
							*this.state = GuardedBodyState::Done;
							this.inner.as_mut().set(None);
							return Poll::Ready(Some(Err(e)));
						},
						Poll::Ready(Some(Ok(frame))) => {
							let Some(data) = frame.data_ref() else {
								return Poll::Ready(Some(Ok(frame)));
							};

							if this.decode_buffer.len().saturating_add(data.len()) > *this.buffer_limit {
								*this.state = GuardedBodyState::Blocked(Bytes::from_static(
									b"Stream frame exceeds security budget",
								));
								continue;
							}
							this.decode_buffer.extend_from_slice(data);
							loop {
								match this.sse_decoder.decode(this.decode_buffer) {
									Ok(Some(sse_frame)) => {
										match GuardedSseBody::extract_text_delta(&sse_frame) {
											Ok(Some(delta)) => this.pending_text.push_str(&delta),
											Ok(None) => {},
											Err(()) => {
												*this.state = GuardedBodyState::Blocked(Bytes::from_static(
													b"Invalid structured stream",
												));
												break;
											},
										}
										if let Some(raw) = GuardedSseBody::encode_frame(sse_frame) {
											if this.held_frames.len() >= 1024
												|| this.held_bytes.saturating_add(raw.len()) > *this.buffer_limit
											{
												*this.state = GuardedBodyState::Blocked(Bytes::from_static(
													b"Stream window exceeds security budget",
												));
												break;
											}
											*this.held_bytes += raw.len();
											this.held_frames.push(raw);
										}
									},
									Ok(None) => break,
									Err(e) => {
										warn!("SSE decode error in streaming guardrail body: {e}");
										*this.state =
											GuardedBodyState::Blocked(Bytes::from_static(b"Invalid stream framing"));
										break;
									},
								}
							}
							if matches!(this.state, GuardedBodyState::Blocked(_)) {
								this.held_frames.clear();
								continue;
							}

							let over_limit = *this.held_bytes >= *this.buffer_limit;
							if this.pending_text.len() >= *this.eval_threshold || over_limit {
								// Having a full buffer but empty text implies that the
								// buffer is full of non-text frames (e.g. control frames or unsupported SSE formats that fail to decode).
								// In that case, flush the buffer as-is without evaluation, to avoid stalling on unprocessable content.
								if this.pending_text.is_empty() {
									let queue: VecDeque<Bytes> = this.held_frames.drain(..).collect();
									*this.held_bytes = 0;
									*this.state = GuardedBodyState::Flushing { queue, eof: false };
									continue;
								}
								let batch = std::mem::take(this.pending_text);
								let window = format!("{}{}", this.overlap_tail, batch);
								*this.overlap_tail = tail_chars(&window, OVERLAP_BYTES).to_string();
								let mut evaluators = std::mem::take(this.evaluators);
								let fut: EvalFuture = Box::pin(async move {
									let blocked_body = evaluate_window(&mut evaluators, &window).await;
									(evaluators, blocked_body)
								});
								*this.state = GuardedBodyState::Evaluating { fut, eof: false };
							}
						},
						Poll::Ready(None) => {
							match this.sse_decoder.decode_eof(this.decode_buffer) {
								Ok(Some(sse_frame)) => {
									// An event missing its terminating blank line is not a
									// complete disclosure unit, even if the SSE codec accepts EOF.
									let _ = sse_frame;
									*this.state =
										GuardedBodyState::Blocked(Bytes::from_static(b"Truncated stream event"));
								},
								Ok(None) => {},
								Err(e) => {
									warn!("SSE decode error at EOF in streaming guardrail body: {e}");
									this.decode_buffer.clear();
									*this.state =
										GuardedBodyState::Blocked(Bytes::from_static(b"Invalid stream framing"));
								},
							}
							if matches!(this.state, GuardedBodyState::Blocked(_)) {
								this.held_frames.clear();
								continue;
							}

							if this.pending_text.is_empty() {
								let queue: VecDeque<Bytes> = this.held_frames.drain(..).collect();
								*this.held_bytes = 0;
								*this.state = GuardedBodyState::Flushing { queue, eof: true };
								continue;
							}

							let batch = std::mem::take(this.pending_text);
							let window = format!("{}{}", this.overlap_tail, batch);
							this.overlap_tail.clear();
							let mut evaluators = std::mem::take(this.evaluators);
							let fut: EvalFuture = Box::pin(async move {
								let blocked_body = evaluate_window(&mut evaluators, &window).await;
								(evaluators, blocked_body)
							});
							*this.state = GuardedBodyState::Evaluating { fut, eof: true };
						},
					}
				},
			}
		}
	}
}
