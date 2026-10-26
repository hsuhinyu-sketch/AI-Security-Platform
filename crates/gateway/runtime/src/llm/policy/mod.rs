#[cfg(feature = "gateway-llm")]
use ::http::HeaderMap;
use bytes::Bytes;
#[cfg(feature = "gateway-llm")]
use http_body_util::BodyExt as _;
#[cfg(feature = "gateway-llm")]
use itertools::Itertools;
#[cfg(feature = "gateway-llm")]
use serde::de::DeserializeOwned;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

#[cfg(feature = "gateway-llm")]
use crate::http::auth;
#[cfg(feature = "gateway-llm")]
use crate::http::filters::BackendRequestTimeout;
use crate::http::filters::HeaderModifier;
#[cfg(feature = "gateway-llm")]
use crate::http::jwt::Claims;
use crate::http::{Response, StatusCode};
#[cfg(feature = "gateway-llm")]
use crate::llm::policy::webhook::{MaskActionBody, RequestAction, ResponseAction};
#[cfg(feature = "gateway-llm")]
use crate::llm::{AIError, RequestType, ResponseType};
#[cfg(feature = "gateway-llm")]
use crate::proxy::httpproxy::PolicyClient;
#[cfg(feature = "gateway-llm")]
use crate::telemetry::log::RequestLog;
#[cfg(feature = "gateway-llm")]
use crate::telemetry::metrics::{OutboundCallKind, OutboundCallSubtype};
#[cfg(feature = "gateway-llm")]
use crate::types::agent::HeaderValueMatch;
use crate::types::agent::{BackendTrafficPolicy, HeaderMatch, SimpleBackendReference};
use crate::*;

#[cfg(feature = "gateway-llm")]
fn with_default_timeout(mut req: crate::http::Request) -> crate::http::Request {
	req
		.extensions_mut()
		.insert(BackendRequestTimeout(Duration::from_secs(10)));
	req
}

pub mod webhook;

#[cfg(all(feature = "gateway-llm", feature = "providers-azure"))]
mod azure_content_safety;
#[cfg(all(feature = "gateway-llm", feature = "providers-aws"))]
mod bedrock_guardrails;
#[cfg(all(feature = "gateway-llm", feature = "providers-gcp"))]
mod google_model_armor;
#[cfg(feature = "gateway-llm")]
mod moderation;
#[cfg(feature = "gateway-llm")]
mod pii;
#[cfg(feature = "gateway-llm")]
pub mod streaming_guardrails;
pub mod streaming_limits;
#[cfg(feature = "gateway-llm")]
pub(crate) mod streaming_wire;

/// Routes stored in a deterministic order: **longest key to shortest key**, with `"*"` always last.
///
/// This lets us iterate and match more-specific suffixes first.
#[derive(Debug, Clone, Default)]
pub struct SortedRoutes {
	inner: IndexMap<Strng, crate::llm::RouteType>,
}

impl SortedRoutes {
	pub fn is_empty(&self) -> bool {
		self.inner.is_empty()
	}

	pub fn insert(&mut self, k: Strng, v: crate::llm::RouteType) -> Option<crate::llm::RouteType> {
		let prev = self.inner.insert(k, v);
		self.sort();
		prev
	}

	fn sort(&mut self) {
		// Sort by:
		// - wildcard last
		// - longer keys first
		// - stable tie-breaker (lexicographic) for deterministic output
		let mut entries: Vec<(Strng, crate::llm::RouteType)> =
			std::mem::take(&mut self.inner).into_iter().collect();
		entries.sort_by(|(a, _), (b, _)| {
			let a = a.as_str();
			let b = b.as_str();
			(a == "*", std::cmp::Reverse(a.len()), a).cmp(&(b == "*", std::cmp::Reverse(b.len()), b))
		});
		self.inner = entries.into_iter().collect();
	}
}

impl std::ops::Deref for SortedRoutes {
	type Target = IndexMap<Strng, crate::llm::RouteType>;

	fn deref(&self) -> &Self::Target {
		&self.inner
	}
}

impl<'a> IntoIterator for &'a SortedRoutes {
	type Item = (&'a Strng, &'a crate::llm::RouteType);
	type IntoIter = indexmap::map::Iter<'a, Strng, crate::llm::RouteType>;

	fn into_iter(self) -> Self::IntoIter {
		self.inner.iter()
	}
}

impl FromIterator<(Strng, crate::llm::RouteType)> for SortedRoutes {
	fn from_iter<T: IntoIterator<Item = (Strng, crate::llm::RouteType)>>(iter: T) -> Self {
		let mut routes = Self {
			inner: iter.into_iter().collect(),
		};
		routes.sort();
		routes
	}
}

impl Serialize for SortedRoutes {
	fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
		self.inner.serialize(serializer)
	}
}

impl<'de> Deserialize<'de> for SortedRoutes {
	fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
		let mut routes = Self {
			inner: IndexMap::<Strng, crate::llm::RouteType>::deserialize(deserializer)?,
		};
		routes.sort();
		Ok(routes)
	}
}

#[apply(schema!)]
#[derive(Default)]
pub struct Policy {
	/// Finite per-response resource admission before streaming conversion.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub streaming_limits: Option<streaming_limits::StreamingLimits>,
	/// Prompt and response guardrails to apply to LLM traffic.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub prompt_guard: Option<PromptGuard>,
	/// Default request body values added only when the client did not provide them.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub defaults: Option<HashMap<String, serde_json::Value>>,
	/// Request body values that replace client-provided values.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub overrides: Option<HashMap<String, serde_json::Value>>,
	/// Request body values computed from CEL expressions.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub transformations: Option<HashMap<String, Arc<cel::Expression>>>,
	/// Messages to add before or after the client prompt.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub prompts: Option<PromptEnrichment>,
	/// Model name aliases that rewrite requested model names.
	#[serde(
		rename = "modelAliases",
		default,
		skip_serializing_if = "HashMap::is_empty"
	)]
	pub model_aliases: HashMap<Strng, Strng>,
	/// Compiled wildcard patterns, sorted by specificity (longer patterns first).
	/// Not serialized - computed from model_aliases during policy creation.
	/// Wrapped in Arc to avoid cloning compiled regex during policy merging.
	#[serde(skip)]
	pub wildcard_patterns: Arc<Vec<(ModelAliasPattern, Strng)>>,
	/// Prompt caching settings for providers that support cache markers.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub prompt_caching: Option<PromptCachingConfig>,
	/// Route type overrides selected by request path suffix.
	#[serde(default, skip_serializing_if = "SortedRoutes::is_empty")]
	#[cfg_attr(
		feature = "schema",
		schemars(with = "std::collections::HashMap<String, crate::llm::RouteType>")
	)]
	pub routes: SortedRoutes,
}

impl crate::store::HasExpressions for Policy {
	fn expressions(&self) -> impl Iterator<Item = &cel::Expression> {
		self
			.transformations
			.iter()
			.flatten()
			.map(|(_, expr)| expr.as_ref())
	}
}

/// Wildcard pattern converted to regex for model name matching.
/// Stores the compiled regex and original pattern length for specificity sorting.
#[apply(schema!)]
pub struct ModelAliasPattern {
	#[serde(with = "serde_regex")]
	#[cfg_attr(feature = "schema", schemars(with = "String"))]
	regex: regex::Regex,
	pattern_len: usize,
}

impl ModelAliasPattern {
	pub fn from_wildcard(pattern: &str) -> Result<Self, String> {
		if !pattern.contains('*') {
			return Err(format!("Pattern '{}' contains no wildcards", pattern));
		}

		// Convert wildcard to regex: escape all chars, then replace \* with (.*)
		let escaped = regex::escape(pattern);
		let regex_pattern = escaped.replace(r"\*", "(.*)");

		let regex = regex::Regex::new(&format!("^{}$", regex_pattern))
			.map_err(|e| format!("Invalid wildcard pattern '{}': {}", pattern, e))?;

		Ok(ModelAliasPattern {
			regex,
			pattern_len: pattern.len(),
		})
	}

	pub fn matches(&self, model: &str) -> bool {
		self.regex.is_match(model)
	}

	pub fn specificity(&self) -> usize {
		self.pattern_len
	}
}

pub use gateway_llm::provider::PromptCachingConfig;

#[apply(schema!)]
pub struct PromptEnrichment {
	/// Messages appended to the end of each chat request.
	#[serde(default, skip_serializing_if = "Vec::is_empty")]
	pub append: Vec<crate::llm::SimpleChatCompletionMessage>,
	/// Messages prepended to the beginning of each chat request.
	#[serde(default, skip_serializing_if = "Vec::is_empty")]
	pub prepend: Vec<crate::llm::SimpleChatCompletionMessage>,
}

#[apply(schema!)]
pub struct PromptGuard {
	/// Apply prompt guards to streaming responses and realtime websocket messages.
	#[serde(default, skip_serializing_if = "PromptGuardStreamingMode::is_enabled")]
	pub streaming: PromptGuardStreamingMode,
	/// Guards applied to client requests before they reach the LLM.
	#[serde(default, skip_serializing_if = "Vec::is_empty")]
	pub request: Vec<RequestGuard>,
	/// Guards applied to LLM responses before they reach the client.
	#[serde(default, skip_serializing_if = "Vec::is_empty")]
	pub response: Vec<ResponseGuard>,
}

#[apply(schema!)]
#[derive(Default, Copy, PartialEq, Eq)]
pub enum PromptGuardStreamingMode {
	/// Do not apply streaming guards; guarded HTTP streams are refused before sending.
	#[serde(rename = "Disabled")]
	Disabled,
	/// Apply configured response guards to streams by default.
	#[default]
	#[serde(rename = "Enabled")]
	Enabled,
}

impl PromptGuardStreamingMode {
	pub(crate) fn is_enabled(&self) -> bool {
		*self == Self::Enabled
	}
}

#[cfg(feature = "gateway-llm")]
enum GuardrailOutcome {
	None,
	Masked,
	Rejected(Response),
	/// Guard service was unreachable and `failure_mode = FailOpen`; request is allowed
	/// through but must be recorded as `FailOpen`, not `Allow`.
	FailOpen,
}

/// A streaming guardrail evaluator. Each guard kind gets one stateless implementation
/// that evaluates a text window and reports whether it should be blocked.
///
/// Batching and overlap are owned by the driver (`GuardedSseBody` for SSE,
/// `guarded_realtime_proxy` for WebSockets): the driver accumulates text until an
/// evaluation threshold is reached, prepends an overlap tail from previously
/// evaluated text (so patterns spanning a batch boundary are still seen
/// contiguously), and calls `evaluate` with the combined window.
///
/// The trait is object-safe and `Send` so it can be boxed and driven from the
/// `GuardedSseBody` future.
pub use gateway_llm::{StreamingEvaluator, StreamingGuardrailOutcome};

#[cfg(feature = "gateway-llm")]
struct TextResponse {
	content: String,
}

#[cfg(feature = "gateway-llm")]
impl crate::llm::ResponseType for TextResponse {
	fn to_llm_response(&self, include_completion_in_log: bool) -> crate::llm::LLMResponse {
		crate::llm::LLMResponse {
			completion: include_completion_in_log.then(|| vec![self.content.clone()]),
			..Default::default()
		}
	}

	fn to_webhook_choices(&self) -> anyhow::Result<Vec<webhook::ResponseChoice>> {
		Ok(vec![webhook::ResponseChoice {
			message: crate::llm::SimpleChatCompletionMessage {
				role: "assistant".into(),
				content: self.content.clone().into(),
			},
		}])
	}

	fn set_webhook_choices(&mut self, resp: Vec<webhook::ResponseChoice>) -> anyhow::Result<()> {
		if let Some(choice) = resp.into_iter().next() {
			self.content = choice.message.content.to_string();
		}
		Ok(())
	}

	fn serialize(&self) -> serde_json::Result<Vec<u8>> {
		serde_json::to_vec(
			&self
				.to_webhook_choices()
				.map_err(serde::ser::Error::custom)?,
		)
	}
}

/// Adapter that wraps plain text extracted from a realtime WebSocket event as a `RequestType`.
///
/// The OpenAI Realtime API uses structured events (`conversation.item.create`, etc.) with typed
/// content. The proxy extracts text from those events before calling request guards, so by the
/// time guards run there is a plain `&str` rather than a full request object. This adapter wraps
/// that string to satisfy the `&mut dyn RequestType` interface that all guard implementations
/// expect.
#[cfg(feature = "gateway-llm")]
struct TextRequest {
	content: String,
}

#[cfg(feature = "gateway-llm")]
impl crate::llm::RequestType for TextRequest {
	fn supports_model(&self) -> bool {
		false
	}

	fn model(&mut self) -> &mut Option<String> {
		unimplemented!("TextRequest does not support model")
	}

	fn prepend_prompts(&mut self, _: Vec<crate::llm::SimpleChatCompletionMessage>) {}
	fn append_prompts(&mut self, _: Vec<crate::llm::SimpleChatCompletionMessage>) {}

	fn to_llm_request(
		&self,
		_: platform_core::prelude::Strng,
		_: bool,
	) -> Result<crate::llm::LLMRequest, crate::llm::AIError> {
		unimplemented!("TextRequest does not support to_llm_request")
	}

	fn get_messages(&self) -> Vec<crate::llm::SimpleChatCompletionMessage> {
		vec![crate::llm::SimpleChatCompletionMessage {
			role: "user".into(),
			content: self.content.clone().into(),
		}]
	}

	fn set_messages(&mut self, msgs: Vec<crate::llm::SimpleChatCompletionMessage>) {
		if let Some(m) = msgs.into_iter().next() {
			self.content = m.content.to_string();
		}
	}
}

#[cfg(feature = "gateway-llm")]
impl PromptGuard {
	/// Apply request guards to a plain-text string extracted from a realtime WebSocket frame.
	///
	/// Returns the rejection body if the content should be blocked. A mask that cannot
	/// be applied to the original WebSocket payload must not disclose the original text.
	pub async fn apply_realtime_request_guards(
		&self,
		text: &str,
		client: &crate::proxy::httpproxy::PolicyClient,
	) -> Option<Bytes> {
		let headers = ::http::HeaderMap::new();
		let mut req = TextRequest {
			content: text.to_string(),
		};
		for g in &self.request {
			match Policy::apply_single_request_guard(g, &mut req, &headers, client, None).await {
				Ok(GuardrailOutcome::Rejected(rejected)) => {
					Policy::record_guardrail_trip(
						client,
						crate::telemetry::metrics::GuardrailPhase::Request,
						crate::telemetry::metrics::GuardrailAction::Reject,
					);
					let body = rejected
						.into_body()
						.collect()
						.await
						.map(|b| b.to_bytes())
						.unwrap_or_else(|_| g.rejection.body.clone());
					return Some(body);
				},
				// Realtime cannot safely rewrite the original event here: fail closed.
				Ok(GuardrailOutcome::Masked) => {
					Policy::record_guardrail_trip(
						client,
						crate::telemetry::metrics::GuardrailPhase::Request,
						crate::telemetry::metrics::GuardrailAction::Mask,
					);
					return Some(Bytes::from_static(
						b"Realtime masking requires a structured event adapter",
					));
				},
				Ok(GuardrailOutcome::None) => {
					Policy::record_guardrail_trip(
						client,
						crate::telemetry::metrics::GuardrailPhase::Request,
						crate::telemetry::metrics::GuardrailAction::Allow,
					);
				},
				Ok(GuardrailOutcome::FailOpen) => {
					Policy::record_guardrail_trip(
						client,
						crate::telemetry::metrics::GuardrailPhase::Request,
						crate::telemetry::metrics::GuardrailAction::FailOpen,
					);
				},
				Err(e) => match g.failure_mode() {
					FailureMode::FailClosed => {
						tracing::warn!("request guard error in realtime path, failing closed: {e}");
						Policy::record_guardrail_trip(
							client,
							crate::telemetry::metrics::GuardrailPhase::Request,
							crate::telemetry::metrics::GuardrailAction::Reject,
						);
						return Some(g.rejection.body.clone());
					},
					FailureMode::FailOpen => {
						tracing::warn!("request guard error in realtime path, failing open: {e}");
						Policy::record_guardrail_trip(
							client,
							crate::telemetry::metrics::GuardrailPhase::Request,
							crate::telemetry::metrics::GuardrailAction::FailOpen,
						);
					},
				},
			}
		}
		None
	}

	/// Returns `true` if there is at least one response guard configured.
	pub fn has_response_guards(&self) -> bool {
		!self.response.is_empty()
	}

	/// Build one `StreamingEvaluator` per configured response guard.
	///
	/// Each evaluator is a stateless wrapper around the existing non-streaming
	/// response-guard logic; the caller drives windowed batching.
	pub fn begin_streaming_response_guard(
		&self,
		client: &crate::proxy::httpproxy::PolicyClient,
		http_headers: &HeaderMap,
	) -> Vec<Box<dyn StreamingEvaluator>> {
		self
			.response
			.iter()
			.map(|g| streaming_guardrails::make_evaluator(g, client.clone(), http_headers.clone()))
			.collect()
	}

	pub async fn evaluate_streaming_response_window(
		guard: &ResponseGuard,
		window: &str,
		client: &crate::proxy::httpproxy::PolicyClient,
		http_headers: &HeaderMap,
	) -> anyhow::Result<Option<StreamingGuardrailOutcome>> {
		if window.is_empty() {
			return Ok(None);
		}
		let mut resp = TextResponse {
			content: window.to_string(),
		};
		match Policy::apply_single_response_guard(guard, &mut resp, http_headers, client).await? {
			GuardrailOutcome::Rejected(rejected) => {
				let body = rejected.into_body().collect().await?.to_bytes();
				Ok(Some(StreamingGuardrailOutcome::Blocked(body)))
			},
			GuardrailOutcome::Masked => {
				// Evaluating a rewritten TextResponse does not rewrite the original
				// provider frames. Returning Pass here would disclose unmasked data.
				Ok(Some(StreamingGuardrailOutcome::Blocked(
					Bytes::from_static(b"Streaming masking requires an event rewriting adapter"),
				)))
			},
			GuardrailOutcome::None => Ok(None),
			GuardrailOutcome::FailOpen => Ok(None),
		}
	}
}

impl Policy {
	/// Returns `true` if any prompt guard has response guards that require streaming evaluation.
	pub fn has_streaming_response_guards(&self) -> bool {
		self
			.prompt_guard
			.as_ref()
			.map(|g| g.streaming.is_enabled() && !g.response.is_empty())
			.unwrap_or(false)
	}
}

impl Policy {
	pub fn compile_model_alias_patterns(&mut self) {
		let mut patterns = Vec::new();

		for (key, value) in &self.model_aliases {
			if key.contains('*') {
				match ModelAliasPattern::from_wildcard(key.as_str()) {
					Ok(pattern) => {
						patterns.push((pattern, value.clone()));
					},
					Err(e) => {
						// Log warning but continue - don't fail entire policy
						tracing::warn!(
							pattern = %key,
							error = %e,
							"Invalid model alias wildcard pattern, skipping"
						);
					},
				}
			}
		}

		// Sort by specificity: longer patterns first (more specific matches)
		patterns.sort_by_key(|(pattern, _)| std::cmp::Reverse(pattern.specificity()));

		self.wildcard_patterns = Arc::new(patterns);

		tracing::debug!(
			exact_aliases = self.model_aliases.len(),
			wildcard_patterns = self.wildcard_patterns.len(),
			"Compiled model alias patterns"
		);
	}

	pub fn resolve_model_alias(&self, model: &str) -> Option<&Strng> {
		// Fast path: exact match in HashMap (O(1))
		if let Some(target) = self.model_aliases.get(model) {
			return Some(target);
		}

		// Slow path: pattern matching (sorted by specificity, checks longer patterns first)
		for (pattern, target) in self.wildcard_patterns.iter() {
			if pattern.matches(model) {
				tracing::debug!(
					model = %model,
					target = %target,
					pattern_specificity = pattern.specificity(),
					"Model alias pattern match"
				);
				return Some(target);
			}
		}

		None
	}

	#[cfg(feature = "gateway-llm")]
	pub fn apply_prompt_enrichment(&self, chat: &mut dyn RequestType) {
		if let Some(prompts) = &self.prompts {
			if !prompts.prepend.is_empty() {
				chat.prepend_prompts(prompts.prepend.clone());
			}
			if !prompts.append.is_empty() {
				chat.append_prompts(prompts.append.clone());
			}
		}
	}

	#[cfg(feature = "gateway-llm")]
	pub fn resolve_route(&self, path: &str) -> crate::llm::RouteType {
		let mut wildcard: Option<crate::llm::RouteType> = None;

		// `self.routes` is stored longest->shortest, with "*" last, so the first match wins.
		for (path_suffix, rt) in self.routes.iter() {
			if path_suffix.as_str() == "*" {
				wildcard = Some(*rt);
				continue;
			}
			if path.ends_with(path_suffix.as_str()) {
				return *rt;
			}
		}

		wildcard.unwrap_or(crate::llm::RouteType::Completions)
	}

	#[cfg(feature = "gateway-llm")]
	pub fn has_request_body_mutations(&self) -> bool {
		self.defaults.is_some() || self.overrides.is_some() || self.transformations.is_some()
	}

	#[cfg(feature = "gateway-llm")]
	pub fn unmarshal_request<T: DeserializeOwned>(
		&self,
		bytes: &Bytes,
		log: &mut Option<&mut RequestLog>,
	) -> Result<T, AIError> {
		if !self.has_request_body_mutations() {
			// Fast path: directly bytes to typed
			return serde_json::from_slice(bytes.as_ref()).map_err(AIError::RequestParsing);
		}
		// Slow path: bytes --> json (transform) --> typed
		let v: serde_json::Value =
			serde_json::from_slice(bytes.as_ref()).map_err(AIError::RequestParsing)?;
		self.unmarshal_request_value(v, log)
	}

	#[cfg(feature = "gateway-llm")]
	pub fn unmarshal_request_value<T: DeserializeOwned>(
		&self,
		v: serde_json::Value,
		log: &mut Option<&mut RequestLog>,
	) -> Result<T, AIError> {
		let v = self.apply_request_body_mutations(v, log)?;
		serde_json::from_value(v).map_err(AIError::RequestParsing)
	}

	#[cfg(feature = "gateway-llm")]
	pub fn apply_request_body_mutations(
		&self,
		v: serde_json::Value,
		log: &mut Option<&mut RequestLog>,
	) -> Result<serde_json::Value, AIError> {
		if !self.has_request_body_mutations() {
			return Ok(v);
		}
		let exec = cel::Executor::new_llm(log.as_ref().and_then(|x| x.request_snapshot.as_deref()), &v);
		let to_set: Vec<_> = self
			.transformations
			.iter()
			.flatten()
			.map(|(k, expr)| (k, Self::eval_transformation_expression(expr, &exec)))
			.collect();

		let serde_json::Value::Object(mut map) = v else {
			return Err(AIError::MissingField("request must be an object".into()));
		};
		for (k, v) in self.overrides.iter().flatten() {
			map.insert(k.clone(), v.clone());
		}
		for (k, v) in to_set.into_iter() {
			match v {
				Some(v) => {
					map.insert(k.clone(), v);
				},
				None => {
					map.remove(k);
				},
			}
		}
		for (k, v) in self.defaults.iter().flatten() {
			map.entry(k.clone()).or_insert_with(|| v.clone());
		}
		Ok(serde_json::Value::Object(map))
	}

	#[cfg(feature = "gateway-llm")]
	fn eval_transformation_expression(
		expression: &cel::Expression,
		exec: &cel::Executor<'_>,
	) -> Option<serde_json::Value> {
		exec.eval(expression).ok()?.json().ok()
	}

	#[cfg(feature = "gateway-llm")]
	pub async fn apply_prompt_guard(
		&self,
		backend_info: &auth::BackendInfo,
		req: &mut dyn RequestType,
		http_headers: &HeaderMap,
		claims: Option<Claims>,
	) -> anyhow::Result<Option<Response>> {
		let client = PolicyClient::new(backend_info.inputs.clone());
		for g in self
			.prompt_guard
			.as_ref()
			.iter()
			.flat_map(|g| g.request.iter())
		{
			match Self::apply_single_request_guard(g, req, http_headers, &client, claims.clone()).await? {
				GuardrailOutcome::Rejected(res) => {
					Self::record_guardrail_trip(
						&client,
						crate::telemetry::metrics::GuardrailPhase::Request,
						crate::telemetry::metrics::GuardrailAction::Reject,
					);
					return Ok(Some(res));
				},
				GuardrailOutcome::Masked => {
					Self::record_guardrail_trip(
						&client,
						crate::telemetry::metrics::GuardrailPhase::Request,
						crate::telemetry::metrics::GuardrailAction::Mask,
					);
				},
				GuardrailOutcome::None => {
					Self::record_guardrail_trip(
						&client,
						crate::telemetry::metrics::GuardrailPhase::Request,
						crate::telemetry::metrics::GuardrailAction::Allow,
					);
				},
				GuardrailOutcome::FailOpen => {
					Self::record_guardrail_trip(
						&client,
						crate::telemetry::metrics::GuardrailPhase::Request,
						crate::telemetry::metrics::GuardrailAction::FailOpen,
					);
				},
			}
		}
		Ok(None)
	}

	/// Evaluate a single request guard against `req` and return the outcome.
	///
	/// Callers are responsible for recording metrics and acting on the result.
	/// This is the single place where every `RequestGuardKind` is dispatched,
	/// so both the HTTP request path (`apply_prompt_guard`) and the realtime
	/// WebSocket path (`apply_realtime_request_guards`) stay in sync.
	#[cfg(feature = "gateway-llm")]
	async fn apply_single_request_guard(
		guard: &RequestGuard,
		req: &mut dyn RequestType,
		http_headers: &HeaderMap,
		client: &PolicyClient,
		claims: Option<Claims>,
	) -> anyhow::Result<GuardrailOutcome> {
		match &guard.kind {
			RequestGuardKind::Regex(rg) => Self::apply_regex(req, rg, &guard.rejection),
			RequestGuardKind::Webhook(wh) => Self::apply_webhook(req, http_headers, client, wh).await,
			RequestGuardKind::OpenAIModeration(m) => {
				match Self::apply_moderation(req, claims.clone(), client, &guard.rejection, m).await? {
					Some(res) => Ok(GuardrailOutcome::Rejected(res)),
					None => Ok(GuardrailOutcome::None),
				}
			},
			#[cfg(feature = "providers-aws")]
			RequestGuardKind::BedrockGuardrails(bg) => {
				Self::apply_bedrock_guardrails_request(req, claims.clone(), client, &guard.rejection, bg)
					.await
			},
			#[cfg(feature = "providers-gcp")]
			RequestGuardKind::GoogleModelArmor(gma) => {
				match Self::apply_google_model_armor_request(
					req,
					claims.clone(),
					client,
					&guard.rejection,
					gma,
				)
				.await?
				{
					Some(res) => Ok(GuardrailOutcome::Rejected(res)),
					None => Ok(GuardrailOutcome::None),
				}
			},
			#[cfg(feature = "providers-azure")]
			RequestGuardKind::AzureContentSafety(acs) => {
				match Self::apply_azure_content_safety_request(
					req,
					claims.clone(),
					client,
					&guard.rejection,
					acs,
				)
				.await?
				{
					Some(res) => Ok(GuardrailOutcome::Rejected(res)),
					None => Ok(GuardrailOutcome::None),
				}
			},
		}
	}

	#[cfg(feature = "gateway-llm")]
	async fn apply_moderation(
		req: &mut dyn RequestType,
		claims: Option<Claims>,
		client: &PolicyClient,
		rej: &RequestRejection,
		moderation: &Moderation,
	) -> anyhow::Result<Option<Response>> {
		let resp = moderation::send_request(req, claims, client, moderation).await?;
		if resp.results.iter().any(|r| r.flagged) {
			Ok(Some(rej.as_response()))
		} else {
			Ok(None)
		}
	}

	#[cfg(feature = "providers-aws")]
	#[cfg(feature = "gateway-llm")]
	async fn apply_bedrock_guardrails_request(
		req: &mut dyn RequestType,
		claims: Option<Claims>,
		client: &PolicyClient,
		rej: &RequestRejection,
		guardrails: &BedrockGuardrails,
	) -> anyhow::Result<GuardrailOutcome> {
		let resp = bedrock_guardrails::send_request(req, claims.clone(), client, guardrails).await?;
		if resp.is_blocked() {
			Ok(GuardrailOutcome::Rejected(rej.as_response()))
		} else if resp.is_anonymized() {
			let output_texts = resp.output_texts();
			let mut msgs = req.get_messages();
			for (msg, text) in msgs.iter_mut().zip(output_texts) {
				msg.content = text.into();
			}
			req.set_messages(msgs);
			Ok(GuardrailOutcome::Masked)
		} else {
			Ok(GuardrailOutcome::None)
		}
	}

	#[cfg(feature = "providers-aws")]
	#[cfg(feature = "gateway-llm")]
	async fn apply_bedrock_guardrails_response(
		resp: &mut dyn ResponseType,
		claims: Option<Claims>,
		client: &PolicyClient,
		rej: &RequestRejection,
		guardrails: &BedrockGuardrails,
	) -> anyhow::Result<GuardrailOutcome> {
		// Extract text content from response choices
		let content: Vec<String> = resp
			.to_webhook_choices()?
			.into_iter()
			.map(|c| c.message.content.to_string())
			.collect();

		if content.is_empty() {
			return Ok(GuardrailOutcome::None);
		}

		let guardrail_resp =
			bedrock_guardrails::send_response(content, claims, client, guardrails).await?;
		if guardrail_resp.is_blocked() {
			Ok(GuardrailOutcome::Rejected(rej.as_response()))
		} else if guardrail_resp.is_anonymized() {
			let output_texts = guardrail_resp.output_texts();
			let mut choices = resp.to_webhook_choices()?;
			for (choice, text) in choices.iter_mut().zip(output_texts) {
				choice.message.content = text.into();
			}
			resp.set_webhook_choices(choices)?;
			Ok(GuardrailOutcome::Masked)
		} else {
			Ok(GuardrailOutcome::None)
		}
	}

	#[cfg(feature = "providers-gcp")]
	#[cfg(feature = "gateway-llm")]
	async fn apply_google_model_armor_request(
		req: &mut dyn RequestType,
		claims: Option<Claims>,
		client: &PolicyClient,
		rej: &RequestRejection,
		model_armor: &GoogleModelArmor,
	) -> anyhow::Result<Option<Response>> {
		let resp = google_model_armor::send_request(req, claims.clone(), client, model_armor).await?;
		if resp.is_blocked() {
			Ok(Some(rej.as_response()))
		} else {
			Ok(None)
		}
	}

	#[cfg(feature = "providers-azure")]
	#[cfg(feature = "gateway-llm")]
	async fn apply_azure_content_safety_request(
		req: &mut dyn RequestType,
		claims: Option<Claims>,
		client: &PolicyClient,
		rej: &RequestRejection,
		config: &AzureContentSafety,
	) -> anyhow::Result<Option<Response>> {
		if let Some(ref analyze_text) = config.analyze_text {
			let resp = azure_content_safety::send_analyze_text_for_request(
				req,
				claims.clone(),
				client,
				config,
				analyze_text,
			)
			.await?;
			let threshold = analyze_text.severity_threshold.unwrap_or(2);
			if resp.is_blocked(threshold) {
				return Ok(Some(rej.as_response()));
			}
		}
		if let Some(ref detect_jailbreak) = config.detect_jailbreak {
			let resp = azure_content_safety::send_detect_jailbreak_for_request(
				req,
				claims.clone(),
				client,
				config,
				detect_jailbreak,
			)
			.await?;
			if resp.jailbreak_detected() {
				return Ok(Some(rej.as_response()));
			}
		}
		Ok(None)
	}

	#[cfg(feature = "providers-gcp")]
	#[cfg(feature = "gateway-llm")]
	async fn apply_google_model_armor_response(
		resp: &mut dyn ResponseType,
		claims: Option<Claims>,
		client: &PolicyClient,
		rej: &RequestRejection,
		model_armor: &GoogleModelArmor,
	) -> anyhow::Result<Option<Response>> {
		// Extract text content from response choices
		let content: Vec<String> = resp
			.to_webhook_choices()?
			.into_iter()
			.map(|c| c.message.content.to_string())
			.collect();

		if content.is_empty() {
			return Ok(None);
		}

		let guardrail_resp =
			google_model_armor::send_response(content, claims.clone(), client, model_armor).await?;
		if guardrail_resp.is_blocked() {
			Ok(Some(rej.as_response()))
		} else {
			Ok(None)
		}
	}

	#[cfg(feature = "providers-azure")]
	#[cfg(feature = "gateway-llm")]
	async fn apply_azure_content_safety_response(
		resp: &mut dyn ResponseType,
		claims: Option<Claims>,
		client: &PolicyClient,
		rej: &RequestRejection,
		config: &AzureContentSafety,
	) -> anyhow::Result<Option<Response>> {
		let content: Vec<String> = resp
			.to_webhook_choices()?
			.into_iter()
			.map(|c| c.message.content.to_string())
			.collect();

		if content.is_empty() {
			return Ok(None);
		}

		if let Some(ref analyze_text) = config.analyze_text {
			let guardrail_resp = azure_content_safety::send_analyze_text_for_response(
				content.clone(),
				claims,
				client,
				config,
				analyze_text,
			)
			.await?;
			let threshold = analyze_text.severity_threshold.unwrap_or(2);
			if guardrail_resp.is_blocked(threshold) {
				return Ok(Some(rej.as_response()));
			}
		}
		// Note: detect_jailbreak is request-only, not applied to responses.
		Ok(None)
	}

	#[cfg(feature = "gateway-llm")]
	fn apply_regex(
		req: &mut dyn RequestType,
		rgx: &RegexRules,
		rej: &RequestRejection,
	) -> anyhow::Result<GuardrailOutcome> {
		let mut msgs = req.get_messages();
		let mut any_changed = false;
		for msg in &mut msgs {
			match Self::apply_prompt_guard_regex(&msg.content, rgx) {
				Some(RegexResult::Reject) => {
					return Ok(GuardrailOutcome::Rejected(rej.as_response()));
				},
				Some(RegexResult::Mask(content)) => {
					any_changed = true;
					msg.content = content.into();
				},
				None => {},
			}
		}
		if any_changed {
			req.set_messages(msgs);
			return Ok(GuardrailOutcome::Masked);
		}
		Ok(GuardrailOutcome::None)
	}

	#[cfg(feature = "gateway-llm")]
	fn apply_regex_response(
		resp: &mut dyn ResponseType,
		rgx: &RegexRules,
		rej: &RequestRejection,
	) -> anyhow::Result<GuardrailOutcome> {
		let mut msgs = resp.to_webhook_choices()?;
		let mut any_changed = false;
		for msg in &mut msgs {
			match Self::apply_prompt_guard_regex(&msg.message.content, rgx) {
				Some(RegexResult::Reject) => {
					return Ok(GuardrailOutcome::Rejected(rej.as_response()));
				},
				Some(RegexResult::Mask(content)) => {
					any_changed = true;
					msg.message.content = content.into();
				},
				None => {},
			}
		}
		if any_changed {
			resp.set_webhook_choices(msgs)?;
			return Ok(GuardrailOutcome::Masked);
		}
		Ok(GuardrailOutcome::None)
	}

	#[cfg(feature = "gateway-llm")]
	async fn apply_webhook(
		req: &mut dyn RequestType,
		http_headers: &HeaderMap,
		client: &PolicyClient,
		webhook: &Webhook,
	) -> anyhow::Result<GuardrailOutcome> {
		let messsages = req.get_messages();
		let headers = Self::get_webhook_forward_headers(http_headers, &webhook.forward_header_matches);
		let whr = match webhook::send_request(
			&client
				.with_outbound(OutboundCallKind::Policy, OutboundCallSubtype::Guardrail)
				.bind_reference(&webhook.target, &[]),
			&headers,
			messsages,
		)
		.await
		{
			Ok(whr) => whr,
			Err(e) => {
				return match webhook.failure_mode {
					FailureMode::FailOpen => {
						warn!("webhook guardrail unavailable, failing open: {}", e);
						Ok(GuardrailOutcome::FailOpen)
					},
					FailureMode::FailClosed => Err(e),
				};
			},
		};
		match whr.action {
			RequestAction::Mask(mask) => {
				debug!(
					"webhook masked request: {}",
					mask
						.reason
						.unwrap_or_else(|| "no reason specified".to_string())
				);
				let MaskActionBody::PromptMessages(body) = mask.body else {
					anyhow::bail!("invalid webhook response");
				};
				req.set_messages(body.messages);
				Ok(GuardrailOutcome::Masked)
			},
			RequestAction::Reject(rej) => {
				debug!(
					"webhook rejected request: {}",
					rej
						.reason
						.unwrap_or_else(|| "no reason specified".to_string())
				);
				Ok(GuardrailOutcome::Rejected(
					::http::response::Builder::new()
						.status(rej.status_code)
						.body(http::Body::from(rej.body))?,
				))
			},
			RequestAction::Pass(pass) => {
				debug!(
					"webhook passed request: {}",
					pass
						.reason
						.unwrap_or_else(|| "no reason specified".to_string())
				);
				Ok(GuardrailOutcome::None)
			},
		}
	}

	#[cfg(feature = "gateway-llm")]
	async fn apply_webhook_response(
		resp: &mut dyn ResponseType,
		http_headers: &HeaderMap,
		client: &PolicyClient,
		webhook: &Webhook,
	) -> anyhow::Result<GuardrailOutcome> {
		let messsages = resp.to_webhook_choices()?;
		let headers = Self::get_webhook_forward_headers(http_headers, &webhook.forward_header_matches);
		let whr = match webhook::send_response(
			&client
				.with_outbound(OutboundCallKind::Policy, OutboundCallSubtype::Guardrail)
				.bind_reference(&webhook.target, &[]),
			&headers,
			messsages,
		)
		.await
		{
			Ok(whr) => whr,
			Err(e) => {
				return match webhook.failure_mode {
					FailureMode::FailOpen => {
						warn!("webhook guardrail unavailable, failing open: {}", e);
						Ok(GuardrailOutcome::FailOpen)
					},
					FailureMode::FailClosed => Err(e),
				};
			},
		};
		match whr.action {
			ResponseAction::Mask(mask) => {
				debug!(
					"webhook masked response: {}",
					mask
						.reason
						.unwrap_or_else(|| "no reason specified".to_string())
				);
				let MaskActionBody::ResponseChoices(body) = mask.body else {
					anyhow::bail!("invalid webhook response");
				};
				let msgs = body.choices;
				resp.set_webhook_choices(msgs)?;
				Ok(GuardrailOutcome::Masked)
			},
			ResponseAction::Reject(rej) => {
				debug!(
					"webhook rejected response: {}",
					rej
						.reason
						.unwrap_or_else(|| "no reason specified".to_string())
				);
				Ok(GuardrailOutcome::Rejected(
					::http::response::Builder::new()
						.status(rej.status_code)
						.body(http::Body::from(rej.body))?,
				))
			},
			ResponseAction::Pass(pass) => {
				debug!(
					"webhook passed response: {}",
					pass
						.reason
						.unwrap_or_else(|| "no reason specified".to_string())
				);
				Ok(GuardrailOutcome::None)
			},
		}
	}

	#[cfg(feature = "gateway-llm")]
	fn get_webhook_forward_headers(
		http_headers: &HeaderMap,
		header_matches: &[HeaderMatch],
	) -> HeaderMap {
		let mut headers = HeaderMap::new();
		for HeaderMatch { name, value } in header_matches {
			// Only handle regular headers (HeaderMap doesn't contain pseudo headers)
			let header_name = match name {
				crate::http::HeaderOrPseudo::Header(h) => h,
				_ => continue, // Skip pseudo headers
			};
			let Some(have) = http_headers.get(header_name.as_str()) else {
				continue;
			};
			match value {
				HeaderValueMatch::Exact(want) => {
					if have != want {
						continue;
					}
				},
				HeaderValueMatch::Regex(want) => {
					// Must be a valid string to do regex match
					let Some(have_str) = have.to_str().ok() else {
						continue;
					};
					let Some(m) = want.find(have_str) else {
						continue;
					};
					// Make sure we matched the entire thing
					if !(m.start() == 0 && m.end() == have_str.len()) {
						continue;
					}
				},
				HeaderValueMatch::Invalid => continue,
			}
			headers.insert(header_name, have.clone());
		}
		headers
	}

	#[cfg(feature = "gateway-llm")]
	fn record_guardrail_trip(
		client: &PolicyClient,
		phase: crate::telemetry::metrics::GuardrailPhase,
		action: crate::telemetry::metrics::GuardrailAction,
	) {
		client.record_guardrail_check(phase, action);
	}

	#[cfg(feature = "gateway-llm")]
	fn apply_prompt_guard_regex(original_content: &str, rgx: &RegexRules) -> Option<RegexResult> {
		let mut working: Option<String> = None;

		for r in &rgx.rules {
			match r {
				RegexRule::Builtin { builtin } => {
					let rec = match builtin {
						Builtin::Ssn => &*pii::SSN,
						Builtin::CreditCard => &*pii::CC,
						Builtin::PhoneNumber => &*pii::PHONE,
						Builtin::Email => &*pii::EMAIL,
						Builtin::CaSin => &*pii::CA_SIN,
					};
					let results = pii::recognizer(rec, working.as_deref().unwrap_or(original_content));
					if results.is_empty() {
						continue;
					}
					match &rgx.action {
						Action::Reject => return Some(RegexResult::Reject),
						Action::Mask => {
							let replacement = format!("<{}>", results[0].entity_type);
							let buf = working.get_or_insert_with(|| original_content.to_string());
							// Replace in reverse order to avoid index shifting, coalescing overlaps
							for range in results
								.into_iter()
								.map(|r| r.start..r.end)
								.sorted_unstable_by(|a, b| b.start.cmp(&a.start).then_with(|| a.end.cmp(&b.end)))
								.coalesce(|a, b| {
									if b.end > a.start {
										Ok(b.start..std::cmp::max(a.end, b.end))
									} else {
										Err((a, b))
									}
								}) {
								buf.replace_range(range, &replacement);
							}
						},
					}
				},
				RegexRule::Regex { pattern } => {
					let content = working.as_deref().unwrap_or(original_content);
					if matches!(rgx.action, Action::Reject) {
						if pattern.is_match(content) {
							return Some(RegexResult::Reject);
						}
						continue;
					}
					let ranges: Vec<std::ops::Range<usize>> =
						pattern.find_iter(content).map(|m| m.range()).collect();
					if ranges.is_empty() {
						continue;
					}
					let buf = working.get_or_insert_with(|| original_content.to_string());
					// Reverse order to avoid index shifting
					for range in ranges.into_iter().rev() {
						buf.replace_range(range, "<masked>");
					}
				},
			}
		}
		working.map(RegexResult::Mask)
	}

	#[cfg(feature = "gateway-llm")]
	pub async fn apply_response_prompt_guard(
		client: &PolicyClient,
		resp: &mut dyn ResponseType,
		http_headers: &HeaderMap,
		guards: &Vec<ResponseGuard>,
	) -> anyhow::Result<Option<Response>> {
		for g in guards {
			match Self::apply_single_response_guard(g, resp, http_headers, client).await? {
				GuardrailOutcome::Rejected(res) => {
					Self::record_guardrail_trip(
						client,
						crate::telemetry::metrics::GuardrailPhase::Response,
						crate::telemetry::metrics::GuardrailAction::Reject,
					);
					return Ok(Some(res));
				},
				GuardrailOutcome::Masked => {
					Self::record_guardrail_trip(
						client,
						crate::telemetry::metrics::GuardrailPhase::Response,
						crate::telemetry::metrics::GuardrailAction::Mask,
					);
				},
				GuardrailOutcome::None => {
					Self::record_guardrail_trip(
						client,
						crate::telemetry::metrics::GuardrailPhase::Response,
						crate::telemetry::metrics::GuardrailAction::Allow,
					);
				},
				GuardrailOutcome::FailOpen => {
					Self::record_guardrail_trip(
						client,
						crate::telemetry::metrics::GuardrailPhase::Response,
						crate::telemetry::metrics::GuardrailAction::FailOpen,
					);
				},
			}
		}
		Ok(None)
	}

	#[cfg(feature = "gateway-llm")]
	async fn apply_single_response_guard(
		guard: &ResponseGuard,
		resp: &mut dyn ResponseType,
		http_headers: &HeaderMap,
		client: &PolicyClient,
	) -> anyhow::Result<GuardrailOutcome> {
		match &guard.kind {
			ResponseGuardKind::Regex(rg) => Self::apply_regex_response(resp, rg, &guard.rejection),
			ResponseGuardKind::Webhook(wh) => {
				Self::apply_webhook_response(resp, http_headers, client, wh).await
			},
			#[cfg(feature = "providers-aws")]
			ResponseGuardKind::BedrockGuardrails(bg) => {
				Self::apply_bedrock_guardrails_response(resp, None, client, &guard.rejection, bg).await
			},
			#[cfg(feature = "providers-gcp")]
			ResponseGuardKind::GoogleModelArmor(gma) => {
				match Self::apply_google_model_armor_response(resp, None, client, &guard.rejection, gma)
					.await?
				{
					Some(res) => Ok(GuardrailOutcome::Rejected(res)),
					None => Ok(GuardrailOutcome::None),
				}
			},
			#[cfg(feature = "providers-azure")]
			ResponseGuardKind::AzureContentSafety(acs) => {
				match Self::apply_azure_content_safety_response(resp, None, client, &guard.rejection, acs)
					.await?
				{
					Some(res) => Ok(GuardrailOutcome::Rejected(res)),
					None => Ok(GuardrailOutcome::None),
				}
			},
		}
	}
}

#[cfg(feature = "gateway-llm")]
enum RegexResult {
	Mask(String),
	Reject,
}

#[apply(schema!)]
pub struct RequestGuard {
	/// Response returned when the request is rejected.
	#[serde(default)]
	pub rejection: RequestRejection,
	/// Guardrail provider or rule set to apply.
	#[serde(flatten)]
	pub kind: RequestGuardKind,
}

#[cfg(feature = "gateway-llm")]
impl RequestGuard {
	/// Returns the configured failure mode for this guard, defaulting to `FailOpen` for
	/// guard types that do not have an explicit `failure_mode` field.
	fn failure_mode(&self) -> FailureMode {
		match &self.kind {
			RequestGuardKind::Webhook(wh) => wh.failure_mode,
			_ => FailureMode::FailOpen,
		}
	}
}

#[apply(schema!)]
pub enum RequestGuardKind {
	/// Apply regex-based masking or rejection rules.
	Regex(RegexRules),
	/// Call a webhook to evaluate the prompt.
	Webhook(Webhook),
	/// Use OpenAI moderation to evaluate the prompt.
	OpenAIModeration(Moderation),
	/// Use AWS Bedrock Guardrails to evaluate the prompt.
	#[cfg(feature = "providers-aws")]
	BedrockGuardrails(BedrockGuardrails),
	/// Use Google Model Armor to evaluate the prompt.
	#[cfg(feature = "providers-gcp")]
	GoogleModelArmor(GoogleModelArmor),
	/// Use Azure Content Safety to evaluate the prompt.
	#[cfg(feature = "providers-azure")]
	AzureContentSafety(AzureContentSafety),
}

#[apply(schema!)]
pub struct RegexRules {
	/// Action to take when a regex rule matches.
	#[serde(default)]
	pub action: Action,
	/// Regex or built-in patterns to evaluate.
	pub rules: Vec<RegexRule>,
}

#[apply(schema!)]
#[serde(untagged)]
pub enum RegexRule {
	/// Use a built-in sensitive data pattern.
	Builtin {
		/// Built-in pattern name.
		builtin: Builtin,
	},
	/// Use a custom regular expression.
	Regex {
		/// Regular expression pattern to evaluate.
		#[serde(with = "serde_regex")]
		#[cfg_attr(feature = "schema", schemars(with = "String"))]
		pattern: regex::Regex,
	},
}

impl RequestRejection {
	pub fn as_response(&self) -> Response {
		let mut response = ::http::response::Builder::new()
			.status(self.status)
			.body(http::Body::from(self.body.clone()))
			.expect("static request should succeed");

		// Apply header modifications if present
		if let Some(ref headers) = self.headers
			&& let Err(e) = headers.apply(response.headers_mut())
		{
			warn!("Failed to apply rejection response headers: {}", e);
		}

		response
	}
}

#[apply(schema!)]
pub enum Builtin {
	/// U.S. Social Security number pattern.
	#[serde(rename = "ssn")]
	Ssn,
	/// Credit card number pattern.
	CreditCard,
	/// Phone number pattern.
	PhoneNumber,
	/// Email address pattern.
	Email,
	/// Canadian Social Insurance Number pattern.
	CaSin,
}

#[apply(schema!)]
pub struct Rule<T> {
	action: Action,
	rule: T,
}

#[apply(schema!)]
pub struct NamedRegex {
	#[serde(with = "serde_regex")]
	#[cfg_attr(feature = "schema", schemars(with = "String"))]
	pattern: regex::Regex,
	name: String,
}

/// Defines how the proxy behaves when a webhook guardrail is unreachable or
/// returns an error.
///
/// Defaults to `failClosed`. When failing closed, the error is propagated and
/// the LLM request is rejected. When failing open, the request is allowed
/// through despite the webhook failure.
pub use gateway_llm::FailureMode;

#[apply(schema!)]
pub struct Webhook {
	/// Backend that receives guardrail webhook requests.
	pub target: SimpleBackendReference,
	/// Incoming request headers to forward to the webhook.
	#[serde(default, skip_serializing_if = "Vec::is_empty")]
	pub forward_header_matches: Vec<HeaderMatch>,
	/// Behavior when the webhook is unreachable or returns an error.
	/// Defaults to `failClosed`.
	#[serde(default, skip_serializing_if = "crate::serdes::is_default")]
	pub failure_mode: FailureMode,
}

#[apply(schema!)]
pub struct Moderation {
	/// Moderation model to use. Defaults to `omni-moderation-latest`.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub model: Option<Strng>,
	/// Backend policies used when calling the moderation provider.
	#[serde(
		default,
		deserialize_with = "crate::types::local::de_from_local_backend_policy",
		skip_serializing_if = "Vec::is_empty"
	)]
	#[cfg_attr(
		feature = "schema",
		schemars(with = "Option<crate::types::local::SimpleLocalBackendPolicies>")
	)]
	pub policies: Vec<BackendTrafficPolicy>,
}

/// Configuration for AWS Bedrock Guardrails integration.
#[apply(schema!)]
pub struct BedrockGuardrails {
	/// The unique identifier of the guardrail
	pub guardrail_identifier: Strng,
	/// The version of the guardrail
	pub guardrail_version: Strng,
	/// AWS region where the guardrail is deployed
	pub region: Strng,
	/// Backend policies for AWS authentication (optional, defaults to implicit AWS auth)
	#[serde(
		default,
		deserialize_with = "crate::types::local::de_from_local_backend_policy",
		skip_serializing_if = "Vec::is_empty"
	)]
	#[cfg_attr(
		feature = "schema",
		schemars(with = "Option<crate::types::local::SimpleLocalBackendPolicies>")
	)]
	pub policies: Vec<BackendTrafficPolicy>,
}

/// Configuration for Google Cloud Model Armor integration.
#[apply(schema!)]
pub struct GoogleModelArmor {
	/// The template ID for the Model Armor configuration
	pub template_id: Strng,
	/// The GCP project ID
	pub project_id: Strng,
	/// The GCP region (default: us-central1)
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub location: Option<Strng>,
	/// Backend policies for GCP authentication (optional, defaults to implicit GCP auth)
	#[serde(
		default,
		deserialize_with = "crate::types::local::de_from_local_backend_policy",
		skip_serializing_if = "Vec::is_empty"
	)]
	#[cfg_attr(
		feature = "schema",
		schemars(with = "Option<crate::types::local::SimpleLocalBackendPolicies>")
	)]
	pub policies: Vec<BackendTrafficPolicy>,
}

/// Configuration for Azure Content Safety integration.
///
/// Uses the Azure AI Content Safety APIs to detect harmful content
/// and jailbreak attempts. The endpoint and authentication are shared
/// across all enabled features.
#[apply(schema!)]
pub struct AzureContentSafety {
	/// The Azure Content Safety endpoint hostname (e.g., "<resource-name>.cognitiveservices.azure.com")
	pub endpoint: Strng,
	/// Backend policies for Azure authentication (optional, defaults to implicit Azure auth)
	#[serde(
		default,
		deserialize_with = "crate::types::local::de_from_local_backend_policy",
		skip_serializing_if = "Vec::is_empty"
	)]
	#[cfg_attr(
		feature = "schema",
		schemars(with = "Option<crate::types::local::SimpleLocalBackendPolicies>")
	)]
	pub policies: Vec<BackendTrafficPolicy>,
	/// Cached implicit Azure auth credential, shared across requests.
	#[serde(skip)]
	#[cfg_attr(feature = "schema", schemars(skip))]
	#[cfg(feature = "providers-azure")]
	pub cached_azure_auth: crate::http::auth::AzureAuth,
	/// Analyze Text configuration for detecting harmful content categories
	/// (Hate, SelfHarm, Sexual, Violence) and blocklist matches.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub analyze_text: Option<AnalyzeTextConfig>,
	/// Detect Text Jailbreak configuration for detecting jailbreak attempts.
	/// Only applicable to request guards.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub detect_jailbreak: Option<DetectJailbreakConfig>,
}

/// Configuration for the Analyze Text API.
#[apply(schema!)]
pub struct AnalyzeTextConfig {
	/// Severity threshold (0-6 for FourSeverityLevels). Content at or above this level is blocked. Default: 2.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub severity_threshold: Option<i32>,
	/// API version to use (default: "2024-09-01")
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub api_version: Option<Strng>,
	/// Blocklist names to check against
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub blocklist_names: Option<Vec<String>>,
	/// When true, further analysis stops if a blocklist is hit
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub halt_on_blocklist_hit: Option<bool>,
}

/// Configuration for the Detect Jailbreak API.
#[apply(schema!)]
pub struct DetectJailbreakConfig {
	/// API version to use (default: "2024-02-15-preview")
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub api_version: Option<Strng>,
}

#[apply(schema!)]
#[derive(Default)]
pub enum Action {
	/// Replace matching content with masked text.
	#[default]
	Mask,
	/// Reject the request or response when content matches.
	Reject,
}

#[apply(schema!)]
pub struct RequestRejection {
	/// Response body returned when content is rejected.
	#[serde(default = "default_body", serialize_with = "ser_string_or_bytes")]
	pub body: Bytes,
	/// HTTP status code returned when content is rejected.
	#[serde(default = "default_code", with = "http_serde::status_code")]
	#[cfg_attr(feature = "schema", schemars(with = "std::num::NonZeroU16"))]
	pub status: StatusCode,
	/// Headers to add, set, or remove from the rejection response.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub headers: Option<HeaderModifier>,
}

impl Default for RequestRejection {
	fn default() -> Self {
		Self {
			body: default_body(),
			status: default_code(),
			headers: None,
		}
	}
}

#[apply(schema!)]
pub struct ResponseGuard {
	/// Response returned when the LLM response is rejected.
	#[serde(default)]
	pub rejection: RequestRejection,
	/// Guardrail provider or rule set to apply.
	#[serde(flatten)]
	pub kind: ResponseGuardKind,
}

#[apply(schema!)]
pub enum ResponseGuardKind {
	/// Apply regex-based masking or rejection rules.
	Regex(RegexRules),
	/// Call a webhook to evaluate the response.
	Webhook(Webhook),
	/// Use AWS Bedrock Guardrails to evaluate the response.
	#[cfg(feature = "providers-aws")]
	BedrockGuardrails(BedrockGuardrails),
	/// Use Google Model Armor to evaluate the response.
	#[cfg(feature = "providers-gcp")]
	GoogleModelArmor(GoogleModelArmor),
	/// Use Azure Content Safety to evaluate the response.
	#[cfg(feature = "providers-azure")]
	AzureContentSafety(AzureContentSafety),
}

#[apply(schema!)]
pub struct PromptGuardRegex {}
fn default_code() -> StatusCode {
	StatusCode::FORBIDDEN
}

fn default_body() -> Bytes {
	Bytes::from_static(b"The request was rejected due to inappropriate content")
}
