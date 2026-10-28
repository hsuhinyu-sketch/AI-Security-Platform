//! Host implementation of bounded text generation. Protocols supply live authorization
//! checks; this adapter alone owns route re-entry, provider checks and the final send proof.
use std::sync::{
	Arc, OnceLock, Weak,
	atomic::{AtomicBool, Ordering},
};

use gateway_protocol_core::{
	execution::ExecutionFuture,
	model::{BoundTextGeneration, TextRequest, TextResponse, TextRole, TextStop},
};
use headers::HeaderMapExt;
use serde_json::{Value, json};

use super::{ProxyError, RoutingGuards, httpproxy::HTTPProxy};
use crate::{
	RuntimeContext,
	execution_budget::ExecutionScope,
	http::{Request, Response},
	store::BackendPolicies,
	transport::stream::Extension,
	types::agent::{BindKey, Listener},
};

/// Rechecks must include the originating protocol operation and its live parent.
/// No cached boolean can stand in for these checks.
pub(crate) trait Guard: Send + Sync {
	fn check(&self) -> Result<(), ProxyError>;
	fn correlate(&self, request_id: String) -> Result<(), ProxyError>;
	fn denial(&self, reason: &str) -> ProxyError;
}

pub(crate) struct Binding {
	pub config: Arc<security_integration_runtime::SecurityConfig>,
	pub allowed_models: Vec<String>,
	pub scope: ExecutionScope,
	pub revision: gateway_contracts::ConfigLease,
	pub guards: Option<RoutingGuards>,
	pub flow: Option<crate::security_flow::FlowAccess>,
	pub guard: Arc<dyn Guard>,
}

pub(crate) struct Target {
	pub authority: String,
	pub path: String,
	pub model: String,
}

/// Request-local trusted dispatch. Weak ownership avoids Session -> Runtime cycles.
#[derive(Clone)]
pub(crate) struct Route {
	inputs: Weak<RuntimeContext>,
	bind_name: BindKey,
	listener: Option<Arc<Listener>>,
	target: std::net::SocketAddr,
	connection: Arc<Extension>,
	// Captured before wire authentication consumes the credential. Never exposed to consumers.
	authorization: Option<http::HeaderValue>,
}

impl Route {
	pub(crate) fn new(
		proxy: &HTTPProxy,
		connection: Arc<Extension>,
		authorization: Option<http::HeaderValue>,
	) -> Self {
		Self {
			inputs: Arc::downgrade(&proxy.inputs),
			bind_name: proxy.bind_name.clone(),
			listener: proxy.selected_listener.clone(),
			target: proxy.target_address,
			connection,
			authorization,
		}
	}

	pub(crate) fn bind(self, target: Target, binding: Binding) -> Bound {
		Bound {
			route: self,
			target,
			binding: Arc::new(binding),
			claimed: AtomicBool::new(false),
		}
	}

	async fn call(&self, request: Request) -> Result<Response, ProxyError> {
		let inputs = self
			.inputs
			.upgrade()
			.ok_or(ProxyError::AuthorizationFailed)?;
		// The configured authority is routing data, never a DNS/network destination.
		// An explicit port must name a registered local Bind. Do not silently fall
		// back to the MCP listener or an internal wildcard when it does not exist.
		let port = request.uri().port_u16().unwrap_or(self.target.port());
		let bind = {
			let store = inputs.stores.read_binds();
			// Discovery can contain distinct address-specific Binds on one port.
			// A port-only target must never select one by HashMap iteration order.
			if store
				.bind_addresses()
				.iter()
				.filter(|a| a.port() == port)
				.count()
				!= 1
			{
				return Err(ProxyError::AuthorizationFailed);
			}
			store
				.find_bind_by_port(port)
				.ok_or(ProxyError::AuthorizationFailed)?
		};
		let same_bind = bind.key == self.bind_name;
		let target = std::net::SocketAddr::new(self.target.ip(), port);
		let proxy = HTTPProxy {
			inputs,
			bind_name: bind.key.clone(),
			selected_listener: if same_bind {
				self.listener.clone()
			} else {
				None
			},
			target_address: target,
		};
		Ok(proxy.proxy(self.connection.clone(), request).await)
	}
}

pub(crate) struct Bound {
	route: Route,
	target: Target,
	binding: Arc<Binding>,
	claimed: AtomicBool,
}

#[derive(Clone)]
pub(crate) struct Call {
	binding: Arc<Binding>,
	max_tokens: u64,
	state: Arc<State>,
}

struct State {
	model: OnceLock<String>,
	sent: AtomicBool,
}

fn allowed(value: &Value, fields: &[&str]) -> bool {
	value
		.as_object()
		.is_some_and(|v| v.keys().all(|k| fields.contains(&k.as_str())))
}
fn bounded_text(value: &Value, max: usize) -> bool {
	value.as_str().is_some_and(|s| s.len() <= max)
}

fn final_model<'a>(body: &'a Value, max_tokens: u64, models: &[String]) -> Option<&'a str> {
	let tokens = body
		.get("max_tokens")
		.or_else(|| body.get("max_completion_tokens"))
		.and_then(Value::as_u64);
	let model = body["model"]
		.as_str()
		.filter(|m| !m.is_empty() && m.len() <= 128)?;
	if security_audit::StateJournal::encoded_len(body, 32768).is_err()
		|| !models.iter().any(|m| m == model)
		|| !allowed(
			body,
			&[
				"model",
				"messages",
				"max_tokens",
				"max_completion_tokens",
				"stream",
				"stop",
			],
		) || body.get("stream").is_some_and(|v| v != false)
		|| (body.get("max_tokens").is_some() && body.get("max_completion_tokens").is_some())
		|| !tokens.is_some_and(|n| n > 0 && n <= max_tokens)
		|| !body["messages"].as_array().is_some_and(|a| {
			!a.is_empty()
				&& a.len() <= 17
				&& a.iter().all(|m| {
					allowed(m, &["role", "content"])
						&& matches!(m["role"].as_str(), Some("system" | "user" | "assistant"))
						&& bounded_text(&m["content"], 8192)
				})
		}) {
		return None;
	}
	Some(model)
}

impl Call {
	pub(crate) async fn verify(
		&self,
		request: &mut Request,
		policies: &BackendPolicies,
	) -> Result<(), ProxyError> {
		self.binding.guard.check()?;
		let active = policies
			.security_audit
			.as_ref()
			.ok_or(ProxyError::AuthorizationFailed)?;
		if !active
			.same_configuration(&self.binding.config)
			.map_err(|_| ProxyError::AuthorizationFailed)?
			|| active.execution_budget.is_none()
			|| request.extensions().get::<ExecutionScope>().is_none()
			|| !policies
				.llm_provider
				.as_ref()
				.is_some_and(|p| matches!(p.provider, crate::llm::AIProvider::OpenAI(_)))
		{
			return Err(
				self
					.binding
					.guard
					.denial("task-sampling-model-route-contract"),
			);
		}
		let body: Value = crate::json::inspect_body(request)
			.await
			.map_err(|_| self.binding.guard.denial("task-sampling-model-body"))?;
		let model =
			final_model(&body, self.max_tokens, &self.binding.allowed_models).ok_or_else(|| {
				self
					.binding
					.guard
					.denial("task-sampling-final-model-request")
			})?;
		if request.method() != http::Method::POST || self.state.model.set(model.into()).is_err() {
			return Err(
				self
					.binding
					.guard
					.denial("task-sampling-final-model-request"),
			);
		}
		self.binding.guard.check()
	}

	pub(crate) fn before_send(&self) -> Result<(), ProxyError> {
		self.binding.guard.check()?;
		if self.state.model.get().is_none() || self.state.sent.swap(true, Ordering::AcqRel) {
			return Err(self.binding.guard.denial("task-sampling-model-replay"));
		}
		Ok(())
	}
}

fn decode_response(generated: &Value, model: &str) -> Option<TextResponse> {
	let choice = &generated["choices"][0];
	if !generated["choices"]
		.as_array()
		.is_some_and(|c| c.len() == 1)
		|| choice["message"]["role"] != "assistant"
		|| !bounded_text(&choice["message"]["content"], 8192)
		|| choice["message"].get("tool_calls").is_some()
		|| choice["message"].get("function_call").is_some()
	{
		return None;
	}
	Some(TextResponse {
		model: model.into(),
		text: choice["message"]["content"].as_str()?.into(),
		stop: match choice["finish_reason"].as_str()? {
			"stop" => TextStop::EndTurn,
			"length" => TextStop::MaxTokens,
			_ => return None,
		},
	})
}

impl BoundTextGeneration for Bound {
	type Error = ProxyError;

	fn generate(&self, input: TextRequest) -> ExecutionFuture<'_, TextResponse, ProxyError> {
		Box::pin(async move {
			self.binding.guard.check()?;
			if self.claimed.swap(true, Ordering::AcqRel) {
				return Err(self.binding.guard.denial("task-sampling-model-replay"));
			}
			let messages: Vec<Value> = input.messages.into_iter().map(|m| json!({"role":match m.role {
				TextRole::System => "system", TextRole::User => "user", TextRole::Assistant => "assistant" },"content":m.text})).collect();
			let mut body = json!({"model":self.target.model,"messages":messages,"max_tokens":input.max_tokens,"stream":false});
			if let Some(stop) = input.stop {
				body["stop"] = json!(stop);
			}
			// Validate at ingress too; transformations are checked again immediately before send.
			final_model(&body, input.max_tokens, &self.binding.allowed_models)
				.ok_or(ProxyError::AuthorizationFailed)?;
			let call = Call {
				binding: self.binding.clone(),
				max_tokens: input.max_tokens,
				state: Arc::new(State {
					model: OnceLock::new(),
					sent: AtomicBool::new(false),
				}),
			};
			let mut request = http::Request::builder()
				.method("POST")
				.uri(format!(
					"http://{}{}",
					self.target.authority, self.target.path
				))
				.header("content-type", "application/json")
				.header("accept", "application/json")
				.body(crate::json::to_body(body).map_err(|_| ProxyError::AuthorizationFailed)?)?;
			let authorization = self.route.authorization.clone().ok_or_else(|| {
				self
					.binding
					.guard
					.denial("task-sampling-caller-credential-unavailable")
			})?;
			request
				.headers_mut()
				.insert(http::header::AUTHORIZATION, authorization);
			request
				.extensions_mut()
				.insert(self.binding.scope.fork_call());
			request.extensions_mut().insert(call.clone());
			if let Some(guards) = &self.binding.guards {
				request.extensions_mut().insert(guards.clone());
			}
			let request_id = crate::security::request_id(request.extensions_mut());
			self.binding.guard.correlate(request_id)?;
			request
				.extensions_mut()
				.insert(self.binding.revision.clone());
			if let Some(flow) = &self.binding.flow {
				request.extensions_mut().insert(flow.clone());
			}
			// No arbitrary caller headers/extensions, detached producer, retries or mirrors.
			let response = Box::pin(self.route.call(request)).await?;
			if response.status() != http::StatusCode::OK || !call.state.sent.load(Ordering::Acquire) {
				return Err(self.binding.guard.denial("task-sampling-model-failed"));
			}
			if !response
				.headers()
				.get(http::header::CONTENT_TYPE)
				.and_then(|h| h.to_str().ok())
				.is_some_and(|s| s.starts_with("application/json"))
			{
				return Err(self.binding.guard.denial("task-sampling-model-format"));
			}
			let encoding = response.headers().typed_get::<headers::ContentEncoding>();
			let bytes = crate::http::compression::to_bytes_with_decompression(
				response.into_body(),
				encoding.as_ref(),
				65536,
			)
			.await
			.map_err(|_| self.binding.guard.denial("task-sampling-output-limit"))?
			.1;
			let generated: Value = serde_json::from_slice(&bytes)
				.map_err(|_| self.binding.guard.denial("task-sampling-output-shape"))?;
			let model = call
				.state
				.model
				.get()
				.ok_or(ProxyError::AuthorizationFailed)?;
			let result = decode_response(&generated, model)
				.ok_or_else(|| self.binding.guard.denial("task-sampling-output-shape"))?;
			self.binding.guard.check()?;
			Ok(result)
		})
	}
}

#[cfg(test)]
mod tests;
