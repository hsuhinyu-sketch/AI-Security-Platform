#[cfg(feature = "gateway-llm")]
use std::str::FromStr;
use std::sync::Arc;

#[cfg(feature = "gateway-llm")]
use ::http::request::Parts;
#[cfg(feature = "gateway-llm")]
use ::http::uri::{Authority, PathAndQuery};
#[cfg(feature = "gateway-llm")]
use ::http::{HeaderMap, HeaderName, HeaderValue, header};
#[cfg(feature = "gateway-llm")]
use axum_extra::headers::authorization::Bearer;
#[cfg(feature = "gateway-llm")]
use headers::{ContentEncoding, HeaderMapExt};
use platform_core::prelude::Strng;
#[cfg(feature = "gateway-llm")]
use platform_core::strng;
pub use policy::Policy;
#[cfg(feature = "gateway-llm")]
use rand::RngExt;
#[cfg(feature = "gateway-llm")]
use serde::de::DeserializeOwned;
#[cfg(feature = "gateway-llm")]
use tiktoken_rs::CoreBPE;
#[cfg(feature = "gateway-llm")]
use tiktoken_rs::tokenizer::{Tokenizer, get_tokenizer};

#[cfg(feature = "providers-aws")]
use crate::http::auth::AwsAuth;
#[cfg(feature = "providers-azure")]
use crate::http::auth::AzureAuth;
#[cfg(feature = "providers-gcp")]
use crate::http::auth::GcpAuth;
#[cfg(feature = "gateway-llm")]
use crate::http::auth::{AppliedBackendAuthLocation, BackendAuth};
#[cfg(feature = "gateway-llm")]
use crate::http::jwt::Claims;
#[cfg(feature = "gateway-llm")]
use crate::http::{Body, Request, Response};
#[cfg(feature = "gateway-llm")]
pub use crate::llm::types::{RequestType, ResponseType};
#[cfg(feature = "gateway-llm")]
use crate::proxy::httpproxy::PolicyClient;
#[cfg(feature = "gateway-llm")]
use crate::store::{BackendPolicies, LLMResponsePolicies};
#[cfg(feature = "gateway-llm")]
use crate::telemetry::log::{AsyncLog, RequestLog};
#[cfg(feature = "gateway-llm")]
use crate::types::agent::{BackendTrafficPolicy, SimpleBackendReference, Target};
#[cfg(feature = "gateway-llm")]
use crate::types::loadbalancer::ActiveHandle;
use crate::*;

#[cfg(feature = "gateway-llm")]
pub mod anthropic;
#[cfg(feature = "gateway-llm")]
pub mod azure;
#[cfg(feature = "gateway-llm")]
pub mod bedrock;
#[cfg(feature = "gateway-llm")]
pub mod copilot;
#[cfg(feature = "gateway-llm")]
pub mod custom;
#[cfg(feature = "gateway-llm")]
pub mod gemini;
#[cfg(feature = "gateway-llm")]
pub mod model_router;
#[cfg(feature = "gateway-llm")]
pub mod openai;
#[cfg(feature = "gateway-llm")]
pub mod vertex;

#[cfg(feature = "gateway-llm")]
mod conversion;
pub mod cost;
#[cfg(feature = "gateway-llm")]
mod execution;
pub mod policy;
mod types;

#[cfg(all(test, feature = "gateway-llm"))]
mod type_contract_tests;

pub use gateway_llm::{CacheTokenConvention, LLMResponse};
#[cfg(feature = "gateway-llm")]
use policy::streaming_guardrails::GuardedSseBody;
pub use types::SimpleChatCompletionMessage;
#[cfg(feature = "gateway-llm")]
use types::count_tokens::ResponseExt as _;

#[cfg(feature = "gateway-llm")]
use crate::cel::{Executor, LLMContext, RequestSnapshot};
#[cfg(feature = "gateway-llm")]
use crate::guardrails::{ResponseContext, VehicleStreamingResponseEvaluator};
#[cfg(feature = "gateway-llm")]
use crate::proxy::dtrace;
#[cfg(feature = "gateway-llm")]
use crate::store;

#[cfg(feature = "gateway-llm")]
fn normalize_sse_response_headers(mut resp: Response) -> Response {
	resp.headers_mut().insert(
		header::CONTENT_TYPE,
		HeaderValue::from_static("text/event-stream"),
	);
	resp.headers_mut().remove(header::CONTENT_LENGTH);
	resp
}

#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg(feature = "gateway-llm")]
pub struct AIBackend {
	pub providers: crate::types::loadbalancer::EndpointSet<NamedAIProvider>,
}

#[cfg(feature = "gateway-llm")]
impl AIBackend {
	pub fn select_provider(&self) -> Option<(Arc<NamedAIProvider>, ActiveHandle)> {
		self.select_provider_where(|_| true)
	}
	pub fn select_provider_where(
		&self,
		permits: impl FnMut(&NamedAIProvider) -> bool,
	) -> Option<(Arc<NamedAIProvider>, ActiveHandle)> {
		let candidates = self.providers.eligible_active(permits);
		if candidates.is_empty() {
			return None;
		}
		// Intentionally allow `rand::seq::index::sample` so we can pick the same element twice
		// This avoids starvation where the worst endpoint gets 0 traffic
		let a = rand::rng().random_range(0..candidates.len());
		let b = rand::rng().random_range(0..candidates.len());
		let best = [a, b]
			.into_iter()
			.map(|idx| {
				let (endpoint, info) = &candidates[idx];
				(endpoint.clone(), info)
			})
			.max_by(|(_, a), (_, b)| a.score().total_cmp(&b.score()));
		let (ep, ep_info) = best?;
		let handle = self.providers.start_request(ep.name.clone(), ep_info);
		Some((ep, handle))
	}
}

#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg(feature = "gateway-llm")]
pub struct NamedAIProvider {
	pub name: Strng,
	pub provider: AIProvider,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub provider_backend: Option<SimpleBackendReference>,
	pub host_override: Option<Target>,
	pub path_override: Option<Strng>,
	pub path_prefix: Option<Strng>,
	/// Whether to tokenize on the request flow. This enables us to do more accurate rate limits,
	/// since we know (part of) the cost of the request upfront.
	/// This comes with the cost of an expensive operation.
	#[serde(default)]
	pub tokenize: bool,
	#[serde(default, skip_serializing_if = "Vec::is_empty")]
	pub inline_policies: Vec<BackendTrafficPolicy>,
}

pub use gateway_llm::provider::RouteType;

#[apply(schema!)]
#[cfg(feature = "gateway-llm")]
pub enum AIProvider {
	OpenAI(openai::Provider),
	Gemini(gemini::Provider),
	#[cfg(feature = "providers-gcp")]
	Vertex(vertex::Provider),
	Anthropic(anthropic::Provider),
	#[cfg(feature = "providers-aws")]
	Bedrock(bedrock::Provider),
	#[cfg(feature = "providers-azure")]
	Azure(azure::Provider),
	Copilot(copilot::Provider),
	Custom(custom::Provider),
}

#[apply(schema!)]
#[cfg(feature = "gateway-llm")]
pub enum LocalModelAIProvider {
	OpenAI,
	Gemini,
	#[cfg(feature = "providers-gcp")]
	Vertex,
	Anthropic,
	#[cfg(feature = "providers-aws")]
	Bedrock,
	#[cfg(feature = "providers-azure")]
	Azure,
	Copilot,
	Custom(custom::Provider),
}

#[cfg(feature = "gateway-llm")]
trait Provider {
	const NAME: Strng;
}

#[derive(Debug, Clone)]
pub struct LLMRequest {
	/// Input tokens derived by tokenizing the request. Not always enabled
	pub input_tokens: Option<u64>,
	pub input_format: InputFormat,
	pub native_format: Option<gateway_llm::provider::ProviderFormat>,
	pub cache_convention: CacheTokenConvention,
	pub request_model: Strng,
	pub provider: Strng,
	pub streaming: bool,
	pub params: LLMRequestParams,
	pub prompt: Option<Arc<Vec<SimpleChatCompletionMessage>>>,
	pub provider_state: Option<ProviderState>,
}

#[derive(Debug, Clone)]
pub enum ProviderState {
	#[cfg(feature = "gateway-llm")]
	Bedrock {
		/// Reverse mapping from Bedrock-safe tool names back to client tool names.
		tool_names: Arc<conversion::bedrock::BedrockToolNameMap>,
	},
}

/// Classify how the upstream reports cached tokens, from the source wire format the
/// gateway is about to parse — not the provider name, which can carry another
/// provider's native semantics (e.g. Vertex serving Anthropic models).
#[cfg(feature = "gateway-llm")]
fn cache_convention_for(
	provider: &AIProvider,
	native_format: Option<custom::ProviderFormat>,
	_request_model: &str,
) -> CacheTokenConvention {
	provider
		.protocol()
		.cache_convention(native_format, _request_model)
}

pub use gateway_llm::provider::InputFormat;

#[derive(Default, Clone, Debug, Serialize, Deserialize, ::cel::DynamicType)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
pub struct LLMRequestParams {
	#[serde(skip_serializing_if = "Option::is_none")]
	pub temperature: Option<f64>,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub top_p: Option<f64>,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub frequency_penalty: Option<f64>,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub presence_penalty: Option<f64>,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub seed: Option<i64>,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub max_tokens: Option<u64>,
	// Embeddings
	#[serde(skip_serializing_if = "Option::is_none")]
	pub encoding_format: Option<Strng>,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub dimensions: Option<u64>,
}
impl PartialEq for LLMRequestParams {
	fn eq(&self, _: &Self) -> bool {
		// ignore for now since we have f64
		false
	}
}
impl Eq for LLMRequestParams {}

#[derive(Debug, Clone)]
pub struct LLMInfo {
	pub request: LLMRequest,
	pub response: LLMResponse,
}

impl LLMInfo {
	pub fn new(req: LLMRequest, resp: LLMResponse) -> Self {
		Self {
			request: req,
			response: resp,
		}
	}
	pub fn input_tokens(&self) -> Option<u64> {
		self.response.input_tokens.or(self.request.input_tokens)
	}
}

#[derive(Debug)]
#[allow(clippy::large_enum_variant)]
#[cfg(feature = "gateway-llm")]
pub enum RequestResult {
	Success(Request, LLMRequest),
	Rejected(Response),
}

#[cfg(feature = "gateway-llm")]
impl AIProvider {
	pub(crate) fn protocol(&self) -> gateway_llm::provider::adapter::Adapter<'_> {
		use gateway_llm::provider::adapter::{Adapter, Custom};
		match self {
			Self::OpenAI(p) => Adapter::OpenAI(p.model.as_deref()),
			Self::Anthropic(p) => Adapter::Anthropic(p.model.as_deref()),
			Self::Copilot(p) => Adapter::Copilot(p.model.as_deref()),
			Self::Gemini(p) => Adapter::Gemini(p.model.as_deref()),
			#[cfg(feature = "providers-azure")]
			Self::Azure(p) => Adapter::Azure(p.endpoint()),
			#[cfg(feature = "providers-aws")]
			Self::Bedrock(p) => Adapter::Bedrock(p.endpoint()),
			#[cfg(feature = "providers-gcp")]
			Self::Vertex(p) => Adapter::Vertex(p.endpoint()),
			Self::Custom(p) => Adapter::Custom(Custom {
				model: p.model.as_deref(),
				formats: &p.formats,
			}),
		}
	}

	#[cfg(feature = "gateway-llm")]
	fn is_bedrock(&self) -> bool {
		self.protocol().is_bedrock()
	}
	pub fn provider(&self) -> Strng {
		match self {
			AIProvider::OpenAI(_p) => openai::Provider::NAME,
			AIProvider::Anthropic(_p) => anthropic::Provider::NAME,
			AIProvider::Gemini(_p) => gemini::Provider::NAME,
			#[cfg(feature = "providers-gcp")]
			AIProvider::Vertex(_p) => vertex::Provider::NAME,
			#[cfg(feature = "providers-aws")]
			AIProvider::Bedrock(_p) => bedrock::Provider::NAME,
			#[cfg(feature = "providers-azure")]
			AIProvider::Azure(_p) => azure::Provider::NAME,
			AIProvider::Copilot(_p) => copilot::Provider::NAME,
			AIProvider::Custom(p) => p
				.provider_override
				.clone()
				.unwrap_or(custom::Provider::NAME),
		}
	}

	pub fn override_model(&self) -> Option<Strng> {
		self.protocol().override_model().map(Into::into)
	}

	pub fn supported_formats(&self, _request_model: Option<&str>) -> Vec<custom::ProviderFormat> {
		self.protocol().supported_formats(_request_model)
	}

	pub fn supports_format(
		&self,
		format: custom::ProviderFormat,
		request_model: Option<&str>,
	) -> bool {
		self.supported_formats(request_model).contains(&format)
	}

	pub fn native_format_for(
		&self,
		input_format: InputFormat,
		request_model: Option<&str>,
	) -> Option<custom::ProviderFormat> {
		self
			.protocol()
			.native_format_for(input_format, request_model)
	}
}

#[cfg(feature = "gateway-llm")]
impl AIProvider {
	/// Default backend policies (TLS + auth) for connecting to the provider. Split from
	/// [`Self::default_connector_target`] so callers can compute effective policies, resolve the LLM
	/// route from them, and only then pick the connection target. Returns `None` for custom providers,
	/// which require an explicit host override or provider backend.
	pub fn default_connector_policies(&self) -> Option<BackendPolicies> {
		let btls = BackendPolicies {
			backend_tls: Some(http::backendtls::SYSTEM_TRUST.clone()),
			// We will use original request for now
			..Default::default()
		};
		Some(match self {
			AIProvider::OpenAI(_) | AIProvider::Gemini(_) | AIProvider::Anthropic(_) => btls,
			AIProvider::Copilot(_) => BackendPolicies {
				backend_auth: Some(BackendAuth::Copilot),
				..btls
			},
			#[cfg(feature = "providers-gcp")]
			AIProvider::Vertex(_) => BackendPolicies {
				backend_auth: Some(BackendAuth::Gcp(GcpAuth::default())),
				..btls
			},
			#[cfg(feature = "providers-aws")]
			AIProvider::Bedrock(p) => BackendPolicies {
				backend_auth: Some(BackendAuth::Aws(AwsAuth::Implicit {
					service_name: None,
					assume_role: None,
					source_credentials_cache: p.source_credentials_cache.clone(),
					assume_role_cache: p.assume_role_cache.clone(),
				})),
				..btls
			},
			#[cfg(feature = "providers-azure")]
			AIProvider::Azure(p) => BackendPolicies {
				backend_auth: Some(BackendAuth::Azure(AzureAuth::Implicit {
					cached_cred: p.cached_cred.clone(),
				})),
				..btls
			},
			AIProvider::Custom(_) => return None,
		})
	}

	/// Default connection target for the provider, for the given LLM route. Route-aware because some
	/// providers serve routes from different hosts (Bedrock rerank uses `bedrock-agent-runtime` and
	/// Vertex rerank uses `discoveryengine`, distinct from the chat/embeddings host). Returns `None`
	/// for custom providers, which require an explicit host override or provider backend.
	pub fn default_connector_target(&self, _route_type: RouteType) -> Option<Target> {
		self
			.protocol()
			.host(_route_type)
			.map(|host| Target::Hostname(host, 443))
	}

	pub fn setup_request(
		&self,
		req: &mut Request,
		route_type: RouteType,
		llm_request: Option<&LLMRequest>,
		path_override: Option<&str>,
		path_prefix: Option<&str>,
		has_host_override: bool,
	) -> anyhow::Result<()> {
		if let Some(path_override) = path_override {
			http::modify_req_uri(req, |uri| {
				uri.path_and_query = Some(PathAndQuery::from_str(path_override)?);
				Ok(())
			})?;
		} else {
			self.set_default_path(req, route_type, llm_request, path_prefix, has_host_override)?;
		}
		if !has_host_override {
			self.set_default_authority(req, route_type)?;
		}
		self.set_required_fields(req, route_type, llm_request)?;
		Ok(())
	}

	pub fn set_default_path(
		&self,
		req: &mut Request,
		route_type: RouteType,
		llm_request: Option<&LLMRequest>,
		path_prefix: Option<&str>,
		has_host_override: bool,
	) -> anyhow::Result<()> {
		let details = llm_request.map(|request| gateway_llm::provider::endpoint::RequestDetails {
			model: &request.request_model,
			native_format: request.native_format,
			streaming: request.streaming,
		});
		if let Some(path) = self.protocol().request_path(
			req.uri(),
			route_type,
			details,
			path_prefix,
			has_host_override,
		)? {
			http::modify_req_uri(req, |uri| {
				uri.path_and_query = Some(path);
				Ok(())
			})?;
		}
		Ok(())
	}

	pub fn set_default_authority(
		&self,
		req: &mut Request,
		route_type: RouteType,
	) -> anyhow::Result<()> {
		if let Some(host) = self.protocol().host(route_type) {
			http::modify_req_uri(req, |uri| {
				uri.authority = Some(Authority::from_str(&host)?);
				Ok(())
			})?;
			#[cfg(feature = "providers-aws")]
			if let Self::Bedrock(provider) = self {
				req.extensions_mut().insert(bedrock::AwsRegion {
					region: provider.region.to_string(),
				});
			}
		}
		Ok(())
	}

	pub fn set_required_fields(
		&self,
		req: &mut Request,
		_route_type: RouteType,
		_llm_request: Option<&LLMRequest>,
	) -> anyhow::Result<()> {
		match self {
			AIProvider::Anthropic(_) => {
				http::modify_req(req, |req| {
					if let Some(authz) = req.headers.typed_get::<headers::Authorization<Bearer>>() {
						// Check whether the backend auth location was explicitly configured by the user.
						// When explicit, we must not rewrite it
						// (e.g. Databricks Anthropic Messages API requires Authorization: Bearer <jwt>).
						let explicit_authorization = req
							.extensions
							.get::<AppliedBackendAuthLocation>()
							.is_some_and(|auth| auth.explicit);

						if authz.token().starts_with(anthropic::OAUTH_TOKEN_PREFIX) || explicit_authorization {
							// OAuth tokens ("sk-ant-oat*") keep Authorization: Bearer; drop any x-api-key.
							// Explicitly configured Authorization auth also keeps the header as-is.
							req.headers.remove("x-api-key");
						} else {
							// All other tokens are moved to x-api-key (standard API key auth).
							req.headers.remove(http::header::AUTHORIZATION);
							let mut api_key = HeaderValue::from_str(authz.token())?;
							api_key.set_sensitive(true);
							req.headers.insert("x-api-key", api_key);
						}
					}
					// https://docs.anthropic.com/en/api/versioning
					req
						.headers
						.insert("anthropic-version", HeaderValue::from_static("2023-06-01"));
					Ok(())
				})
			},
			#[cfg(feature = "providers-azure")]
			AIProvider::Azure(p) => {
				// Foundry's Anthropic-native endpoint requires the anthropic-version header,
				// but only for Claude models — GPT models use the OpenAI-compatible path.
				let model = _llm_request.map(|r| r.request_model.as_str()).unwrap_or("");
				if matches!(p.resource_type, azure::AzureResourceType::Foundry)
					&& p.is_anthropic_model(Some(model))
					&& matches!(
						_route_type,
						RouteType::Messages | RouteType::AnthropicTokenCount
					) {
					http::modify_req(req, |req| {
						req
							.headers
							.insert("anthropic-version", HeaderValue::from_static("2023-06-01"));
						Ok(())
					})
				} else {
					Ok(())
				}
			},
			_ => Ok(()),
		}
	}

	// Anthropic does not like CORS requests, but we are not really directly CORS since we are proxying requests.
	// Securing the requests and management of CORS is handled by the proxy so we just directly send.
	pub fn strip_browser_cors_headers(&self, req: &mut Request) {
		if !matches!(self, AIProvider::Anthropic(_)) {
			return;
		}

		let headers = req.headers_mut();
		headers.remove("origin");
		headers.remove("access-control-request-method");
		headers.remove("access-control-request-headers");

		let sec_fetch_headers: Vec<HeaderName> = headers
			.keys()
			.filter(|name| name.as_str().starts_with("sec-fetch-"))
			.cloned()
			.collect();
		for name in sec_fetch_headers {
			headers.remove(name);
		}
	}

	pub async fn process_completions_request(
		&self,
		backend_info: &crate::http::auth::BackendInfo,
		policies: Option<&Policy>,
		req: Request,
		tokenize: bool,
		log: &mut Option<&mut RequestLog>,
	) -> Result<RequestResult, AIError> {
		let (parts, mut req) = self
			.read_body_and_default_model::<types::completions::Request>(policies, req, log)
			.await?;

		// If a user doesn't request usage, we will not get token information which we need
		// We always set it.
		// TODO?: this may impact the user, if they make assumptions about the stream NOT including usage.
		// Notably, this adds a final SSE event.
		// We could actually go remove that on the response, but it would mean we cannot do passthrough-parsing,
		// so unless we have a compelling use case for it, for now we keep it.
		if req.stream.unwrap_or_default() && req.stream_options.is_none() {
			req.stream_options = Some(types::completions::StreamOptions {
				include_usage: true,
				rest: Default::default(),
			});
		}
		if matches!(self, AIProvider::OpenAI(_)) {
			req.normalize_openai_token_limit();
		}
		self
			.process_request(
				backend_info,
				policies,
				InputFormat::Completions,
				req,
				parts,
				tokenize,
				log,
			)
			.await
	}

	pub async fn process_messages_request(
		&self,
		backend_info: &crate::http::auth::BackendInfo,
		policies: Option<&Policy>,
		req: Request,
		tokenize: bool,
		log: &mut Option<&mut RequestLog>,
	) -> Result<RequestResult, AIError> {
		let (parts, req) = self
			.read_body_and_default_model::<types::messages::Request>(policies, req, log)
			.await?;

		self
			.process_request(
				backend_info,
				policies,
				InputFormat::Messages,
				req,
				parts,
				tokenize,
				log,
			)
			.await
	}

	pub async fn process_embeddings_request(
		&self,
		backend_info: &crate::http::auth::BackendInfo,
		policies: Option<&Policy>,
		req: Request,
		tokenize: bool,
		log: &mut Option<&mut RequestLog>,
	) -> Result<RequestResult, AIError> {
		let (parts, req) = self
			.read_body_and_default_model::<types::embeddings::Request>(policies, req, log)
			.await?;

		self
			.process_request(
				backend_info,
				policies,
				InputFormat::Embeddings,
				req,
				parts,
				tokenize,
				log,
			)
			.await
	}

	pub async fn process_rerank_request(
		&self,
		backend_info: &crate::http::auth::BackendInfo,
		policies: Option<&Policy>,
		req: Request,
		tokenize: bool,
		log: &mut Option<&mut RequestLog>,
	) -> Result<RequestResult, AIError> {
		let (parts, req) = self
			.read_body_and_default_model::<types::rerank::Request>(policies, req, log)
			.await?;

		self
			.process_request(
				backend_info,
				policies,
				InputFormat::Rerank,
				req,
				parts,
				tokenize,
				log,
			)
			.await
	}

	pub async fn process_responses_request(
		&self,
		backend_info: &crate::http::auth::BackendInfo,
		policies: Option<&Policy>,
		req: Request,
		tokenize: bool,
		log: &mut Option<&mut RequestLog>,
	) -> Result<RequestResult, AIError> {
		let (mut parts, req) = self
			.read_body_and_default_model::<types::responses::Request>(policies, req, log)
			.await?;

		// Strip client-specific headers that cause AWS signature mismatches for Bedrock
		if self.is_bedrock() {
			parts.headers.remove("conversation_id");
			parts.headers.remove("session_id");
		}

		self
			.process_request(
				backend_info,
				policies,
				InputFormat::Responses,
				req,
				parts,
				tokenize,
				log,
			)
			.await
	}

	pub async fn process_count_tokens_request(
		&self,
		backend_info: &crate::http::auth::BackendInfo,
		req: Request,
		policies: Option<&Policy>,
		log: &mut Option<&mut RequestLog>,
	) -> Result<RequestResult, AIError> {
		let (parts, req) = self
			.read_body_and_default_model::<types::count_tokens::Request>(policies, req, log)
			.await?;

		// Some Anthropic-compatible clients (e.g. Claude Code) always call
		// `/v1/messages/count_tokens`. For providers/models without a native
		// count-tokens endpoint, we must still answer this route, so we fall
		// back to local token estimation using the normalized messages payload.
		let use_local = !self.supports_format(
			custom::ProviderFormat::AnthropicTokenCount,
			req.model.as_deref(),
		);
		if use_local {
			let messages = req.get_messages();
			let model = req.model.as_deref().unwrap_or_default();
			let count = num_tokens_from_messages(model, &messages)?;
			let body = serde_json::to_vec(&types::count_tokens::Response {
				input_tokens: count,
			})
			.map_err(AIError::ResponseMarshal)?;
			let resp = ::http::Response::builder()
				.status(::http::StatusCode::OK)
				.header(::http::header::CONTENT_TYPE, "application/json")
				.body(Body::from(body))
				.expect("failed to build count_tokens response");
			return Ok(RequestResult::Rejected(resp));
		}

		self
			.process_request(
				backend_info,
				policies,
				InputFormat::CountTokens,
				req,
				parts,
				false,
				log,
			)
			.await
	}

	pub async fn process_detect_request(
		&self,
		backend_info: &crate::http::auth::BackendInfo,
		policies: Option<&Policy>,
		hreq: Request,
		log: &mut Option<&mut RequestLog>,
	) -> Result<RequestResult, AIError> {
		// We don't use read_body_and_default_model here because we need a lot of special logic
		// Unfortunately we buffer just due to how our interface works. Ideally we could not when
		// it is not even JSON
		let buffer = http::buffer_limit(&hreq);
		let is_json = hreq
			.headers()
			.typed_get::<headers::ContentType>()
			.map(|v| v == headers::ContentType::json())
			.unwrap_or_default();
		let (parts, body) = hreq.into_parts();
		let Ok(bytes) = http::read_body_with_limit(body, buffer).await else {
			return Err(AIError::RequestTooLarge);
		};

		let req = if is_json {
			if let Some(p) = policies
				&& p.has_request_body_mutations()
			{
				p.unmarshal_request(&bytes, log)
			} else {
				serde_json::from_slice(bytes.as_ref()).map_err(AIError::RequestParsing)
			}
			.unwrap_or_else(|_| types::detect::Request::new_raw(bytes))
		} else {
			types::detect::Request::new_raw(bytes)
		};

		self
			.process_request(
				backend_info,
				policies,
				InputFormat::Detect,
				req,
				parts,
				false,
				log,
			)
			.await
	}

	#[allow(clippy::too_many_arguments)]
	async fn process_request(
		&self,
		backend_info: &crate::http::auth::BackendInfo,
		policies: Option<&Policy>,
		original_format: InputFormat,
		mut req: impl RequestType,
		mut parts: ::http::request::Parts,
		tokenize: bool,
		log: &mut Option<&mut RequestLog>,
	) -> Result<RequestResult, AIError> {
		let request_model = if req.supports_model() {
			req.model().as_deref().map(str::to_string)
		} else {
			None
		};
		let native_format = if original_format == InputFormat::Detect {
			None
		} else {
			self
				.native_format_for(original_format, request_model.as_deref())
				.ok_or_else(|| {
					AIError::UnsupportedConversion(strng::format!(
						"from {original_format:?} to provider {}",
						self.provider()
					))
				})?
				.into()
		};

		if let Some(p) = policies {
			p.apply_prompt_enrichment(&mut req);

			if original_format.supports_prompt_guard() {
				let http_headers = &parts.headers;
				let claims = parts.extensions.get::<Claims>().cloned();
				if let Some(dr) = p
					.apply_prompt_guard(backend_info, &mut req, http_headers, claims)
					.await
					.map_err(|e| {
						warn!("failed to call prompt guard webhook: {e}");
						AIError::PromptWebhookError
					})? {
					return Ok(RequestResult::Rejected(dr));
				}
			}
		}

		let mut llm_info = req.to_llm_request(self.provider(), tokenize)?;
		if original_format == InputFormat::Detect {
			types::detect::amend_request_info(&mut llm_info, parts.uri.path());
		}
		llm_info.native_format = native_format;
		llm_info.cache_convention = cache_convention_for(self, native_format, &llm_info.request_model);
		if let Some(log) = log
			&& log.cel.cel_context.needs_llm_prompt()
			&& original_format.supports_prompt_guard()
		{
			llm_info.prompt = Some(req.get_messages().into());
		}

		let encoded = self.protocol().encode(
			original_format,
			native_format,
			&llm_info.request_model,
			&execution::Encoder {
				provider: self,
				request: &req,
				headers: &parts.headers,
				caching: policies.and_then(|policy| policy.prompt_caching.as_ref()),
			},
		)?;
		if !encoded.tool_name_map.is_empty() {
			llm_info.provider_state = Some(ProviderState::Bedrock {
				tool_names: Arc::new(encoded.tool_name_map),
			});
		}
		let new_request = encoded.body;

		parts.extensions.insert(llm_info.clone());

		parts.headers.remove(header::CONTENT_LENGTH);
		let req = Request::from_parts(parts, Body::from(new_request));
		Ok(RequestResult::Success(req, llm_info))
	}

	#[allow(clippy::too_many_arguments)]
	pub async fn process_response(
		&self,
		client: PolicyClient,
		req: LLMRequest,
		rate_limit: LLMResponsePolicies,
		req_snapshot: Option<Arc<RequestSnapshot>>,
		log: AsyncLog<llm::LLMInfo>,
		include_completion_in_log: bool,
		model_catalog: Option<&cost::CatalogReader>,
		resp: Response,
	) -> Result<Response, AIError> {
		// Non-success responses are plain JSON, not event-stream data.
		// Only enter the streaming path for successful responses; errors
		// fall through to the buffered path where process_error translates them.
		if req.streaming && resp.status().is_success() {
			return self.process_streaming(
				client,
				req,
				rate_limit,
				req_snapshot,
				log,
				include_completion_in_log,
				model_catalog.cloned(),
				resp,
			);
		}

		// Buffer the body
		let buffer_limit = http::response_buffer_limit(&resp);
		let (mut parts, body) = resp.into_parts();
		let body = dtrace::TracingBody::maybe_wrap("llm raw response", body, buffer_limit);
		let ce = parts.headers.typed_get::<ContentEncoding>();
		let (encoding, bytes) =
			http::compression::to_bytes_with_decompression(body, ce.as_ref(), buffer_limit)
				.await
				.map_err(|e| map_compression_error(e, &parts.headers))?;

		// Snapshot decompressed bytes for CEL response.body access before re-compression,
		// so maybe_buffer_response_body can skip decompression entirely.
		// Also strip encoding headers now that the body is decompressed; the chat
		// completions path re-adds Content-Encoding when it re-compresses.
		if encoding.is_some() {
			parts
				.extensions
				.insert(crate::cel::BufferedBody(bytes.clone()));
			parts.headers.remove(header::CONTENT_ENCODING);
			parts.headers.remove(header::TRANSFER_ENCODING);
		}

		// count_tokens has simplified response handling (just format translation)
		if req.input_format == InputFormat::CountTokens {
			if !self
				.protocol()
				.supports_count_tokens_response(Some(&req.request_model))
			{
				return Err(AIError::UnsupportedConversion(
					"count_tokens response not supported for this provider".into(),
				));
			}
			let (bytes, count) = types::count_tokens::Response::translate_response(bytes)?;

			parts.headers.remove(header::CONTENT_LENGTH);
			let llm_resp = LLMResponse {
				count_tokens: Some(count),
				..Default::default()
			};
			return Ok(Self::finalize_response(
				parts,
				bytes.into(),
				req,
				llm_resp,
				model_catalog,
				&log,
			));
		}

		// embeddings has simplified response handling
		if req.input_format == InputFormat::Embeddings {
			parts.headers.remove(header::CONTENT_LENGTH);
			if !parts.status.is_success() {
				let body = self.process_error(&req, parts.status, &bytes)?;
				return Ok(Self::finalize_response(
					parts,
					body.into(),
					req,
					LLMResponse::default(),
					model_catalog,
					&log,
				));
			}
			let (llm_resp, bytes) = self.process_embeddings_response(&req, &parts.headers, bytes)?;
			return Ok(Self::finalize_response(
				parts,
				bytes.into(),
				req,
				llm_resp,
				model_catalog,
				&log,
			));
		}

		// rerank has simplified response handling (like embeddings)
		if req.input_format == InputFormat::Rerank {
			parts.headers.remove(header::CONTENT_LENGTH);
			if !parts.status.is_success() {
				let body = self.process_error(&req, parts.status, &bytes)?;
				return Ok(Self::finalize_response(
					parts,
					body.into(),
					req,
					LLMResponse::default(),
					model_catalog,
					&log,
				));
			}
			let (llm_resp, bytes) = self.process_rerank_response(bytes)?;
			return Ok(Self::finalize_response(
				parts,
				bytes.into(),
				req,
				llm_resp,
				model_catalog,
				&log,
			));
		}

		let (llm_resp, body) = if !parts.status.is_success() {
			let body = self.process_error(&req, parts.status, &bytes)?;
			(LLMResponse::default(), body)
		} else {
			let mut resp = self.process_success(&req, &bytes)?;
			let prompt_guard_headers =
				response_prompt_guard_headers(&parts.headers, rate_limit.request_traceparent.as_ref());

			// Apply response prompt guard
			if let Some(dr) = Policy::apply_response_prompt_guard(
				&client,
				resp.as_mut(),
				&prompt_guard_headers,
				&rate_limit.prompt_guard,
			)
			.await
			.map_err(|e| {
				warn!("failed to apply response prompt guard: {e}");
				AIError::PromptWebhookError
			})? {
				return Ok(dr);
			}

			let llm_resp = resp.to_llm_response(include_completion_in_log);
			let body = resp.serialize().map_err(AIError::ResponseParsing)?;
			(llm_resp, Bytes::copy_from_slice(&body))
		};

		if let Some(guardrails) = client.guardrails() {
			let content = String::from_utf8_lossy(&body).to_string();
			let ctx = ResponseContext {
				content,
				model: req.request_model.to_string(),
			};
			let decision = guardrails
				.check_response(&ctx, client.vehicle_state())
				.await;
			if !decision.is_allowed() {
				let _ = decision.to_safety_event("llm-model", req.request_model.to_string());
				return Ok(decision.to_http_response());
			}
		}

		let body = if let Some(encoding) = encoding {
			parts
				.headers
				.insert(header::CONTENT_ENCODING, HeaderValue::from_static(encoding));
			Body::from(
				http::compression::encode_body(&body, encoding)
					.await
					.map_err(AIError::Encoding)?,
			)
		} else {
			Body::from(body)
		};
		parts.headers.remove(header::CONTENT_LENGTH);
		let llm_info = LLMInfo::new(req, llm_resp);
		parts
			.extensions
			.insert(crate::cel::LLMContext::from_catalog(
				llm_info.clone(),
				model_catalog,
			));
		let resp = Response::from_parts(parts, body);

		if !rate_limit.local_rate_limit.is_empty() || rate_limit.remote_rate_limit.is_some() {
			let exec = cel::Executor::new_response(req_snapshot.as_deref(), &resp);
			// In the initial request, we subtracted the approximate request tokens.
			// Now we should have the real request tokens and the response tokens
			amend_tokens(rate_limit, &llm_info, exec);
		}
		log.store(Some(llm_info));
		Ok(resp)
	}

	fn finalize_response(
		mut parts: ::http::response::Parts,
		body: Body,
		req: LLMRequest,
		llm_resp: LLMResponse,
		model_catalog: Option<&cost::CatalogReader>,
		log: &AsyncLog<llm::LLMInfo>,
	) -> Response {
		let llm_info = LLMInfo::new(req, llm_resp);
		parts
			.extensions
			.insert(crate::cel::LLMContext::from_catalog(
				llm_info.clone(),
				model_catalog,
			));
		log.store(Some(llm_info));
		Response::from_parts(parts, body)
	}

	fn process_embeddings_response(
		&self,
		_req: &LLMRequest,
		_headers: &::http::HeaderMap,
		bytes: Bytes,
	) -> Result<(LLMResponse, Bytes), AIError> {
		use gateway_llm::provider::response::AuxiliaryEncoding as E;
		match self
			.protocol()
			.auxiliary_encoding(InputFormat::Embeddings, Some(&_req.request_model))?
		{
			#[cfg(feature = "providers-aws")]
			E::Bedrock => {
				let translated = conversion::bedrock::from_embeddings::translate_response(
					&bytes,
					_headers,
					&_req.request_model,
				)?;
				let llm_resp = translated.to_llm_response(false);
				let body = translated.serialize().map_err(AIError::ResponseParsing)?;
				Ok((llm_resp, Bytes::from(body)))
			},
			#[cfg(feature = "providers-gcp")]
			E::Vertex => {
				let translated =
					conversion::vertex::from_embeddings::translate_response(&bytes, &_req.request_model)?;
				let llm_resp = translated.to_llm_response(false);
				let body = translated.serialize().map_err(AIError::ResponseParsing)?;
				Ok((llm_resp, Bytes::from(body)))
			},
			E::Passthrough => {
				let resp: types::embeddings::Response =
					serde_json::from_slice(&bytes).map_err(logged_response_parsing(&bytes))?;
				Ok((resp.to_llm_response(false), bytes))
			},
			#[allow(unreachable_patterns)]
			_ => Err(AIError::UnsupportedConversion(
				"provider codec is not compiled".into(),
			)),
		}
	}

	fn process_rerank_response(&self, bytes: Bytes) -> Result<(LLMResponse, Bytes), AIError> {
		use gateway_llm::provider::response::AuxiliaryEncoding as E;
		match self
			.protocol()
			.auxiliary_encoding(InputFormat::Rerank, None)?
		{
			#[cfg(feature = "providers-aws")]
			E::Bedrock => {
				let translated = conversion::bedrock::from_rerank::translate_response(&bytes)?;
				let llm_resp = translated.to_llm_response(false);
				let body = translated.serialize().map_err(AIError::ResponseParsing)?;
				Ok((llm_resp, Bytes::from(body)))
			},
			#[cfg(feature = "providers-gcp")]
			E::Vertex => {
				let translated = conversion::vertex::from_rerank::translate_response(&bytes)?;
				let llm_resp = translated.to_llm_response(false);
				let body = translated.serialize().map_err(AIError::ResponseParsing)?;
				Ok((llm_resp, Bytes::from(body)))
			},
			E::Passthrough => {
				let resp =
					types::rerank::parse_response_lenient(&bytes).map_err(logged_response_parsing(&bytes))?;
				Ok((resp.to_llm_response(false), bytes))
			},
			#[allow(unreachable_patterns)]
			_ => Err(AIError::UnsupportedConversion(
				"provider codec is not compiled".into(),
			)),
		}
	}

	fn parse_completions_response(bytes: &Bytes) -> Result<Box<dyn ResponseType>, AIError> {
		Ok(Box::new(
			serde_json::from_slice::<types::completions::Response>(bytes).map_err(|e| {
				warn!(
					error = %e,
					body = %String::from_utf8_lossy(bytes),
					"failed to parse completions response"
				);
				AIError::ResponseParsing(e)
			})?,
		))
	}

	fn parse_responses_response(bytes: &Bytes) -> Result<Box<dyn ResponseType>, AIError> {
		Ok(Box::new(
			serde_json::from_slice::<types::responses::Response>(bytes).map_err(|e| {
				warn!(
					error = %e,
					body = %String::from_utf8_lossy(bytes),
					"failed to parse responses response"
				);
				AIError::ResponseParsing(e)
			})?,
		))
	}

	fn parse_messages_response(bytes: &Bytes) -> Result<Box<dyn ResponseType>, AIError> {
		Ok(Box::new(
			serde_json::from_slice::<types::messages::Response>(bytes)
				.map_err(AIError::ResponseParsing)?,
		))
	}

	fn process_success(
		&self,
		req: &LLMRequest,
		bytes: &Bytes,
	) -> Result<Box<dyn ResponseType>, AIError> {
		use gateway_llm::provider::response::{ResponseDetails, ResponseEncoding as E};
		match self.protocol().response_encoding(ResponseDetails {
			input_format: req.input_format,
			native_format: req.native_format,
			request_model: &req.request_model,
		})? {
			E::Completions => Self::parse_completions_response(bytes),
			E::Messages => Self::parse_messages_response(bytes),
			E::Responses => Self::parse_responses_response(bytes),
			E::Detect => Ok(Box::new(
				serde_json::from_slice::<types::detect::Response>(bytes)
					.unwrap_or_else(|_| types::detect::Response::new_raw(bytes.clone())),
			)),
			E::OpenAIToMessages => conversion::completions::from_messages::translate_response(bytes),
			E::AnthropicToCompletions => {
				conversion::messages::from_completions::translate_response(bytes)
			},
			E::OpenAIToResponses => {
				conversion::openai_compat::to_responses::translate_response(bytes, &req.request_model)
			},
			#[cfg(feature = "providers-aws")]
			E::BedrockToCompletions => conversion::bedrock::from_completions::translate_response(
				bytes,
				&req.request_model,
				bedrock_tool_name_map(req),
			),
			#[cfg(feature = "providers-aws")]
			E::BedrockToMessages => conversion::bedrock::from_messages::translate_response(
				bytes,
				&req.request_model,
				bedrock_tool_name_map(req),
			),
			#[cfg(feature = "providers-aws")]
			E::BedrockToResponses => conversion::bedrock::from_responses::translate_response(
				bytes,
				&req.request_model,
				bedrock_tool_name_map(req),
			),
			#[cfg(not(feature = "providers-aws"))]
			_ => Err(AIError::UnsupportedConversion(
				"Bedrock is not compiled".into(),
			)),
		}
	}

	#[allow(clippy::too_many_arguments)]
	pub fn process_streaming(
		&self,
		client: PolicyClient,
		req: LLMRequest,
		response_policies: LLMResponsePolicies,
		req_snapshot: Option<Arc<RequestSnapshot>>,
		log: AsyncLog<llm::LLMInfo>,
		include_completion_in_log: bool,
		model_catalog: Option<cost::CatalogReader>,
		resp: Response,
	) -> Result<Response, AIError> {
		let model = req.request_model.clone();
		let input_format = req.input_format;
		let native_format = req.native_format;
		#[cfg(feature = "providers-aws")]
		let bedrock_tool_name_map = bedrock_tool_name_map(&req).cloned();
		// Store an empty response, as we stream in info we will parse into it
		let llmresp = llm::LLMInfo {
			request: req,
			response: LLMResponse::default(),
		};
		log.store(Some(llmresp));
		let buffer = http::response_buffer_limit(&resp);

		// Decompress before the SSE parser, which expects plaintext chunks.
		let (mut parts, body) = resp.into_parts();
		let body = dtrace::TracingBody::maybe_wrap("llm raw response", body, buffer);
		let ce = parts.headers.typed_get::<ContentEncoding>();
		let (body, decompressed_encoding) = http::compression::decompress_body(body, ce.as_ref())
			.map_err(|e| map_compression_error(e, &parts.headers))?;

		// Strip encoding headers after successful decompression
		if decompressed_encoding.is_some() {
			parts.headers.remove(header::CONTENT_ENCODING);
			parts.headers.remove(header::CONTENT_LENGTH);
			parts.headers.remove(header::TRANSFER_ENCODING);
		}

		// Build headers for guardrail evaluation (same as buffered path).
		let prompt_guard_headers = response_prompt_guard_headers(
			&parts.headers,
			response_policies.request_traceparent.as_ref(),
		);

		let resp = Response::from_parts(parts, body);
		let resp = if matches!(input_format, InputFormat::Detect) {
			resp
		} else {
			normalize_sse_response_headers(resp)
		};

		// Build evaluators before format translation so guardrails run against translated
		// SSE output, not raw upstream bytes. Applying them before translation silently
		// breaks Bedrock (AWS Event Stream is binary, not SSE) and any provider whose
		// wire format differs from SSE. Detect paths are raw pass-throughs; skip them.
		let mut evaluators = if response_policies.streaming_prompt_guard_enabled
			&& !response_policies.prompt_guard.is_empty()
		{
			use policy::PromptGuard;
			let temp_guard = PromptGuard {
				streaming: policy::PromptGuardStreamingMode::Enabled,
				request: vec![],
				response: response_policies.prompt_guard.clone(),
			};
			temp_guard.begin_streaming_response_guard(&client, &prompt_guard_headers)
		} else {
			vec![]
		};

		if let Some(guardrails) = client.guardrails().cloned() {
			evaluators.push(Box::new(VehicleStreamingResponseEvaluator::new(
				guardrails,
				model.to_string(),
				client.vehicle_state().clone(),
			)));
		}
		if !evaluators.is_empty() && matches!(input_format, InputFormat::Detect) {
			return Err(AIError::UnsupportedConversion(strng::literal!(
				"guarded streaming requires an explicit output format"
			)));
		}
		let limits = response_policies.streaming_limits;
		let resp =
			resp.map(|body| policy::streaming_limits::limited(body, buffer, self.is_bedrock(), limits));
		let resp = if !evaluators.is_empty() {
			resp.map(|body| policy::streaming_wire::validated(body, buffer, self.is_bedrock()))
		} else {
			resp
		};

		let logger = AmendOnDrop::with_catalog(log, response_policies, req_snapshot, model_catalog);
		let stream_format = match self {
			#[cfg(feature = "providers-aws")]
			AIProvider::Bedrock(_) => "awsEventStream",
			_ => "sseJson",
		};
		crate::proxy::dtrace::trace(|trace| {
			trace.llm_streaming_translation(
				self.provider().to_string(),
				format!("{input_format:?}"),
				native_format.map(|f| format!("{f:?}")),
				stream_format.to_string(),
			)
		});
		use gateway_llm::provider::response::StreamEncoding as E;
		let stream_encoding =
			self
				.protocol()
				.stream_encoding(gateway_llm::provider::response::ResponseDetails {
					input_format,
					native_format,
					request_model: &model,
				})?;
		let translated = match stream_encoding {
			E::Completions => {
				conversion::completions::passthrough_stream(logger, include_completion_in_log, resp)
			},
			E::Messages => resp.map(|body| {
				conversion::messages::passthrough_stream(body, buffer, logger, include_completion_in_log)
			}),
			E::Responses => resp.map(|body| {
				conversion::responses::passthrough_stream(body, buffer, logger, include_completion_in_log)
			}),
			E::AnthropicToCompletions => resp
				.map(|body| conversion::messages::from_completions::translate_stream(body, buffer, logger)),
			E::OpenAIToMessages => resp
				.map(|body| conversion::completions::from_messages::translate_stream(body, buffer, logger)),
			E::OpenAIToResponses => resp.map(|body| {
				conversion::openai_compat::to_responses::translate_stream(body, buffer, logger)
			}),
			E::Detect => types::detect::passthrough_stream(logger, resp),
			#[cfg(feature = "providers-aws")]
			E::DetectBedrock => types::detect::passthrough_aws_stream(logger, resp),
			#[cfg(feature = "providers-aws")]
			E::BedrockToCompletions => {
				let message = conversion::bedrock::message_id(&resp);
				resp.map(move |body| {
					conversion::bedrock::from_completions::translate_stream(
						body,
						buffer,
						logger,
						&model,
						&message,
						bedrock_tool_name_map,
					)
				})
			},
			#[cfg(feature = "providers-aws")]
			E::BedrockToMessages => {
				let message = conversion::bedrock::message_id(&resp);
				resp.map(move |body| {
					conversion::bedrock::from_messages::translate_stream(
						body,
						buffer,
						logger,
						&model,
						&message,
						include_completion_in_log,
						bedrock_tool_name_map,
					)
				})
			},
			#[cfg(feature = "providers-aws")]
			E::BedrockToResponses => {
				let message = conversion::bedrock::message_id(&resp);
				resp.map(move |body| {
					conversion::bedrock::from_responses::translate_stream(
						body,
						buffer,
						logger,
						&model,
						&message,
						bedrock_tool_name_map,
					)
				})
			},
			#[cfg(not(feature = "providers-aws"))]
			_ => {
				return Err(AIError::UnsupportedConversion(
					"Bedrock is not compiled".into(),
				));
			},
		};

		let translated = if !evaluators.is_empty() {
			// The converter owns the only accounting logger.
			translated.map(|body| {
				Body::new(GuardedSseBody::new(
					body,
					evaluators,
					buffer,
					None::<AmendOnDrop>,
				))
			})
		} else {
			translated
		};
		Ok(translated.map(policy::streaming_limits::terminal))
	}

	async fn read_body_and_default_model<T: RequestType + DeserializeOwned>(
		&self,
		policies: Option<&Policy>,
		hreq: Request,
		log: &mut Option<&mut RequestLog>,
	) -> Result<(Parts, T), AIError> {
		let buffer = http::buffer_limit(&hreq);
		let (parts, body) = hreq.into_parts();
		let Ok(bytes) = http::read_body_with_limit(body, buffer).await else {
			return Err(AIError::RequestTooLarge);
		};

		if self.override_model().is_none()
			&& types::detect::extract_model_from_path(parts.uri.path()).is_none()
			&& !policies.is_some_and(Policy::has_request_body_mutations)
		{
			let mut req: T = serde_json::from_slice(bytes.as_ref()).map_err(AIError::RequestParsing)?;
			let model = req.model();
			let Some(model_value) = model.as_deref() else {
				return Err(AIError::MissingField("model not specified".into()));
			};
			if let Some(p) = policies
				&& let Some(aliased) = p.resolve_model_alias(model_value)
			{
				*model = Some(aliased.to_string());
			}
			return Ok((parts, req));
		}

		let mut request: serde_json::Value =
			serde_json::from_slice(bytes.as_ref()).map_err(AIError::RequestParsing)?;
		self.set_provider_request_model(&parts, &mut request)?;
		let mut request = if let Some(p) = policies {
			p.apply_request_body_mutations(request, log)?
		} else {
			request
		};
		self.finalize_request_model(policies, &mut request)?;
		let req: T = serde_json::from_value(request).map_err(AIError::RequestParsing)?;

		Ok((parts, req))
	}

	fn set_provider_request_model(
		&self,
		parts: &Parts,
		req: &mut serde_json::Value,
	) -> Result<(), AIError> {
		let Some(obj) = req.as_object_mut() else {
			return Err(AIError::MissingField("request must be an object".into()));
		};
		if let Some(provider_model) = &self.override_model() {
			obj.insert(
				"model".to_string(),
				serde_json::Value::String(provider_model.to_string()),
			);
		} else if !matches!(obj.get("model"), Some(serde_json::Value::String(_)))
			&& let Some(path_model) = types::detect::extract_model_from_path(parts.uri.path())
		{
			obj.insert(
				"model".to_string(),
				serde_json::Value::String(path_model.to_string()),
			);
		}
		Ok(())
	}

	fn finalize_request_model(
		&self,
		policies: Option<&Policy>,
		req: &mut serde_json::Value,
	) -> Result<(), AIError> {
		let Some(obj) = req.as_object_mut() else {
			return Err(AIError::MissingField("request must be an object".into()));
		};
		let Some(model) = obj.get("model").and_then(serde_json::Value::as_str) else {
			return Err(AIError::MissingField("model not specified".into()));
		};
		if let Some(p) = policies
			&& let Some(aliased) = p.resolve_model_alias(model)
		{
			obj.insert(
				"model".to_string(),
				serde_json::Value::String(aliased.to_string()),
			);
		}
		Ok(())
	}

	fn process_error(
		&self,
		req: &LLMRequest,
		status: ::http::StatusCode,
		bytes: &Bytes,
	) -> Result<Bytes, AIError> {
		use gateway_llm::provider::response::{ErrorEncoding as E, ResponseDetails};
		match self.protocol().error_encoding(ResponseDetails {
			input_format: req.input_format,
			native_format: req.native_format,
			request_model: &req.request_model,
		})? {
			E::Passthrough => Ok(bytes.clone()),
			E::AnthropicToCompletions => conversion::messages::from_completions::translate_error(bytes),
			E::OpenAIToMessages => conversion::completions::from_messages::translate_error(bytes, status),
			E::GoogleToCompletions => conversion::completions::translate_google_error(bytes),
			E::GoogleToResponses => conversion::gemini::from_responses::translate_error(bytes),
			E::GoogleToMessages => conversion::messages::translate_google_error(bytes),
			E::Anthropic => conversion::messages::translate_anthropic_error(bytes, status),
			#[cfg(feature = "providers-aws")]
			E::Bedrock => conversion::bedrock::invalid_request_error(bytes),
			#[cfg(feature = "providers-aws")]
			E::BedrockToMessages => conversion::bedrock::from_messages::translate_error(bytes),
			#[cfg(not(feature = "providers-aws"))]
			_ => Err(AIError::UnsupportedConversion(
				"Bedrock is not compiled".into(),
			)),
		}
	}
}

#[cfg(feature = "gateway-llm")]
fn bedrock_tool_name_map(req: &LLMRequest) -> Option<&conversion::bedrock::BedrockToolNameMap> {
	match &req.provider_state {
		Some(ProviderState::Bedrock { tool_names }) => Some(tool_names.as_ref()),
		_ => None,
	}
}

#[cfg(feature = "gateway-llm")]
fn map_compression_error(e: http::compression::Error, headers: &::http::HeaderMap) -> AIError {
	match e {
		http::compression::Error::UnsupportedEncoding => AIError::UnsupportedEncoding(strng::new(
			headers
				.get(header::CONTENT_ENCODING)
				.and_then(|v| v.to_str().ok())
				.unwrap_or("unknown"),
		)),
		http::compression::Error::LimitExceeded => AIError::ResponseTooLarge,
		http::compression::Error::Io(e) => AIError::Encoding(axum_core::Error::new(e)),
		http::compression::Error::Body(e) => AIError::Encoding(e),
	}
}

#[cfg(feature = "gateway-llm")]
fn num_tokens_from_messages(
	model: &str,
	messages: &[SimpleChatCompletionMessage],
) -> Result<u64, AIError> {
	// NOTE: This estimator only accounts for textual content in normalized messages.
	// Non-text items in Responses inputs (e.g., tool calls, images, files) are ignored here.
	// Use provider token counting endpoints if you need precise totals for those cases.
	let tokenizer = get_tokenizer(model).unwrap_or(Tokenizer::Cl100kBase);
	if tokenizer != Tokenizer::Cl100kBase && tokenizer != Tokenizer::O200kBase {
		// Chat completion is only supported chat models
		return Err(AIError::UnsupportedModel);
	}
	let bpe = get_bpe_from_tokenizer(tokenizer);

	let tokens_per_message = 3;

	let mut num_tokens: u64 = 0;
	for message in messages {
		num_tokens += tokens_per_message;
		// Role is always 1 token
		num_tokens += 1;
		num_tokens += bpe
			.encode_with_special_tokens(message.content.as_str())
			.len() as u64;
	}
	num_tokens += 3; // every reply is primed with <|start|>assistant<|message|>
	Ok(num_tokens)
}

/// Tokenizers take about 200ms to load and are lazy loaded. This loads them on demand, outside the
/// request path
#[cfg(feature = "gateway-llm")]
pub fn preload_tokenizers() {
	let _ = tiktoken_rs::cl100k_base_singleton();
	let _ = tiktoken_rs::o200k_base_singleton();
}

#[cfg(feature = "gateway-llm")]
pub fn get_bpe_from_tokenizer<'a>(tokenizer: Tokenizer) -> &'a CoreBPE {
	match tokenizer {
		Tokenizer::O200kHarmony => tiktoken_rs::o200k_harmony_singleton(),
		Tokenizer::O200kBase => tiktoken_rs::o200k_base_singleton(),
		Tokenizer::Cl100kBase => tiktoken_rs::cl100k_base_singleton(),
		Tokenizer::R50kBase => tiktoken_rs::r50k_base_singleton(),
		Tokenizer::P50kBase => tiktoken_rs::r50k_base_singleton(),
		Tokenizer::P50kEdit => tiktoken_rs::r50k_base_singleton(),
		Tokenizer::Gpt2 => tiktoken_rs::r50k_base_singleton(),
	}
}

#[cfg(feature = "gateway-llm")]
pub(crate) fn logged_response_parsing(
	bytes: &[u8],
) -> impl FnOnce(serde_json::Error) -> AIError + '_ {
	|e| {
		const LOGGED_BODY_LIMIT: usize = 1024;
		let body = &bytes[..bytes.len().min(LOGGED_BODY_LIMIT)];
		warn!(
			error = %e,
			body = %String::from_utf8_lossy(body),
			"failed to parse response"
		);
		AIError::ResponseParsing(e)
	}
}

#[derive(thiserror::Error, Debug)]
pub enum AIError {
	#[error("missing field: {0}")]
	MissingField(Strng),
	#[error("model not found")]
	ModelNotFound,
	#[error("message not found")]
	MessageNotFound,
	#[error("response was missing fields")]
	IncompleteResponse,
	#[error("unknown model")]
	UnknownModel,
	#[error("todo: streaming is not currently supported for this provider")]
	StreamingUnsupported,
	#[error("unsupported model")]
	UnsupportedModel,
	#[error("unsupported content")]
	UnsupportedContent,
	#[error("unsupported conversion: {0}")]
	UnsupportedConversion(Strng),
	#[error("request was too large")]
	RequestTooLarge,
	#[error("response was too large")]
	ResponseTooLarge,
	#[error("prompt guard failed")]
	PromptWebhookError,
	#[error("failed to parse request: {0}")]
	RequestParsing(serde_json::Error),
	#[error("failed to marshal request: {0}")]
	RequestMarshal(serde_json::Error),
	#[error("failed to parse response: {0}")]
	ResponseParsing(serde_json::Error),
	#[error("invalid response: {0}")]
	InvalidResponse(Strng),
	#[error("failed to marshal response: {0}")]
	ResponseMarshal(serde_json::Error),
	#[error("unsupported content encoding: {0}")]
	UnsupportedEncoding(Strng),
	#[error("failed to encode response: {0}")]
	Encoding(axum_core::Error),
	#[error("error computing tokens")]
	JoinError(#[from] tokio::task::JoinError),
}

impl From<gateway_llm::WireError> for AIError {
	fn from(error: gateway_llm::WireError) -> Self {
		match error {
			gateway_llm::WireError::ResponseMarshal(error) => Self::ResponseMarshal(error),
			gateway_llm::WireError::IncompleteResponse => Self::IncompleteResponse,
			gateway_llm::WireError::UnsupportedConversion(message) => {
				Self::UnsupportedConversion(message)
			},
			gateway_llm::WireError::RequestMarshal(error) => Self::RequestMarshal(error),
			gateway_llm::WireError::ResponseParsing(error) => Self::ResponseParsing(error),
			gateway_llm::WireError::InvalidResponse(error) => Self::InvalidResponse(error),
			gateway_llm::WireError::MissingField(error) => Self::MissingField(error),
			gateway_llm::WireError::RequestParsing(error) => Self::RequestParsing(error),
		}
	}
}

#[cfg(feature = "gateway-llm")]
fn response_prompt_guard_headers(
	response_headers: &HeaderMap,
	request_traceparent: Option<&HeaderValue>,
) -> HeaderMap {
	let mut headers = response_headers.clone();
	if let Some(traceparent) = request_traceparent {
		headers.insert(http::x_headers::TRACEPARENT, traceparent.clone());
	}
	headers
}

#[cfg(feature = "gateway-llm")]
fn amend_tokens(rate_limit: store::LLMResponsePolicies, llm_resp: &LLMInfo, exec: Executor) {
	let input_mismatch = match (
		llm_resp.request.input_tokens,
		llm_resp.response.input_tokens,
	) {
		// Already counted 'req'
		(Some(req), Some(resp)) => (resp as i64) - (req as i64),
		// No request or response count... this is probably an issue.
		(_, None) => 0,
		// No request counted, so count the full response
		(_, Some(resp)) => resp as i64,
	};
	let response = llm_resp.response.output_tokens.unwrap_or_default();
	let tokens_to_remove = input_mismatch + (response as i64);

	for lrl in &rate_limit.local_rate_limit {
		lrl.amend_tokens(tokens_to_remove)
	}
	if let Some(rrl) = rate_limit.remote_rate_limit {
		rrl.amend_tokens(tokens_to_remove, &exec)
	}
}

#[cfg(feature = "gateway-llm")]
pub struct AmendOnDrop {
	log: AsyncLog<llm::LLMInfo>,
	pol: Option<LLMResponsePolicies>,
	req: Option<Arc<RequestSnapshot>>,
	catalog: Option<cost::CatalogReader>,
}

#[cfg(feature = "gateway-llm")]
impl AmendOnDrop {
	pub fn new(
		log: AsyncLog<llm::LLMInfo>,
		pol: LLMResponsePolicies,
		req: Option<Arc<RequestSnapshot>>,
		catalog: Option<Arc<cost::ModelCatalog>>,
	) -> Self {
		Self::with_catalog(log, pol, req, catalog.map(Into::into))
	}
	pub fn with_catalog(
		log: AsyncLog<llm::LLMInfo>,
		pol: LLMResponsePolicies,
		req: Option<Arc<RequestSnapshot>>,
		catalog: Option<cost::CatalogReader>,
	) -> Self {
		Self {
			log,
			pol: Some(pol),
			req,
			catalog,
		}
	}
	pub fn non_atomic_mutate(&self, f: impl FnOnce(&mut llm::LLMInfo)) {
		self.log.non_atomic_mutate(f);
	}
	pub fn report_rate_limit(&mut self) {
		if let Some(pol) = self.pol.take()
			&& (!pol.local_rate_limit.is_empty() || pol.remote_rate_limit.is_some())
		{
			self.log.non_atomic_mutate(|r| {
				let ctx = LLMContext::from_catalog(r.clone(), self.catalog.as_ref());
				let exec = cel::Executor::new_llm_rate_limit_streaming(self.req.as_deref(), &ctx);
				amend_tokens(pol, r, exec)
			});
		}
	}
}

#[cfg(feature = "gateway-llm")]
impl Drop for AmendOnDrop {
	fn drop(&mut self) {
		self.report_rate_limit();
	}
}

#[cfg(all(test, feature = "gateway-llm"))]
mod conversion_contract_tests;

#[cfg(all(test, feature = "gateway-llm"))]
mod provider_contract_tests;

#[cfg(all(test, feature = "gateway-llm"))]
mod streaming_contract_tests;

#[cfg(all(test, feature = "gateway-llm"))]
#[cfg(feature = "providers-aws")]
mod bedrock_stream_contract_tests;

#[cfg(all(test, feature = "gateway-llm"))]
#[cfg(feature = "providers-aws")]
mod transport_boundary_tests;

#[cfg(all(test, feature = "gateway-llm"))]
mod streaming_lifecycle_tests;
