//! LLM configuration and Host assembly, compiled only with the LLM capability.
use super::*;
use crate::llm::policy::{PromptCachingConfig, PromptGuard};
use crate::llm::{AIBackend, AIProvider, NamedAIProvider, anthropic, copilot, custom, openai};
use crate::types::agent::HeaderMatch;
use gateway_llm::routing::validate_model_pattern as validate_llm_model_pattern;
use itertools::Itertools;
use std::sync::OnceLock;
use std::time::{SystemTime, UNIX_EPOCH};

#[apply(schema_de!)]
pub struct LocalLLMConfig {
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub(super) port: Option<u16>,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub(super) tls: Option<LocalTLSServerConfig>,
	/// providers defines reusable LLM provider defaults that models may reference.
	#[serde(default, skip_serializing_if = "Vec::is_empty")]
	pub(super) providers: Vec<LocalLLMProvider>,
	/// models defines the set of models that can be served by this gateway. The model name refers to the
	/// model in the users request that is matched; the model sent to the actual LLM can be overridden
	/// on a per-model basis.
	pub(super) models: Vec<LocalLLMModels>,
	/// virtualModels defines a set of models that can be served from the gateway. The model name refers to the
	/// model in the users request that is matched. However, unlike the `models` field, virtual models will
	/// dynamically route to a specific model (configured in `models`) based on the configured logic.
	#[serde(
		default,
		rename = "virtualModels",
		skip_serializing_if = "Vec::is_empty"
	)]
	pub(super) virtual_models: Vec<LocalLLMVirtualModel>,
	/// policies defines policies for handling incoming requests, before a model is selected
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub(super) policies: Option<LocalLLMPolicy>,
}

#[apply(schema_de!)]
pub struct LocalLLMProvider {
	/// name is referenced from llm.models[].provider.reference.
	pub(super) name: Strng,
	/// params customizes parameters for outgoing requests that use this provider.
	#[serde(default)]
	pub(super) params: LocalLLMParams,
	/// provider of the LLM we are connecting to.
	pub(super) provider: LocalModelAIProvider,
	/// defaults defines provider-level policy defaults. Model-level policy fields override these.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub(super) defaults: Option<LocalLLMProviderDefaults>,
}

#[apply(schema_de!)]
#[derive(Default)]
pub struct LocalLLMProviderDefaults {
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub(super) defaults: Option<HashMap<String, serde_json::Value>>,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub(super) overrides: Option<HashMap<String, serde_json::Value>>,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub(super) transformation: Option<HashMap<String, Arc<cel::Expression>>>,
	#[serde(default)]
	pub(super) request_headers: Option<filters::HeaderModifier>,
	#[serde(default)]
	pub(super) response_headers: Option<filters::HeaderModifier>,
	#[serde(rename = "tls", alias = "backendTLS", default)]
	pub(super) backend_tls: Option<http::backendtls::LocalBackendTLS>,
	#[serde(default, deserialize_with = "de_backend_auth")]
	#[cfg_attr(feature = "schema", schemars(with = "Option<BackendAuthCompat>"))]
	pub(super) auth: Option<BackendAuth>,
	#[serde(default)]
	pub(super) health: Option<health::LocalHealthPolicy>,
	#[serde(default)]
	pub(super) backend_tunnel: Option<backend::Tunnel>,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub(super) prompt_caching: Option<PromptCachingConfig>,
}

#[apply(schema_de!)]
pub struct LocalLLMVirtualModel {
	/// name is the public model name clients request.
	pub(super) name: String,
	/// routing selects an existing LLM model backend for each request.
	pub(super) routing: LocalLLMVirtualModelRouting,
}

#[apply(schema_de!)]
pub struct LocalLLMVirtualModelRouting {
	/// weighted enables weight-based selection of the target model.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub(super) weighted: Option<LocalLLMWeightedRouting>,
	/// failover enables priority-based selection of the target model.
	/// Within a priority level, the best provider is selected by a composite score factoring in health
	/// and latency.
	/// If all models within a priority level are degraded, requests will move onto the next priority group.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub(super) failover: Option<LocalLLMFailoverRouting>,
	/// Conditional enables condition-based selection of the target model. Each condition is evaluated
	/// in order until the best match is found.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub(super) conditional: Option<LocalLLMConditionalRouting>,
}

#[apply(schema_de!)]
pub struct LocalLLMWeightedRouting {
	/// targets are existing model names or names matched by wildcard model entries.
	pub(super) targets: Vec<LocalLLMWeightedTarget>,
}

#[apply(schema_de!)]
pub struct LocalLLMWeightedTarget {
	/// model is resolved against llm.models using the same wildcard matching as client requests.
	pub(super) model: String,
	#[serde(default = "default_weight")]
	pub(super) weight: usize,
}

#[apply(schema_de!)]
pub struct LocalLLMFailoverRouting {
	/// targets are grouped by priority. Lower priority values are tried first.
	pub(super) targets: Vec<LocalLLMFailoverTarget>,
}

#[apply(schema_de!)]
pub struct LocalLLMFailoverTarget {
	/// model is resolved against llm.models using the same wildcard matching as client requests.
	pub(super) model: String,
	/// priority groups targets for failover. Lower values are preferred.
	pub(super) priority: usize,
}

#[apply(schema_de!)]
pub struct LocalLLMConditionalRouting {
	/// targets are evaluated in order. The first matching condition selects the model.
	pub(super) targets: Vec<LocalLLMConditionalTarget>,
}

#[apply(schema_de!)]
pub struct LocalLLMConditionalTarget {
	/// when must evaluate to true for this target to be selected. Omit only on the final fallback target.
	#[serde(default)]
	pub(super) when: Option<Arc<cel::Expression>>,
	/// model is resolved against llm.models using the same wildcard matching as client requests.
	pub(super) model: String,
}

/// System-level inference controls. This is intentionally an input model, not a second runtime
/// policy engine: during configuration normalization it is compiled into the LLM gateway's
/// established parameter, local-rate-limit, and endpoint-picker policies.
#[apply(schema_de!)]
#[derive(Default)]
pub struct LocalInferenceConfig {
	/// parameters are applied to every model in this AI system. Model-level settings remain more
	/// specific and take precedence over `defaults`; `overrides` always replaces client input.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub(super) parameters: Option<LocalInferenceParameters>,
	/// quota declares local request and LLM-token buckets without exposing the lower-level
	/// `localRateLimit` location or requiring callers to repeat the bucket type.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub(super) quota: Option<LocalInferenceQuota>,
	/// routing is the system-level endpoint-picker policy for every model backend.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub(super) routing: Option<crate::http::ext_proc::InferenceRouting>,
}

#[apply(schema_de!)]
pub struct LocalInferenceParameters {
	/// defaults are inserted only when the client did not set the request parameter.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub(super) defaults: Option<HashMap<String, serde_json::Value>>,
	/// overrides replace client-provided values and are appropriate for enforced ceilings or
	/// deployment-specific model settings.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub(super) overrides: Option<HashMap<String, serde_json::Value>>,
}

#[apply(schema_de!)]
pub struct LocalInferenceQuota {
	/// requests configures a local request-count token bucket for every LLM route.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub(super) requests: Option<crate::http::localratelimit::RateLimitSpec>,
	/// tokens configures a local LLM-token token bucket for every LLM route. Input tokens are
	/// charged before forwarding and response tokens are reconciled after the response.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub(super) tokens: Option<crate::http::localratelimit::RateLimitSpec>,
}

impl LocalInferenceQuota {
	fn into_rate_limits(self) -> anyhow::Result<Vec<crate::http::localratelimit::RateLimit>> {
		use crate::http::localratelimit::{RateLimit, RateLimitType};

		let mut limits = Vec::with_capacity(2);
		if let Some(mut requests) = self.requests {
			requests.limit_type = RateLimitType::Requests;
			limits.push(
				RateLimit::try_from(requests).context("aiSystems[].inference.quota.requests is invalid")?,
			);
		}
		if let Some(mut tokens) = self.tokens {
			tokens.limit_type = RateLimitType::Tokens;
			limits.push(
				RateLimit::try_from(tokens).context("aiSystems[].inference.quota.tokens is invalid")?,
			);
		}
		if limits.is_empty() {
			bail!("aiSystems[].inference.quota must configure requests and/or tokens");
		}
		Ok(limits)
	}
}

#[apply(schema_de!)]
pub struct LocalLLMModels {
	/// name is the name of the model we are matching from a users request. If params.model is set, that
	/// will be used in the request to the LLM provider. If not, the incoming model is used.
	pub(super) name: String,
	/// visibility controls whether clients can request this model directly (rather than only via a `virtualModel`).
	#[serde(
		default,
		skip_serializing_if = "llm::model_router::ModelVisibility::is_public"
	)]
	pub(super) visibility: llm::model_router::ModelVisibility,
	/// params customizes parameters for the outgoing request
	#[serde(default)]
	pub(super) params: LocalLLMParams,
	/// provider of the LLM we are connecting too
	pub(super) provider: LocalModelAIProvider,
	/// passthrough controls how requests are handled.
	/// By default, requests will be parsed and translated as needed.
	/// With passthrough, they will be unmodified and optionally inspected (with `detect`).
	/// In this mode, requests must be sent in the native format of the provider.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub(super) passthrough: Option<LocalLLMPassthrough>,
	/// authorization configures HTTP authorization rules for requests to this model.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub(super) authorization: Option<Authorization>,

	// Policies
	/// defaults allows setting default values for the request. If these are not present in the request body, they will be set.
	/// To override even when set, use `overrides`.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub(super) defaults: Option<HashMap<String, serde_json::Value>>,
	/// overrides allows setting values for the request, overriding any existing values
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub(super) overrides: Option<HashMap<String, serde_json::Value>>,
	/// transformation allows setting values from CEL expressions for the request, overriding any existing values.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub(super) transformation: Option<HashMap<String, Arc<cel::Expression>>>,
	/// requestHeaders modifies headers in requests to the LLM provider.
	#[serde(default)]
	pub(super) request_headers: Option<filters::HeaderModifier>,
	/// responseHeaders modifies headers in responses from the LLM provider.
	#[serde(default)]
	pub(super) response_headers: Option<filters::HeaderModifier>,
	/// tls configures TLS when connecting to the LLM provider.
	#[serde(rename = "tls", alias = "backendTLS", default)]
	pub(super) backend_tls: Option<http::backendtls::LocalBackendTLS>,
	/// auth configures authentication when connecting to the LLM provider.
	#[serde(default, deserialize_with = "de_backend_auth")]
	#[cfg_attr(feature = "schema", schemars(with = "Option<BackendAuthCompat>"))]
	pub(super) auth: Option<BackendAuth>,
	/// health configures outlier detection for this model backend.
	#[serde(default)]
	pub(super) health: Option<health::LocalHealthPolicy>,
	/// backendTunnel configures tunneling when connecting to the LLM provider.
	#[serde(default)]
	pub(super) backend_tunnel: Option<backend::Tunnel>,
	/// guardrails to apply to the request or response
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub(super) guardrails: Option<PromptGuard>,
	/// promptCaching configures cache point insertion for supported LLM providers.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub(super) prompt_caching: Option<PromptCachingConfig>,

	/// matches specifies the conditions under which this model should be used in addition to matching the model name.
	#[serde(default, skip_serializing_if = "Vec::is_empty")]
	pub(super) matches: Vec<LLMRouteMatch>,
	/// Per-model streaming resource limits, intersected with shared limits.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub(super) streaming_limits: Option<llm::policy::streaming_limits::StreamingLimits>,
}

#[apply(schema_de!)]
pub enum LocalLLMPassthrough {
	/// Pass through the request while extracting LLM telemetry and rate-limit inputs when possible.
	Detect,
	/// Pass through the request without interpreting it as LLM traffic.
	Opaque,
}

impl LocalLLMPassthrough {
	fn route_type(&self) -> crate::llm::RouteType {
		match self {
			LocalLLMPassthrough::Detect => crate::llm::RouteType::Detect,
			LocalLLMPassthrough::Opaque => crate::llm::RouteType::Passthrough,
		}
	}
}

#[apply(schema_de!)]
pub struct LLMRouteMatch {
	#[serde(default, skip_serializing_if = "Vec::is_empty")]
	pub headers: Vec<HeaderMatch>,
}

#[derive(Debug, Clone, serde::Deserialize)]
#[serde(rename_all = "lowercase", deny_unknown_fields)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub enum LocalModelAIProvider {
	#[serde(rename = "reference")]
	Reference(Strng),
	#[serde(rename = "openai", alias = "openAI")]
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
	// Providers below are synthetic conversions to custom with preconfigured defaults.
	Cohere,
	Ollama,
	Baseten,
	Cerebras,
	Deepinfra,
	Deepseek,
	Groq,
	Huggingface,
	Mistral,
	Openrouter,
	Togetherai,
	XAI,
	Fireworks,
}

#[apply(schema_de!)]
pub struct SecretFromFile(
	#[cfg_attr(feature = "schema", schemars(with = "FileOrInline"))]
	#[serde(
		serialize_with = "ser_redact",
		deserialize_with = "deser_key_from_file"
	)]
	SecretString,
);

#[apply(schema_de!)]
#[derive(Default)]
pub struct LocalLLMParams {
	/// The model to send to the provider.
	/// If unset, the same model will be used from the request.
	#[serde(default)]
	pub(super) model: Option<Strng>,
	/// An API key to attach to the request.
	/// If unset this will be automatically detected from the environment.
	#[serde(default)]
	pub(super) api_key: Option<SecretFromFile>,
	// For Bedorkc: The AWS region to use
	pub(super) aws_region: Option<Strng>,
	// For Vertex: The Google region to use
	pub(super) vertex_region: Option<Strng>,
	// For Vertex: The Google project ID to use
	pub(super) vertex_project: Option<Strng>,
	/// For Azure: the resource name of the deployment
	pub(super) azure_resource_name: Option<Strng>,
	/// For Azure: the type of Azure endpoint (openAI or foundry)
	pub(super) azure_resource_type: Option<crate::llm::azure::AzureResourceType>,
	/// For Azure: the API version to use
	pub(super) azure_api_version: Option<Strng>,
	/// For Azure: the Foundry project name (required for foundry resource type)
	pub(super) azure_project_name: Option<Strng>,
	/// Base URL for the upstream provider. Expands to hostOverride, pathPrefix, and tls for https URLs.
	#[serde(default)]
	pub(super) base_url: Option<Strng>,
	/// Override the upstream host for this provider.
	#[serde(default)]
	#[deprecated(note = "use baseUrl instead")]
	pub(super) host_override: Option<Target>,
	/// Override the upstream path for this provider.
	#[serde(default)]
	#[deprecated(note = "use baseUrl instead")]
	pub(super) path_override: Option<Strng>,
	/// Override the default base path prefix for this provider.
	#[serde(default)]
	#[deprecated(note = "use baseUrl instead")]
	pub(super) path_prefix: Option<Strng>,
	/// Whether to tokenize the request before forwarding it upstream.
	#[serde(default)]
	pub(super) tokenize: bool,
}

impl LocalLLMModels {
	#[allow(deprecated)]
	fn apply_provider_reference(&mut self, provider: &LocalLLMProvider) -> anyhow::Result<()> {
		let LocalLLMParams {
			model: model_override,
			api_key: None,
			aws_region: None,
			vertex_region: None,
			vertex_project: None,
			azure_resource_name: None,
			azure_resource_type: None,
			azure_api_version: None,
			azure_project_name: None,
			base_url: None,
			host_override: None,
			path_override: None,
			path_prefix: None,
			tokenize: false,
		} = std::mem::take(&mut self.params)
		else {
			bail!(
				"model {} references provider {} and can only set params.model",
				self.name,
				provider.name
			);
		};
		if matches!(&provider.provider, LocalModelAIProvider::Reference(_)) {
			bail!(
				"llm.providers.{} cannot reference another provider",
				provider.name
			);
		}
		self.params = provider.params.clone();
		if let Some(model_override) = model_override {
			self.params.model = Some(model_override);
		}
		self.provider = provider.provider.clone();
		if let Some(defaults) = provider.defaults.clone() {
			self.defaults = merge_optional_maps(defaults.defaults, self.defaults.take());
			self.overrides = merge_optional_maps(defaults.overrides, self.overrides.take());
			self.transformation =
				merge_optional_maps(defaults.transformation, self.transformation.take());
			self.request_headers = self.request_headers.take().or(defaults.request_headers);
			self.response_headers = self.response_headers.take().or(defaults.response_headers);
			self.backend_tls = self.backend_tls.take().or(defaults.backend_tls);
			self.auth = self.auth.take().or(defaults.auth);
			self.health = self.health.take().or(defaults.health);
			self.backend_tunnel = self.backend_tunnel.take().or(defaults.backend_tunnel);
			self.prompt_caching = self.prompt_caching.take().or(defaults.prompt_caching);
		}
		Ok(())
	}

	#[allow(deprecated)]
	fn apply_provider_defaults(&mut self) {
		if self.params.base_url.is_some()
			|| self.params.host_override.is_some()
			|| self.params.path_override.is_some()
		{
			return;
		}
		match &self.provider {
			LocalModelAIProvider::Cohere => {
				self
					.params
					.base_url
					.get_or_insert_with(|| strng::new("https://api.cohere.ai"));
			},
			LocalModelAIProvider::Ollama => {
				self
					.params
					.base_url
					.get_or_insert_with(|| strng::new("http://localhost:11434/v1"));
			},
			LocalModelAIProvider::Baseten => {
				self
					.params
					.base_url
					.get_or_insert_with(|| strng::new("https://inference.baseten.co/v1"));
			},
			LocalModelAIProvider::Cerebras => {
				self
					.params
					.base_url
					.get_or_insert_with(|| strng::new("https://api.cerebras.ai/v1"));
			},
			LocalModelAIProvider::Deepinfra => {
				self
					.params
					.base_url
					.get_or_insert_with(|| strng::new("https://api.deepinfra.com/v1/openai"));
			},
			LocalModelAIProvider::Deepseek => {
				self
					.params
					.base_url
					.get_or_insert_with(|| strng::new("https://api.deepseek.com/v1"));
			},
			LocalModelAIProvider::Groq => {
				self
					.params
					.base_url
					.get_or_insert_with(|| strng::new("https://api.groq.com/openai/v1"));
			},
			LocalModelAIProvider::Huggingface => {
				self
					.params
					.base_url
					.get_or_insert_with(|| strng::new("https://router.huggingface.co/v1"));
			},
			LocalModelAIProvider::Mistral => {
				self
					.params
					.base_url
					.get_or_insert_with(|| strng::new("https://api.mistral.ai/v1"));
			},
			LocalModelAIProvider::Openrouter => {
				self
					.params
					.base_url
					.get_or_insert_with(|| strng::new("https://openrouter.ai/api/v1"));
			},
			LocalModelAIProvider::Togetherai => {
				self
					.params
					.base_url
					.get_or_insert_with(|| strng::new("https://api.together.xyz/v1"));
			},
			LocalModelAIProvider::XAI => {
				self
					.params
					.base_url
					.get_or_insert_with(|| strng::new("https://api.x.ai/v1"));
			},
			LocalModelAIProvider::Fireworks => {
				self
					.params
					.base_url
					.get_or_insert_with(|| strng::new("https://api.fireworks.ai/inference/v1"));
			},
			_ => {},
		}
	}

	#[allow(deprecated)]
	fn apply_base_url(&mut self) -> anyhow::Result<()> {
		let Some(base_url) = self.params.base_url.as_deref() else {
			return Ok(());
		};
		let url = url::Url::parse(base_url)
			.with_context(|| format!("invalid params.baseUrl for model {}", self.name))?;
		let port = url.port_or_known_default().with_context(|| {
			format!(
				"params.baseUrl for model {} must use http or https, or include an explicit port",
				self.name
			)
		})?;
		let host = url
			.host_str()
			.with_context(|| format!("params.baseUrl for model {} must include a host", self.name))?;
		self
			.params
			.host_override
			.get_or_insert_with(|| (host, port).into());
		let path = url.path().trim_end_matches('/');
		if !path.is_empty() && self.params.path_override.is_none() {
			self
				.params
				.path_prefix
				.get_or_insert_with(|| strng::new(path));
		}
		if url.scheme() == "https" && self.backend_tls.is_none() {
			self.backend_tls = Some(http::backendtls::LocalBackendTLS::default());
		}
		Ok(())
	}
}

pub(super) fn merge_optional_maps<T>(
	base: Option<HashMap<String, T>>,
	overrides: Option<HashMap<String, T>>,
) -> Option<HashMap<String, T>> {
	match (base, overrides) {
		(None, None) => None,
		(Some(base), None) => Some(base),
		(None, Some(overrides)) => Some(overrides),
		(Some(mut base), Some(overrides)) => {
			base.extend(overrides);
			Some(base)
		},
	}
}

/// Compile the system-centric inference input model into the established LLM runtime policy
/// model. Keeping this translation at normalization time makes the new layout non-breaking:
/// `llm.policies`, model-level parameter policy, and `aiSystems[].inference` all use the same
/// execution path.
pub(super) fn compile_ai_system_inference(
	system_name: &str,
	mut llm: LocalLLMConfig,
	inference: Option<LocalInferenceConfig>,
) -> anyhow::Result<LocalLLMConfig> {
	let Some(LocalInferenceConfig {
		parameters,
		quota,
		routing,
	}) = inference
	else {
		return Ok(llm);
	};

	if let Some(LocalInferenceParameters {
		defaults,
		overrides,
	}) = parameters
	{
		for model in &mut llm.models {
			model.defaults = merge_optional_maps(defaults.clone(), model.defaults.take());
			model.overrides = merge_optional_maps(overrides.clone(), model.overrides.take());
		}
	}

	if quota.is_some() || routing.is_some() {
		let policies = llm.policies.get_or_insert_with(Default::default);
		if let Some(quota) = quota {
			policies.local_rate_limit.extend(quota.into_rate_limits()?);
		}
		if let Some(routing) = routing {
			if policies.inference_routing.is_some() {
				bail!(
					"aiSystems['{system_name}'] configures inference.routing and llm.policies.inferenceRouting; configure routing in only one location"
				);
			}
			policies.inference_routing = Some(routing);
		}
	}

	Ok(llm)
}

pub(super) fn custom_provider_format(
	format: custom::ProviderFormat,
	path: Option<&'static str>,
) -> custom::ProviderFormatConfig {
	custom::ProviderFormatConfig {
		format,
		path: path.map(strng::new),
	}
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[cfg_attr(feature = "schema", schemars(untagged, deny_unknown_fields))]
#[allow(clippy::large_enum_variant)] // Size is not sensitive for local config
pub enum LocalAIBackend {
	Provider(LocalNamedAIProvider),
	Groups { groups: Vec<LocalAIProviders> },
}

// Custom impl to avoid terrible 'not match any variant of untagged' errors.
impl<'de> Deserialize<'de> for LocalAIBackend {
	fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
	where
		D: Deserializer<'de>,
	{
		serde_untagged::UntaggedEnumVisitor::new()
			.map(|map| {
				let v: serde_json::Value = map.deserialize()?;

				if let serde_json::Value::Object(m) = &v
					&& m.len() == 1
					&& let Some(g) = m.get("groups")
				{
					Ok(LocalAIBackend::Groups {
						groups: Vec::<LocalAIProviders>::deserialize(g).map_err(serde::de::Error::custom)?,
					})
				} else {
					Ok(LocalAIBackend::Provider(
						LocalNamedAIProvider::deserialize(&v).map_err(serde::de::Error::custom)?,
					))
				}
			})
			.deserialize(deserializer)
	}
}

#[apply(schema_de!)]
pub struct LocalAIProviders {
	pub(super) providers: Vec<LocalNamedAIProvider>,
}

#[apply(schema_de!)]
pub struct LocalNamedAIProvider {
	pub name: Strng,
	pub provider: AIProvider,
	/// Override the upstream host for this provider.
	pub host_override: Option<Target>,
	/// Override the upstream path for this provider.
	pub path_override: Option<Strng>,
	/// Override the default base path prefix for this provider.
	pub path_prefix: Option<Strng>,
	/// Whether to tokenize on the request flow. This enables us to do more accurate rate limits,
	/// since we know (part of) the cost of the request upfront.
	/// This comes with the cost of an expensive operation.
	#[serde(default)]
	pub tokenize: bool,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub policies: Option<LocalBackendPolicies>,
}

impl LocalAIBackend {
	pub async fn translate(
		self,
		resources: &crate::resource_manager::ResourceFetcher,
	) -> anyhow::Result<AIBackend> {
		let providers = match self {
			LocalAIBackend::Provider(p) => {
				vec![vec![p]]
			},
			LocalAIBackend::Groups { groups } => groups.into_iter().map(|g| g.providers).collect_vec(),
		};
		let mut ep_groups = vec![];
		for g in providers {
			let mut group = vec![];
			for p in g {
				validate_inference_routing_scope(
					p.policies.as_ref(),
					InferenceRoutingScope::AIProviderPolicies,
				)?;
				let policies = match p.policies {
					Some(p) => p.translate(resources).await?,
					None => Vec::new(),
				};
				group.push((
					p.name.clone(),
					NamedAIProvider {
						name: p.name,
						provider: p.provider,
						provider_backend: None,
						host_override: p.host_override,
						path_override: p.path_override,
						path_prefix: p.path_prefix,
						tokenize: p.tokenize,
						inline_policies: policies,
					},
				));
			}
			ep_groups.push(group);
		}
		let es = types::loadbalancer::EndpointSet::new(ep_groups);
		Ok(AIBackend { providers: es })
	}
}

#[apply(schema_de!)]
#[derive(Default)]
pub(super) struct LocalLLMPolicy {
	#[serde(flatten)]
	pub(super) gateway: LocalGatewayPolicy,
	/// Guardrails to apply to every configured model.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub(super) guardrails: Option<PromptGuard>,
	/// Local rate limits for incoming requests.
	#[serde(default)]
	pub(super) local_rate_limit: Vec<crate::http::localratelimit::RateLimit>,
	/// Remote rate limit checks for incoming requests.
	#[serde(default)]
	pub(super) remote_rate_limit: Option<crate::http::remoteratelimit::RemoteRateLimit>,
	/// Select an LLM inference destination through an endpoint picker before contacting the provider.
	#[serde(default)]
	pub(super) inference_routing: Option<crate::http::ext_proc::InferenceRouting>,
	/// Shared streaming limits applied to every model.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub(super) streaming_limits: Option<llm::policy::streaming_limits::StreamingLimits>,
}

pub(super) fn validate_llm_routing_capability(
	llm: &LocalLLMConfig,
	location: &str,
	profile: crate::capabilities::GatewayProfile,
) -> anyhow::Result<()> {
	if llm
		.policies
		.as_ref()
		.is_some_and(|policies| policies.inference_routing.is_some())
	{
		require_gateway_capability(
			profile,
			crate::capabilities::GatewayCapability::InferenceRouting,
			&format!("{location}.policies.inferenceRouting"),
		)?;
	}
	Ok(())
}

static STARTUP_TIMESTAMP: OnceLock<u64> = OnceLock::new();

pub(super) fn merge_prompt_guards(
	shared: Option<PromptGuard>,
	model: Option<PromptGuard>,
) -> Option<PromptGuard> {
	match (shared, model) {
		(None, None) => None,
		(Some(guardrails), None) | (None, Some(guardrails)) => Some(guardrails),
		(Some(mut shared), Some(model)) => {
			if model.streaming.is_enabled() {
				shared.streaming = model.streaming;
			}
			shared.request.extend(model.request);
			shared.response.extend(model.response);
			Some(shared)
		},
	}
}

#[derive(Clone)]
pub(super) struct ResolvedLLMModelTarget {
	pub(super) name: String,
	pub(super) provider: NamedAIProvider,
	pub(super) inline_policies: Vec<BackendTrafficPolicy>,
}

pub(super) struct LocalLLMModelRegistry {
	pub(super) models: Vec<LocalLLMModels>,
	pub(super) virtual_models: Vec<LocalLLMVirtualModel>,
}

pub(super) struct ResolvedLLMModelRegistry {
	pub(super) models: Vec<ResolvedLLMModelTarget>,
}

pub(super) enum LocalLLMVirtualRoutingStrategy<'a> {
	Weighted(&'a LocalLLMWeightedRouting),
	Failover(&'a LocalLLMFailoverRouting),
	Conditional(&'a LocalLLMConditionalRouting),
}

pub(super) fn llm_model_matches(pattern: &str, model: &str) -> anyhow::Result<bool> {
	validate_llm_model_pattern(pattern)?;
	Ok(gateway_llm::routing::model_name_matches(pattern, model))
}

impl<'a> LocalLLMVirtualRoutingStrategy<'a> {
	fn targets(&self) -> Box<dyn Iterator<Item = &'a str> + 'a> {
		match self {
			Self::Weighted(weighted) => {
				Box::new(weighted.targets.iter().map(|target| target.model.as_str()))
			},
			Self::Failover(failover) => {
				Box::new(failover.targets.iter().map(|target| target.model.as_str()))
			},
			Self::Conditional(conditional) => Box::new(
				conditional
					.targets
					.iter()
					.map(|target| target.model.as_str()),
			),
		}
	}
}

impl LocalLLMVirtualModel {
	fn routing_strategy(&self) -> anyhow::Result<LocalLLMVirtualRoutingStrategy<'_>> {
		let strategy_count = usize::from(self.routing.weighted.is_some())
			+ usize::from(self.routing.failover.is_some())
			+ usize::from(self.routing.conditional.is_some());
		if strategy_count != 1 {
			bail!(
				"virtual model {} must specify exactly one routing strategy",
				self.name
			);
		}
		if let Some(conditional) = self.routing.conditional.as_ref() {
			if conditional.targets.is_empty() {
				bail!(
					"virtual model {} must specify at least one conditional target",
					self.name
				);
			}
			if let Some(unconditional_idx) = conditional
				.targets
				.iter()
				.position(|target| target.when.is_none())
				&& unconditional_idx + 1 != conditional.targets.len()
			{
				bail!(
					"virtual model {} conditional fallback target must be last",
					self.name
				);
			}
			return Ok(LocalLLMVirtualRoutingStrategy::Conditional(conditional));
		}
		if let Some(weighted) = self.routing.weighted.as_ref() {
			if weighted.targets.is_empty() {
				bail!(
					"virtual model {} must specify at least one weighted target",
					self.name
				);
			}
			return Ok(LocalLLMVirtualRoutingStrategy::Weighted(weighted));
		}
		let failover = self
			.routing
			.failover
			.as_ref()
			.expect("strategy count checked");
		if failover.targets.is_empty() {
			bail!(
				"virtual model {} must specify at least one failover target",
				self.name
			);
		}
		Ok(LocalLLMVirtualRoutingStrategy::Failover(failover))
	}
}

impl LocalLLMModelRegistry {
	fn new(
		models: Vec<LocalLLMModels>,
		virtual_models: Vec<LocalLLMVirtualModel>,
	) -> anyhow::Result<Self> {
		let registry = Self {
			models,
			virtual_models,
		};
		registry.validate_model_patterns()?;
		registry.validate_virtual_models()?;
		Ok(registry)
	}

	fn validate_model_patterns(&self) -> anyhow::Result<()> {
		for model in &self.models {
			validate_llm_model_pattern(&model.name)?;
		}
		Ok(())
	}

	fn model_matches(&self, target: &str) -> anyhow::Result<bool> {
		for model in &self.models {
			if llm_model_matches(&model.name, target)? {
				return Ok(true);
			}
		}
		Ok(false)
	}

	fn validate_virtual_models(&self) -> anyhow::Result<()> {
		for virtual_model in &self.virtual_models {
			for target in virtual_model.routing_strategy()?.targets() {
				if !self.model_matches(target)? {
					bail!("virtual model target {target} does not match any llm.models entry");
				}
			}
		}
		Ok(())
	}

	fn ordered_models(&self) -> Vec<(usize, LocalLLMModels)> {
		gateway_llm::routing::ordered_model_indices(self.models.iter().map(|model| model.name.as_str()))
			.into_iter()
			.map(|index| (index, self.models[index].clone()))
			.collect()
	}

	fn into_virtual_models(self) -> Vec<LocalLLMVirtualModel> {
		self.virtual_models
	}
}

impl ResolvedLLMModelRegistry {
	fn new() -> Self {
		Self { models: Vec::new() }
	}

	fn push(&mut self, model: ResolvedLLMModelTarget) {
		self.models.push(model);
	}

	fn resolve(&self, target: &str) -> anyhow::Result<ResolvedLLMModelTarget> {
		for model in &self.models {
			if llm_model_matches(&model.name, target)? {
				return Ok(model.clone());
			}
		}
		bail!("virtual model target {target} does not match any llm.models entry")
	}
}

pub(super) fn llm_route_types(
	passthrough: Option<&LocalLLMPassthrough>,
) -> Vec<(Strng, crate::llm::RouteType)> {
	if let Some(passthrough) = passthrough {
		return vec![(strng::new("*"), passthrough.route_type())];
	}
	vec![
		(
			strng::new("/v1/chat/completions"),
			crate::llm::RouteType::Completions,
		),
		(strng::new("/v1/messages"), crate::llm::RouteType::Messages),
		// TODO: we could do this to support vertex calls. But we would need to extract the model name from the URL
		(strng::new(":rawPredict"), crate::llm::RouteType::Messages),
		(
			strng::new(":streamRawPredict"),
			crate::llm::RouteType::Messages,
		),
		(
			strng::new("/v1/responses"),
			crate::llm::RouteType::Responses,
		),
		(
			strng::new("/v1/images/generations"),
			crate::llm::RouteType::Detect,
		),
		(
			strng::new("/v1/images/edits"),
			crate::llm::RouteType::Detect,
		),
		(
			strng::new("/v1/images/variations"),
			crate::llm::RouteType::Detect,
		),
		(
			strng::new("/v1/responses/compact"),
			crate::llm::RouteType::Detect,
		),
		(
			strng::new("/v1/embeddings"),
			crate::llm::RouteType::Embeddings,
		),
		(strng::new("/v1/rerank"), crate::llm::RouteType::Rerank),
		(strng::new("/v2/rerank"), crate::llm::RouteType::Rerank),
		(strng::new("*"), crate::llm::RouteType::Passthrough),
	]
}

pub(super) fn ensure_ai_provider_model(provider: &mut AIProvider, model: &str) {
	let model = || Some(strng::new(model));
	match provider {
		AIProvider::Anthropic(p) => p.model = p.model.clone().or_else(model),
		AIProvider::OpenAI(p) => p.model = p.model.clone().or_else(model),
		AIProvider::Copilot(p) => p.model = p.model.clone().or_else(model),
		AIProvider::Gemini(p) => p.model = p.model.clone().or_else(model),
		AIProvider::Custom(p) => p.model = p.model.clone().or_else(model),
		#[cfg(feature = "providers-gcp")]
		AIProvider::Vertex(p) => p.model = p.model.clone().or_else(model),
		#[cfg(feature = "providers-aws")]
		AIProvider::Bedrock(p) => p.model = p.model.clone().or_else(model),
		#[cfg(feature = "providers-azure")]
		AIProvider::Azure(p) => p.model = p.model.clone().or_else(model),
	}
}

#[allow(deprecated)]
pub(super) async fn convert_llm_config(
	resources: &crate::resource_manager::ResourceFetcher,
	config: &crate::Config,
	gateway: ListenerTarget,
	llm_config: LocalLLMConfig,
	gateway_id: &str,
) -> anyhow::Result<(
	Bind,
	Vec<Route>,
	Vec<TargetedPolicy>,
	Vec<BackendWithPolicies>,
)> {
	let LocalLLMConfig {
		port,
		tls,
		providers,
		models,
		virtual_models,
		policies,
	} = llm_config;
	let port = port.unwrap_or(DEFAULT_LLM_PORT);
	let tls = match tls {
		Some(tls) => Some(
			tls
				.into_server_tls_config_with_resources(config.dynamic_ca_cert_cache.clone(), resources)
				.await?,
		),
		None => None,
	};
	let llm_registry = LocalLLMModelRegistry::new(models, virtual_models)?;

	let mut all_policies = vec![];
	let mut all_backends = vec![];
	let mut routes = Vec::new();
	let mut shared_prompt_guard = None;
	let mut shared_streaming_limits = None;
	let mut shared_inference_routing = None;
	let (listener_gateway_policies, listener_route_policies) = if let Some(pol) = policies {
		let LocalLLMPolicy {
			streaming_limits,
			gateway,
			guardrails,
			local_rate_limit,
			remote_rate_limit,
			inference_routing,
		} = pol;
		// Guardrail is per-model config, but we let users configure it top level. Pull it out here.
		shared_prompt_guard = guardrails;
		shared_streaming_limits = streaming_limits;
		shared_inference_routing = inference_routing;
		// Rate limit is applied per-route as well. Resolve them here.
		let route_policies = split_policies(
			resources,
			FilterOrPolicy {
				local_rate_limit: (!local_rate_limit.is_empty())
					.then_some(LocalRateLimitPolicy::Explicit(local_rate_limit)),
				remote_rate_limit: remote_rate_limit.map(LocalExplicitOrConditional::Explicit),
				..Default::default()
			},
			None,
		)
		.await?;

		// Rest of policies are PreRoute gateway policies; resolve these to our listener.
		let gateway_policies: FilterOrPolicy = gateway.into();
		let gateway_policies = split_policies(
			resources,
			gateway_policies,
			config.as_policy_context(&format!("listener/{gateway_id}")),
		)
		.await?;
		(
			gateway_policies.route_policies,
			route_policies.route_policies,
		)
	} else {
		(vec![], vec![])
	};

	// Get static startup unix timestamp

	let startup_timestamp = *STARTUP_TIMESTAMP.get_or_init(|| {
		SystemTime::now()
			.duration_since(UNIX_EPOCH)
			.unwrap()
			.as_secs()
	});

	let ordered_models = llm_registry.ordered_models();
	let mut resolved_models = ResolvedLLMModelRegistry::new();
	let mut router_models = Vec::new();
	let mut providers_by_name = HashMap::new();
	for provider in providers {
		if providers_by_name
			.insert(provider.name.clone(), provider)
			.is_some()
		{
			bail!("llm.providers contains duplicate provider names");
		}
	}

	// Create routes and backends for each model
	for (idx, (_, model_config)) in ordered_models.into_iter().enumerate() {
		let mut model_config = model_config;
		if let LocalModelAIProvider::Reference(reference) = &model_config.provider {
			let provider = providers_by_name.get(reference).with_context(|| {
				format!(
					"model {} references unknown provider {}",
					model_config.name, reference
				)
			})?;
			model_config.apply_provider_reference(provider)?;
		}
		model_config.apply_provider_defaults();
		model_config.apply_base_url()?;
		let model_name = strng::new(&model_config.name);
		// Index is needed because the same name can be used with different match criteria
		let backend_key = strng::format!("{gateway_id}:model:{}:{idx}", model_config.name);
		let p = model_config.params.clone();
		let model = p.model;
		let llm_routes = llm_route_types(model_config.passthrough.as_ref());

		// Use provider from config and set the model name
		let provider = match &model_config.provider {
			LocalModelAIProvider::Reference(reference) => {
				bail!(
					"model {} has unresolved provider reference {}",
					model_config.name,
					reference
				)
			},
			LocalModelAIProvider::Anthropic => AIProvider::Anthropic(anthropic::Provider { model }),
			LocalModelAIProvider::OpenAI => AIProvider::OpenAI(openai::Provider { model }),
			LocalModelAIProvider::Copilot => AIProvider::Copilot(copilot::Provider { model }),
			LocalModelAIProvider::Gemini => AIProvider::Gemini(crate::llm::gemini::Provider { model }),
			LocalModelAIProvider::Custom(custom_provider) => {
				if custom_provider.formats.is_empty() {
					bail!(
						"custom provider for model {} must specify at least one format",
						model_config.name
					);
				}
				if p.host_override.is_none() {
					bail!(
						"custom provider for model {} requires params.baseUrl",
						model_config.name
					);
				}
				AIProvider::Custom(crate::llm::custom::Provider {
					model: model.or_else(|| custom_provider.model.clone()),
					..custom_provider.clone()
				})
			},
			LocalModelAIProvider::Cohere => AIProvider::Custom(custom::Provider {
				model,
				provider_override: Some(strng::literal!("cohere")),
				formats: vec![
					custom_provider_format(
						custom::ProviderFormat::Completions,
						Some("/compatibility/v1/chat/completions"),
					),
					custom_provider_format(
						custom::ProviderFormat::Embeddings,
						Some("/compatibility/v1/embeddings"),
					),
					custom_provider_format(custom::ProviderFormat::Rerank, Some("/v2/rerank")),
				],
			}),
			LocalModelAIProvider::Ollama => AIProvider::Custom(custom::Provider {
				model,
				provider_override: Some(strng::literal!("ollama")),
				formats: vec![
					custom_provider_format(custom::ProviderFormat::Completions, None),
					custom_provider_format(custom::ProviderFormat::Responses, None),
					custom_provider_format(custom::ProviderFormat::Embeddings, None),
				],
			}),
			LocalModelAIProvider::Baseten => AIProvider::Custom(custom::Provider {
				model,
				provider_override: Some(strng::literal!("baseten")),
				formats: vec![
					custom_provider_format(custom::ProviderFormat::Completions, None),
					custom_provider_format(custom::ProviderFormat::Messages, None),
				],
			}),
			LocalModelAIProvider::Cerebras => AIProvider::Custom(custom::Provider {
				model,
				provider_override: Some(strng::literal!("cerebras")),
				formats: vec![custom_provider_format(
					custom::ProviderFormat::Completions,
					None,
				)],
			}),
			LocalModelAIProvider::Deepinfra => AIProvider::Custom(custom::Provider {
				model,
				provider_override: Some(strng::literal!("deepinfra")),
				formats: vec![
					custom_provider_format(custom::ProviderFormat::Completions, None),
					custom_provider_format(
						custom::ProviderFormat::Messages,
						Some("/anthropic/v1/messages"),
					),
					custom_provider_format(custom::ProviderFormat::Embeddings, None),
				],
			}),
			LocalModelAIProvider::Deepseek => AIProvider::Custom(custom::Provider {
				model,
				provider_override: Some(strng::literal!("deepseek")),
				formats: vec![
					custom_provider_format(custom::ProviderFormat::Completions, None),
					custom_provider_format(
						custom::ProviderFormat::Messages,
						Some("/anthropic/v1/messages"),
					),
				],
			}),
			LocalModelAIProvider::Groq => AIProvider::Custom(custom::Provider {
				model,
				provider_override: Some(strng::literal!("groq")),
				formats: vec![
					custom_provider_format(custom::ProviderFormat::Completions, None),
					custom_provider_format(custom::ProviderFormat::Responses, None),
				],
			}),
			LocalModelAIProvider::Huggingface => AIProvider::Custom(custom::Provider {
				model,
				provider_override: Some(strng::literal!("huggingface")),
				formats: vec![
					custom_provider_format(custom::ProviderFormat::Completions, None),
					custom_provider_format(custom::ProviderFormat::Responses, None),
				],
			}),
			LocalModelAIProvider::Mistral => AIProvider::Custom(custom::Provider {
				model,
				provider_override: Some(strng::literal!("mistral")),
				formats: vec![
					custom_provider_format(custom::ProviderFormat::Completions, None),
					custom_provider_format(custom::ProviderFormat::Embeddings, None),
				],
			}),
			LocalModelAIProvider::Openrouter => AIProvider::Custom(custom::Provider {
				model,
				provider_override: Some(strng::literal!("openrouter")),
				formats: vec![
					custom_provider_format(custom::ProviderFormat::Completions, None),
					custom_provider_format(custom::ProviderFormat::Messages, None),
					custom_provider_format(custom::ProviderFormat::Responses, None),
					custom_provider_format(custom::ProviderFormat::Embeddings, None),
					custom_provider_format(custom::ProviderFormat::Rerank, None),
				],
			}),
			LocalModelAIProvider::Togetherai => AIProvider::Custom(custom::Provider {
				model,
				provider_override: Some(strng::literal!("togetherai")),
				formats: vec![
					custom_provider_format(custom::ProviderFormat::Completions, None),
					custom_provider_format(custom::ProviderFormat::Embeddings, None),
					custom_provider_format(custom::ProviderFormat::Rerank, None),
				],
			}),
			LocalModelAIProvider::XAI => AIProvider::Custom(custom::Provider {
				model,
				provider_override: Some(strng::literal!("xai")),
				formats: vec![
					custom_provider_format(custom::ProviderFormat::Completions, None),
					custom_provider_format(custom::ProviderFormat::Responses, None),
					custom_provider_format(custom::ProviderFormat::Realtime, None),
				],
			}),
			LocalModelAIProvider::Fireworks => AIProvider::Custom(custom::Provider {
				model,
				provider_override: Some(strng::literal!("fireworks")),
				formats: vec![
					custom_provider_format(custom::ProviderFormat::Completions, None),
					custom_provider_format(custom::ProviderFormat::Messages, None),
					custom_provider_format(custom::ProviderFormat::Responses, None),
					custom_provider_format(custom::ProviderFormat::Embeddings, None),
					custom_provider_format(custom::ProviderFormat::Rerank, None),
				],
			}),
			#[cfg(feature = "providers-gcp")]
			LocalModelAIProvider::Vertex => AIProvider::Vertex(crate::llm::vertex::Provider {
				model,
				region: p.vertex_region,
				project_id: p.vertex_project.context("vertex requires vertex_project")?,
			}),
			#[cfg(feature = "providers-aws")]
			LocalModelAIProvider::Bedrock => AIProvider::Bedrock(crate::llm::bedrock::Provider {
				model,
				region: p.aws_region.context("bedrock requires aws_region")?,
				guardrail_identifier: None,
				guardrail_version: None,
				source_credentials_cache: Default::default(),
				assume_role_cache: Default::default(),
			}),
			#[cfg(feature = "providers-azure")]
			LocalModelAIProvider::Azure => AIProvider::Azure(crate::llm::azure::Provider {
				model,
				resource_name: p
					.azure_resource_name
					.context("azure requires azureResourceName")?,
				resource_type: p
					.azure_resource_type
					.context("azure requires azureResourceType")?,
				api_version: p.azure_api_version,
				project_name: p.azure_project_name,
				cached_cred: Default::default(),
			}),
		};

		// Create backend auth policy
		let mut pols = vec![];
		if let Some(key) = p.api_key.as_ref() {
			let backend_auth = BackendAuth::Key {
				value: key.0.clone(),
				location: None,
			};
			pols.push(BackendTrafficPolicy::BackendAuth(backend_auth));
		}

		// Create AI backend
		let named_provider = NamedAIProvider {
			name: model_name.clone(),
			provider,
			provider_backend: None,
			host_override: p.host_override,
			path_override: p.path_override,
			path_prefix: p.path_prefix,
			tokenize: p.tokenize,
			inline_policies: pols,
		};
		let resolved_provider = named_provider.clone();

		let ai_backend = AIBackend {
			providers: crate::types::loadbalancer::EndpointSet::new(vec![vec![(
				model_name.clone(),
				named_provider,
			)]]),
		};

		let mut pols = vec![];
		if let Some(p) = model_config.backend_tls.clone() {
			pols.push(BackendTrafficPolicy::BackendTLS(
				p.try_into(resources).await?,
			));
		}
		if let Some(p) = model_config.auth.clone() {
			pols.push(BackendTrafficPolicy::BackendAuth(p));
		}
		if let Some(p) = model_config.backend_tunnel.clone() {
			pols.push(BackendTrafficPolicy::Tunnel(p));
		}
		if let Some(rh) = model_config.request_headers.clone() {
			pols.push(BackendTrafficPolicy::RequestHeaderModifier(rh));
		}
		if let Some(rh) = model_config.response_headers.clone() {
			pols.push(BackendTrafficPolicy::ResponseHeaderModifier(Arc::new(rh)));
		}
		if let Some(p) = model_config.health.clone() {
			pols.push(BackendTrafficPolicy::Health(p.try_into().map_err(
				|e: crate::cel::Error| anyhow::anyhow!("health.unhealthyExpression: {}", e),
			)?));
		}
		if let Some(authorization) = model_config.authorization.clone() {
			pols.push(BackendTrafficPolicy::Authorization(authorization));
		}
		if let Some(inference_routing) = shared_inference_routing.clone() {
			pols.push(BackendTrafficPolicy::InferenceRouting(inference_routing));
		}
		let prompt_guard =
			merge_prompt_guards(shared_prompt_guard.clone(), model_config.guardrails.clone());
		pols.push(BackendTrafficPolicy::AI(Arc::new(llm::Policy {
			streaming_limits: match (model_config.streaming_limits, shared_streaming_limits) {
				(Some(a), Some(b)) => Some(a.stricter(b)),
				(a, b) => a.or(b),
			},
			defaults: model_config.defaults.clone(),
			overrides: model_config.overrides.clone(),
			transformations: model_config.transformation.clone(),
			prompt_guard,
			prompts: None,
			model_aliases: Default::default(),
			wildcard_patterns: Arc::new(vec![]),
			prompt_caching: model_config.prompt_caching.clone(),
			routes: Default::default(),
		})));
		let resolved_inline_policies = pols.clone();
		let backend_with_policies = BackendWithPolicies {
			backend: Backend::AI(local_name(backend_key.clone()), ai_backend),
			inline_policies: pols,
		};
		all_backends.push(backend_with_policies);
		resolved_models.push(ResolvedLLMModelTarget {
			name: model_config.name.clone(),
			provider: resolved_provider,
			inline_policies: resolved_inline_policies,
		});

		router_models.push(llm::model_router::ModelRoute {
			name: model_config.name.clone(),
			visibility: model_config.visibility,
			header_matches: model_config
				.matches
				.iter()
				.map(|m| m.headers.clone())
				.collect(),
			backend_key,
			policies: llm::model_router::ModelRoutePolicies {
				llm: Arc::new(crate::llm::Policy {
					routes: llm_routes.into_iter().collect(),
					..Default::default()
				}),
				authorization: model_config.authorization.clone(),
			},
			backend_policies: vec![],
		});
	}

	let virtual_models = llm_registry.into_virtual_models();
	let mut router_virtual_models = Vec::new();
	for (idx, virtual_model) in virtual_models.into_iter().enumerate() {
		let llm_policy = Arc::new(crate::llm::Policy {
			routes: llm_route_types(None).into_iter().collect(),
			..Default::default()
		});
		let routing = match virtual_model.routing_strategy()? {
			LocalLLMVirtualRoutingStrategy::Conditional(conditional) => {
				for target in &conditional.targets {
					resolved_models.resolve(&target.model)?;
				}
				llm::model_router::VirtualModelRouting::Conditional(
					conditional
						.targets
						.iter()
						.map(|target| llm::model_router::ConditionalTarget {
							model: target.model.clone(),
							when: target.when.clone(),
						})
						.collect(),
				)
			},
			LocalLLMVirtualRoutingStrategy::Weighted(weighted) => {
				for target in &weighted.targets {
					resolved_models.resolve(&target.model)?;
				}
				llm::model_router::VirtualModelRouting::Weighted(
					weighted
						.targets
						.iter()
						.map(|target| llm::model_router::WeightedTarget {
							model: target.model.clone(),
							weight: target.weight,
						})
						.collect(),
				)
			},
			LocalLLMVirtualRoutingStrategy::Failover(failover) => {
				let provider_groups = failover
					.targets
					.iter()
					.sorted_by_key(|target| target.priority)
					.chunk_by(|target| target.priority)
					.into_iter()
					.map(|(_, targets)| {
						targets
							.map(|target| {
								let resolved = resolved_models.resolve(&target.model)?;
								let mut provider = resolved.provider.clone();
								provider.name = strng::new(&target.model);
								ensure_ai_provider_model(&mut provider.provider, &target.model);
								provider
									.inline_policies
									.extend(resolved.inline_policies.clone());
								Ok((strng::new(&target.model), provider))
							})
							.collect::<anyhow::Result<Vec<_>>>()
					})
					.collect::<anyhow::Result<Vec<_>>>()?;
				let backend_key = strng::format!("{gateway_id}:virtual-model:{}:{idx}", virtual_model.name);
				all_backends.push(BackendWithPolicies {
					backend: Backend::AI(
						local_name(backend_key.clone()),
						AIBackend {
							providers: crate::types::loadbalancer::EndpointSet::new(provider_groups),
						},
					),
					inline_policies: vec![],
				});
				llm::model_router::VirtualModelRouting::Failover { backend_key }
			},
		};
		router_virtual_models.push(llm::model_router::VirtualModelRoute {
			name: virtual_model.name,
			llm_policy,
			routing,
		});
	}

	let router_backend_key = strng::format!("{gateway_id}:router");
	all_backends.push(BackendWithPolicies {
		backend: Backend::LLMRouter(
			local_name(router_backend_key.clone()),
			Arc::new(llm::model_router::ModelRouter::new(
				router_models,
				router_virtual_models,
				startup_timestamp,
			)),
		),
		inline_policies: vec![],
	});

	routes.push(Route {
		key: strng::format!("{gateway_id}:request"),
		service_key: None,
		service_port: 0,
		name: RouteName {
			name: strng::format!("{gateway_id}:request"),
			namespace: strng::new("internal"),
			rule_name: None,
			kind: None,
		},
		hostnames: vec![],
		matches: vec![RouteMatch {
			path: PathMatch::PathPrefix(strng::new("/")),
			method: None,
			headers: vec![],
			query: vec![],
		}],
		backends: vec![RouteBackendReference {
			weight: 1,
			target: BackendReference::Backend(strng::format!("/{router_backend_key}")).into(),
			inline_policies: vec![],
		}],
		inline_policies: vec![],
	});

	// Create listener
	let listener_key: ListenerKey = strng::new(gateway_id);
	let listener_name = ListenerName {
		gateway_name: gateway.gateway_name.clone(),
		gateway_namespace: gateway.gateway_namespace.clone(),
		listener_name: strng::new(gateway_id),
		listener_set: None,
	};
	let tls_enabled = tls.is_some();
	let listener = Listener {
		key: listener_key.clone(),
		name: listener_name.clone(),
		hostname: strng::new("*"),
		protocol: match tls {
			Some(tls) => ListenerProtocol::HTTPS(tls),
			None => ListenerProtocol::HTTP,
		},
	};

	if !listener_gateway_policies.is_empty() || !listener_route_policies.is_empty() {
		let pc = listener_gateway_policies.len();
		let target = PolicyTarget::Gateway(listener_name.clone().into());
		for (idx, pol) in listener_gateway_policies.into_iter().enumerate() {
			let key = strng::format!("listener/{gateway_id}/{idx}");
			all_policies.push(TargetedPolicy {
				key,
				name: None,
				target: target.clone(),
				inheritance: Default::default(),
				policy: (pol, PolicyPhase::Gateway).into(),
			});
		}
		for (idx, pol) in listener_route_policies.into_iter().enumerate() {
			let key = strng::format!("listener/{gateway_id}/{}", pc + idx);
			all_policies.push(TargetedPolicy {
				key,
				name: None,
				target: target.clone(),
				inheritance: Default::default(),
				policy: (pol, PolicyPhase::Route).into(),
			});
		}
	}

	let mut listener_set = ListenerSet::default();
	listener_set.insert(listener);

	// Create bind
	let sockaddr = if cfg!(target_family = "unix") && config.ipv6_enabled {
		SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), port)
	} else {
		SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), port)
	};

	let bind = Bind {
		key: strng::format!("bind/{}", port),
		address: sockaddr,
		protocol: if tls_enabled {
			BindProtocol::tls
		} else {
			BindProtocol::http
		},
		listeners: listener_set,
		tunnel_protocol: TunnelProtocol::Direct,
		mode: BindMode::Standard,
	};

	Ok((bind, routes, all_policies, all_backends))
}
