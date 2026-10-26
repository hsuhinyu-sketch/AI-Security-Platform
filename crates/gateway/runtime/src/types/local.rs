// Disabled input slots retain null compatibility and are rejected by the existing
// deserializers. They never construct a provider, model router or execution object.
#[cfg(feature = "gateway-llm")]
#[path = "local/llm.rs"]
mod llm_config;
#[cfg(feature = "gateway-llm")]
pub use llm_config::*;
#[cfg(not(feature = "gateway-llm"))]
pub type LocalLLMConfig = serde_json::Value;
#[cfg(not(feature = "gateway-llm"))]
pub type LocalAIBackend = serde_json::Value;
#[cfg(not(feature = "gateway-llm"))]
pub type LocalInferenceConfig = serde_json::Value;

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use ::http::Uri;
use anyhow::{Context, Error, anyhow, bail};
use macro_rules_attribute::apply;
use platform_core::prelude::Strng;
use secrecy::SecretString;

#[cfg(feature = "providers-aws")]
use crate::agentcore;
use crate::http::auth::BackendAuth;
use crate::http::backendtls::{LocalBackendTLS, ResolvedBackendTLS};
use crate::http::transformation_cel::{LocalTransformationConfig, Transformation};
use crate::http::{filters, health, retry, timeout, transformation_cel};
use crate::mcp::{FailureMode, McpAuthorization};
use crate::store::{LocalWorkload, RequestPolicy};
use crate::types::agent::{
	A2aPolicy, Authorization, Backend, BackendKey, BackendReference, BackendTrafficPolicy,
	BackendWithPolicies, Bind, BindMode, BindProtocol, FrontendPolicy, JwtAuthentication, Listener,
	ListenerKey, ListenerName, ListenerProtocol, ListenerSet, ListenerTarget, LocalMcpAuthentication,
	McpAuthentication, McpBackend, McpTarget, McpTargetName, McpTargetSpec, OpenAPITarget, PathMatch,
	PolicyPhase, PolicyTarget, PolicyType, ResourceName, Route, RouteBackendReference,
	RouteBackendTarget, RouteGroupKey, RouteMatch, RouteName, ServerTLSConfig, SimpleBackend,
	SimpleBackendReference, SimpleBackendWithPolicies, SseTargetSpec, StreamableHTTPTargetSpec,
	TCPRoute, TCPRouteBackendReference, Target, TargetedPolicy, TracingConfig, TrafficPolicy,
	TunnelProtocol, TypedResourceName, validate_mcp_target_name,
};
use crate::types::discovery::{NamespacedHostname, Service};
use crate::types::{backend, frontend};
use crate::*;

type LocalExtAuthzPolicy = LocalExplicitOrConditional<crate::http::ext_authz::ExtAuthz>;
type LocalDirectResponsePolicy = LocalExplicitOrConditional<filters::DirectResponse>;
type LocalExtProcPolicy = LocalExplicitOrConditional<crate::http::ext_proc::ExtProc>;
type LocalRemoteRateLimitPolicy =
	LocalExplicitOrConditional<crate::http::remoteratelimit::RemoteRateLimit>;
type LocalTransformationPolicy = LocalExplicitOrConditional<LocalTransformationConfig>;
type LocalMcpGuardrails = crate::mcp::guardrails::McpGuardrails;
#[cfg(feature = "gateway-llm")]
const DEFAULT_LLM_PORT: u16 = 4000;
const DEFAULT_MCP_PORT: u16 = 3000;

// Windows has different output, for now easier to just not deal with it

impl NormalizedLocalConfig {
	pub async fn from(
		config: &crate::Config,
		resources: &crate::resource_manager::ResourceFetcher,
		gateway_name: ListenerTarget,
		s: &str,
	) -> anyhow::Result<NormalizedLocalConfig> {
		let scope = resources.scope_full_computation();
		let result = Self::compute(config, resources, gateway_name, s).await;
		scope.finish(result.is_ok());
		result
	}

	/// The Host owns the resource scope when preparation extends past normalization (RAG JWTs).
	pub(crate) async fn compute(
		config: &crate::Config,
		resources: &crate::resource_manager::ResourceFetcher,
		gateway_name: ListenerTarget,
		s: &str,
	) -> anyhow::Result<NormalizedLocalConfig> {
		let s = s.replace("# yaml-language-server: $schema", "#");
		let s = shellexpand::full(&s)?;
		let local_config: LocalConfig = serdes::yamlviajson::from_str(&s)?;
		convert(resources, gateway_name, config, local_config).await
	}
}

pub fn migrate_deprecated_local_config(s: &str) -> anyhow::Result<String> {
	let cfg: serde_json::Value = serdes::yamlviajson::from_str(s)?;
	let cfg = migrate_deprecated_frontend_policies(cfg)?;
	serdes::yamlviajson::to_string(&cfg)
}

fn migrate_deprecated_frontend_policies(
	mut cfg: serde_json::Value,
) -> anyhow::Result<serde_json::Value> {
	let Some(root) = cfg.as_object_mut() else {
		return Ok(cfg);
	};

	let Some(config) = root.get("config").and_then(serde_json::Value::as_object) else {
		return Ok(cfg);
	};

	let deprecated_logging = config.get("logging").cloned();
	let deprecated_tracing = config.get("tracing").cloned();
	if deprecated_logging.is_none() && deprecated_tracing.is_none() {
		return Ok(cfg);
	}

	let mut deprecated_config = serde_json::Map::new();
	if let Some(logging) = deprecated_logging {
		deprecated_config.insert("logging".to_string(), logging);
	}
	if let Some(tracing) = deprecated_tracing {
		deprecated_config.insert("tracing".to_string(), tracing);
	}
	let mut deprecated_root = serde_json::Map::new();
	deprecated_root.insert(
		"config".to_string(),
		serde_json::Value::Object(deprecated_config),
	);
	let deprecated_cfg_yaml =
		serdes::yamlviajson::to_string(&serde_json::Value::Object(deprecated_root))?;
	let deprecated_cfg = crate::config::parse_config(deprecated_cfg_yaml, None)?;

	let mut frontend_policies: LocalFrontendPolicies = serde_json::from_value(
		root
			.get("frontendPolicies")
			.cloned()
			.unwrap_or_else(|| serde_json::Value::Object(serde_json::Map::new())),
	)?;
	merge_deprecated_frontend_policies(&deprecated_cfg, &mut frontend_policies)?;

	let has_deprecated_log = has_deprecated_frontend_log_fields(&deprecated_cfg.logging);
	let has_deprecated_tracing = deprecated_cfg.tracing.is_some();

	let frontend_policies_map = root
		.entry("frontendPolicies")
		.or_insert_with(|| serde_json::Value::Object(serde_json::Map::new()));
	let Some(frontend_policies_map) = frontend_policies_map.as_object_mut() else {
		anyhow::bail!("frontendPolicies must be an object");
	};
	if has_deprecated_log {
		let Some(access_log) = frontend_policies.access_log else {
			anyhow::bail!("internal error: migrated accessLog was not generated");
		};
		frontend_policies_map.insert("accessLog".to_string(), serde_json::to_value(access_log)?);
		frontend_policies_map.remove("logging");
	}
	if has_deprecated_tracing && let Some(tracing) = frontend_policies.tracing {
		frontend_policies_map.insert("tracing".to_string(), serde_json::to_value(tracing)?);
	}

	let Some(config) = root
		.get_mut("config")
		.and_then(serde_json::Value::as_object_mut)
	else {
		return Ok(cfg);
	};
	if has_deprecated_log {
		match config.get_mut("logging") {
			Some(serde_json::Value::Object(logging)) => {
				logging.remove("filter");
				logging.remove("fields");
				if logging.is_empty() {
					config.remove("logging");
				}
			},
			Some(_) => {
				config.remove("logging");
			},
			None => {},
		}
	}
	if has_deprecated_tracing {
		config.remove("tracing");
	}
	Ok(cfg)
}

fn has_deprecated_frontend_log_fields(log: &crate::telemetry::log::Config) -> bool {
	!log.fields.add.is_empty() || !log.fields.remove.is_empty() || log.filter.is_some()
}

fn merge_deprecated_frontend_policies(
	deprecated: &crate::Config,
	frontend_policies: &mut LocalFrontendPolicies,
) -> anyhow::Result<()> {
	let log = &deprecated.logging;
	let has_deprecated_log = has_deprecated_frontend_log_fields(log);
	if has_deprecated_log {
		if frontend_policies.access_log.is_some() {
			anyhow::bail!(
				"cannot use deprecated config.logging together with frontendPolicies.accessLog"
			);
		}
		frontend_policies.access_log = Some(frontend::LoggingPolicy {
			filter: log.filter.clone(),
			add: log.fields.add.clone(),
			remove: log.fields.remove.clone(),
			otlp: None,
			database: None,
			access_log_policy: None,
		});
	}
	if let Some(tracing) = deprecated.tracing.clone() {
		if frontend_policies.tracing.is_some() {
			anyhow::bail!("cannot use deprecated config.tracing together with frontendPolicies.tracing");
		}
		let trc::DeprecatedConfig {
			endpoint,
			headers,
			protocol,
			fields,
			random_sampling,
			client_sampling,
			path,
		} = tracing;

		let mut policies = if !headers.is_empty() {
			let backend_xfm = transformation_cel::LocalTransformationConfig {
				request: Some(transformation_cel::LocalTransform {
					set: headers
						.into_iter()
						.map(|(k, v)| (strng::new(k), strng::new(v)))
						.collect(),
					..Default::default()
				}),
				response: None,
			};
			let backend_xfm = Transformation::try_from_local_config(backend_xfm, true)?;
			vec![BackendTrafficPolicy::Transformation(Arc::new(backend_xfm))]
		} else {
			Vec::new()
		};
		if let Some(ep) = endpoint {
			let (backend, use_tls) = parse_deprecated_tracing_endpoint(&ep)
				.with_context(|| format!("failed parsing tracing endpoint: {}", ep))?;
			if use_tls {
				policies.push(BackendTrafficPolicy::BackendTLS(
					ResolvedBackendTLS::default().try_into()?,
				));
			}
			frontend_policies.tracing = Some(TracingConfig {
				provider_backend: SimpleBackendReference::InlineBackend(backend),
				policies,
				attributes: Arc::unwrap_or_clone(fields.add),
				resources: Default::default(), // Not supported in the old config
				filter: None,                  // Not supported in the old config
				remove: Arc::unwrap_or_clone(fields.remove).into_iter().collect(),
				random_sampling,
				client_sampling,
				path,
				protocol: match protocol {
					Protocol::Grpc => crate::types::agent::TracingProtocol::Grpc,
					Protocol::Http => crate::types::agent::TracingProtocol::Http,
				},
			});
		}
	}
	Ok(())
}

fn parse_deprecated_tracing_endpoint(endpoint: &str) -> anyhow::Result<(Target, bool)> {
	if !endpoint.contains("://") {
		return Ok((Target::try_from(endpoint)?, false));
	}

	let uri = Uri::try_from(endpoint)?;
	let Some(scheme) = uri.scheme_str() else {
		return Ok((Target::try_from(endpoint)?, false));
	};
	if !matches!(scheme, "http" | "https" | "grpc") {
		anyhow::bail!("unsupported tracing endpoint scheme: {scheme}");
	}
	let host = uri
		.host()
		.with_context(|| format!("tracing endpoint {endpoint} must include a host"))?;
	let port = uri.port_u16().or_else(|| match scheme {
		"http" => Some(80),
		"https" => Some(443),
		"grpc" => Some(4317),
		_ => unreachable!("unsupported tracing endpoint scheme checked above"),
	});
	let Some(port) = port else {
		anyhow::bail!("unsupported tracing endpoint scheme: {scheme}");
	};
	Ok((Target::from((host, port)), scheme == "https"))
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct NormalizedLocalConfig {
	#[cfg(feature = "gateway-rag")]
	#[serde(skip)]
	pub rag_systems: Vec<RagSystemConfig>,
	pub binds: Vec<Bind>,
	pub listener_routes: Vec<(ListenerKey, Vec<Route>)>,
	pub listener_tcp_routes: Vec<(ListenerKey, Vec<TCPRoute>)>,
	pub policies: Vec<TargetedPolicy>,
	pub backends: Vec<BackendWithPolicies>,
	pub route_groups: Vec<(RouteGroupKey, Vec<Route>)>,
	// Note: here we use LocalWorkload since it conveys useful info, we could maybe change but not a problem
	// for now
	pub workloads: Vec<LocalWorkload>,
	pub services: Vec<Service>,
}

#[apply(schema_de!)]
pub struct LocalConfig {
	#[serde(default)]
	#[cfg_attr(feature = "schema", schemars(with = "Option<RawConfig>"))]
	#[allow(unused)]
	config: Arc<Option<serde_json::Value>>,
	#[serde(default)]
	binds: Vec<LocalBind>,
	#[serde(default)]
	frontend_policies: LocalFrontendPolicies,
	/// policies defines additional policies that can be attached to various other configurations.
	/// This is an advanced feature; users should typically use the inline `policies` field under route/gateway.
	#[serde(default)]
	policies: Vec<LocalPolicy>,
	#[serde(default)]
	#[cfg_attr(
		feature = "schema",
		schemars(with = "Vec<std::collections::HashMap<String, serde_json::Value>>")
	)]
	workloads: Vec<LocalWorkload>,
	#[serde(default)]
	#[cfg_attr(
		feature = "schema",
		schemars(with = "Vec<std::collections::HashMap<String, serde_json::Value>>")
	)]
	services: Vec<Service>,
	#[serde(default)]
	backends: Vec<FullLocalBackend>,
	#[serde(default, rename = "routeGroups")]
	route_groups: Vec<LocalRouteGroup>,
	#[serde(default)]
	#[cfg_attr(
		not(feature = "gateway-llm"),
		serde(deserialize_with = "unavailable_llm")
	)]
	#[cfg_attr(
		all(feature = "schema", not(feature = "gateway-llm")),
		schemars(with = "Option<serde_json::Value>")
	)]
	llm: Option<LocalLLMConfig>,
	#[serde(default)]
	#[cfg_attr(
		not(feature = "gateway-mcp"),
		serde(deserialize_with = "unavailable_mcp")
	)]
	mcp: Option<LocalSimpleMcpConfig>,
	/// aiSystems declares independently deployable AI gateway compositions. Each enabled gateway
	/// receives its own listener and can therefore be combined without protocol coupling.
	#[serde(default, rename = "aiSystems")]
	ai_systems: Vec<LocalAiSystemConfig>,
}

#[apply(schema_de!)]
pub struct LocalSimpleMcpConfig {
	#[serde(default, skip_serializing_if = "Option::is_none")]
	port: Option<u16>,
	#[serde(flatten)]
	backend: LocalMcpBackend,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	policies: Option<FilterOrPolicy>,
}

/// A named composition of the existing LLM, A2A, and MCP gateway capabilities.
///
/// Every selected gateway has a separate protocol listener. LLM and MCP reuse their existing
/// configuration formats; A2A receives a normal HTTP backend and automatically enables the A2A
/// request/response adapter for that route.
#[apply(schema_de!)]
pub struct LocalAiSystemConfig {
	/// name is the stable identifier for this AI system. `id` is accepted as an alias so
	/// system-centric configuration can use the same terminology as deployment metadata.
	#[serde(alias = "id")]
	pub name: Strng,
	/// Common security controls applied to every enabled gateway in this AI system.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	#[cfg_attr(feature = "schema", schemars(with = "Option<serde_json::Value>"))]
	security: Option<security_integration_runtime::SecurityConfig>,
	/// inference contains system-wide LLM controls. It is compiled into the selected LLM
	/// gateway's existing parameter, rate-limit, and routing policies.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	#[cfg_attr(
		not(feature = "gateway-llm"),
		serde(deserialize_with = "unavailable_llm")
	)]
	inference: Option<LocalInferenceConfig>,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	#[cfg_attr(
		not(feature = "gateway-llm"),
		serde(deserialize_with = "unavailable_llm")
	)]
	#[cfg_attr(
		all(feature = "schema", not(feature = "gateway-llm")),
		schemars(with = "Option<serde_json::Value>")
	)]
	llm: Option<LocalLLMConfig>,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	#[cfg_attr(
		not(feature = "gateway-a2a"),
		serde(deserialize_with = "unavailable_a2a")
	)]
	a2a: Option<LocalA2aGatewayConfig>,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	#[cfg_attr(
		not(feature = "gateway-mcp"),
		serde(deserialize_with = "unavailable_mcp")
	)]
	mcp: Option<LocalSimpleMcpConfig>,
	/// RAG declares the separately mounted retrieval/ingestion HTTP gateway. Its security policy
	/// stays in this AI system's `security` block; RAG-specific source, context, and backend values
	/// are validated here and used when the RAG router is mounted by the host application.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	#[cfg_attr(feature = "schema", schemars(with = "Option<serde_json::Value>"))]
	rag: Option<LocalRagGatewayConfig>,
}

impl LocalConfig {
	/// Exposes declared AI-system compositions to a host that mounts additional protocol routers.
	pub fn ai_systems(&self) -> &[LocalAiSystemConfig] {
		&self.ai_systems
	}
}

impl LocalAiSystemConfig {
	/// Returns the RAG listener configuration, if this AI system enables the RAG capability.
	#[cfg(feature = "gateway-rag")]
	pub fn rag_config(&self) -> Option<&gateway_rag::RagGatewayConfig> {
		self.rag.as_ref().map(|rag| &rag.gateway)
	}
}

/// RAG's storage and context controls are provider-neutral, while authentication is intentionally
/// supplied by the host gateway's existing JWT validator rather than by the vector backend.
#[cfg(not(feature = "gateway-rag"))]
type LocalRagGatewayConfig = serde_json::Value;

#[cfg(feature = "gateway-rag")]
#[apply(schema_de!)]
pub struct LocalRagGatewayConfig {
	#[serde(flatten)]
	#[cfg_attr(feature = "schema", schemars(with = "serde_json::Value"))]
	gateway: gateway_rag::RagGatewayConfig,
	/// Every RAG listener requires a signature-verifying JWT configuration. The listener derives
	/// Subject / Tenant / Agent facts from its validated claims and never accepts them in JSON.
	authentication: crate::http::jwt::LocalJwtConfig,
}

/// An owned RAG listener declaration extracted from one local AI-system configuration. It is the
/// boundary used by the runtime host, keeping local YAML parsing out of RAG core crates.
#[cfg(feature = "gateway-rag")]
#[derive(Debug, Clone)]
pub struct RagSystemConfig {
	pub name: String,
	pub gateway: gateway_rag::RagGatewayConfig,
	pub security: security_integration_runtime::SecurityConfig,
	pub authentication: crate::http::jwt::LocalJwtConfig,
}

#[cfg(feature = "gateway-rag")]
impl RagSystemConfig {
	fn new(
		name: String,
		security: Option<Arc<security_integration_runtime::SecurityConfig>>,
		rag: LocalRagGatewayConfig,
	) -> anyhow::Result<Self> {
		let security = security
			.ok_or_else(|| anyhow!("aiSystems['{name}'].rag requires a security configuration"))?;
		if security.mode != security_integration_runtime::SecurityMode::Enforce {
			bail!("aiSystems['{name}'].rag requires security.mode: enforce");
		}
		security
			.validate_composition()
			.map_err(|reason| anyhow!("aiSystems['{name}'].security: {reason}"))?;
		if !rag.authentication.is_strict() {
			bail!("aiSystems['{name}'].rag requires authentication.mode: strict");
		}
		rag.gateway.validate().map_err(anyhow::Error::msg)?;
		Ok(Self {
			name,
			gateway: rag.gateway,
			security: Arc::unwrap_or_clone(security),
			authentication: rag.authentication,
		})
	}
}

#[apply(schema_de!)]
pub struct LocalA2aGatewayConfig {
	/// A2A uses an independent HTTP listener so it can coexist with LLM and MCP endpoints.
	pub port: u16,
	pub backend: LocalRouteBackend,
}

#[derive(Debug, Clone, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "schema", schemars(rename = "LocalConditionalPolicy_{T}"))]
struct LocalConditionalPolicy<T> {
	/// condition must evaluate to true for this policy to execute. If unset, the policy is the fallback.
	#[serde(default)]
	condition: Option<Arc<crate::cel::Expression>>,
	/// Policy settings for this conditional entry.
	#[serde(flatten)]
	policy: T,
}

#[apply(schema_de!)]
#[cfg_attr(feature = "schema", schemars(rename = "LocalConditionalPolicies_{T}"))]
struct LocalConditionalPolicies<T> {
	/// conditional policy entries. An entry without a condition must be the final fallback.
	conditional: Vec<LocalConditionalPolicy<T>>,
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[cfg_attr(
	feature = "schema",
	schemars(
		untagged,
		deny_unknown_fields,
		rename = "LocalExplicitOrConditional_{T}"
	)
)]
enum LocalExplicitOrConditional<T> {
	Conditional(LocalConditionalPolicies<T>),
	Explicit(T),
}

// Custom impl to avoid terrible 'not match any variant of untagged' errors.
impl<'de, T> Deserialize<'de> for LocalExplicitOrConditional<T>
where
	T: serde::de::DeserializeOwned,
{
	fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
	where
		D: Deserializer<'de>,
	{
		serde_untagged::UntaggedEnumVisitor::new()
			.map(|map| {
				let v: serde_json::Value = map.deserialize()?;

				if let serde_json::Value::Object(m) = &v
					&& m.contains_key("conditional")
				{
					Ok(LocalExplicitOrConditional::Conditional(
						serde_json::from_value(v).map_err(serde::de::Error::custom)?,
					))
				} else {
					Ok(LocalExplicitOrConditional::Explicit(
						serde_json::from_value(v).map_err(serde::de::Error::custom)?,
					))
				}
			})
			.deserialize(deserializer)
	}
}

impl<T> LocalExplicitOrConditional<T> {
	fn into_policy(self) -> anyhow::Result<RequestPolicy<T>> {
		match self {
			LocalExplicitOrConditional::Explicit(policy) => Ok(RequestPolicy::single(policy)),
			LocalExplicitOrConditional::Conditional(policies) => {
				validate_local_conditional_policies(&policies)?;
				Ok(RequestPolicy::from_policies(
					policies
						.conditional
						.into_iter()
						.map(|entry| (entry.policy, entry.condition)),
				))
			},
		}
	}
}

fn configure_ext_authz_cache_store(policy: LocalExtAuthzPolicy) -> LocalExtAuthzPolicy {
	match policy {
		LocalExplicitOrConditional::Explicit(policy) => {
			LocalExplicitOrConditional::Explicit(policy.with_configured_cache_store())
		},
		LocalExplicitOrConditional::Conditional(mut policies) => {
			policies.conditional = policies
				.conditional
				.into_iter()
				.map(|entry| LocalConditionalPolicy {
					condition: entry.condition,
					policy: entry.policy.with_configured_cache_store(),
				})
				.collect();
			LocalExplicitOrConditional::Conditional(policies)
		},
	}
}

fn validate_local_conditional_policies<T>(
	policies: &LocalConditionalPolicies<T>,
) -> anyhow::Result<()> {
	if policies.conditional.is_empty() {
		bail!("conditional policies must have at least one entry");
	}
	if policies.conditional.len() > 64 {
		bail!("conditional policies may have at most 64 entries");
	}
	if let Some(unconditional_idx) = policies
		.conditional
		.iter()
		.position(|entry| entry.condition.is_none())
		&& unconditional_idx + 1 != policies.conditional.len()
	{
		bail!("conditional policy entries without condition must be last");
	}
	Ok(())
}

impl LocalExplicitOrConditional<LocalTransformationConfig> {
	fn into_transformation_policy(self) -> anyhow::Result<RequestPolicy<Transformation>> {
		match self {
			LocalExplicitOrConditional::Explicit(policy) => Ok(RequestPolicy::single(
				Transformation::try_from_local_config(policy, true)?,
			)),
			LocalExplicitOrConditional::Conditional(policies) => {
				validate_local_conditional_policies(&policies)?;
				Ok(RequestPolicy::from_policies(
					policies
						.conditional
						.into_iter()
						.map(|entry| {
							Transformation::try_from_local_config(entry.policy, true)
								.map(|policy| (policy, entry.condition))
						})
						.collect::<anyhow::Result<Vec<_>>>()?,
				))
			},
		}
	}
}

#[derive(Debug, Clone, serde::Deserialize)]
#[serde(untagged)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "schema", schemars(untagged, deny_unknown_fields))]
enum LocalRateLimitPolicy {
	Conditional(LocalConditionalPolicies<crate::http::localratelimit::RateLimit>),
	Explicit(Vec<crate::http::localratelimit::RateLimit>),
}

impl LocalRateLimitPolicy {
	fn is_empty(&self) -> bool {
		match self {
			LocalRateLimitPolicy::Conditional(policies) => policies.conditional.is_empty(),
			LocalRateLimitPolicy::Explicit(policies) => policies.is_empty(),
		}
	}

	fn into_request_policy(
		self,
	) -> anyhow::Result<RequestPolicy<Vec<crate::http::localratelimit::RateLimit>>> {
		match self {
			LocalRateLimitPolicy::Explicit(policies) => Ok(RequestPolicy::single(policies)),
			LocalRateLimitPolicy::Conditional(policies) => {
				validate_local_conditional_policies(&policies)?;
				Ok(RequestPolicy::from_policies(
					policies
						.conditional
						.into_iter()
						.map(|entry| (vec![entry.policy], entry.condition)),
				))
			},
		}
	}
}

#[apply(schema_de!)]
struct LocalBind {
	/// Port to bind on. Omit it for an internal wildcard bind (which serves any destination port
	/// via in-process routing). A numeric port is required unless `mode` is `internal`.
	#[serde(default)]
	port: Option<u16>,
	listeners: Vec<LocalListener>,
	#[serde(default)]
	tunnel_protocol: TunnelProtocol,
	/// Whether the bind opens an OS listener socket. Defaults to `standard` (binds the port).
	/// Set to `internal` to create a routing-only bind that does not bind a socket.
	#[serde(default)]
	mode: BindMode,
}

#[apply(schema_de!)]
pub struct LocalListenerName {
	// User facing name
	#[serde(default)]
	pub name: Option<Strng>,
	#[serde(default)]
	pub namespace: Option<Strng>,
}

#[apply(schema_de!)]
struct LocalListener {
	#[serde(flatten)]
	name: LocalListenerName,
	/// Can be a wildcard
	hostname: Option<Strng>,
	#[serde(default)]
	protocol: LocalListenerProtocol,
	tls: Option<LocalTLSServerConfig>,
	routes: Option<Vec<LocalRoute>>,
	tcp_routes: Option<Vec<LocalTCPRoute>>,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	policies: Option<LocalGatewayPolicy>,
}

#[derive(Debug, Clone, Default, serde::Deserialize)]
#[serde(rename_all = "UPPERCASE", deny_unknown_fields)]
#[allow(clippy::upper_case_acronyms)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
enum LocalListenerProtocol {
	#[default]
	HTTP,
	HTTPS,
	TLS,
	TCP,
	HBONE,
}

#[derive(Default)]
#[apply(schema_de!)]
pub struct LocalTLSServerConfig {
	/// Certificate source mode. Static mode uses cert/key as the leaf certificate; dynamic CA
	/// mode uses cert/key as a CA for on-demand SNI leaf certificate issuance.
	#[serde(default)]
	pub mode: LocalTLSServerMode,
	pub cert: PathBuf,
	pub key: PathBuf,
	pub root: Option<PathBuf>,
	/// Optional cipher suite allowlist (order is preserved).
	#[cfg_attr(feature = "schema", schemars(with = "Option<Vec<String>>"))]
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub cipher_suites: Option<Vec<crate::transport::tls::CipherSuite>>,
	/// Minimum supported TLS version (only TLS 1.2 and 1.3 are supported).
	#[serde(
		default,
		skip_serializing_if = "Option::is_none",
		rename = "minTLSVersion",
		alias = "minTlsVersion"
	)]
	pub min_tls_version: Option<frontend::TLSVersion>,
	/// Maximum supported TLS version (only TLS 1.2 and 1.3 are supported).
	#[serde(
		default,
		skip_serializing_if = "Option::is_none",
		rename = "maxTLSVersion",
		alias = "maxTlsVersion"
	)]
	pub max_tls_version: Option<frontend::TLSVersion>,
	/// Key exchange groups allowed for negotiating TLS.
	#[cfg_attr(feature = "schema", schemars(with = "Option<Vec<String>>"))]
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub key_exchange_groups: Option<Vec<crate::transport::tls::KeyExchangeGroup>>,
}

#[apply(schema_enum!)]
#[derive(Default)]
pub enum LocalTLSServerMode {
	#[default]
	Static,
	DynamicCa,
}

#[apply(schema_de!)]
pub struct LocalRouteName {
	#[serde(default)]
	pub name: Option<Strng>,
	#[serde(default)]
	pub namespace: Option<Strng>,
	#[serde(default)]
	pub rule_name: Option<Strng>,
}

#[apply(schema_de!)]
pub struct LocalRouteGroup {
	name: RouteGroupKey,
	routes: Vec<LocalRoute>,
}

#[apply(schema_de!)]
pub struct LocalRoute {
	#[serde(flatten)]
	name: LocalRouteName,
	/// Can be a wildcard
	#[serde(default, skip_serializing_if = "Vec::is_empty")]
	hostnames: Vec<Strng>,
	#[serde(default = "default_matches")]
	matches: Vec<RouteMatch>,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	policies: Option<FilterOrPolicy>,
	#[serde(default, skip_serializing_if = "Vec::is_empty")]
	backends: Vec<LocalRouteBackend>,
}

#[apply(schema_de!)]
pub struct LocalRouteBackend {
	#[serde(default = "default_weight")]
	pub weight: usize,
	#[serde(flatten)]
	pub backend: LocalBackend,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub policies: Option<LocalBackendPolicies>,
}

fn default_weight() -> usize {
	1
}

#[apply(schema_de!)]
pub struct FullLocalBackend {
	pub name: BackendKey,
	#[serde(flatten)]
	pub spec: FullLocalBackendSpec,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub policies: Option<LocalBackendPolicies>,
}

#[apply(schema_de!)]
#[allow(clippy::large_enum_variant)]
pub enum FullLocalBackendSpec {
	#[serde(rename = "host")]
	Opaque(Target),
	/// Route to the in-process admin service instead of a network upstream.
	#[serde(rename = "internal")]
	Internal(InternalBackend),
	#[serde(rename = "mcp")]
	#[cfg_attr(
		not(feature = "gateway-mcp"),
		serde(deserialize_with = "unavailable_mcp_backend")
	)]
	MCP(LocalMcpBackend),
	#[serde(rename = "ai")]
	#[cfg_attr(
		not(feature = "gateway-llm"),
		serde(deserialize_with = "unavailable_llm_backend")
	)]
	AI(LocalAIBackend),
	#[serde(rename = "aws")]
	#[cfg(feature = "providers-aws")]
	Aws(LocalAwsBackend),
}

impl From<FullLocalBackendSpec> for LocalBackend {
	fn from(spec: FullLocalBackendSpec) -> Self {
		match spec {
			FullLocalBackendSpec::Opaque(t) => LocalBackend::Opaque(t),
			FullLocalBackendSpec::Internal(t) => LocalBackend::Internal(t),
			FullLocalBackendSpec::MCP(m) => LocalBackend::MCP(m),
			FullLocalBackendSpec::AI(a) => LocalBackend::AI(a),
			#[cfg(feature = "providers-aws")]
			FullLocalBackendSpec::Aws(a) => LocalBackend::Aws(a),
		}
	}
}

#[apply(schema_de!)]
pub struct LocalAwsBackend {
	#[serde(flatten)]
	pub service: LocalAwsService,
}

#[apply(schema_de!)]
pub enum LocalAwsService {
	#[serde(rename = "agentCore")]
	AgentCore(LocalAgentCoreBackend),
}

#[apply(schema_de!)]
pub struct LocalAgentCoreBackend {
	pub agent_runtime_arn: String,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub qualifier: Option<String>,
}

#[apply(schema!)]
/// Selects how an internal backend maps proxy requests to the admin API.
pub enum InternalBackend {
	/// Forward the request to the admin API using the request's current path and query.
	#[serde(rename = "forward")]
	Forward,
	/// Rewrite all requests to this admin API path, preserving the original query string.
	#[serde(untagged)]
	Path(Strng),
}

#[apply(schema_de!)]
#[allow(clippy::large_enum_variant)] // Size is not sensitive for local config
pub enum LocalBackend {
	// This one is a reference
	Service {
		name: NamespacedHostname,
		port: u16,
	},
	Backend(BackendKey),
	// Rest are inlined
	#[serde(rename = "host")]
	Opaque(Target), // Hostname or IP
	/// Route to the in-process admin service instead of a network upstream.
	Internal(InternalBackend),
	Dynamic {},
	#[serde(rename = "mcp")]
	#[cfg_attr(
		not(feature = "gateway-mcp"),
		serde(deserialize_with = "unavailable_mcp_backend")
	)]
	MCP(LocalMcpBackend),
	#[serde(rename = "ai")]
	#[cfg_attr(
		not(feature = "gateway-llm"),
		serde(deserialize_with = "unavailable_llm_backend")
	)]
	AI(LocalAIBackend),
	#[serde(rename = "aws")]
	#[cfg(feature = "providers-aws")]
	Aws(LocalAwsBackend),
	#[serde(rename = "routeGroup")]
	RouteGroup(RouteGroupKey),
	Invalid,
}

impl LocalBackend {
	async fn make_mcp_backend(
		b: Backend,
		policies: Option<MCPLocalBackendPolicies>,
		tls: bool,
		resources: &crate::resource_manager::ResourceFetcher,
	) -> Result<BackendWithPolicies, anyhow::Error> {
		let mut inline_policies = match policies {
			Some(p) => {
				LocalBackendPolicies {
					simple: p.simple,
					mcp_authorization: p.mcp_authorization,
					mcp_guardrails: p.mcp_guardrails,
					security_pipeline: p.security_pipeline,
					a2a: None,
					inference_routing: None,
					ai: None,
					response_header_modifier: None,
					request_redirect: None,
					health: None,
					ext_authz: None,
					authorization: None,
				}
				.translate(resources)
				.await?
			},
			None => Vec::new(),
		};
		if tls {
			inline_policies.push(BackendTrafficPolicy::BackendTLS(
				LocalBackendTLS::default().try_into(resources).await?,
			));
		}
		Ok(BackendWithPolicies {
			backend: b,
			inline_policies,
		})
	}

	async fn process_mcp_backend(
		name: ResourceName,
		backend: McpBackendHost,
		policies: Option<MCPLocalBackendPolicies>,
		resources: &crate::resource_manager::ResourceFetcher,
	) -> anyhow::Result<(
		SimpleBackendReference,
		Option<String>,
		Option<BackendWithPolicies>,
	)> {
		Ok(match backend.process()? {
			ProcessedMcpBackendHost::Inline { backend, path, tls } => {
				let (bref, be) = mcp_to_simple_backend_and_ref(name, backend);
				let be = match be {
					Some(b) => Some(Self::make_mcp_backend(b, policies, tls, resources).await?),
					None => None,
				};
				(bref, Some(path), be)
			},
			ProcessedMcpBackendHost::Reference { .. } if policies.is_some() => {
				anyhow::bail!("cannot use backend reference when policies are defined for an MCP target");
			},
			ProcessedMcpBackendHost::Reference { backend, path } => (backend, path, None),
		})
	}

	pub async fn as_backends(
		&self,
		name: ResourceName,
		resources: &crate::resource_manager::ResourceFetcher,
		mcp_session_ttl: Duration,
	) -> anyhow::Result<Vec<BackendWithPolicies>> {
		Ok(match self {
			LocalBackend::Service { .. } => vec![], // These stay as references
			LocalBackend::Backend(_) => vec![],     // These stay as references
			LocalBackend::Opaque(tgt) => vec![Backend::Opaque(name, tgt.clone()).into()],
			LocalBackend::Internal(tgt) => vec![Backend::Internal(name, tgt.clone()).into()],
			LocalBackend::Dynamic { .. } => vec![Backend::Dynamic(name, ()).into()],
			LocalBackend::MCP(tgt) => {
				let mut targets = vec![];
				let mut backends = vec![];
				for (idx, t) in tgt.targets.iter().enumerate() {
					validate_mcp_target_name(t.name.as_str()).map_err(Error::msg)?;
					let name = strng::format!("mcp/{}/{}", name.clone(), idx);
					let spec = match t.spec.clone() {
						LocalMcpTargetSpec::Sse { backend } => {
							let (bref, path, be) = Self::process_mcp_backend(
								local_name(name.clone()),
								backend,
								t.policies.clone(),
								resources,
							)
							.await?;
							if let Some(be) = be {
								backends.push(be);
							}
							McpTargetSpec::Sse(SseTargetSpec {
								backend: bref,
								path: path.ok_or_else(|| anyhow!("path is required when backend is set"))?,
							})
						},
						LocalMcpTargetSpec::Mcp { backend } => {
							let (bref, path, be) = Self::process_mcp_backend(
								local_name(name.clone()),
								backend,
								t.policies.clone(),
								resources,
							)
							.await?;
							if let Some(be) = be {
								backends.push(be);
							}
							McpTargetSpec::Mcp(StreamableHTTPTargetSpec {
								backend: bref,
								path: path.ok_or_else(|| anyhow!("path is required when backend is set"))?,
							})
						},
						LocalMcpTargetSpec::Stdio {
							cmd,
							args,
							env,
							clear_env,
						} => McpTargetSpec::Stdio {
							cmd,
							args,
							env,
							clear_env,
						},
						LocalMcpTargetSpec::OpenAPI { backend, schema } => {
							let (bref, _, be) = Self::process_mcp_backend(
								local_name(name.clone()),
								backend,
								t.policies.clone(),
								resources,
							)
							.await?;
							if let Some(be) = be {
								backends.push(be);
							}

							let openapi_schema = schema.load_openapi_schema(resources).await?;
							McpTargetSpec::OpenAPI(OpenAPITarget {
								backend: bref,
								schema: openapi_schema.into(),
							})
						},
					};
					let t = McpTarget {
						name: t.name.clone(),
						spec,
					};
					targets.push(Arc::new(t));
				}
				let stateful = match &tgt.stateful_mode {
					McpStatefulMode::Stateless => false,
					McpStatefulMode::Stateful => true,
				};
				let m = McpBackend {
					targets,
					stateful,
					always_use_prefix: tgt.prefix_mode.as_ref().is_some_and(|pm| match pm {
						McpPrefixMode::Always => true,
						McpPrefixMode::Conditional => false,
					}),
					failure_mode: tgt.failure_mode.unwrap_or_default(),
					session_idle_ttl: mcp_session_ttl,
				};
				backends.push(Backend::MCP(name, m).into());
				backends
			},
			#[cfg(feature = "gateway-llm")]
			LocalBackend::AI(tgt) => {
				let be = tgt.clone().translate(resources).await?;
				vec![Backend::AI(name, be).into()]
			},
			#[cfg(not(feature = "gateway-llm"))]
			LocalBackend::AI(_) => bail!("LLM support is not compiled; enable gateway-llm"),
			#[cfg(feature = "providers-aws")]
			LocalBackend::Aws(aws_backend) => {
				let config = match &aws_backend.service {
					LocalAwsService::AgentCore(ac) => {
						let agentcore_config =
							agentcore::AgentCoreConfig::new(ac.agent_runtime_arn.clone(), ac.qualifier.clone())?;
						crate::aws::AwsBackendConfig {
							service: crate::aws::AwsService::AgentCore(agentcore_config),
						}
					},
				};
				vec![Backend::Aws(name, config).into()]
			},
			LocalBackend::RouteGroup(_) => vec![], // Route groups stay as references
			LocalBackend::Invalid => vec![Backend::Invalid.into()],
		})
	}
}

impl SimpleLocalBackend {
	pub fn as_backends(
		&self,
		name: ResourceName,
		policies: Vec<BackendTrafficPolicy>,
	) -> Option<SimpleBackendWithPolicies> {
		match self {
			SimpleLocalBackend::Service { .. } => None, // These stay as references
			SimpleLocalBackend::Opaque(tgt) => Some(SimpleBackendWithPolicies {
				backend: SimpleBackend::Opaque(name, tgt.clone()),
				inline_policies: policies,
			}),
			SimpleLocalBackend::Backend(_) => None,
			SimpleLocalBackend::Invalid => Some(SimpleBackend::Invalid.into()),
		}
	}
}

#[apply(schema_de!)]
#[derive(Default)]
pub enum McpStatefulMode {
	Stateless,
	#[default]
	Stateful,
}

#[apply(schema_de!)]
#[derive(Default)]
pub enum McpPrefixMode {
	Always,
	#[default]
	Conditional,
}

#[apply(schema_de!)]
pub struct LocalMcpBackend {
	pub targets: Vec<Arc<LocalMcpTarget>>,
	#[serde(default)]
	pub stateful_mode: McpStatefulMode,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub prefix_mode: Option<McpPrefixMode>,
	/// Behavior when one or more MCP targets fail to initialize or fail during fanout.
	/// Defaults to `failClosed`.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub failure_mode: Option<FailureMode>,
}

#[apply(schema_de!)]
pub struct LocalMcpTarget {
	pub name: McpTargetName,
	#[serde(flatten)]
	pub spec: LocalMcpTargetSpec,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub policies: Option<MCPLocalBackendPolicies>,
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[cfg_attr(feature = "schema", schemars(with = "McpBackendHostSerde"))]
pub enum McpBackendHost {
	Host {
		host: String,
		port: Option<u16>,
		path: Option<String>,
	},
	Backend {
		backend: BackendKey,
		path: Option<String>,
	},
}

#[derive(Debug, Clone, serde::Deserialize)]
#[serde(untagged)]
#[allow(dead_code)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
enum McpBackendHostSerde {
	HostUri {
		host: String,
	},
	HostParts {
		host: String,
		port: u16,
		path: String,
	},
	Backend {
		backend: BackendKey,
		#[serde(default, skip_serializing_if = "Option::is_none")]
		path: Option<String>,
	},
}

#[apply(schema_de!)]
struct McpBackendHostInput {
	host: Option<String>,
	port: Option<u16>,
	path: Option<String>,
	backend: Option<BackendKey>,
}

pub enum ProcessedMcpBackendHost {
	Inline {
		backend: Target,
		path: String,
		tls: bool,
	},
	Reference {
		backend: SimpleBackendReference,
		path: Option<String>,
	},
}

impl<'de> serde::Deserialize<'de> for McpBackendHost {
	fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
	where
		D: serde::Deserializer<'de>,
	{
		let raw = McpBackendHostInput::deserialize(deserializer)?;
		match (raw.host, raw.port, raw.path, raw.backend) {
			(Some(host), port, path, None) => Ok(Self::Host { host, port, path }),
			(None, None, path, Some(backend)) => Ok(Self::Backend { backend, path }),
			(None, Some(_), _, Some(_)) | (Some(_), _, _, Some(_)) => Err(serde::de::Error::custom(
				"cannot mix host/port with backend for MCP target backend configuration",
			)),
			(None, Some(_), _, None) => Err(serde::de::Error::custom(
				"host is required when port is set for MCP target backend configuration",
			)),
			(None, None, Some(_), None) => Err(serde::de::Error::custom(
				"host or backend is required when path is set for MCP target backend configuration",
			)),
			(None, None, None, None) => Err(serde::de::Error::custom(
				"host or backend is required for MCP target backend configuration",
			)),
		}
	}
}

impl McpBackendHost {
	pub fn process(&self) -> anyhow::Result<ProcessedMcpBackendHost> {
		Ok(match self {
			McpBackendHost::Backend { backend, path } => ProcessedMcpBackendHost::Reference {
				backend: SimpleBackendReference::Backend(backend.clone()),
				path: path.clone(),
			},
			McpBackendHost::Host { host, port, path } => match (host, port, path) {
				(host, Some(port), Some(path)) => {
					let b = Target::from((host.as_str(), *port));
					ProcessedMcpBackendHost::Inline {
						backend: b,
						path: path.clone(),
						tls: false,
					}
				},
				(host, None, None) => {
					let uri = Uri::try_from(host.as_str())?;
					let Some(host) = uri.host() else {
						anyhow::bail!("no host")
					};
					let scheme = uri.scheme().unwrap_or(&http::Scheme::HTTP);
					let port = uri.port_u16();
					let path = uri.path();
					let port = match (scheme, port) {
						(s, p) if s == &http::Scheme::HTTP => p.unwrap_or(80),
						(s, p) if s == &http::Scheme::HTTPS => p.unwrap_or(443),
						(_, _) => {
							anyhow::bail!("invalid scheme: {:?}", scheme);
						},
					};

					let b = Target::from((host, port));
					ProcessedMcpBackendHost::Inline {
						backend: b,
						path: path.to_string(),
						tls: scheme == &http::Scheme::HTTPS,
					}
				},
				_ => {
					anyhow::bail!("if port or path is set, both must be set; otherwise, use only host")
				},
			},
		})
	}
}

#[apply(schema_de!)]
pub enum LocalMcpTargetSpec {
	#[serde(rename = "sse")]
	Sse {
		#[serde(flatten)]
		backend: McpBackendHost,
	},
	#[serde(rename = "mcp")]
	Mcp {
		#[serde(flatten)]
		backend: McpBackendHost,
	},
	#[serde(rename = "stdio")]
	Stdio {
		cmd: String,
		#[serde(default, skip_serializing_if = "Vec::is_empty")]
		args: Vec<String>,
		#[serde(default, skip_serializing_if = "HashMap::is_empty")]
		env: HashMap<String, String>,
		#[serde(default, skip_serializing_if = "std::ops::Not::not")]
		clear_env: bool,
	},
	#[serde(rename = "openapi")]
	OpenAPI {
		#[serde(flatten)]
		backend: McpBackendHost,
		schema: serdes::FileInlineOrRemote,
	},
}

fn default_matches() -> Vec<RouteMatch> {
	vec![RouteMatch {
		headers: vec![],
		path: PathMatch::PathPrefix("/".into()),
		method: None,
		query: vec![],
	}]
}

#[apply(schema_de!)]
struct LocalTCPRoute {
	#[serde(flatten)]
	name: LocalRouteName,
	/// Can be a wildcard
	#[serde(default, skip_serializing_if = "Vec::is_empty")]
	hostnames: Vec<Strng>,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	policies: Option<TCPFilterOrPolicy>,
	#[serde(default, skip_serializing_if = "Vec::is_empty")]
	backends: Vec<LocalTCPRouteBackend>,
}

#[apply(schema_de!)]
pub struct LocalTCPRouteBackend {
	#[serde(default = "default_weight")]
	pub weight: usize,
	#[serde(flatten)]
	pub backend: SimpleLocalBackend,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub policies: Option<LocalTCPBackendPolicies>,
}

#[apply(schema_de!)]
#[cfg_attr(feature = "schema", schemars(with = "SimpleLocalBackendSerde"))]
pub enum SimpleLocalBackend {
	/// Service reference. Service must be defined in the top level services list.
	Service { name: NamespacedHostname, port: u16 },
	/// Hostname or IP address
	#[serde(rename = "host")]
	Opaque(
		/// Hostname or IP address
		Target,
	),
	Backend(
		/// Explicit backend reference. Backend must be defined in the top level backends list
		BackendKey,
	),
	#[serde(skip_deserializing)] // No need to deserialize an intentionally invalid entry
	#[cfg_attr(feature = "schema", schemars(skip))]
	Invalid,
}

#[allow(dead_code)]
#[apply(schema_de!)]
enum SimpleLocalBackendSerde {
	/// Service reference. Service must be defined in the top level services list.
	Service { name: NamespacedHostname, port: u16 },
	/// Hostname or IP address
	#[serde(rename = "host")]
	Opaque(
		/// Hostname or IP address
		Target,
	),
	Backend(
		/// Explicit backend reference. Backend must be defined in the top level backends list
		BackendKey,
	),
}

impl SimpleLocalBackend {
	pub fn as_backend(&self, name: ResourceName) -> Option<Backend> {
		match self {
			SimpleLocalBackend::Service { .. } => None, // These stay as references
			SimpleLocalBackend::Backend(_) => None,     // These stay as references
			SimpleLocalBackend::Opaque(tgt) => Some(Backend::Opaque(name, tgt.clone())),
			SimpleLocalBackend::Invalid => Some(Backend::Invalid),
		}
	}
}

#[apply(schema_de!)]
struct LocalPolicy {
	/// Policy name used when attaching this policy to a target.
	pub name: ResourceName,
	/// Gateway, listener, route, or backend that this policy attaches to.
	pub target: PolicyTarget,

	/// When the policy runs. Gateway policies run before route selection, while route policies run after route selection.
	/// Use route policies by default unless the policy needs to affect route selection.
	#[serde(default)]
	pub phase: PolicyPhase,
	/// Policy settings to apply to the selected target.
	pub policy: FilterOrPolicy,
}

pub fn de_transform<'de, D>(
	deserializer: D,
) -> Result<Option<crate::http::transformation_cel::Transformation>, D::Error>
where
	D: Deserializer<'de>,
{
	<Option<LocalTransformationConfig>>::deserialize(deserializer)?
		.map(|c| http::transformation_cel::Transformation::try_from_local_config(c, true))
		.transpose()
		.map_err(serde::de::Error::custom)
}

pub fn de_backend_auth<'de, D>(deserializer: D) -> Result<Option<BackendAuth>, D::Error>
where
	D: Deserializer<'de>,
{
	Option::<BackendAuthCompat>::deserialize(deserializer)?
		.map(|auth| match auth {
			BackendAuthCompat::Full(BackendAuth::OAuthTokenExchange(auth)) => {
				// OAuth has a few cross-field checks serde won't catch on its own.
				// Keep them here so untagged compat parsing still returns the real error.
				auth.validate_load().map_err(serde::de::Error::custom)?;
				Ok(BackendAuth::OAuthTokenExchange(auth))
			},
			BackendAuthCompat::Full(auth) => Ok(auth),
			BackendAuthCompat::PlainKey { key } => Ok(BackendAuth::Key {
				value: key,
				location: None,
			}),
		})
		.transpose()
}

#[derive(Debug, Clone, serde::Deserialize)]
#[serde(untagged)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
enum BackendAuthCompat {
	PlainKey {
		#[cfg_attr(feature = "schema", schemars(with = "FileOrInline"))]
		#[serde(deserialize_with = "deser_key_from_file")]
		key: SecretString,
	},
	Full(BackendAuth),
}

#[apply(schema_de!)]
#[derive(Default)]
struct LocalGatewayPolicy {
	/// Authenticate browser requests with OIDC authorization code flow.
	#[serde(default)]
	oidc: Option<crate::http::oidc::LocalOidcConfig>,
	/// Authenticate incoming requests with JWT bearer tokens.
	#[serde(default)]
	jwt_auth: Option<crate::http::jwt::LocalJwtConfig>,
	/// Authorization rules for incoming HTTP requests.
	#[serde(default)]
	authorization: Option<Authorization>,
	/// Authorize incoming requests by calling an external authorization service.
	#[serde(default)]
	ext_authz: Option<LocalExtAuthzPolicy>,
	/// Send request and response data to an external processing service.
	#[serde(default)]
	ext_proc: Option<LocalExtProcPolicy>,
	/// Handle CORS preflight requests and append configured CORS headers to applicable requests.
	#[serde(default)]
	cors: Option<http::cors::Cors>,
	/// Modify request and response headers, bodies, or metadata.
	#[serde(default)]
	#[cfg_attr(
		feature = "schema",
		schemars(with = "Option<LocalTransformationPolicy>")
	)]
	transformations: Option<LocalTransformationPolicy>,
	/// Authenticate incoming requests with Basic Auth credentials from an htpasswd user database.
	#[serde(default)]
	basic_auth: Option<crate::http::basicauth::LocalBasicAuth>,
	/// Authenticate incoming requests with API keys.
	#[serde(default)]
	api_key: Option<crate::http::apikey::LocalAPIKeys>,
}

impl From<LocalGatewayPolicy> for FilterOrPolicy {
	fn from(val: LocalGatewayPolicy) -> Self {
		let LocalGatewayPolicy {
			oidc,
			jwt_auth,
			authorization,
			ext_authz,
			ext_proc,
			cors,
			transformations,
			basic_auth,
			api_key,
		} = val;
		FilterOrPolicy {
			oidc,
			jwt_auth,
			authorization,
			ext_authz,
			ext_proc,
			cors,
			transformations,
			basic_auth,
			api_key,
			..Default::default()
		}
	}
}

#[apply(schema_de!)]
#[derive(Default)]
pub struct SimpleLocalBackendPolicies {
	// Filters. Keep in sync with RouteFilter
	/// Modify request headers before forwarding to this backend.
	#[serde(default)]
	pub request_header_modifier: Option<filters::HeaderModifier>,

	/// Modify request and response data for this backend.
	#[serde(default)]
	#[serde(deserialize_with = "de_transform")]
	#[cfg_attr(
		feature = "schema",
		schemars(with = "Option<http::transformation_cel::LocalTransformationConfig>")
	)]
	pub transformations: Option<crate::http::transformation_cel::Transformation>,

	/// TLS settings used when connecting to this backend.
	#[serde(rename = "backendTLS", default)]
	pub backend_tls: Option<http::backendtls::LocalBackendTLS>,
	/// Authentication credentials sent to this backend.
	#[serde(default, deserialize_with = "de_backend_auth")]
	#[cfg_attr(feature = "schema", schemars(with = "Option<BackendAuthCompat>"))]
	pub backend_auth: Option<BackendAuth>,

	/// HTTP protocol settings for this backend.
	#[serde(default)]
	pub http: Option<backend::HTTP>,
	/// TCP protocol settings for this backend.
	#[serde(default)]
	pub tcp: Option<backend::TCP>,

	/// Tunnel settings used when connecting to this backend.
	#[serde(default)]
	pub backend_tunnel: Option<backend::Tunnel>,
}

#[apply(schema_de!)]
#[derive(Default)]
pub struct MCPLocalBackendPolicies {
	#[serde(flatten)]
	simple: SimpleLocalBackendPolicies,
	/// Authorization rules for MCP requests.
	#[serde(default)]
	#[cfg_attr(
		not(feature = "gateway-mcp"),
		serde(deserialize_with = "unavailable_mcp")
	)]
	pub mcp_authorization: Option<McpAuthorization>,
	/// External MCP policy processors.
	#[serde(default)]
	#[cfg_attr(
		not(feature = "gateway-mcp"),
		serde(deserialize_with = "unavailable_mcp")
	)]
	pub mcp_guardrails: Option<LocalMcpGuardrails>,
	/// Composable SecurityGateway controls enforced for MCP Tool calls.
	#[serde(default)]
	#[cfg_attr(feature = "schema", schemars(with = "Option<serde_json::Value>"))]
	pub security_pipeline: Option<security_pipeline::SecurityPipelineConfig>,
}

#[apply(schema_de!)]
#[derive(Default)]
pub struct LocalBackendPolicies {
	#[serde(flatten)]
	simple: SimpleLocalBackendPolicies,

	/// Modify response headers returned from this backend.
	#[serde(default)]
	pub response_header_modifier: Option<filters::HeaderModifier>,

	/// Return a redirect response instead of forwarding to this backend.
	#[serde(default)]
	pub request_redirect: Option<filters::RequestRedirect>,

	/// Detect unhealthy backend responses and temporarily remove unhealthy endpoints.
	#[serde(default)]
	pub health: Option<health::LocalHealthPolicy>,

	/// Authorize incoming requests by calling an external authorization service after this backend is selected.
	#[serde(default)]
	pub ext_authz: Option<crate::http::ext_authz::ExtAuthz>,
	/// Authorize incoming requests after this backend is selected.
	#[serde(default)]
	pub authorization: Option<Authorization>,

	/// Authorization rules for MCP requests.
	#[serde(default)]
	#[cfg_attr(
		not(feature = "gateway-mcp"),
		serde(deserialize_with = "unavailable_mcp")
	)]
	pub mcp_authorization: Option<McpAuthorization>,
	/// External MCP policy processors.
	#[serde(default)]
	#[cfg_attr(
		not(feature = "gateway-mcp"),
		serde(deserialize_with = "unavailable_mcp")
	)]
	pub mcp_guardrails: Option<LocalMcpGuardrails>,
	/// Composable SecurityGateway controls enforced for MCP Tool calls.
	#[serde(default)]
	#[cfg_attr(feature = "schema", schemars(with = "Option<serde_json::Value>"))]
	pub security_pipeline: Option<security_pipeline::SecurityPipelineConfig>,
	/// Mark this traffic as A2A to enable A2A processing and telemetry.
	#[serde(default)]
	#[cfg_attr(
		not(feature = "gateway-a2a"),
		serde(deserialize_with = "unavailable_a2a")
	)]
	pub a2a: Option<A2aPolicy>,
	/// Route requests through an endpoint picker before forwarding to this backend.
	#[serde(default)]
	pub inference_routing: Option<crate::http::ext_proc::InferenceRouting>,
	/// Mark this as LLM traffic to enable LLM processing.
	#[serde(default)]
	#[cfg_attr(
		not(feature = "gateway-llm"),
		serde(deserialize_with = "unavailable_llm")
	)]
	pub ai: Option<llm::Policy>,
}

enum InferenceRoutingScope {
	ServiceRouteBackend,
	NonServiceRouteBackend,
	NamedBackend,
	AIProviderPolicies,
}

fn validate_inference_routing_scope(
	policies: Option<&LocalBackendPolicies>,
	scope: InferenceRoutingScope,
) -> anyhow::Result<()> {
	if policies.is_none_or(|p| p.inference_routing.is_none()) {
		return Ok(());
	}
	match scope {
		InferenceRoutingScope::ServiceRouteBackend => Ok(()),
		InferenceRoutingScope::NonServiceRouteBackend => {
			bail!("inferenceRouting is only supported on service route backends")
		},
		InferenceRoutingScope::NamedBackend => {
			bail!("inferenceRouting is only supported on service route backends, not named backends")
		},
		InferenceRoutingScope::AIProviderPolicies => {
			bail!(
				"inferenceRouting is only supported on service route backends, not AI provider policies"
			)
		},
	}
}

impl LocalBackendPolicies {
	pub async fn translate(
		self,
		resources: &crate::resource_manager::ResourceFetcher,
	) -> anyhow::Result<Vec<BackendTrafficPolicy>> {
		let LocalBackendPolicies {
			simple:
				SimpleLocalBackendPolicies {
					request_header_modifier,
					transformations,
					backend_tls,
					backend_auth,
					http,
					tcp,
					backend_tunnel,
				},
			mcp_authorization,
			mcp_guardrails,
			security_pipeline,
			a2a,
			inference_routing,
			ai,
			response_header_modifier,
			request_redirect,
			health,
			ext_authz,
			authorization,
		} = self;
		let mut pols = vec![];
		if let Some(p) = tcp {
			pols.push(BackendTrafficPolicy::TCP(p));
		}
		if let Some(p) = backend_tunnel {
			pols.push(BackendTrafficPolicy::Tunnel(p));
		}
		if let Some(p) = http {
			pols.push(BackendTrafficPolicy::HTTP(p));
		}
		if let Some(p) = request_header_modifier {
			pols.push(BackendTrafficPolicy::RequestHeaderModifier(p));
		}
		if let Some(p) = response_header_modifier {
			pols.push(BackendTrafficPolicy::ResponseHeaderModifier(Arc::new(p)));
		}
		if let Some(p) = request_redirect {
			pols.push(BackendTrafficPolicy::RequestRedirect(p));
		}
		if let Some(p) = transformations {
			pols.push(BackendTrafficPolicy::Transformation(Arc::new(p)));
		}
		if let Some(p) = mcp_authorization {
			pols.push(BackendTrafficPolicy::McpAuthorization(p))
		}
		if let Some(p) = mcp_guardrails {
			for w in p.load_warnings() {
				tracing::warn!("{w}");
			}
			pols.push(BackendTrafficPolicy::McpGuardrails(Arc::new(p)))
		}
		if let Some(p) = security_pipeline {
			pols.push(BackendTrafficPolicy::SecurityPipeline(Arc::new(p)))
		}
		if let Some(p) = a2a {
			pols.push(BackendTrafficPolicy::A2a(p))
		}
		if let Some(p) = inference_routing {
			pols.push(BackendTrafficPolicy::InferenceRouting(p))
		}
		if let Some(p) = backend_tls {
			pols.push(BackendTrafficPolicy::BackendTLS(
				p.try_into(resources).await?,
			))
		}
		if let Some(p) = backend_auth {
			pols.push(BackendTrafficPolicy::BackendAuth(p))
		}
		if let Some(p) = ext_authz {
			pols.push(BackendTrafficPolicy::ExtAuthz(Arc::new(
				p.with_configured_cache_store(),
			)))
		}
		if let Some(p) = authorization {
			pols.push(BackendTrafficPolicy::Authorization(p))
		}
		if let Some(mut p) = ai {
			p.compile_model_alias_patterns();
			pols.push(BackendTrafficPolicy::AI(Arc::new(p)))
		}
		if let Some(p) = health {
			pols.push(BackendTrafficPolicy::Health(p.try_into().map_err(
				|e: crate::cel::Error| anyhow::anyhow!("health.unhealthyExpression: {}", e),
			)?));
		}
		Ok(pols)
	}
}

#[apply(schema_de!)]
#[derive(Default)]
pub struct LocalTCPBackendPolicies {
	/// TLS settings used when connecting to this backend.
	#[serde(rename = "backendTLS", default)]
	pub backend_tls: Option<http::backendtls::LocalBackendTLS>,
	/// Tunnel settings used when connecting to this backend.
	#[serde(default)]
	pub backend_tunnel: Option<backend::Tunnel>,
}

impl LocalTCPBackendPolicies {
	pub async fn translate(
		self,
		resources: &crate::resource_manager::ResourceFetcher,
	) -> anyhow::Result<Vec<BackendTrafficPolicy>> {
		let LocalTCPBackendPolicies {
			backend_tls,
			backend_tunnel,
		} = self;
		let mut pols = vec![];
		if let Some(p) = backend_tls {
			pols.push(BackendTrafficPolicy::BackendTLS(
				p.try_into(resources).await?,
			))
		}
		if let Some(p) = backend_tunnel {
			pols.push(BackendTrafficPolicy::Tunnel(p))
		}
		Ok(pols)
	}
}

#[apply(schema_de!)]
#[derive(Default)]
struct LocalFrontendPolicies {
	/// Settings for handling incoming HTTP requests.
	#[serde(default)]
	pub http: Option<frontend::HTTP>,
	/// Settings for handling incoming TLS connections.
	#[serde(default)]
	pub tls: Option<frontend::TLS>,
	/// Settings for handling incoming TCP connections.
	#[serde(default)]
	pub tcp: Option<frontend::TCP>,
	/// CEL authorization for downstream network connections.
	#[serde(default)]
	pub network_authorization: Option<frontend::NetworkAuthorization>,
	/// Enable downstream PROXY protocol handling on this gateway or port, including
	/// version matching and whether PROXY headers are required or optional.
	#[serde(default, rename = "proxyProtocol", alias = "proxy")]
	pub proxy_protocol: Option<frontend::Proxy>,
	/// Enable or disable downstream HTTP CONNECT handling.
	#[serde(default)]
	pub connect: Option<frontend::Connect>,
	/// Settings for request access logs.
	#[serde(default, alias = "logging")]
	pub access_log: Option<frontend::LoggingPolicy>,
	/// Settings for exporting request traces.
	#[serde(default)]
	#[serde(deserialize_with = "crate::telemetry::trc::deserialize_optional")]
	pub tracing: Option<TracingConfig>,
}

#[apply(schema_de!)]
#[derive(Default)]
pub struct FilterOrPolicy {
	// Filters. Keep in sync with RouteFilter
	/// Modify request headers before forwarding.
	#[serde(default)]
	request_header_modifier: Option<filters::HeaderModifier>,

	/// Modify response headers before returning to the client.
	#[serde(default)]
	response_header_modifier: Option<filters::HeaderModifier>,

	/// Return a redirect response instead of forwarding the request.
	#[serde(default)]
	request_redirect: Option<filters::RequestRedirect>,

	/// Rewrite the request path or authority before forwarding.
	#[serde(default)]
	url_rewrite: Option<filters::UrlRewrite>,

	/// Send a copy of matching requests to another backend.
	#[serde(default)]
	request_mirror: Option<filters::RequestMirror>,

	/// Return a configured response instead of forwarding the request.
	#[serde(default)]
	direct_response: Option<LocalDirectResponsePolicy>,

	/// Handle CORS preflight requests and append configured CORS headers to applicable requests.
	#[serde(default)]
	cors: Option<http::cors::Cors>,

	// Policy
	/// Authorization rules for MCP requests.
	#[serde(default)]
	#[cfg_attr(
		not(feature = "gateway-mcp"),
		serde(deserialize_with = "unavailable_mcp")
	)]
	mcp_authorization: Option<McpAuthorization>,
	/// External MCP policy processors.
	#[serde(default)]
	#[cfg_attr(
		not(feature = "gateway-mcp"),
		serde(deserialize_with = "unavailable_mcp")
	)]
	mcp_guardrails: Option<LocalMcpGuardrails>,
	/// Composable SecurityGateway controls enforced for MCP Tool calls.
	#[serde(default)]
	#[cfg_attr(feature = "schema", schemars(with = "Option<serde_json::Value>"))]
	security_pipeline: Option<security_pipeline::SecurityPipelineConfig>,
	/// Authorization rules for incoming HTTP requests.
	#[serde(default)]
	authorization: Option<Authorization>,
	/// Authenticate MCP clients.
	#[serde(default)]
	#[cfg_attr(
		not(feature = "gateway-mcp"),
		serde(deserialize_with = "unavailable_mcp")
	)]
	mcp_authentication: Option<LocalMcpAuthentication>,
	/// Mark this traffic as A2A to enable A2A processing and telemetry.
	#[serde(default)]
	#[cfg_attr(
		not(feature = "gateway-a2a"),
		serde(deserialize_with = "unavailable_a2a")
	)]
	a2a: Option<A2aPolicy>,
	/// Mark this as LLM traffic to enable LLM processing.
	#[serde(default)]
	#[cfg_attr(
		not(feature = "gateway-llm"),
		serde(deserialize_with = "unavailable_llm")
	)]
	ai: Option<llm::Policy>,
	/// TLS settings used when connecting to the backend.
	#[serde(rename = "backendTLS", default)]
	backend_tls: Option<http::backendtls::LocalBackendTLS>,
	/// Tunnel settings used when connecting to the backend.
	#[serde(rename = "backendTunnel", default)]
	backend_tunnel: Option<backend::Tunnel>,
	/// Authentication credentials sent to the backend.
	#[serde(default, deserialize_with = "de_backend_auth")]
	#[cfg_attr(feature = "schema", schemars(with = "Option<BackendAuthCompat>"))]
	backend_auth: Option<BackendAuth>,
	/// Local rate limits for incoming requests.
	#[serde(default)]
	local_rate_limit: Option<LocalRateLimitPolicy>,
	/// Remote rate limit checks for incoming requests.
	#[serde(default)]
	remote_rate_limit: Option<LocalRemoteRateLimitPolicy>,
	/// Authenticate incoming requests with JWT bearer tokens.
	#[serde(default)]
	jwt_auth: Option<crate::http::jwt::LocalJwtConfig>,
	/// Authenticate browser requests with OIDC authorization code flow.
	#[serde(default)]
	oidc: Option<crate::http::oidc::LocalOidcConfig>,
	/// Authenticate incoming requests with Basic Auth credentials from an htpasswd user database.
	#[serde(default)]
	basic_auth: Option<crate::http::basicauth::LocalBasicAuth>,
	/// Authenticate incoming requests with API keys.
	#[serde(default)]
	api_key: Option<crate::http::apikey::LocalAPIKeys>,
	/// Authorize incoming requests by calling an external authorization service.
	#[serde(default)]
	ext_authz: Option<LocalExtAuthzPolicy>,
	/// Send request and response data to an external processing service.
	#[serde(default)]
	ext_proc: Option<LocalExtProcPolicy>,
	/// Modify request and response headers, bodies, or metadata.
	#[serde(default)]
	#[cfg_attr(
		feature = "schema",
		schemars(with = "Option<LocalTransformationPolicy>")
	)]
	transformations: Option<LocalTransformationPolicy>,

	/// Handle CSRF protection by validating request origins against configured allowed origins.
	#[serde(default)]
	csrf: Option<http::csrf::Csrf>,

	// TrafficPolicy
	/// Buffer request and response bodies.
	#[serde(default)]
	buffer: Option<http::buffer::Buffer>,
	/// Set request timeout limits.
	#[serde(default)]
	timeout: Option<timeout::Policy>,
	/// Retry matching failed upstream requests.
	#[serde(default)]
	retry: Option<retry::Policy>,
}

#[apply(schema_de!)]
struct TCPFilterOrPolicy {
	#[serde(default, skip_serializing_if = "Option::is_none")]
	#[serde(rename = "backendTLS")]
	backend_tls: Option<LocalBackendTLS>,
}

async fn convert(
	resources: &crate::resource_manager::ResourceFetcher,
	gateway: ListenerTarget,
	config: &crate::Config,
	i: LocalConfig,
) -> anyhow::Result<NormalizedLocalConfig> {
	validate_gateway_capabilities(&i)?;
	validate_local_listener_ports(&i)?;
	let LocalConfig {
		config: _,
		mut frontend_policies,
		binds,
		policies,
		workloads,
		services,
		backends,
		route_groups,
		#[cfg(feature = "gateway-llm")]
		llm,
		#[cfg(not(feature = "gateway-llm"))]
			llm: _,
		mcp,
		ai_systems,
	} = i;
	merge_deprecated_frontend_policies(config, &mut frontend_policies)?;
	let mut all_policies = vec![];
	let mut all_backends = vec![];
	let mut all_binds = vec![];
	let mut all_listener_routes = vec![];
	let mut all_listener_tcp_routes = vec![];
	for b in binds {
		// A standard bind requires a numeric port; an internal bind may omit the port to act as
		// the wildcard fallback that serves any destination port via in-process routing.
		if b.port.is_none() && b.mode != BindMode::Internal {
			bail!("a bind without a port must set mode: internal");
		}
		// The runtime treats an internal bind with port 0 as the wildcard, whether the port was
		// omitted or explicitly set to 0. Keep both representations on the single `bind/wildcard`
		// key (and address port 0) so they are indistinguishable downstream.
		let bind_port = b.port.unwrap_or(0);
		let is_wildcard = b.mode == BindMode::Internal && bind_port == 0;
		let bind_name = if is_wildcard {
			strng::literal!("bind/wildcard")
		} else {
			strng::format!("bind/{bind_port}")
		};
		let mut ls = ListenerSet::default();
		for (idx, l) in b.listeners.into_iter().enumerate() {
			let (l, routes, tcp_routes, pol, backends) = convert_listener(
				resources,
				config,
				idx,
				l,
				bind_name.clone(),
				gateway.clone(),
			)
			.await?;
			all_listener_routes.push((l.key.clone(), routes));
			all_listener_tcp_routes.push((l.key.clone(), tcp_routes));
			all_policies.extend_from_slice(&pol);
			all_backends.extend_from_slice(&backends);
			ls.insert(l)
		}
		let sockaddr = if cfg!(target_family = "unix") && config.ipv6_enabled {
			SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), bind_port)
		} else {
			// Windows and IPv6 don't mix well apparently?
			SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), bind_port)
		};
		let b = Bind {
			key: bind_name,
			address: sockaddr,
			protocol: detect_bind_protocol(&ls),
			listeners: ls,
			tunnel_protocol: b.tunnel_protocol,
			mode: b.mode,
		};
		all_binds.push(b)
	}

	for p in policies {
		p.target.validate()?;
		let policy_key = p.name.to_string();
		let res = split_policies(resources, p.policy, config.as_policy_context(&policy_key)).await?;
		if (res.route_policies.len() + res.backend_policies.len()) != 1 {
			bail!("'policies' must contain exactly 1 policy");
		}
		let tp = if let Some(route_policy) = res.route_policies.into_iter().next() {
			PolicyType::from((route_policy, p.phase))
		} else {
			res.backend_policies.into_iter().next().unwrap().into()
		};
		let tgt_policy = TargetedPolicy {
			name: Some(TypedResourceName {
				kind: strng::literal!("Local"),
				name: p.name.name.clone(),
				namespace: p.name.namespace.clone(),
			}),
			key: p.name.to_string().into(),
			target: p.target,
			inheritance: Default::default(),
			policy: tp,
		};
		all_policies.push(tgt_policy);
	}

	for b in backends {
		validate_inference_routing_scope(b.policies.as_ref(), InferenceRoutingScope::NamedBackend)?;
		let policies = b.policies.map(|p| async { p.translate(resources).await });
		let policies = match policies {
			Some(policies) => policies.await?,
			None => Vec::new(),
		};
		let name = local_name(b.name);
		let lb: LocalBackend = b.spec.into();
		let mut bws = lb
			.as_backends(name.clone(), resources, config.mcp.session_ttl)
			.await?;

		// as_backends may expand a single LocalBackend into multiple Backends (e.g. MCP)
		// attach the policies to the "main" one
		// do not use `Backend::name` as it may create a computed name, not based
		if let Some(primary_bw) = bws
			.iter_mut()
			.find(|bw| bw.backend.resource_name() == Some(&name))
		{
			primary_bw.inline_policies.extend_from_slice(&policies);
		} else {
			anyhow::bail!("as_backends did not return a backend with the expected name: {name}");
		}

		all_backends.extend(bws);
	}

	// Convert llm config if present
	#[cfg(feature = "gateway-llm")]
	if let Some(llm_config) = llm {
		let (llm_bind, llm_routes, llm_policies, llm_backends) =
			convert_llm_config(resources, config, gateway.clone(), llm_config, "llm").await?;
		all_listener_routes.push((strng::new("llm"), llm_routes));
		all_listener_tcp_routes.push((strng::new("llm"), Vec::new()));
		all_binds.push(llm_bind);
		all_policies.extend_from_slice(&llm_policies);
		all_backends.extend_from_slice(&llm_backends);
	}
	if let Some(mcp_config) = mcp {
		let (mcp_bind, mcp_routes, mcp_policies, mcp_backends) =
			convert_mcp_config(resources, config, gateway.clone(), mcp_config, "mcp").await?;
		all_listener_routes.push((strng::new("mcp"), mcp_routes));
		all_listener_tcp_routes.push((strng::new("mcp"), Vec::new()));
		all_binds.push(mcp_bind);
		all_policies.extend_from_slice(&mcp_policies);
		all_backends.extend_from_slice(&mcp_backends);
	}
	#[cfg(feature = "gateway-rag")]
	let mut rag_systems = Vec::new();
	let mut ai_system_names = HashSet::new();
	for ai_system in ai_systems {
		let LocalAiSystemConfig {
			name,
			security,
			inference,
			llm,
			a2a,
			mcp,
			rag,
		} = ai_system;
		if name.is_empty() {
			bail!("aiSystems[].name must not be empty");
		}
		if !ai_system_names.insert(name.clone()) {
			bail!("aiSystems contains duplicate system name '{name}'");
		}
		if llm.is_none() && a2a.is_none() && mcp.is_none() && rag.is_none() {
			bail!("aiSystems['{name}'] must enable at least one gateway");
		}
		if llm.is_none() && inference.is_some() {
			bail!("aiSystems['{name}'].inference requires the LLM gateway");
		}
		let security = security
			.map(|mut security| {
				if security.required_audit.is_some() && config.security_audit.is_none() {
					bail!("aiSystems['{name}'].security.requiredAudit requires config.securityAudit");
				}
				if let Some(parent) = &config.dependency_egress {
					security.dependency_egress = Some(
						security
							.dependency_egress
							.as_ref()
							.map_or_else(|| parent.clone(), |local| parent.intersect(local)),
					);
				}
				security
					.prepare_a2a_store()
					.map_err(|reason| anyhow!("aiSystems['{name}'].security: {reason}"))?;
				Ok::<_, anyhow::Error>(Arc::new(security))
			})
			.transpose()?;
		#[cfg(feature = "gateway-rag")]
		if let Some(rag) = rag {
			rag_systems.push(RagSystemConfig::new(
				name.to_string(),
				security.clone(),
				rag,
			)?);
		}
		#[cfg(feature = "gateway-llm")]
		if let Some(llm_config) = llm {
			let llm_config = compile_ai_system_inference(&name, llm_config, inference)?;
			let gateway_id = format!("ai-system:{name}:llm");
			let (bind, mut routes, policies, mut backends) =
				convert_llm_config(resources, config, gateway.clone(), llm_config, &gateway_id).await?;
			attach_security_audit(&mut routes, &mut backends, security.as_ref());
			let listener_key = bind.listeners.get_exactly_one()?.key.clone();
			all_listener_routes.push((listener_key.clone(), routes));
			all_listener_tcp_routes.push((listener_key, Vec::new()));
			all_binds.push(bind);
			all_policies.extend(policies);
			all_backends.extend(backends);
		}
		if let Some(a2a_config) = a2a {
			let gateway_id = format!("ai-system:{name}:a2a");
			let (bind, mut routes, policies, mut backends) =
				convert_a2a_config(resources, config, gateway.clone(), a2a_config, &gateway_id).await?;
			attach_security_audit(&mut routes, &mut backends, security.as_ref());
			let listener_key = bind.listeners.get_exactly_one()?.key.clone();
			all_listener_routes.push((listener_key.clone(), routes));
			all_listener_tcp_routes.push((listener_key, Vec::new()));
			all_binds.push(bind);
			all_policies.extend(policies);
			all_backends.extend(backends);
		}
		if let Some(mcp_config) = mcp {
			let gateway_id = format!("ai-system:{name}:mcp");
			let (bind, mut routes, policies, mut backends) =
				convert_mcp_config(resources, config, gateway.clone(), mcp_config, &gateway_id).await?;
			attach_security_audit(&mut routes, &mut backends, security.as_ref());
			let listener_key = bind.listeners.get_exactly_one()?.key.clone();
			all_listener_routes.push((listener_key.clone(), routes));
			all_listener_tcp_routes.push((listener_key, Vec::new()));
			all_binds.push(bind);
			all_policies.extend(policies);
			all_backends.extend(backends);
		}
	}

	// Convert route groups
	let mut all_route_groups = vec![];
	for rg in route_groups {
		let rg_key = rg.name.clone();
		let mut routes = vec![];
		for (idx, lr) in rg.routes.into_iter().enumerate() {
			let route_group_listener_key: ListenerKey = strng::format!("routegroup/{rg_key}");
			let (route, backends) =
				convert_route(resources, config, lr, idx, route_group_listener_key).await?;
			all_backends.extend_from_slice(&backends);
			routes.push(route);
		}
		all_route_groups.push((rg_key, routes));
	}

	// Add frontend policies targeted to this listener
	all_policies.extend_from_slice(&split_frontend_policies(gateway, frontend_policies).await?);
	if let Some(parent) = &config.dependency_egress {
		for policy in &mut all_policies {
			if let crate::types::agent::PolicyType::Backend(policy) = &mut policy.policy {
				inherit_dependency_policy(std::slice::from_mut(policy), parent)?;
			}
		}
		for backend in &mut all_backends {
			inherit_dependency_policy(&mut backend.inline_policies, parent)?;
		}
		for (_, routes) in all_listener_routes
			.iter_mut()
			.chain(all_route_groups.iter_mut())
		{
			for route in routes {
				for backend in &mut route.backends {
					inherit_dependency_policy(&mut backend.inline_policies, parent)?;
				}
			}
		}
	}

	let normalized = NormalizedLocalConfig {
		#[cfg(feature = "gateway-rag")]
		rag_systems,
		binds: all_binds,
		listener_routes: all_listener_routes,
		listener_tcp_routes: all_listener_tcp_routes,
		policies: all_policies,
		backends: all_backends.into_iter().collect(),
		route_groups: all_route_groups,
		workloads,
		services,
	};
	if let Some(policy) = &config.dependency_egress {
		validate_nested_dependency_endpoints(&serde_json::to_value(&normalized)?, policy)?;
	}
	Ok(normalized)
}

fn validate_nested_dependency_endpoints(
	value: &serde_json::Value,
	policy: &security_integration_runtime::dependency_egress::DependencyEgressConfig,
) -> anyhow::Result<()> {
	match value {
		serde_json::Value::Object(fields) => {
			for (key, value) in fields {
				if key == "securityAudit" && value.is_object() {
					let security: security_integration_runtime::SecurityConfig =
						serde_json::from_value(value.clone())?;
					security
						.check_dependency_endpoints(policy)
						.map_err(anyhow::Error::msg)?;
				} else {
					validate_nested_dependency_endpoints(value, policy)?;
				}
			}
		},
		serde_json::Value::Array(values) => {
			for value in values {
				validate_nested_dependency_endpoints(value, policy)?;
			}
		},
		_ => {},
	}
	Ok(())
}

fn inherit_dependency_policy(
	policies: &mut [BackendTrafficPolicy],
	parent: &security_integration_runtime::dependency_egress::DependencyEgressConfig,
) -> anyhow::Result<()> {
	for policy in policies {
		if let BackendTrafficPolicy::SecurityAudit(security) = policy {
			let security = Arc::make_mut(security);
			security.dependency_egress = Some(
				security
					.dependency_egress
					.as_ref()
					.map_or_else(|| parent.clone(), |local| parent.intersect(local)),
			);
			// Inheritance must preserve the shared runtime handles. Reinitializing a memory
			// TaskStore here would split one AI system into different ownership registries.
			security
				.validate_composition()
				.map_err(anyhow::Error::msg)?;
		}
	}
	Ok(())
}

fn validate_gateway_capabilities(config: &LocalConfig) -> anyhow::Result<()> {
	validate_gateway_capabilities_for_profile(config, crate::capabilities::compiled_profile())
}

fn validate_gateway_capabilities_for_profile(
	config: &LocalConfig,
	profile: crate::capabilities::GatewayProfile,
) -> anyhow::Result<()> {
	// Hot updates validate LocalConfig directly instead of reparsing the startup Config.
	let raw = config.config.as_ref().as_ref();
	let configured = |value: Option<&serde_json::Value>| value.is_some_and(|value| !value.is_null());
	if configured(raw.and_then(|value| value.get("database")))
		|| configured(
			raw
				.and_then(|value| value.get("logging"))
				.and_then(|value| value.get("database")),
		) {
		crate::telemetry::log_store::validate_compiled()?;
	}
	if configured(raw.and_then(|value| value.get("tracing"))) {
		crate::telemetry::trc::validate_compiled()?;
	}
	if !profile.supports(crate::capabilities::GatewayCapability::Llm)
		&& config
			.config
			.as_ref()
			.as_ref()
			.and_then(|config| config.get("modelCatalog"))
			.is_some_and(|sources| {
				!sources.is_null() && sources.as_array().is_none_or(|sources| !sources.is_empty())
			})
	{
		bail!("modelCatalog requires LLM support; enable gateway-llm");
	}
	if config.llm.is_some() {
		require_gateway_capability(profile, crate::capabilities::GatewayCapability::Llm, "llm")?;
		#[cfg(feature = "gateway-llm")]
		validate_llm_routing_capability(config.llm.as_ref().expect("present"), "llm", profile)?;
	}
	if config.mcp.is_some() {
		require_gateway_capability(profile, crate::capabilities::GatewayCapability::Mcp, "mcp")?;
	}
	for system in &config.ai_systems {
		let prefix = format!("aiSystems['{}']", system.name);
		if system.inference.is_some() && system.llm.is_none() {
			bail!("{prefix}.inference requires the LLM gateway");
		}
		if let Some(security) = &system.security {
			crate::capabilities::validate_security(security, profile).map_err(anyhow::Error::msg)?;
			security
				.validate_composition()
				.map_err(|reason| anyhow!("{prefix}.security: {reason}"))?;
			if security.capability_broker.is_some() && system.mcp.is_none() {
				bail!("{prefix}.security.capabilityBroker requires the MCP gateway");
			}
			if security.a2a_objects.is_some() && system.a2a.is_none() {
				bail!("{prefix}.security.a2aObjects requires the A2A gateway");
			}
			if system.a2a.is_none()
				&& security
					.execution_budget
					.as_ref()
					.is_some_and(|b| b.task_cleanup.is_some())
			{
				bail!("{prefix}.security.executionBudget.taskCleanup requires the A2A gateway");
			}
			if system.a2a.is_some()
				&& security.execution_budget.is_some()
				&& security.a2a_objects.is_none()
			{
				bail!("{prefix}.security.executionBudget requires a2aObjects for A2A gateways");
			}
			if security.mcp_sessions.is_some() && system.mcp.is_none() {
				bail!("{prefix}.security.mcpSessions requires the MCP gateway");
			}
			if system.mcp.is_some()
				&& (security.cross_component.is_some() || security.execution_budget.is_some())
				&& security.mcp_sessions.is_none()
			{
				bail!(
					"{prefix}.security.crossComponent/executionBudget requires mcpSessions for MCP gateways"
				);
			}
			if let Some(objects) = &security.a2a_objects {
				if let security_integration_runtime::a2a_objects::TaskStoreConfig::Sqlite {
					namespace,
					..
				} = &objects.storage
				{
					if namespace.as_str() != system.name.as_str() {
						bail!("{prefix}.security.a2aObjects.storage.namespace must equal the AI system name");
					}
				}
			}
			if !security.pipeline.required_tool_approvals.is_empty() && system.mcp.is_none() {
				bail!("{prefix}.security.requiredToolApprovals requires the MCP gateway");
			}
		}
		if system.llm.is_some() {
			require_gateway_capability(
				profile,
				crate::capabilities::GatewayCapability::Llm,
				&format!("{prefix}.llm"),
			)?;
			#[cfg(feature = "gateway-llm")]
			validate_llm_routing_capability(
				system.llm.as_ref().expect("present"),
				&format!("{prefix}.llm"),
				profile,
			)?;
		}
		if system.a2a.is_some() {
			require_gateway_capability(
				profile,
				crate::capabilities::GatewayCapability::A2a,
				&format!("{prefix}.a2a"),
			)?;
		}
		if system.mcp.is_some() {
			require_gateway_capability(
				profile,
				crate::capabilities::GatewayCapability::Mcp,
				&format!("{prefix}.mcp"),
			)?;
		}
		if system.security.is_some() {
			require_gateway_capability(
				profile,
				crate::capabilities::GatewayCapability::SecurityS1,
				&format!("{prefix}.security"),
			)?;
		}
		if system.rag.is_some() {
			require_gateway_capability(
				profile,
				crate::capabilities::GatewayCapability::Rag,
				&format!("{prefix}.rag"),
			)?;
			#[cfg(feature = "gateway-rag")]
			{
				let rag = system.rag.as_ref().expect("checked above");
				rag
					.gateway
					.validate()
					.map_err(|error| anyhow!("{prefix}.rag is invalid: {error}"))?;
				let security = system
					.security
					.as_ref()
					.ok_or_else(|| anyhow!("{prefix}.rag requires a security configuration"))?;
				if security.mode != security_integration_runtime::SecurityMode::Enforce {
					bail!("{prefix}.rag requires security.mode: enforce");
				}
				if !rag.authentication.is_strict() {
					bail!("{prefix}.rag requires authentication.mode: strict");
				}
			}
		}
	}
	Ok(())
}

fn require_gateway_capability(
	profile: crate::capabilities::GatewayProfile,
	capability: crate::capabilities::GatewayCapability,
	location: &str,
) -> anyhow::Result<()> {
	if profile.supports(capability) {
		return Ok(());
	}
	anyhow::bail!(
		"{location} requires {}, which is not compiled into this gateway profile",
		capability.display_name()
	)
}

fn validate_local_listener_ports(config: &LocalConfig) -> anyhow::Result<()> {
	let mut ports = HashMap::new();

	let mut insert_local_listener_port = |port: u16, label: String| {
		if let Some(existing) = ports.insert(port, label.clone()) {
			bail!(
				"port {port} is configured by both {existing} and {label}; binds and gateway listeners must use unique ports"
			);
		}
		Ok(())
	};
	let mut wildcard_binds = Vec::new();
	for (idx, bind) in config.binds.iter().enumerate() {
		// An internal bind whose effective port is 0 (port omitted or explicitly `0`) is the
		// wildcard fallback, which opens no socket (so there is no port to deconflict). There can be
		// at most one, since lookups would otherwise resolve the wildcard ambiguously. Everything
		// else with a numeric port participates in uniqueness checks.
		if bind.mode == BindMode::Internal && bind.port.unwrap_or(0) == 0 {
			wildcard_binds.push(idx);
		} else if let Some(port) = bind.port {
			insert_local_listener_port(port, format!("binds[{idx}]"))?;
		}
	}
	if wildcard_binds.len() > 1 {
		bail!(
			"at most one wildcard bind (an internal bind without a numeric port) is allowed, but found {}: binds{:?}",
			wildcard_binds.len(),
			wildcard_binds
		);
	}
	#[cfg(feature = "gateway-llm")]
	if let Some(llm) = &config.llm {
		insert_local_listener_port(
			llm.port.unwrap_or(DEFAULT_LLM_PORT),
			if llm.port.is_some() {
				"llm".to_string()
			} else {
				"llm (default)".to_string()
			},
		)?;
	}
	if let Some(mcp) = &config.mcp {
		insert_local_listener_port(
			mcp.port.unwrap_or(DEFAULT_MCP_PORT),
			if mcp.port.is_some() {
				"mcp".to_string()
			} else {
				"mcp (default)".to_string()
			},
		)?;
	}
	for ai_system in &config.ai_systems {
		#[cfg(feature = "gateway-llm")]
		if let Some(llm) = &ai_system.llm {
			insert_local_listener_port(
				llm.port.unwrap_or(DEFAULT_LLM_PORT),
				format!("aiSystems[{}].llm", ai_system.name),
			)?;
		}
		if let Some(a2a) = &ai_system.a2a {
			insert_local_listener_port(a2a.port, format!("aiSystems[{}].a2a", ai_system.name))?;
		}
		if let Some(mcp) = &ai_system.mcp {
			insert_local_listener_port(
				mcp.port.unwrap_or(DEFAULT_MCP_PORT),
				format!("aiSystems[{}].mcp", ai_system.name),
			)?;
		}
		#[cfg(feature = "gateway-rag")]
		if let Some(rag) = &ai_system.rag {
			insert_local_listener_port(
				rag.gateway.port,
				format!("aiSystems[{}].rag", ai_system.name),
			)?;
		}
	}
	Ok(())
}

async fn convert_mcp_config(
	resources: &crate::resource_manager::ResourceFetcher,
	config: &crate::Config,
	gateway: ListenerTarget,
	mcp_config: LocalSimpleMcpConfig,
	gateway_id: &str,
) -> anyhow::Result<(
	Bind,
	Vec<Route>,
	Vec<TargetedPolicy>,
	Vec<BackendWithPolicies>,
)> {
	let LocalSimpleMcpConfig {
		port,
		backend,
		policies,
	} = mcp_config;
	let port = port.unwrap_or(DEFAULT_MCP_PORT);
	let route_key = strng::format!("{gateway_id}:default");

	let resolved_policies = if let Some(pol) = policies {
		split_policies(resources, pol, config.as_policy_context(&route_key)).await?
	} else {
		ResolvedPolicies::default()
	};

	let mut routes = Vec::new();
	let route = Route {
		key: route_key.clone(),
		service_key: None,
		service_port: 0,
		name: RouteName {
			name: strng::new("default"),
			namespace: strng::new("internal"),
			rule_name: None,
			kind: None,
		},
		hostnames: vec![],
		matches: default_matches(),
		backends: vec![RouteBackendReference {
			weight: 1,
			target: BackendReference::Backend(strng::format!("/{gateway_id}")).into(),
			inline_policies: resolved_policies.backend_policies,
		}],
		inline_policies: resolved_policies.route_policies,
	};
	routes.push(route);

	let listener_key: ListenerKey = strng::new(gateway_id);
	let listener_name = ListenerName {
		gateway_name: gateway.gateway_name.clone(),
		gateway_namespace: gateway.gateway_namespace.clone(),
		listener_name: strng::new(gateway_id),
		listener_set: None,
	};
	let listener = Listener {
		key: listener_key,
		name: listener_name,
		hostname: strng::new("*"),
		protocol: ListenerProtocol::HTTP,
	};

	let mut listener_set = ListenerSet::default();
	listener_set.insert(listener);

	let sockaddr = if cfg!(target_family = "unix") && config.ipv6_enabled {
		SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), port)
	} else {
		SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), port)
	};

	let bind = Bind {
		key: strng::format!("bind/{}", port),
		address: sockaddr,
		protocol: BindProtocol::http,
		listeners: listener_set,
		tunnel_protocol: TunnelProtocol::Direct,
		mode: BindMode::Standard,
	};

	let backends = LocalBackend::MCP(backend)
		.as_backends(
			local_name(strng::new(gateway_id)),
			resources,
			config.mcp.session_ttl,
		)
		.await?;

	Ok((bind, routes, vec![], backends))
}

async fn convert_a2a_config(
	resources: &crate::resource_manager::ResourceFetcher,
	config: &crate::Config,
	gateway: ListenerTarget,
	a2a_config: LocalA2aGatewayConfig,
	gateway_id: &str,
) -> anyhow::Result<(
	Bind,
	Vec<Route>,
	Vec<TargetedPolicy>,
	Vec<BackendWithPolicies>,
)> {
	let LocalA2aGatewayConfig { port, mut backend } = a2a_config;
	let backend_policies = backend.policies.get_or_insert_with(Default::default);
	backend_policies.a2a = Some(A2aPolicy {});

	let listener = LocalListener {
		name: LocalListenerName {
			name: Some(strng::new(gateway_id)),
			namespace: Some(strng::new("internal")),
		},
		hostname: None,
		protocol: LocalListenerProtocol::HTTP,
		tls: None,
		routes: Some(vec![LocalRoute {
			name: LocalRouteName {
				name: Some(strng::format!("{gateway_id}:request")),
				namespace: Some(strng::new("internal")),
				rule_name: None,
			},
			hostnames: vec![],
			matches: default_matches(),
			policies: None,
			backends: vec![backend],
		}]),
		tcp_routes: None,
		policies: None,
	};
	let bind_key = strng::format!("bind/{port}");
	let (listener, routes, _, policies, backends) =
		convert_listener(resources, config, 0, listener, bind_key.clone(), gateway).await?;
	let mut listeners = ListenerSet::default();
	listeners.insert(listener);
	let address = if cfg!(target_family = "unix") && config.ipv6_enabled {
		SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), port)
	} else {
		SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), port)
	};
	Ok((
		Bind {
			key: bind_key,
			address,
			protocol: BindProtocol::http,
			listeners,
			tunnel_protocol: TunnelProtocol::Direct,
			mode: BindMode::Standard,
		},
		routes,
		policies,
		backends,
	))
}

fn attach_security_audit(
	routes: &mut [Route],
	backends: &mut [BackendWithPolicies],
	security: Option<&Arc<security_integration_runtime::SecurityConfig>>,
) {
	let Some(security) = security else {
		return;
	};
	for route in routes {
		for backend in &mut route.backends {
			backend
				.inline_policies
				.push(BackendTrafficPolicy::SecurityAudit(security.clone()));
		}
	}
	for backend in backends {
		backend
			.inline_policies
			.push(BackendTrafficPolicy::SecurityAudit(security.clone()));
	}
}

fn detect_bind_protocol(listeners: &ListenerSet) -> BindProtocol {
	if listeners
		.iter()
		.any(|l| matches!(l.protocol, ListenerProtocol::HTTPS(_)))
	{
		return BindProtocol::tls;
	}
	if listeners
		.iter()
		.any(|l| matches!(l.protocol, ListenerProtocol::TLS(_)))
	{
		return BindProtocol::tls;
	}
	if listeners
		.iter()
		.any(|l| matches!(l.protocol, ListenerProtocol::TCP))
	{
		return BindProtocol::tcp;
	}
	BindProtocol::http
}

async fn convert_listener(
	resources: &crate::resource_manager::ResourceFetcher,
	config: &crate::Config,
	idx: usize,
	l: LocalListener,
	bind_key: Strng,
	gateway: ListenerTarget,
) -> anyhow::Result<(
	Listener,
	Vec<Route>,
	Vec<TCPRoute>,
	Vec<TargetedPolicy>,
	Vec<BackendWithPolicies>,
)> {
	let LocalListener {
		name,
		policies,
		hostname,
		protocol,
		tls,
		routes,
		tcp_routes,
	} = l;

	let protocol = match protocol {
		LocalListenerProtocol::HTTP => {
			if routes.is_none() {
				bail!("protocol HTTP requires 'routes'")
			}
			ListenerProtocol::HTTP
		},
		LocalListenerProtocol::HTTPS => {
			if routes.is_none() {
				bail!("protocol HTTPS requires 'routes'")
			}
			ListenerProtocol::HTTPS(
				tls
					.ok_or(anyhow!("HTTPS listener requires 'tls'"))?
					.into_server_tls_config_with_resources(config.dynamic_ca_cert_cache.clone(), resources)
					.await?,
			)
		},
		LocalListenerProtocol::TLS => {
			if tcp_routes.is_none() {
				bail!("protocol TLS requires 'tcpRoutes'")
			}
			ListenerProtocol::TLS(match tls {
				Some(tls) => Some(
					tls
						.into_server_tls_config_with_resources(config.dynamic_ca_cert_cache.clone(), resources)
						.await?,
				),
				None => None,
			})
		},
		LocalListenerProtocol::TCP => {
			if tcp_routes.is_none() {
				bail!("protocol TCP requires 'tcpRoutes'")
			}
			ListenerProtocol::TCP
		},
		LocalListenerProtocol::HBONE => ListenerProtocol::HBONE,
	};

	if tcp_routes.is_some() && routes.is_some() {
		bail!("only 'routes' or 'tcpRoutes' may be set");
	}

	let listener_name = name
		.name
		.unwrap_or_else(|| strng::format!("listener{}", idx));
	let gateway_name = gateway.gateway_name.clone();
	let gateway_namespace = gateway.gateway_namespace.clone();
	let name = ListenerName {
		gateway_name,
		gateway_namespace,
		listener_name,
		listener_set: None,
	};
	let hostname = hostname.unwrap_or_default();
	let key: ListenerKey = strng::format!(
		"{}/{}/{bind_key}/{}",
		name.gateway_namespace,
		name.gateway_name,
		name.listener_name
	);

	let mut all_policies = vec![];
	let mut all_backends = vec![];

	let mut rs = Vec::new();
	for (idx, l) in routes.into_iter().flatten().enumerate() {
		let (route, backends) = convert_route(resources, config, l, idx, key.clone()).await?;
		all_backends.extend_from_slice(&backends);
		rs.push(route)
	}

	let mut trs = Vec::new();
	for (idx, l) in tcp_routes.into_iter().flatten().enumerate() {
		let (route, policies, backends) = convert_tcp_route(l, idx, key.clone(), resources).await?;
		all_policies.extend_from_slice(&policies);
		all_backends.extend_from_slice(&backends);
		trs.push(route)
	}

	if let Some(pol) = policies {
		let listener_policy_id = strng::format!("listener/{key}");
		let pols = split_policies(
			resources,
			pol.into(),
			config.as_policy_context(listener_policy_id),
		)
		.await?;
		let target = PolicyTarget::Gateway(name.clone().into());
		for (idx, pol) in pols.route_policies.into_iter().enumerate() {
			let key = strng::format!("listener/{key}/{idx}");
			all_policies.push(TargetedPolicy {
				key,
				name: None,
				target: target.clone(),
				inheritance: Default::default(),
				policy: (pol, PolicyPhase::Gateway).into(),
			});
		}
	}

	let l = Listener {
		key,
		name,
		hostname,
		protocol,
	};
	Ok((l, rs, trs, all_policies, all_backends))
}

pub async fn convert_route(
	resources: &crate::resource_manager::ResourceFetcher,
	config: &crate::Config,
	lr: LocalRoute,
	idx: usize,
	listener_key: ListenerKey,
) -> anyhow::Result<(Route, Vec<BackendWithPolicies>)> {
	let LocalRoute {
		name,
		hostnames,
		matches,
		policies,
		backends,
	} = lr;

	let route_name = name.name.unwrap_or_else(|| strng::format!("route{}", idx));
	let namespace = name.namespace.unwrap_or_else(|| strng::new("default"));
	let key = strng::format!("{listener_key}/{namespace}/{route_name}");

	let mut backend_refs = Vec::new();
	let mut external_backends = Vec::new();
	for (idx, b) in backends.iter().enumerate() {
		validate_inference_routing_scope(
			b.policies.as_ref(),
			if matches!(b.backend, LocalBackend::Service { .. }) {
				InferenceRoutingScope::ServiceRouteBackend
			} else {
				InferenceRoutingScope::NonServiceRouteBackend
			},
		)?;
		let backend_key = strng::format!("{key}/backend{idx}");
		let policies = b
			.policies
			.clone()
			.map(|p| async { p.translate(resources).await });
		let policies = match policies {
			Some(policies) => policies.await?,
			None => Vec::new(),
		};
		let be_name = local_name(backend_key.clone());
		let target = match &b.backend {
			LocalBackend::RouteGroup(rg) => RouteBackendTarget::RouteGroup(rg.clone()),
			other => {
				let bref = match other {
					LocalBackend::Service { name, port } => BackendReference::Service {
						name: name.clone(),
						port: *port,
					},
					LocalBackend::Backend(n) => BackendReference::Backend(n.clone()),
					LocalBackend::Invalid => BackendReference::Invalid,
					_ => BackendReference::Backend(strng::format!("/{}", backend_key)),
				};
				bref.into()
			},
		};
		let backends = b
			.backend
			.as_backends(be_name.clone(), resources, config.mcp.session_ttl)
			.await?;
		let bref = RouteBackendReference {
			weight: b.weight,
			target,
			inline_policies: policies,
		};
		backend_refs.push(bref);
		external_backends.extend_from_slice(&backends);
	}
	let resolved = if let Some(pol) = policies {
		split_policies(
			resources,
			pol,
			Some(AttachedPolicyContext {
				oidc_policy_id: crate::http::oidc::PolicyId::route(&key),
				oidc_cookie_encoder: config.oidc_cookie_encoder.as_ref(),
			}),
		)
		.await?
	} else {
		ResolvedPolicies::default()
	};
	for br in backend_refs.iter_mut() {
		br.inline_policies
			.extend_from_slice(&resolved.backend_policies);
	}
	let inline_policies = resolved.route_policies;
	let route = Route {
		key,
		service_key: None,
		service_port: 0,
		name: RouteName {
			name: route_name,
			namespace,
			rule_name: None,
			kind: None,
		},
		hostnames,
		matches,
		backends: backend_refs,
		inline_policies,
	};
	Ok((route, external_backends))
}

#[derive(Default)]
pub(crate) struct ResolvedPolicies {
	pub(crate) backend_policies: Vec<BackendTrafficPolicy>,
	pub(crate) route_policies: Vec<TrafficPolicy>,
}

pub struct AttachedPolicyContext<'a> {
	pub oidc_policy_id: crate::http::oidc::PolicyId,
	pub oidc_cookie_encoder: Option<&'a crate::http::sessionpersistence::Encoder>,
}

async fn split_frontend_policies(
	gateway: ListenerTarget,
	pol: LocalFrontendPolicies,
) -> Result<Vec<TargetedPolicy>, Error> {
	if pol.tracing.is_some() {
		crate::telemetry::trc::validate_compiled()?;
	}
	if let Some(logging) = &pol.access_log {
		logging.validate_compiled()?;
	}
	let mut pols = Vec::new();

	let mut add = |p: FrontendPolicy, name: &str| {
		let key = strng::format!("frontend/{name}");
		pols.push(TargetedPolicy {
			key: key.clone(),
			name: None,
			target: PolicyTarget::Gateway(gateway.clone()),
			inheritance: Default::default(),
			policy: p.into(),
		});
	};
	let LocalFrontendPolicies {
		http,
		tls,
		tcp,
		network_authorization,
		proxy_protocol,
		connect,
		access_log,
		tracing,
	} = pol;
	if let Some(p) = http {
		add(FrontendPolicy::HTTP(p), "http");
	}
	if let Some(p) = tls {
		add(FrontendPolicy::TLS(p), "tls");
	}
	if let Some(p) = tcp {
		add(FrontendPolicy::TCP(p), "tcp");
	}
	if let Some(p) = network_authorization {
		add(
			FrontendPolicy::NetworkAuthorization(p),
			"networkAuthorization",
		);
	}
	if let Some(p) = proxy_protocol {
		add(FrontendPolicy::Proxy(p), "proxy");
	}
	if let Some(p) = connect {
		add(FrontendPolicy::Connect(p), "connect");
	}
	if let Some(mut p) = access_log {
		p.init_access_log_policy();
		add(FrontendPolicy::AccessLog(p), "accessLog");
	}
	if let Some(tracing_config) = tracing {
		// Build logging fields from attributes for lazy tracer creation
		let logging_fields = Arc::new(crate::telemetry::log::LoggingFields {
			remove: Arc::new(tracing_config.remove.iter().cloned().collect()),
			add: Arc::new(tracing_config.attributes.clone()),
		});

		add(
			FrontendPolicy::Tracing(Arc::new(crate::types::agent::TracingPolicy {
				config: tracing_config,
				fields: logging_fields,
				#[cfg(feature = "telemetry-otlp")]
				tracer: once_cell::sync::OnceCell::new(),
			})),
			"tracing",
		);
	}
	Ok(pols)
}
pub(crate) async fn split_policies(
	resources: &crate::resource_manager::ResourceFetcher,
	pol: FilterOrPolicy,
	attached: Option<AttachedPolicyContext<'_>>,
) -> Result<ResolvedPolicies, Error> {
	let mut resolved = ResolvedPolicies::default();
	let ResolvedPolicies {
		backend_policies,
		route_policies,
	} = &mut resolved;
	let FilterOrPolicy {
		request_header_modifier,
		response_header_modifier,
		request_redirect,
		url_rewrite,
		request_mirror,
		direct_response,
		cors,
		mcp_authorization,
		mcp_guardrails,
		security_pipeline,
		mcp_authentication,
		a2a,
		ai,
		backend_tls,
		backend_tunnel,
		backend_auth,
		authorization,
		local_rate_limit,
		remote_rate_limit,
		jwt_auth,
		oidc: oidc_config,
		basic_auth,
		api_key,
		transformations,
		csrf,
		ext_authz,
		ext_proc,
		buffer,
		timeout,
		retry,
	} = pol;
	if let Some(p) = request_header_modifier {
		route_policies.push(TrafficPolicy::RequestHeaderModifier(RequestPolicy::single(
			p,
		)));
	}
	if let Some(p) = response_header_modifier {
		route_policies.push(TrafficPolicy::ResponseHeaderModifier(
			RequestPolicy::single(p),
		));
	}
	if let Some(p) = request_redirect {
		route_policies.push(TrafficPolicy::RequestRedirect(RequestPolicy::single(p)));
	}
	if let Some(p) = url_rewrite {
		route_policies.push(TrafficPolicy::UrlRewrite(RequestPolicy::single(p)));
	}
	if let Some(p) = request_mirror {
		route_policies.push(TrafficPolicy::RequestMirror(vec![p]));
	}

	// Filters
	if let Some(p) = direct_response {
		route_policies.push(TrafficPolicy::DirectResponse(p.into_policy()?));
	}
	if let Some(p) = cors {
		route_policies.push(TrafficPolicy::CORS(RequestPolicy::single(p)));
	}

	// Backend policies
	if let Some(p) = mcp_authorization {
		backend_policies.push(BackendTrafficPolicy::McpAuthorization(p))
	}
	if let Some(p) = mcp_guardrails {
		for w in p.load_warnings() {
			tracing::warn!("{w}");
		}
		backend_policies.push(BackendTrafficPolicy::McpGuardrails(Arc::new(p)))
	}
	if let Some(p) = security_pipeline {
		backend_policies.push(BackendTrafficPolicy::SecurityPipeline(Arc::new(p)))
	}
	if let Some(p) = mcp_authentication {
		let authn: McpAuthentication = p.translate(resources).await?;
		route_policies.push(TrafficPolicy::JwtAuth(RequestPolicy::single(
			JwtAuthentication {
				jwt: authn.jwt_validator.as_ref().clone(),
				mcp: Some(authn),
			},
		)));
	}
	if let Some(p) = a2a {
		backend_policies.push(BackendTrafficPolicy::A2a(p))
	}
	if let Some(p) = backend_tls {
		backend_policies.push(BackendTrafficPolicy::BackendTLS(
			p.try_into(resources).await?,
		))
	}
	if let Some(p) = backend_tunnel {
		backend_policies.push(BackendTrafficPolicy::Tunnel(p))
	}
	if let Some(p) = backend_auth {
		backend_policies.push(BackendTrafficPolicy::BackendAuth(p))
	}

	// Route policies
	if let Some(mut p) = ai {
		p.compile_model_alias_patterns();
		route_policies.push(TrafficPolicy::AI(Arc::new(p)))
	}
	if let Some(p) = jwt_auth {
		route_policies.push(TrafficPolicy::JwtAuth(RequestPolicy::single(
			JwtAuthentication {
				jwt: p.try_into(resources).await?,
				mcp: None,
			},
		)));
	}
	let compiled_oidc = if let Some(oidc) = oidc_config {
		let Some(AttachedPolicyContext {
			oidc_policy_id,
			oidc_cookie_encoder,
		}) = attached
		else {
			return Err(Error::msg("oidc policies must be attached"));
		};
		let Some(oidc_cookie_encoder) = oidc_cookie_encoder else {
			return Err(Error::msg(
				"OIDC_COOKIE_SECRET is required when oidc is configured",
			));
		};
		Some(TrafficPolicy::Oidc(RequestPolicy::single(
			oidc
				.compile(resources, oidc_policy_id, oidc_cookie_encoder)
				.await?,
		)))
	} else {
		None
	};
	if let Some(p) = basic_auth {
		route_policies.push(TrafficPolicy::BasicAuth(RequestPolicy::single(
			p.try_into()?,
		)));
	}
	if let Some(p) = api_key {
		route_policies.push(TrafficPolicy::APIKey(RequestPolicy::single(p.into())));
	}
	if let Some(p) = transformations {
		route_policies.push(TrafficPolicy::Transformation(
			p.into_transformation_policy()?,
		));
	}
	if let Some(p) = csrf {
		route_policies.push(TrafficPolicy::Csrf(RequestPolicy::single(p)))
	}
	if let Some(p) = authorization {
		route_policies.push(TrafficPolicy::Authorization(p))
	}
	if let Some(p) = ext_authz {
		route_policies.push(TrafficPolicy::ExtAuthz(
			configure_ext_authz_cache_store(p).into_policy()?,
		))
	}
	if let Some(p) = ext_proc {
		route_policies.push(TrafficPolicy::ExtProc(p.into_policy()?))
	}
	if let Some(p) = local_rate_limit
		&& !p.is_empty()
	{
		route_policies.push(TrafficPolicy::LocalRateLimit(p.into_request_policy()?))
	}
	if let Some(p) = remote_rate_limit {
		route_policies.push(TrafficPolicy::RemoteRateLimit(p.into_policy()?))
	}

	// Traffic policies
	if let Some(p) = buffer {
		route_policies.push(TrafficPolicy::Buffer(RequestPolicy::single(p)));
	}
	if let Some(p) = timeout {
		route_policies.push(TrafficPolicy::Timeout(p));
	}
	if let Some(p) = retry {
		route_policies.push(TrafficPolicy::Retry(p));
	}
	if let Some(oidc) = compiled_oidc {
		route_policies.push(oidc);
	}
	Ok(resolved)
}

async fn convert_tcp_route(
	lr: LocalTCPRoute,
	idx: usize,
	listener_key: ListenerKey,
	resources: &crate::resource_manager::ResourceFetcher,
) -> anyhow::Result<(TCPRoute, Vec<TargetedPolicy>, Vec<BackendWithPolicies>)> {
	let LocalTCPRoute {
		name,
		hostnames,
		policies,
		backends,
	} = lr;

	let route_name = name
		.name
		.unwrap_or_else(|| strng::format!("tcproute{}", idx));
	let namespace = name.namespace.unwrap_or_else(|| strng::new("default"));
	let key = strng::format!("{listener_key}/{namespace}/{route_name}");

	let external_policies = vec![];

	let mut backend_refs = Vec::new();
	let mut external_backends = Vec::new();
	for (idx, b) in backends.iter().enumerate() {
		let backend_key = strng::format!("{key}/backend{idx}");
		let be_name = local_name(backend_key.clone());
		let policies = b
			.policies
			.clone()
			.map(|p| async { p.translate(resources).await });
		let policies = match policies {
			Some(policies) => policies.await?,
			None => Vec::new(),
		};
		let bref = match &b.backend {
			SimpleLocalBackend::Service { name, port } => SimpleBackendReference::Service {
				name: name.clone(),
				port: *port,
			},
			SimpleLocalBackend::Invalid => SimpleBackendReference::Invalid,
			_ => SimpleBackendReference::Backend(strng::format!("/{}", backend_key)),
		};
		let maybe_backend = b.backend.as_backends(be_name.clone(), policies);
		let bref = TCPRouteBackendReference {
			weight: b.weight,
			backend: bref,
			inline_policies: Vec::new(),
		};
		backend_refs.push(bref);
		if let Some(be) = maybe_backend {
			external_backends.push(be.into());
		}
	}

	if let Some(pol) = policies {
		let TCPFilterOrPolicy { backend_tls } = pol;
		if let Some(p) = backend_tls {
			let backend_tls = BackendTrafficPolicy::BackendTLS(p.try_into(resources).await?);
			for br in backend_refs.iter_mut() {
				br.inline_policies.push(backend_tls.clone());
			}
		}
	}
	let route = TCPRoute {
		key,
		service_key: None,
		service_port: 0,
		name: RouteName {
			name: route_name,
			namespace,
			rule_name: None,
			kind: None,
		},
		hostnames,
		backends: backend_refs,
	};
	Ok((route, external_policies, external_backends))
}

// For most local backends we can just use `InlineBackend`. However, for MCP we allow `https://domain/path`
// which implies adding inline policies + parsing the path. So we need to use references.
fn mcp_to_simple_backend_and_ref(
	name: ResourceName,
	b: Target,
) -> (SimpleBackendReference, Option<Backend>) {
	let bref = SimpleBackendReference::Backend(name.to_string().into());
	let backend = SimpleLocalBackend::Opaque(b).as_backend(name);
	(bref, backend)
}

impl LocalTLSServerConfig {
	async fn into_server_tls_config_with_resources(
		self,
		dynamic_ca_cert_cache: crate::DynamicCaCertCacheConfig,
		resources: &crate::resource_manager::ResourceFetcher,
	) -> anyhow::Result<ServerTLSConfig> {
		let cert_pem = resources
			.fetch(crate::resource_manager::ResourceRef::File(self.cert))
			.await?
			.to_vec();
		let key_pem = resources
			.fetch(crate::resource_manager::ResourceRef::File(self.key))
			.await?
			.to_vec();
		let root_pem = match self.root {
			Some(root) => Some(
				resources
					.fetch(crate::resource_manager::ResourceRef::File(root))
					.await?
					.to_vec(),
			),
			None => None,
		};
		match self.mode {
			LocalTLSServerMode::Static => ServerTLSConfig::from_pem_with_profile(
				cert_pem,
				key_pem,
				root_pem,
				vec![b"h2".to_vec(), b"http/1.1".to_vec()],
				self.min_tls_version.map(Into::into),
				self.max_tls_version.map(Into::into),
				self.cipher_suites,
				self.key_exchange_groups,
				false,
			),
			LocalTLSServerMode::DynamicCa => {
				if root_pem.is_some() {
					anyhow::bail!("tls.root is not supported with tls.mode=dynamicCa")
				}
				super::dynamic_ca_cert::build_dynamic_ca_tls_config_with_profile(
					cert_pem,
					key_pem,
					vec![b"h2".to_vec(), b"http/1.1".to_vec()],
					self.min_tls_version.map(Into::into),
					self.max_tls_version.map(Into::into),
					self.cipher_suites,
					self.key_exchange_groups,
					dynamic_ca_cert_cache,
				)
			},
		}
	}
}

pub fn local_name(name: Strng) -> ResourceName {
	ResourceName::new(name, "".into())
}

pub fn de_from_local_backend_policy<'de: 'a, 'a, D>(
	deserializer: D,
) -> Result<Vec<BackendTrafficPolicy>, D::Error>
where
	D: Deserializer<'de>,
{
	let s = SimpleLocalBackendPolicies::deserialize(deserializer)?;
	let resources = crate::resource_manager::ResourceFetcher::files_only();
	// This serde hook has no runtime resource manager, but backend TLS policy
	// compatibility can still resolve local file references.
	// Not ideal but greatly simplifies the code
	futures::executor::block_on(
		LocalBackendPolicies {
			simple: s,
			..Default::default()
		}
		.translate(&resources),
	)
	.map_err(serde::de::Error::custom)
}

#[cfg(all(test, not(feature = "gateway-rag")))]
mod disabled_rag_tests {
	use super::*;

	#[test]
	fn rag_configuration_is_rejected_when_service_is_not_compiled() {
		let config: LocalConfig = serde_json::from_value(serde_json::json!({
			"aiSystems":[{"name":"disabled-rag", "rag":{"port":14103}}]
		}))
		.unwrap();
		let error = validate_gateway_capabilities(&config)
			.unwrap_err()
			.to_string();
		assert!(error.contains(".rag requires RAG Gateway"), "{error}");
		assert!(error.contains("not compiled"), "{error}");
	}
}

#[cfg(not(feature = "gateway-mcp"))]
fn unavailable_mcp<'de, D: serde::Deserializer<'de>, T>(
	deserializer: D,
) -> Result<Option<T>, D::Error> {
	if Option::<serde::de::IgnoredAny>::deserialize(deserializer)?.is_none() {
		return Ok(None);
	}
	Err(serde::de::Error::custom(
		"MCP support is not compiled; enable gateway-mcp",
	))
}
#[cfg(not(feature = "gateway-mcp"))]
fn unavailable_mcp_backend<'de, D: serde::Deserializer<'de>, T>(_: D) -> Result<T, D::Error> {
	Err(serde::de::Error::custom(
		"MCP support is not compiled; enable gateway-mcp",
	))
}
#[cfg(not(feature = "gateway-a2a"))]
fn unavailable_a2a<'de, D: serde::Deserializer<'de>, T>(
	deserializer: D,
) -> Result<Option<T>, D::Error> {
	if Option::<serde::de::IgnoredAny>::deserialize(deserializer)?.is_none() {
		return Ok(None);
	}
	Err(serde::de::Error::custom(
		"A2A support is not compiled; enable gateway-a2a",
	))
}

#[cfg(test)]
#[path = "local/profile_tests.rs"]
mod profile_tests;

#[cfg(not(feature = "gateway-llm"))]
fn unavailable_llm<'de, D: serde::Deserializer<'de>, T>(
	deserializer: D,
) -> Result<Option<T>, D::Error> {
	if Option::<serde_json::Value>::deserialize(deserializer)?.is_none() {
		return Ok(None);
	}
	Err(serde::de::Error::custom(
		"LLM support is not compiled; enable gateway-llm",
	))
}

#[cfg(not(feature = "gateway-llm"))]
fn unavailable_llm_backend<'de, D: serde::Deserializer<'de>>(
	deserializer: D,
) -> Result<LocalAIBackend, D::Error> {
	let _ = serde_json::Value::deserialize(deserializer)?;
	Err(serde::de::Error::custom(
		"LLM support is not compiled; enable gateway-llm",
	))
}
