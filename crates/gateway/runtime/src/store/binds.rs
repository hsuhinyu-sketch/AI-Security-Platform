#[cfg(feature = "gateway-llm")]
use crate::types::agent::Backend;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::net::TcpListener as StdTcpListener;
use std::sync::Arc;

use ::http::HeaderValue;
use anyhow::Context;
use futures_core::Stream;
use hashbrown::{Equivalent, HashMap as HbHashMap};
use itertools::Itertools;
use tokio::sync::watch;
use tracing::{Level, instrument, warn};

use crate::cel::ContextBuilder;
use crate::http::auth::BackendAuth;
use crate::http::authorization::{HTTPAuthorizationSet, NetworkAuthorizationSet};
use crate::http::backendtls::BackendTLS;
use crate::http::ext_proc::InferenceRouting;
use crate::http::{ext_authz, ext_proc, filters, health, oidc, remoteratelimit, retry, timeout};
use crate::llm::policy::ResponseGuard;
use crate::mcp::McpAuthorizationSet;
use crate::proxy::dtrace;
use crate::proxy::httpproxy::PolicyClient;
use crate::store::{BackendPolicy, HasExpressions, PolicyExpressions, RequestPolicy};
use crate::types::agent::{
	A2aPolicy, BackendKey, BackendTargetRef, BackendTrafficPolicy, BackendWithPolicies, Bind,
	BindKey, FrontendPolicy, JwtAuthentication, Listener, ListenerKey, ListenerName,
	McpAuthentication, PolicyInheritance, PolicyKey, PolicyTarget, Route, RouteGroupKey, RouteKey,
	RouteName, RouteSet, TCPRoute, TCPRouteSet, TargetedPolicy, TrafficPolicy,
};
use crate::types::discovery::NamespacedHostname;
use crate::types::{agent, frontend};
use crate::*;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum RouteTarget {
	Listener(ListenerKey),
	Service(NamespacedHostname),
	RouteGroup(RouteGroupKey),
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum RouteTargetRef<'a> {
	Listener(&'a str),
	Service {
		namespace: &'a str,
		hostname: &'a str,
	},
	RouteGroup(&'a str),
}

impl Equivalent<RouteTarget> for RouteTargetRef<'_> {
	fn equivalent(&self, key: &RouteTarget) -> bool {
		self == &RouteTargetRef::from(key)
	}
}

impl<'a> From<&'a RouteTarget> for RouteTargetRef<'a> {
	fn from(value: &'a RouteTarget) -> Self {
		match value {
			RouteTarget::Listener(listener) => RouteTargetRef::Listener(listener.as_str()),
			RouteTarget::Service(service) => RouteTargetRef::Service {
				namespace: service.namespace.as_str(),
				hostname: service.hostname.as_str(),
			},
			RouteTarget::RouteGroup(route_group) => RouteTargetRef::RouteGroup(route_group.as_str()),
		}
	}
}

#[derive(Debug)]
pub struct Store {
	a2a_revision: gateway_contracts::ConfigRevision,
	core_ids: Option<Vec<core_affinity::CoreId>>,
	binds: HashMap<BindKey, Arc<Bind>>,

	policies_by_key: HashMap<PolicyKey, Arc<TargetedPolicy>>,
	policies_by_target: hashbrown::HashMap<PolicyTarget, HashSet<PolicyKey>>,

	backends: HashMap<BackendKey, Arc<BackendWithPolicies>>,

	// Listeners we got before a Bind arrived
	pending_listeners: HashMap<BindKey, HashMap<ListenerKey, Listener>>,
	http_routes: HbHashMap<RouteTarget, Arc<RouteSet>>,
	tcp_routes: HbHashMap<RouteTarget, Arc<TCPRouteSet>>,
	listener_change_tx: watch::Sender<u64>,
	listener_change_rx: watch::Receiver<u64>,

	tx: tokio::sync::mpsc::UnboundedSender<BindEvent>,
	rx: Option<tokio::sync::mpsc::UnboundedReceiver<BindEvent>>,
}

#[derive(Debug)]
pub enum BindEvent {
	Add(Bind, BindListeners),
	Remove(BindKey),
}

#[derive(Debug)]
pub enum BindListeners {
	Single(StdTcpListener),
	PerCore(HashMap<core_affinity::CoreId, StdTcpListener>),
}

impl BindListeners {
	fn local_port(&self) -> Option<u16> {
		match self {
			Self::Single(l) => l.local_addr().ok().map(|a| a.port()),
			Self::PerCore(m) => m
				.values()
				.next()
				.and_then(|l| l.local_addr().ok())
				.map(|a| a.port()),
		}
	}
}

#[serde_with::skip_serializing_none]
#[derive(Default, Debug, Clone, serde::Serialize)]
pub struct FrontendPolices {
	pub http: Option<frontend::HTTP>,
	pub tls: Option<frontend::TLS>,
	pub tcp: Option<frontend::TCP>,
	pub network_authorization: Option<NetworkAuthorizationSet>,
	pub proxy: Option<frontend::Proxy>,
	pub connect: Option<frontend::Connect>,
	pub access_log: Option<frontend::LoggingPolicy>,
	pub tracing: Option<Arc<crate::types::agent::TracingPolicy>>,
	pub access_log_otlp: Option<Arc<crate::types::agent::AccessLogPolicy>>,
	pub metrics_fields: Option<frontend::MetricsFieldsPolicy>,
}

impl FrontendPolices {
	/// Also check trusted/control-plane values that did not pass through YAML.
	pub(crate) fn validate_compiled(&self) -> anyhow::Result<()> {
		if self.tracing.is_some() || self.access_log_otlp.is_some() {
			crate::telemetry::trc::validate_compiled()?;
		}
		if let Some(logging) = &self.access_log {
			logging.validate_compiled()?;
		}
		Ok(())
	}

	pub fn set_if_empty(&mut self, rule: &FrontendPolicy) {
		match rule {
			FrontendPolicy::HTTP(p) => {
				self.http.get_or_insert_with(|| p.clone());
			},
			FrontendPolicy::TLS(p) => {
				self.tls.get_or_insert_with(|| p.clone());
			},
			FrontendPolicy::TCP(p) => {
				self.tcp.get_or_insert_with(|| p.clone());
			},
			FrontendPolicy::NetworkAuthorization(p) => {
				if let Some(existing) = self.network_authorization.as_mut() {
					existing.merge_rule_set(p.0.clone());
				} else {
					self.network_authorization = Some(NetworkAuthorizationSet::new(vec![p.0.clone()].into()));
				}
			},
			FrontendPolicy::Proxy(p) => {
				self.proxy.get_or_insert_with(|| p.clone());
			},
			FrontendPolicy::Connect(p) => {
				self.connect.get_or_insert_with(|| p.clone());
			},
			FrontendPolicy::AccessLog(p) => {
				self.access_log.get_or_insert_with(|| p.clone());
				if let Some(alp) = &p.access_log_policy {
					self.access_log_otlp.get_or_insert_with(|| alp.clone());
				}
			},
			FrontendPolicy::Tracing(p) => {
				self.tracing.get_or_insert_with(|| p.clone());
			},
			FrontendPolicy::Metrics(p) => {
				self.metrics_fields.get_or_insert_with(|| p.clone());
			},
		}
	}
	pub fn register_cel_expressions(&self, ctx: &mut ContextBuilder) {
		if let Some(frontend::LoggingPolicy {
			filter,
			add: fields_add,
			remove: _,
			otlp,
			database,
			access_log_policy: _,
		}) = &self.access_log
		{
			if let Some(f) = filter {
				ctx.register_log_expression(f)
			}
			for (_, v) in fields_add.iter() {
				ctx.register_log_expression(v)
			}
			if let Some(database) = database {
				for (_, v) in database.add.iter() {
					ctx.register_log_expression(v)
				}
			}
			if let Some(otlp) = otlp {
				if let Some(f) = &otlp.filter {
					ctx.register_log_expression(f)
				}
				if let Some(fields) = &otlp.fields {
					for (_, v) in fields.add.iter() {
						ctx.register_log_expression(v)
					}
				}
			}
		}
		if let Some(mf) = &self.metrics_fields {
			for (_, v) in mf.add.iter() {
				ctx.register_log_expression(v)
			}
		}
	}
}

#[serde_with::skip_serializing_none]
#[derive(Default, Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BackendPolicies {
	pub backend_tls: Option<BackendTLS>,
	pub backend_auth: Option<BackendAuth>,
	pub a2a: Option<A2aPolicy>,
	#[cfg(feature = "gateway-llm")]
	pub llm_provider: Option<Arc<llm::NamedAIProvider>>,
	pub llm: Option<Arc<llm::Policy>>,
	pub inference_routing: Option<InferenceRouting>,
	pub authorization: BackendPolicy<HTTPAuthorizationSet>,
	pub ext_authz: BackendPolicy<ext_authz::ExtAuthz>,

	pub mcp_authorization: Option<McpAuthorizationSet>,
	pub mcp_authentication: Option<McpAuthentication>,
	pub mcp_guardrails: Option<Arc<crate::mcp::guardrails::McpGuardrails>>,
	pub security_pipeline: Option<types::agent::LegacySecurityPipeline>,
	pub security_audit: Option<Arc<security_integration_runtime::SecurityConfig>>,

	pub http: Option<types::backend::HTTP>,
	pub tcp: Option<types::backend::TCP>,
	pub tunnel: Option<types::backend::Tunnel>,

	pub request_header_modifier: Option<filters::HeaderModifier>,
	pub response_header_modifier: BackendPolicy<filters::HeaderModifier>,
	pub request_redirect: Option<filters::RequestRedirect>,
	pub request_mirror: Vec<filters::RequestMirror>,
	pub transformation: BackendPolicy<http::transformation_cel::Transformation>,

	pub session_persistence: Option<http::sessionpersistence::Policy>,

	pub health: Option<health::Policy>,

	/// Internal-only override for destination endpoint selection.
	/// Used for stateful MCP routing (session affinity).
	/// Not exposed through config - set programmatically only.
	pub override_dest: Option<std::net::SocketAddr>,
}

impl BackendPolicies {
	/// Model identity for security request construction; this is not execution authority.
	pub(crate) fn model_name(&self) -> Option<&str> {
		#[cfg(feature = "gateway-llm")]
		return self
			.llm_provider
			.as_ref()
			.map(|provider| provider.name.as_str());
		#[cfg(not(feature = "gateway-llm"))]
		None
	}

	pub(crate) fn validate_compiled_protocols(&self) -> Result<(), crate::proxy::ProxyError> {
		if !cfg!(feature = "gateway-llm") && self.llm.is_some() {
			return Err(crate::proxy::ProxyError::ProcessingString(
				"LLM support is not compiled; enable gateway-llm".into(),
			));
		}
		if !cfg!(feature = "inference-routing") && self.inference_routing.is_some() {
			return Err(crate::proxy::ProxyError::ProcessingString(
				"inferenceRouting is not compiled; enable inference-routing".into(),
			));
		}
		if let Some(security) = &self.security_audit {
			crate::capabilities::validate_security(security, crate::capabilities::compiled_profile())
				.map_err(crate::proxy::ProxyError::ProcessingString)?;
		}
		if !cfg!(feature = "gateway-mcp")
			&& (self.mcp_authorization.is_some()
				|| self.mcp_authentication.is_some()
				|| self.mcp_guardrails.is_some())
		{
			return Err(crate::proxy::ProxyError::ProcessingString(
				"MCP support is not compiled; enable gateway-mcp".into(),
			));
		}
		if !cfg!(feature = "gateway-a2a") && self.a2a.is_some() {
			return Err(crate::proxy::ProxyError::ProcessingString(
				"A2A support is not compiled; enable gateway-a2a".into(),
			));
		}
		Ok(())
	}

	// Merges self and other. Other has precedence
	pub fn merge(self, other: BackendPolicies) -> BackendPolicies {
		Self {
			backend_tls: other.backend_tls.or(self.backend_tls),
			backend_auth: other.backend_auth.or(self.backend_auth),
			a2a: other.a2a.or(self.a2a),
			#[cfg(feature = "gateway-llm")]
			llm_provider: other.llm_provider.or(self.llm_provider),
			llm: other.llm.or(self.llm),
			authorization: match (
				self.authorization.into_arc(),
				other.authorization.into_arc(),
			) {
				(Some(left), Some(right)) => BackendPolicy::from_arc(Arc::new(
					Arc::unwrap_or_clone(left).merge(Arc::unwrap_or_clone(right)),
				)),
				(Some(left), None) => BackendPolicy::from_arc(left),
				(None, Some(right)) => BackendPolicy::from_arc(right),
				(None, None) => BackendPolicy::default(),
			},
			// TODO: is this right??
			mcp_authorization: other.mcp_authorization.or(self.mcp_authorization),
			mcp_authentication: other.mcp_authentication.or(self.mcp_authentication),
			mcp_guardrails: other.mcp_guardrails.or(self.mcp_guardrails),
			security_pipeline: other.security_pipeline.or(self.security_pipeline),
			security_audit: other.security_audit.or(self.security_audit),
			inference_routing: other.inference_routing.or(self.inference_routing),
			ext_authz: other.ext_authz.or(self.ext_authz),
			http: other.http.or(self.http),
			tcp: other.tcp.or(self.tcp),
			tunnel: other.tunnel.or(self.tunnel),
			request_header_modifier: other
				.request_header_modifier
				.or(self.request_header_modifier),
			response_header_modifier: other
				.response_header_modifier
				.or(self.response_header_modifier),
			request_redirect: other.request_redirect.or(self.request_redirect),
			request_mirror: if other.request_mirror.is_empty() {
				self.request_mirror
			} else {
				other.request_mirror
			},
			transformation: other.transformation.or(self.transformation),
			session_persistence: other.session_persistence.or(self.session_persistence),
			health: other.health.or(self.health),
			override_dest: other.override_dest.or(self.override_dest),
		}
	}
	pub fn build_inference(
		&self,
		client: PolicyClient,
	) -> Option<Box<ext_proc::InferencePoolRouter>> {
		self
			.inference_routing
			.as_ref()
			.map(|inference| Box::new(inference.build(client)))
	}

	pub fn register_cel_expressions(&self, ctx: &mut ContextBuilder) {
		self.authorization.register_expressions(ctx);
		self.ext_authz.register_expressions(ctx);
		self.transformation.register_expressions(ctx);
		if let Some(llm) = self.llm.as_ref() {
			for expr in llm.expressions() {
				ctx.register_expression(expr);
			}
		}
		if let Some(health) = self.health.as_ref() {
			health.register_expressions(ctx);
		}
	}
}

#[serde_with::skip_serializing_none]
#[derive(Debug, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RoutePolicies {
	pub local_rate_limit: RequestPolicy<Vec<http::localratelimit::RateLimit>>,
	pub remote_rate_limit: RequestPolicy<remoteratelimit::RemoteRateLimit>,
	pub authorization: RequestPolicy<HTTPAuthorizationSet>,
	pub jwt: RequestPolicy<JwtAuthentication>,
	pub oidc: RequestPolicy<oidc::OidcPolicy>,
	pub basic_auth: RequestPolicy<http::basicauth::BasicAuthentication>,
	pub api_key: RequestPolicy<http::apikey::APIKeyAuthentication>,
	pub ext_authz: RequestPolicy<ext_authz::ExtAuthz>,
	pub ext_proc: RequestPolicy<ext_proc::ExtProc>,
	pub transformation: RequestPolicy<http::transformation_cel::Transformation>,
	pub csrf: RequestPolicy<http::csrf::Csrf>,
	pub direct_response: RequestPolicy<filters::DirectResponse>,

	pub llm: RequestPolicy<llm::Policy>,
	pub timeout: RequestPolicy<timeout::Policy>,
	pub retry: RequestPolicy<retry::Policy>,

	pub request_header_modifier: RequestPolicy<filters::HeaderModifier>,
	pub response_header_modifier: RequestPolicy<filters::HeaderModifier>,
	pub request_redirect: RequestPolicy<filters::RequestRedirect>,
	pub url_rewrite: RequestPolicy<filters::UrlRewrite>,
	pub hostname_rewrite: RequestPolicy<agent::HostRedirectOverride>,
	pub request_mirror: RequestPolicy<Vec<filters::RequestMirror>>,
	pub cors: RequestPolicy<http::cors::Cors>,
	pub buffer: RequestPolicy<http::buffer::Buffer>,
}

#[derive(Debug, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GatewayPolicies {
	pub cors: RequestPolicy<http::cors::Cors>,
	pub ext_proc: RequestPolicy<ext_proc::ExtProc>,
	pub oidc: RequestPolicy<oidc::OidcPolicy>,
	pub jwt: RequestPolicy<JwtAuthentication>,
	pub authorization: RequestPolicy<HTTPAuthorizationSet>,
	pub ext_authz: RequestPolicy<ext_authz::ExtAuthz>,
	pub transformation: RequestPolicy<http::transformation_cel::Transformation>,
	pub basic_auth: RequestPolicy<http::basicauth::BasicAuthentication>,
	pub api_key: RequestPolicy<http::apikey::APIKeyAuthentication>,
	pub buffer: RequestPolicy<http::buffer::Buffer>,
}

impl GatewayPolicies {
	pub fn iter(&self) -> impl Iterator<Item = &dyn PolicyExpressions> {
		[
			&self.cors as &dyn PolicyExpressions,
			&self.ext_proc as &dyn PolicyExpressions,
			&self.oidc as &dyn PolicyExpressions,
			&self.jwt as &dyn PolicyExpressions,
			&self.authorization as &dyn PolicyExpressions,
			&self.ext_authz as &dyn PolicyExpressions,
			&self.transformation as &dyn PolicyExpressions,
			&self.basic_auth as &dyn PolicyExpressions,
			&self.api_key as &dyn PolicyExpressions,
		]
		.into_iter()
	}

	pub fn register_cel_expressions(&self, ctx: &mut ContextBuilder) {
		for policy in self.iter() {
			policy.register_expressions(ctx);
		}
	}
}

impl RoutePolicies {
	pub fn iter(&self) -> impl Iterator<Item = &dyn PolicyExpressions> {
		[
			&self.local_rate_limit as &dyn PolicyExpressions,
			&self.remote_rate_limit as &dyn PolicyExpressions,
			&self.authorization as &dyn PolicyExpressions,
			&self.jwt as &dyn PolicyExpressions,
			&self.oidc as &dyn PolicyExpressions,
			&self.basic_auth as &dyn PolicyExpressions,
			&self.api_key as &dyn PolicyExpressions,
			&self.ext_authz as &dyn PolicyExpressions,
			&self.ext_proc as &dyn PolicyExpressions,
			&self.transformation as &dyn PolicyExpressions,
			&self.csrf as &dyn PolicyExpressions,
			&self.direct_response as &dyn PolicyExpressions,
			&self.llm as &dyn PolicyExpressions,
			&self.request_header_modifier as &dyn PolicyExpressions,
			&self.retry as &dyn PolicyExpressions,
			&self.request_redirect as &dyn PolicyExpressions,
			&self.url_rewrite as &dyn PolicyExpressions,
			&self.cors as &dyn PolicyExpressions,
		]
		.into_iter()
	}

	pub fn register_cel_expressions(&self, ctx: &mut ContextBuilder) {
		for policy in self.iter() {
			policy.register_expressions(ctx);
		}
	}
}

#[derive(Debug, Default, Clone)]
pub struct LLMRequestPolicies {
	pub local_rate_limit: Option<Arc<Vec<http::localratelimit::RateLimit>>>,
	pub remote_rate_limit: Option<Arc<http::remoteratelimit::RemoteRateLimit>>,
	pub llm: Option<Arc<llm::Policy>>,
}

impl LLMRequestPolicies {
	pub fn requires_content_adapter(&self) -> bool {
		self
			.llm
			.as_ref()
			.and_then(|p| p.prompt_guard.as_ref())
			.is_some_and(|g| !g.request.is_empty() || !g.response.is_empty())
	}

	/// Selected controls that cannot execute on an opaque request/response body.
	pub fn requires_structured_adapter(&self) -> bool {
		self.llm.as_ref().is_some_and(|p| {
			p.prompt_guard
				.as_ref()
				.is_some_and(|g| !g.request.is_empty() || !g.response.is_empty())
				|| p.defaults.as_ref().is_some_and(|m| !m.is_empty())
				|| p.overrides.as_ref().is_some_and(|m| !m.is_empty())
				|| p.transformations.as_ref().is_some_and(|m| !m.is_empty())
				|| p
					.prompts
					.as_ref()
					.is_some_and(|p| !p.append.is_empty() || !p.prepend.is_empty())
				|| !p.model_aliases.is_empty()
				|| p.prompt_caching.is_some()
				|| p.streaming_limits.is_some()
		}) || self
			.local_rate_limit
			.as_deref()
			.into_iter()
			.flatten()
			.any(|r| r.spec.limit_type == http::localratelimit::RateLimitType::Tokens)
			|| self.remote_rate_limit.as_ref().is_some_and(|r| {
				r.descriptors
					.0
					.iter()
					.any(|d| d.limit_type == http::localratelimit::RateLimitType::Tokens)
			})
	}

	pub fn merge_backend_policies(
		self: Arc<Self>,
		be: Option<Arc<llm::Policy>>,
	) -> Arc<LLMRequestPolicies> {
		let Some(be) = be else { return self };
		let mut route_policies = Arc::unwrap_or_clone(self);
		let Some(re) = route_policies.llm.take() else {
			route_policies.llm = Some(be);
			return Arc::new(route_policies);
		};

		route_policies.llm = Some(Self::merge_llm_policies(&be, &re));
		Arc::new(route_policies)
	}

	fn merge_llm_policies(
		preferred: &Arc<llm::Policy>,
		fallback: &Arc<llm::Policy>,
	) -> Arc<llm::Policy> {
		// Preferred aliases replace fallback aliases entirely (consistent with defaults/overrides).
		let (merged_aliases, merged_wildcard_patterns) = if preferred.model_aliases.is_empty() {
			(
				fallback.model_aliases.clone(),
				Arc::clone(&fallback.wildcard_patterns),
			)
		} else {
			(
				preferred.model_aliases.clone(),
				Arc::clone(&preferred.wildcard_patterns),
			)
		};

		Arc::new(llm::Policy {
			streaming_limits: match (preferred.streaming_limits, fallback.streaming_limits) {
				(Some(a), Some(b)) => Some(a.stricter(b)),
				(a, b) => a.or(b),
			},
			prompt_guard: preferred
				.prompt_guard
				.clone()
				.or_else(|| fallback.prompt_guard.clone()),
			defaults: preferred
				.defaults
				.clone()
				.or_else(|| fallback.defaults.clone()),
			overrides: preferred
				.overrides
				.clone()
				.or_else(|| fallback.overrides.clone()),
			transformations: preferred
				.transformations
				.clone()
				.or_else(|| fallback.transformations.clone()),
			prompts: preferred
				.prompts
				.clone()
				.or_else(|| fallback.prompts.clone()),
			model_aliases: merged_aliases,
			wildcard_patterns: merged_wildcard_patterns,
			prompt_caching: preferred
				.prompt_caching
				.clone()
				.or_else(|| fallback.prompt_caching.clone()),
			routes: if preferred.routes.is_empty() {
				fallback.routes.clone()
			} else {
				preferred.routes.clone()
			},
		})
	}
}

#[derive(Debug, Default)]
pub struct LLMResponsePolicies {
	pub streaming_limits: llm::policy::streaming_limits::StreamingLimits,
	pub local_rate_limit: Vec<http::localratelimit::RateLimit>,
	pub remote_rate_limit: Option<http::remoteratelimit::LLMResponseAmend>,
	pub request_traceparent: Option<HeaderValue>,
	pub prompt_guard: Vec<ResponseGuard>,
	pub streaming_prompt_guard_enabled: bool,
}

impl Default for Store {
	fn default() -> Self {
		Self::with_ipv6_enabled(true)
	}
}

// RoutePath describes the objects traversed to reach the given route.
#[derive(Debug, Clone)]
pub struct RoutePath<'a> {
	pub listener: &'a ListenerName,
	// the originally intended service, pre-routing
	pub service: Option<&'a NamespacedHostname>,
	pub routes: Vec<&'a RouteName>,
	pub route_inlines: Vec<&'a [TrafficPolicy]>,
}

impl<'a> RoutePath<'a> {
	pub fn final_route(&self) -> Option<&'a RouteName> {
		self.routes.last().copied()
	}
}

impl Store {
	fn bind_listener_single(address: std::net::SocketAddr) -> anyhow::Result<StdTcpListener> {
		let listener =
			StdTcpListener::bind(address).with_context(|| format!("bind listener for {address}"))?;
		listener
			.set_nonblocking(true)
			.with_context(|| format!("set nonblocking on {address}"))?;
		Ok(listener)
	}

	fn bind_listener_per_core(
		core_ids: &[core_affinity::CoreId],
		address: std::net::SocketAddr,
	) -> anyhow::Result<HashMap<core_affinity::CoreId, StdTcpListener>> {
		let domain = if address.is_ipv4() {
			socket2::Domain::IPV4
		} else {
			socket2::Domain::IPV6
		};
		let mut listeners = HashMap::with_capacity(core_ids.len());
		for &core_id in core_ids {
			let socket = socket2::Socket::new(domain, socket2::Type::STREAM, None)
				.with_context(|| format!("create listener for {address} on core {}", core_id.id))?;
			#[cfg(target_family = "unix")]
			socket.set_reuse_port(true)?;
			socket
				.bind(&address.into())
				.with_context(|| format!("bind listener for {address} on core {}", core_id.id))?;
			socket
				.listen(1024)
				.with_context(|| format!("listen on {address} on core {}", core_id.id))?;
			let listener: StdTcpListener = socket.into();
			listener
				.set_nonblocking(true)
				.with_context(|| format!("set nonblocking on {address} on core {}", core_id.id))?;
			listeners.insert(core_id, listener);
		}
		Ok(listeners)
	}

	fn bind_listeners(&self, address: std::net::SocketAddr) -> anyhow::Result<BindListeners> {
		match self.core_ids.as_deref() {
			Some(core_ids) => Ok(BindListeners::PerCore(Self::bind_listener_per_core(
				core_ids, address,
			)?)),
			None => Ok(BindListeners::Single(Self::bind_listener_single(address)?)),
		}
	}

	pub fn with_ipv6_enabled(ipv6_enabled: bool) -> Self {
		Self::new(
			ipv6_enabled,
			crate::ThreadingMode::Multithreaded,
			Default::default(),
		)
	}

	pub fn new(
		_ipv6_enabled: bool,
		threading_mode: crate::ThreadingMode,
		_dynamic_ca_cert_cache: crate::DynamicCaCertCacheConfig,
	) -> Self {
		let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
		let (listener_change_tx, listener_change_rx) = watch::channel(0);
		Self {
			a2a_revision: Default::default(),
			core_ids: match threading_mode {
				crate::ThreadingMode::Multithreaded => None,
				crate::ThreadingMode::ThreadPerCore => {
					Some(core_affinity::get_core_ids().unwrap_or_default())
				},
			},
			binds: Default::default(),
			policies_by_key: Default::default(),
			policies_by_target: Default::default(),
			backends: Default::default(),
			pending_listeners: Default::default(),
			http_routes: Default::default(),
			tcp_routes: Default::default(),
			listener_change_tx,
			listener_change_rx,
			tx,
			rx: Some(rx),
		}
	}

	fn listener_target_ref(listener: &ListenerKey) -> RouteTargetRef<'_> {
		RouteTargetRef::Listener(listener.as_str())
	}

	fn service_target_ref(service: &NamespacedHostname) -> RouteTargetRef<'_> {
		RouteTargetRef::Service {
			namespace: service.namespace.as_str(),
			hostname: service.hostname.as_str(),
		}
	}

	fn route_group_target_ref(route_group: &RouteGroupKey) -> RouteTargetRef<'_> {
		RouteTargetRef::RouteGroup(route_group.as_str())
	}

	pub fn get_listener_routes(&self, listener: &ListenerKey) -> Option<Arc<RouteSet>> {
		self
			.http_routes
			.get(&Self::listener_target_ref(listener))
			.cloned()
	}

	pub fn get_listener_tcp_routes(&self, listener: &ListenerKey) -> Option<Arc<TCPRouteSet>> {
		self
			.tcp_routes
			.get(&Self::listener_target_ref(listener))
			.cloned()
	}

	pub fn subscribe_listener_changes(&self) -> watch::Receiver<u64> {
		self.listener_change_rx.clone()
	}

	pub fn get_bind_listener(&self, bind: &BindKey, listener: &ListenerKey) -> Option<Arc<Listener>> {
		self
			.binds
			.get(bind)
			.and_then(|bind| bind.listeners.inner.get(listener).cloned())
	}

	fn notify_listener_changed(&self) {
		self
			.listener_change_tx
			.send_modify(|epoch| *epoch = epoch.saturating_add(1));
	}

	fn bind_listener_changed(old: &Bind, new: &Bind) -> bool {
		for new_listener in new.listeners.iter() {
			let Some(old_listener) = old.listeners.get(&new_listener.key) else {
				// If a new listener is added, no need to notify
				continue;
			};
			if old_listener != new_listener {
				return true;
			}
		}
		for old_listener in old.listeners.iter() {
			let Some(new_listener) = new.listeners.get(&old_listener.key) else {
				// If an old listener is removed, we do need to notify!
				return true;
			};
			if old_listener != new_listener {
				return true;
			}
		}
		false
	}

	fn insert_http_route_target(&mut self, target: RouteTarget, route: Route) {
		let routes = self
			.http_routes
			.entry(target)
			.or_insert_with(|| Arc::new(RouteSet::default()));
		Arc::make_mut(routes).insert(route);
	}

	fn insert_tcp_route_target(&mut self, target: RouteTarget, route: TCPRoute) {
		let routes = self
			.tcp_routes
			.entry(target)
			.or_insert_with(|| Arc::new(TCPRouteSet::default()));
		Arc::make_mut(routes).insert(route);
	}

	fn upsert_bind(&mut self, key: BindKey, mut bind: Bind) {
		debug!(bind=%bind.key, "insert bind");
		let old_bind = self.binds.get(&key).cloned();

		for (_, listener) in self
			.pending_listeners
			.remove(&bind.key)
			.into_iter()
			.flatten()
		{
			debug!("adding pending listener {} to {}", listener.key, bind.key);
			bind.listeners.insert(listener);
		}

		let listeners = if self.binds.contains_key(&key) {
			None
		} else if bind.mode == agent::BindMode::Internal {
			// Internal binds are routing-only; they never open an OS socket and thus never
			// emit a BindEvent::Add (which is what spawns the accept loop). They are still
			// inserted into `self.binds` below so find_bind/find_bind_by_port and in-process
			// re-entry via proxy_bind can reach them.
			debug!(bind=%key, "internal bind; not opening a listener socket");
			None
		} else {
			match self.bind_listeners(bind.address) {
				Ok(listeners) => {
					// When port 0 is used, update the address with the actual bound port.
					if bind.address.port() == 0
						&& let Some(actual_port) = listeners.local_port()
					{
						bind.address.set_port(actual_port);
					}
					Some(listeners)
				},
				Err(err) => {
					warn!(bind=%key, address=%bind.address, error=%err, "failed to start bind listener");
					None
				},
			}
		};
		if let Some(old_bind) = old_bind.as_deref()
			&& Self::bind_listener_changed(old_bind, &bind)
		{
			self.notify_listener_changed();
		}
		self.binds.insert(key.clone(), Arc::new(bind.clone()));
		if let Some(listeners) = listeners {
			let _ = self.tx.send(BindEvent::Add(bind, listeners));
		}
	}

	pub fn subscribe(&mut self) -> impl Stream<Item = BindEvent> + use<> {
		let sub = self.rx.take().expect("bind subscriber already taken");
		tokio_stream::wrappers::UnboundedReceiverStream::new(sub)
	}

	pub fn route_policies(&self, path: &RoutePath<'_>) -> RoutePolicies {
		let listener = &path.listener;
		let gateway = self
			.policies_by_target
			.get(&listener.as_gateway_target_ref());
		let listener = self
			.policies_by_target
			.get(&listener.as_listener_target_ref());
		let service = path
			.service
			.and_then(|s| self.policies_by_target.get(&s.as_policy_target_ref()));

		let mut route_rules = Vec::new();
		for (idx, route) in path.routes.iter().enumerate() {
			route_rules.extend(
				self
					.policies_by_target
					.get(&route.as_route_target_ref())
					.into_iter()
					.flatten()
					.filter_map(|n| self.policies_by_key.get(n))
					.filter_map(|p| {
						p.policy
							.as_traffic_route_phase()
							.map(|inner| (p.inheritance, inner))
					}),
			);
			route_rules.extend(
				self
					.policies_by_target
					.get(&route.as_route_rule_target_ref())
					.into_iter()
					.flatten()
					.filter_map(|n| self.policies_by_key.get(n))
					.filter_map(|p| {
						p.policy
							.as_traffic_route_phase()
							.map(|inner| (p.inheritance, inner))
					}),
			);
			if let Some(inline) = path.route_inlines.get(idx) {
				route_rules.extend(inline.iter().map(|p| (PolicyInheritance::Default, p)));
			}
		}

		let shared_rules = gateway
			.iter()
			.copied()
			.flatten()
			.chain(listener.iter().copied().flatten())
			.chain(service.iter().copied().flatten())
			.filter_map(|n| self.policies_by_key.get(n))
			.filter_map(|p| {
				p.policy
					.as_traffic_route_phase()
					.map(|inner| (p.inheritance, inner))
			});

		let rules = shared_rules.chain(route_rules);

		let mut authz = Vec::new();
		let mut authz_locked = false;
		let mut pol = RoutePolicies::default();
		for (inheritance, rule) in rules {
			let lock_inheritance = inheritance == PolicyInheritance::Override;
			match rule {
				TrafficPolicy::LocalRateLimit(p) => {
					pol
						.local_rate_limit
						.merge_with_inheritance(p, lock_inheritance);
				},
				TrafficPolicy::ExtAuthz(p) => {
					pol.ext_authz.merge_with_inheritance(p, lock_inheritance);
				},
				TrafficPolicy::ExtProc(p) => {
					pol.ext_proc.merge_with_inheritance(p, lock_inheritance);
				},
				TrafficPolicy::RemoteRateLimit(p) => {
					pol
						.remote_rate_limit
						.merge_with_inheritance(p, lock_inheritance);
				},
				TrafficPolicy::JwtAuth(p) => {
					pol.jwt.merge_with_inheritance(p, lock_inheritance);
				},
				TrafficPolicy::Oidc(p) => {
					pol.oidc.merge_with_inheritance(p, lock_inheritance);
				},
				TrafficPolicy::BasicAuth(p) => {
					pol.basic_auth.merge_with_inheritance(p, lock_inheritance);
				},
				TrafficPolicy::APIKey(p) => {
					pol.api_key.merge_with_inheritance(p, lock_inheritance);
				},
				TrafficPolicy::Transformation(p) => {
					pol
						.transformation
						.merge_with_inheritance(p, lock_inheritance);
				},
				TrafficPolicy::Authorization(p) => {
					if !authz_locked {
						authz.push(p.clone().0);
						authz_locked = lock_inheritance;
					}
				},
				TrafficPolicy::AI(p) => {
					pol
						.llm
						.merge_with_inheritance(&RequestPolicy::single_arc(p.clone()), lock_inheritance);
				},
				TrafficPolicy::Csrf(p) => {
					pol.csrf.merge_with_inheritance(p, lock_inheritance);
				},

				TrafficPolicy::Timeout(p) => {
					pol
						.timeout
						.merge_with_inheritance(&RequestPolicy::single(p.clone()), lock_inheritance);
				},
				TrafficPolicy::Retry(p) => {
					pol
						.retry
						.merge_with_inheritance(&RequestPolicy::single(p.clone()), lock_inheritance);
				},
				TrafficPolicy::RequestHeaderModifier(p) => {
					pol
						.request_header_modifier
						.merge_with_inheritance(p, lock_inheritance);
				},
				TrafficPolicy::ResponseHeaderModifier(p) => {
					pol
						.response_header_modifier
						.merge_with_inheritance(p, lock_inheritance);
				},
				TrafficPolicy::RequestRedirect(p) => {
					pol
						.request_redirect
						.merge_with_inheritance(p, lock_inheritance);
				},
				TrafficPolicy::UrlRewrite(p) => {
					pol.url_rewrite.merge_with_inheritance(p, lock_inheritance);
				},
				TrafficPolicy::HostRewrite(p) => {
					pol
						.hostname_rewrite
						.merge_with_inheritance(&RequestPolicy::single(*p), lock_inheritance);
				},
				TrafficPolicy::RequestMirror(p) => {
					pol
						.request_mirror
						.merge_with_inheritance(&RequestPolicy::single(p.clone()), lock_inheritance);
				},
				TrafficPolicy::DirectResponse(p) => {
					pol
						.direct_response
						.merge_with_inheritance(p, lock_inheritance);
				},
				TrafficPolicy::CORS(p) => {
					pol.cors.merge_with_inheritance(p, lock_inheritance);
				},
				TrafficPolicy::Buffer(p) => {
					pol.buffer.set_if_unset(p);
				},
			}
		}
		if !authz.is_empty() {
			pol.authorization = RequestPolicy::single(HTTPAuthorizationSet::new(
				crate::http::authorization::RuleSets::from_arcs(authz),
			));
		}
		dtrace::trace(|t| {
			let s = serde_json::to_value(&pol).unwrap_or_default();
			t.selected_policies("route", s)
		});

		pol
	}

	pub fn gateway_policies(&self, name: &ListenerName) -> GatewayPolicies {
		let gateway = self.policies_by_target.get(&name.as_gateway_target_ref());
		let listener = self.policies_by_target.get(&name.as_listener_target_ref());
		let listener_set = name
			.as_listenerset_target_ref()
			.and_then(|r| self.policies_by_target.get(&r));
		let listener_set_section = name
			.as_listenerset_listener_target_ref()
			.and_then(|r| self.policies_by_target.get(&r));
		let rules = listener
			.iter()
			.copied()
			.flatten()
			.chain(listener_set_section.iter().copied().flatten())
			.chain(listener_set.iter().copied().flatten())
			.chain(gateway.iter().copied().flatten())
			.filter_map(|n| self.policies_by_key.get(n))
			.filter_map(|p| p.policy.as_traffic_gateway_phase());

		let mut authz = Vec::new();
		let mut pol = GatewayPolicies::default();
		for rule in rules {
			match rule {
				TrafficPolicy::CORS(p) => {
					pol.cors.set_if_unset(p);
				},
				TrafficPolicy::Oidc(p) => {
					pol.oidc.set_if_unset(p);
				},
				TrafficPolicy::JwtAuth(p) => {
					pol.jwt.set_if_unset(p);
				},
				TrafficPolicy::BasicAuth(p) => {
					pol.basic_auth.set_if_unset(p);
				},
				TrafficPolicy::APIKey(p) => {
					pol.api_key.set_if_unset(p);
				},
				TrafficPolicy::Authorization(p) => {
					authz.push(p.clone().0);
				},
				TrafficPolicy::ExtAuthz(p) => {
					pol.ext_authz.set_if_unset(p);
				},
				TrafficPolicy::ExtProc(p) => {
					pol.ext_proc.set_if_unset(p);
				},
				TrafficPolicy::Transformation(p) => {
					pol.transformation.set_if_unset(p);
				},
				other => {
					warn!("unexpected gateway policy: {:?}", other);
				},
			}
		}
		if !authz.is_empty() {
			pol.authorization = RequestPolicy::single(HTTPAuthorizationSet::new(
				crate::http::authorization::RuleSets::from_arcs(authz),
			));
		}
		dtrace::trace(|t| {
			let s = serde_json::to_value(&pol).unwrap_or_default();
			t.selected_policies("gateway", s)
		});

		pol
	}

	// sub_backend_policies looks up the sub-backends policies. Generally, these will be queried separately
	// from the primary backend policies and then merged, just due to the lifecycle of when the sub-backend
	// is selected.
	pub fn sub_backend_policies(
		&self,
		sub_backend: BackendTargetRef,
		inline_policies: Option<&[BackendTrafficPolicy]>,
	) -> BackendPolicies {
		self.internal_backend_policies(
			"subBackend",
			None,
			Some(sub_backend),
			if let Some(s) = &inline_policies {
				std::slice::from_ref(s)
			} else {
				&[]
			},
			None,
			&[],
		)
	}

	// inline_backend_policies flattens out a list of inline policies,
	pub fn inline_backend_policies(
		&self,
		inline_policies: &[BackendTrafficPolicy],
	) -> BackendPolicies {
		self.internal_backend_policies(
			"inlineBackend",
			None,
			None,
			std::slice::from_ref(&inline_policies),
			None,
			&[],
		)
	}

	pub fn backend_policies(
		&self,
		backend: BackendTargetRef,
		inline_policies: &[&[BackendTrafficPolicy]],
		path: Option<RoutePath>,
	) -> BackendPolicies {
		let phase = match backend {
			BackendTargetRef::Backend {
				section: Some(_), ..
			}
			| BackendTargetRef::Service { port: Some(_), .. } => "subBackend",
			_ => "backend",
		};
		self.internal_backend_policies(
			phase,
			Some(backend.strip_section()),
			Some(backend.clone()),
			inline_policies,
			path.as_ref().map(|p| p.listener),
			path.as_ref().map(|p| p.routes.as_slice()).unwrap_or(&[]),
		)
	}

	#[allow(clippy::too_many_arguments)]
	fn internal_backend_policies(
		&self,
		phase: &str,
		// backend with section stripped, always
		backend: Option<BackendTargetRef>,
		// backend with section retained.
		// Note this differs from other types, where just one is passed in and we strip them
		sub_backend: Option<BackendTargetRef>,
		inline_policies: &[&[BackendTrafficPolicy]],
		gateway: Option<&ListenerName>,
		routes: &[&RouteName],
	) -> BackendPolicies {
		let backend_rules =
			backend.and_then(|t| self.policies_by_target.get(&PolicyTargetRef::Backend(t)));
		let sub_backend_rules =
			sub_backend.and_then(|t| self.policies_by_target.get(&PolicyTargetRef::Backend(t)));
		let listener_rules =
			gateway.and_then(|t| self.policies_by_target.get(&t.as_listener_target_ref()));
		let gateway_rules =
			gateway.and_then(|t| self.policies_by_target.get(&t.as_gateway_target_ref()));

		// Collect route policies across the full delegation chain, child (most specific) first.
		// For each route: rule-level before route-level, matching route_policies() ordering.
		let mut route_based_keys: Vec<&PolicyKey> = Vec::new();
		for route in routes.iter().rev() {
			if let Some(keys) = self
				.policies_by_target
				.get(&route.as_route_rule_target_ref())
			{
				route_based_keys.extend(keys.iter());
			}
			if let Some(keys) = self.policies_by_target.get(&route.as_route_target_ref()) {
				route_based_keys.extend(keys.iter());
			}
		}

		// Route chain (child->parent) > SubBackend > Backend/Service > Gateway
		let rules = route_based_keys
			.into_iter()
			.chain(sub_backend_rules.iter().copied().flatten())
			.chain(backend_rules.iter().copied().flatten())
			.chain(listener_rules.iter().copied().flatten())
			.chain(gateway_rules.iter().copied().flatten())
			.unique()
			.filter_map(|n| self.policies_by_key.get(n))
			.filter_map(|p| p.policy.as_backend());
		let rules = inline_policies
			.iter()
			.rev()
			.flat_map(|p| p.iter())
			.chain(rules);

		let mut authz = Vec::new();
		let mut mcp_authz = Vec::new();
		let mut pol = BackendPolicies::default();
		for rule in rules {
			match &rule {
				BackendTrafficPolicy::Authorization(p) => {
					authz.push(p.clone().0);
				},
				BackendTrafficPolicy::A2a(p) => {
					pol.a2a.get_or_insert_with(|| p.clone());
				},
				BackendTrafficPolicy::BackendTLS(p) => {
					pol.backend_tls.get_or_insert_with(|| p.clone());
				},
				BackendTrafficPolicy::BackendAuth(p) => {
					pol.backend_auth.get_or_insert_with(|| p.clone());
				},
				BackendTrafficPolicy::InferenceRouting(p) => {
					pol.inference_routing.get_or_insert_with(|| p.clone());
				},
				BackendTrafficPolicy::ExtAuthz(p) => {
					pol.ext_authz.set_if_unset(p);
				},
				BackendTrafficPolicy::AI(p) => {
					pol.llm = Some(match pol.llm.take() {
						Some(existing) => LLMRequestPolicies::merge_llm_policies(&existing, p),
						None => p.clone(),
					});
				},

				BackendTrafficPolicy::HTTP(p) => {
					pol.http.get_or_insert_with(|| p.clone());
				},
				BackendTrafficPolicy::TCP(p) => {
					pol.tcp.get_or_insert_with(|| p.clone());
				},
				BackendTrafficPolicy::Tunnel(p) => {
					pol.tunnel.get_or_insert_with(|| p.clone());
				},

				BackendTrafficPolicy::RequestHeaderModifier(p) => {
					pol.request_header_modifier.get_or_insert_with(|| p.clone());
				},
				BackendTrafficPolicy::ResponseHeaderModifier(p) => {
					pol.response_header_modifier.set_if_unset(p);
				},
				BackendTrafficPolicy::RequestRedirect(p) => {
					pol.request_redirect.get_or_insert_with(|| p.clone());
				},
				BackendTrafficPolicy::Transformation(p) => {
					pol.transformation.set_if_unset(p);
				},
				BackendTrafficPolicy::SessionPersistence(p) => {
					pol.session_persistence.get_or_insert_with(|| p.clone());
				},
				BackendTrafficPolicy::Health(p) => {
					pol.health.get_or_insert_with(|| p.clone());
				},
				BackendTrafficPolicy::RequestMirror(p) => {
					if pol.request_mirror.is_empty() {
						pol.request_mirror = p.clone();
					}
				},
				BackendTrafficPolicy::McpAuthorization(p) => {
					// Authorization policies merge, unlike others
					mcp_authz.push(p.clone().into_inner());
				},
				BackendTrafficPolicy::McpAuthentication(p) => {
					pol.mcp_authentication.get_or_insert_with(|| p.clone());
				},
				BackendTrafficPolicy::McpGuardrails(p) => {
					pol.mcp_guardrails.get_or_insert_with(|| p.clone());
				},
				BackendTrafficPolicy::SecurityPipeline(p) => {
					pol.security_pipeline.get_or_insert_with(|| p.clone());
				},
				BackendTrafficPolicy::SecurityAudit(p) => {
					pol.security_audit.get_or_insert_with(|| p.clone());
				},
			}
		}
		if !authz.is_empty() {
			pol.authorization = BackendPolicy::from_arc(Arc::new(HTTPAuthorizationSet::new(
				crate::http::authorization::RuleSets::from_arcs(authz),
			)));
		}
		if !mcp_authz.is_empty() {
			pol.mcp_authorization = Some(McpAuthorizationSet::new(mcp_authz.into()));
		}
		dtrace::trace(|t| {
			let s = serde_json::to_value(&pol).unwrap_or_default();
			t.selected_policies(phase, s)
		});
		pol
	}

	pub fn all_shutdown_policies(&self) -> Vec<Box<dyn FnOnce() + Send + Sync + 'static>> {
		type ShutdownPolicy = Box<dyn FnOnce() + Send + Sync + 'static>;

		self
			.policies_by_key
			.values()
			.filter_map(|v| v.policy.as_frontend())
			.filter_map(|v| -> Option<ShutdownPolicy> {
				match v {
					#[cfg(feature = "telemetry-otlp")]
					FrontendPolicy::Tracing(t) => {
						let tracer_policy = Arc::clone(t);
						Some(Box::new(move || {
							if let Some(t) = tracer_policy.tracer.get() {
								t.shutdown()
							}
						}) as ShutdownPolicy)
					},
					#[cfg(feature = "telemetry-otlp")]
					FrontendPolicy::AccessLog(t) => {
						let access_log_policy = t.access_log_policy.clone();
						Some(Box::new(move || {
							if let Some(t) = access_log_policy.as_ref().and_then(|l| l.logger.get()) {
								t.shutdown()
							}
						}) as ShutdownPolicy)
					},
					_ => None,
				}
			})
			.collect_vec()
	}

	pub fn all_access_log_policies(&self) -> Vec<Arc<crate::types::agent::AccessLogPolicy>> {
		self
			.binds
			.values()
			.flat_map(|bind| {
				bind.listeners.iter().map(|listener| {
					self.listener_frontend_policies(&listener.name, Some(bind.address.port()), None)
				})
			})
			.filter_map(|fp| fp.access_log_otlp)
			.unique_by(|p| Arc::as_ptr(p) as usize)
			.collect_vec()
	}

	pub fn frontend_policies(&self, gateway: PolicyTargetRef) -> FrontendPolices {
		let gw_rules = self.policies_by_target.get(&gateway);
		let parent_gateway = match gateway {
			PolicyTargetRef::Gateway {
				gateway_name,
				gateway_namespace,
				listener_name: None,
				port: Some(_),
			} => self.policies_by_target.get(&PolicyTargetRef::Gateway {
				gateway_name,
				gateway_namespace,
				listener_name: None,
				port: None,
			}),
			_ => None,
		};
		let rules = gw_rules
			.iter()
			.copied()
			.flatten()
			.chain(parent_gateway.iter().copied().flatten())
			.filter_map(|n| self.policies_by_key.get(n))
			.filter_map(|p| p.policy.as_frontend());

		let mut pol = FrontendPolices::default();
		rules.for_each(|r| pol.set_if_empty(r));
		dtrace::trace(|t| {
			let s = serde_json::to_value(&pol).unwrap_or_default();
			t.selected_policies("frontend", s)
		});
		pol
	}

	pub fn listener_frontend_policies(
		&self,
		name: &ListenerName,
		port: Option<u16>,
		service: Option<PolicyTargetRef>,
	) -> FrontendPolices {
		let gateway = self.policies_by_target.get(&name.as_gateway_target_ref());
		let listener = self.policies_by_target.get(&name.as_listener_target_ref());
		let listener_set = name
			.as_listenerset_target_ref()
			.and_then(|r| self.policies_by_target.get(&r));
		let listener_set_section = name
			.as_listenerset_listener_target_ref()
			.and_then(|r| self.policies_by_target.get(&r));
		let svc = service.and_then(|s| self.policies_by_target.get(&s));
		let gateway_port = port.and_then(|port| {
			self.policies_by_target.get(&PolicyTargetRef::Gateway {
				gateway_name: name.gateway_name.as_ref(),
				gateway_namespace: name.gateway_namespace.as_ref(),
				listener_name: None,
				port: Some(port),
			})
		});
		let rules = svc
			.iter()
			.copied()
			.flatten()
			.chain(listener.iter().copied().flatten())
			.chain(listener_set_section.iter().copied().flatten())
			.chain(listener_set.iter().copied().flatten())
			.chain(gateway_port.iter().copied().flatten())
			.chain(gateway.iter().copied().flatten())
			.filter_map(|n| self.policies_by_key.get(n))
			.filter_map(|p| p.policy.as_frontend());
		let mut pol = FrontendPolices::default();
		rules.for_each(|r| pol.set_if_empty(r));
		dtrace::trace(|t| {
			let s = serde_json::to_value(&pol).unwrap_or_default();
			t.selected_policies("listenerFrontend", s)
		});
		pol
	}

	pub fn bind(&self, bind: &BindKey) -> Option<Arc<Bind>> {
		self.binds.get(bind).cloned()
	}

	pub fn bind_addresses(&self) -> Vec<std::net::SocketAddr> {
		self.binds.values().map(|b| b.address).collect()
	}

	/// find_bind looks up a bind by address. Typically, this is done by the kernel for us, but in some cases
	/// we do userspace routing to a bind.
	pub fn find_bind(&self, want: SocketAddr) -> Option<Arc<Bind>> {
		self
			.binds
			.values()
			.find(|b| {
				let have = b.address;
				if have.ip().is_unspecified() {
					have.port() == want.port()
				} else {
					have == want
				}
			})
			.cloned()
	}

	pub fn find_bind_by_port(&self, port: u16) -> Option<Arc<Bind>> {
		self
			.binds
			.values()
			.find(|b| b.address.port() == port)
			.cloned()
	}

	/// find_wildcard_bind returns the internal wildcard bind, if one is configured. This is the
	/// catch-all used for CONNECT re-entry when no other bind matches the destination port, so a
	/// single internal listener (with a dynamic backend) can serve any destination port.
	///
	/// Local config enforces at most one wildcard bind.
	/// several. Select the lowest key so the choice is deterministic rather than dependent on
	/// HashMap iteration order.
	pub fn find_wildcard_bind(&self) -> Option<Arc<Bind>> {
		self
			.binds
			.values()
			.filter(|b| b.is_wildcard())
			.min_by(|a, b| a.key.cmp(&b.key))
			.cloned()
	}

	pub fn all_policies(&self) -> Vec<Arc<TargetedPolicy>> {
		self.policies_by_key.values().cloned().collect()
	}

	pub fn backend(&self, r: &BackendKey) -> Option<Arc<BackendWithPolicies>> {
		self.backends.get(r).cloned()
	}

	#[instrument(
        level = Level::INFO,
        name="remove_bind",
        skip_all,
        fields(bind),
    )]
	pub fn remove_bind(&mut self, bind: BindKey) {
		self.binds.remove(&bind);
		let _ = self.tx.send(BindEvent::Remove(bind));
	}
	#[instrument(
        level = Level::INFO,
        name="remove_policy",
        skip_all,
        fields(bind),
    )]
	pub fn remove_policy(&mut self, pol: PolicyKey) {
		if let Some(old) = self.policies_by_key.remove(&pol)
			&& let Some(o) = self.policies_by_target.get_mut(&old.target)
		{
			o.remove(&pol);
		}
	}
	#[instrument(
        level = Level::INFO,
        name="remove_backend",
        skip_all,
        fields(bind),
    )]
	pub fn remove_backend(&mut self, backend: BackendKey) {
		self.backends.remove(&backend);
	}

	#[instrument(
        level = Level::INFO,
        name="remove_listener",
        skip_all,
        fields(listener),
    )]
	pub fn remove_listener(&mut self, listener: ListenerKey) {
		let Some((bind_key, bind)) = self.binds.iter().find_map(|(bind_key, bind)| {
			bind
				.listeners
				.contains(&listener)
				.then(|| (bind_key.clone(), bind.clone()))
		}) else {
			return;
		};
		let mut bind = Arc::unwrap_or_clone(bind);
		bind.listeners.remove(&listener);
		self.upsert_bind(bind_key, bind);
	}

	pub fn remove_route_group(&mut self, rg: RouteGroupKey) {
		self.http_routes.remove(&Self::route_group_target_ref(&rg));
	}

	pub fn lookup_route_group(&self, route: &RouteGroupKey) -> Option<Arc<RouteSet>> {
		self
			.http_routes
			.get(&Self::route_group_target_ref(route))
			.cloned()
	}

	fn remove_http_route(&mut self, route_key: &RouteKey) -> bool {
		let mut found = false;
		self.http_routes.retain(|_target, route_set| {
			if route_set.contains(route_key) {
				Arc::make_mut(route_set).remove(route_key);
				found = true;
			}
			!route_set.is_empty()
		});
		found
	}

	fn remove_tcp_route_from_targets(&mut self, route_key: &RouteKey) -> bool {
		let mut found = false;
		self.tcp_routes.retain(|_target, route_set| {
			if route_set.contains(route_key) {
				Arc::make_mut(route_set).remove(route_key);
				found = true;
			}
			!route_set.is_empty()
		});
		found
	}

	#[instrument(
        level = Level::INFO,
        name="remove_route",
        skip_all,
        fields(route),
    )]
	pub fn remove_route(&mut self, route: RouteKey) {
		self.remove_http_route(&route);
	}

	#[instrument(
        level = Level::INFO,
        name="remove_tcp_route",
        skip_all,
        fields(tcp_route),
    )]
	pub fn remove_tcp_route(&mut self, tcp_route: RouteKey) {
		self.remove_tcp_route_from_targets(&tcp_route);
	}

	#[instrument(
        level = Level::INFO,
        name="insert_bind",
        skip_all,
        fields(bind=%bind.key),
    )]
	pub fn insert_bind(&mut self, bind: Bind) {
		let key = bind.key.clone();
		self.upsert_bind(key, bind);
	}

	pub fn insert_backend(&mut self, key: BackendKey, b: BackendWithPolicies) {
		#[cfg(feature = "gateway-llm")]
		if let Backend::AI(_, t) = &b.backend
			&& t.providers.any(|p| p.tokenize)
		{
			preload_tokenizers()
		}
		let arc = Arc::new(b);
		self.backends.insert(key, arc);
	}

	pub fn insert_policy(&mut self, pol: TargetedPolicy) {
		let pol = Arc::new(pol);
		if let Some(old) = self.policies_by_key.insert(pol.key.clone(), pol.clone()) {
			// Remove the old target. We may add it back, though.
			if let Some(o) = self.policies_by_target.get_mut(&old.target) {
				o.remove(&pol.key);
			}
		}
		self
			.policies_by_target
			.entry(pol.target.clone())
			.or_default()
			.insert(pol.key.clone());
	}

	pub fn insert_listener(&mut self, lis: Listener, bind_name: BindKey) {
		debug!(listener=%lis.key,bind=%bind_name, "insert listener");
		if let Some(b) = self.binds.get(&bind_name) {
			let mut bind = Arc::unwrap_or_clone(b.clone());
			bind.listeners.remove(&lis.key);
			bind.listeners.insert(lis);
			self.upsert_bind(bind_name, bind);
		} else {
			debug!("no bind found, keeping listener pending");
			self
				.pending_listeners
				.entry(bind_name)
				.or_default()
				.insert(lis.key.clone(), lis);
		}
	}

	pub fn insert_route_into_group(&mut self, r: Route, ln: RouteGroupKey) {
		debug!(group=%ln, route=%r.key, "insert route");
		self.insert_http_route_target(RouteTarget::RouteGroup(ln), r);
	}

	pub fn insert_route(&mut self, r: Route, ln: ListenerKey) {
		debug!(listener=%ln, route=%r.key, "insert route");
		self.insert_http_route_target(RouteTarget::Listener(ln), r);
	}

	pub fn insert_tcp_route(&mut self, r: TCPRoute, ln: ListenerKey) {
		debug!(listener=%ln,route=%r.key, "insert tcp route");
		self.insert_tcp_route_target(RouteTarget::Listener(ln), r);
	}

	pub fn insert_service_route(&mut self, r: Route, service_key: NamespacedHostname) {
		debug!(service=%service_key, route=%r.key, "insert service route");
		self.insert_http_route_target(RouteTarget::Service(service_key), r);
	}

	pub fn insert_service_tcp_route(&mut self, r: TCPRoute, service_key: NamespacedHostname) {
		debug!(service=%service_key, route=%r.key, "insert service tcp route");
		self.insert_tcp_route_target(RouteTarget::Service(service_key), r);
	}

	pub fn get_service_routes(&self, key: &NamespacedHostname) -> Option<Arc<RouteSet>> {
		self
			.http_routes
			.get(&Self::service_target_ref(key))
			.cloned()
	}

	pub fn get_service_tcp_routes(&self, key: &NamespacedHostname) -> Option<Arc<TCPRouteSet>> {
		self.tcp_routes.get(&Self::service_target_ref(key)).cloned()
	}
}

#[derive(Clone, Debug)]
pub struct StoreUpdater {
	state: Arc<RwLock<Store>>,
}

/// Invalidation is published under the same write lock as the committed configuration.
pub struct StoreWriteGuard<'a> {
	guard: std::sync::RwLockWriteGuard<'a, Store>,
	before: Option<[u8; 32]>,
}
impl std::ops::Deref for StoreWriteGuard<'_> {
	type Target = Store;
	fn deref(&self) -> &Store {
		&self.guard
	}
}
impl std::ops::DerefMut for StoreWriteGuard<'_> {
	fn deref_mut(&mut self) -> &mut Store {
		&mut self.guard
	}
}
impl Drop for StoreWriteGuard<'_> {
	fn drop(&mut self) {
		if self.before.is_none() || self.before != self.guard.a2a_contract_digest() {
			self.guard.a2a_revision.invalidate();
		}
	}
}
impl Store {
	pub(crate) fn a2a_config_lease(&self) -> gateway_contracts::ConfigLease {
		self.a2a_revision.lease()
	}
	/// Store-wide conservative contract. Telemetry-only frontend policies are excluded.
	/// Snapshots are hashed in memory, never logged or persisted.
	fn a2a_contract_digest(&self) -> Option<[u8; 32]> {
		use sha2::Digest;
		fn canonical(value: &mut serde_json::Value) {
			match value {
				serde_json::Value::Object(map) => {
					map.sort_keys();
					for v in map.values_mut() {
						canonical(v);
					}
				},
				serde_json::Value::Array(array) => {
					for v in array {
						canonical(v);
					}
				},
				_ => {},
			}
		}
		fn row(value: impl serde::Serialize) -> Option<String> {
			let mut value = serde_json::to_value(value).ok()?;
			canonical(&mut value);
			serde_json::to_string(&value).ok()
		}
		let mut rows = Vec::new();
		for (key, bind) in &self.binds {
			rows.push(row(("bind", key, bind))?);
		}
		for (key, backend) in &self.backends {
			rows.push(row(("backend", key, backend))?);
		}
		for (key, policy) in &self.policies_by_key {
			if matches!(
				&policy.policy,
				agent::PolicyType::Frontend(
					FrontendPolicy::AccessLog(_) | FrontendPolicy::Tracing(_) | FrontendPolicy::Metrics(_)
				)
			) {
				continue;
			}
			rows.push(row(("policy", key, policy))?);
		}
		for (target, routes) in &self.http_routes {
			rows.push(row(("http", format!("{target:?}"), routes))?);
		}
		for (target, routes) in &self.tcp_routes {
			rows.push(row(("tcp", format!("{target:?}"), routes))?);
		}
		rows.sort_unstable();
		Some(sha2::Sha256::digest(serde_json::to_vec(&rows).ok()?).into())
	}
}
#[apply(schema_ser_schema!)]
pub struct RoutesDump {
	pub http_mesh: HashMap<NamespacedHostname, RouteSet>,
	pub tcp_mesh: HashMap<NamespacedHostname, TCPRouteSet>,
	pub route_groups: HashMap<RouteGroupKey, RouteSet>,
}

#[apply(schema_ser_schema!)]
pub struct DumpListener {
	#[serde(flatten)]
	pub listener: Listener,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub routes: Option<Arc<RouteSet>>,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub tcp_routes: Option<Arc<TCPRouteSet>>,
}

#[apply(schema_ser_schema!)]
pub struct DumpBind {
	#[serde(flatten)]
	pub bind: Arc<Bind>,
	pub listeners: BTreeMap<ListenerKey, DumpListener>,
}

#[apply(schema_ser_schema!)]
pub struct Dump {
	pub binds: Vec<DumpBind>,
	pub routes: RoutesDump,
	#[cfg_attr(feature = "schema", schemars(with = "Vec<serde_json::Value>"))]
	pub policies: Vec<Arc<TargetedPolicy>>,
	#[cfg_attr(feature = "schema", schemars(with = "Vec<serde_json::Value>"))]
	pub backends: Vec<Arc<BackendWithPolicies>>,
}

impl StoreUpdater {
	pub fn new(state: Arc<RwLock<Store>>) -> StoreUpdater {
		Self { state }
	}
	pub fn read(&self) -> std::sync::RwLockReadGuard<'_, Store> {
		self.state.read().expect("mutex acquired")
	}
	pub fn write(&self) -> StoreWriteGuard<'_> {
		let guard = self.state.write().expect("mutex acquired");
		let before = guard.a2a_contract_digest();
		StoreWriteGuard { guard, before }
	}
	pub fn dump(&self) -> Dump {
		let store = self.state.read().expect("mutex");

		// Services all have hostname, so use that as the key
		let binds: Vec<_> = store
			.binds
			.iter()
			.sorted_by_key(|k| k.0)
			.map(|(_, bind)| DumpBind {
				bind: bind.clone(),
				listeners: bind
					.listeners
					.iter()
					.map(|listener| {
						(
							listener.key.clone(),
							DumpListener {
								listener: listener.clone(),
								routes: store.get_listener_routes(&listener.key),
								tcp_routes: store.get_listener_tcp_routes(&listener.key),
							},
						)
					})
					.collect(),
			})
			.collect();
		let policies: Vec<_> = store
			.policies_by_key
			.iter()
			.sorted_by_key(|k| k.0)
			.map(|k| k.1.clone())
			.collect();
		let backends: Vec<_> = store
			.backends
			.iter()
			.sorted_by_key(|k| k.0)
			.map(|k| k.1.clone())
			.collect();
		Dump {
			binds,
			policies,
			backends,
			routes: RoutesDump {
				http_mesh: store
					.http_routes
					.iter()
					.filter_map(|(target, routes)| match target {
						RouteTarget::Service(service) => Some((service.clone(), routes.as_ref().clone())),
						_ => None,
					})
					.collect(),
				tcp_mesh: store
					.tcp_routes
					.iter()
					.filter_map(|(target, routes)| match target {
						RouteTarget::Service(service) => Some((service.clone(), routes.as_ref().clone())),
						_ => None,
					})
					.collect(),
				route_groups: store
					.http_routes
					.iter()
					.filter_map(|(target, routes)| match target {
						RouteTarget::RouteGroup(route_group) => {
							Some((route_group.clone(), routes.as_ref().clone()))
						},
						_ => None,
					})
					.collect(),
			},
		}
	}
	#[allow(clippy::too_many_arguments)]
	pub fn sync_local(
		&self,
		binds: Vec<Bind>,
		listener_routes: Vec<(ListenerKey, Vec<Route>)>,
		listener_tcp_routes: Vec<(ListenerKey, Vec<TCPRoute>)>,
		policies: Vec<TargetedPolicy>,
		backends: Vec<BackendWithPolicies>,
		route_groups: Vec<(RouteGroupKey, Vec<Route>)>,
		prev: PreviousState,
	) -> PreviousState {
		let mut s = self.write();
		let mut old_binds = prev.binds;
		let mut old_routes = prev.routes;
		let mut old_tcp_routes = prev.tcp_routes;
		let mut old_pols = prev.policies;
		let mut old_backends = prev.backends;
		let mut old_route_groups = prev.route_groups;
		let mut next_state = PreviousState {
			binds: Default::default(),
			routes: Default::default(),
			tcp_routes: Default::default(),
			policies: Default::default(),
			backends: Default::default(),
			route_groups: Default::default(),
		};
		for b in binds {
			old_binds.remove(&b.key);
			next_state.binds.insert(b.key.clone());
			s.insert_bind(b);
		}
		for b in backends {
			// Here we use the 'name' as the key. This is appropriate for local case only
			old_backends.remove(&b.backend.name());
			next_state.backends.insert(b.backend.name());
			s.insert_backend(b.backend.name(), b);
		}
		for (listener_key, routes) in listener_routes {
			for route in routes {
				old_routes.remove(&route.key);
				next_state.routes.insert(route.key.clone());
				s.insert_route(route, listener_key.clone());
			}
		}
		for (listener_key, routes) in listener_tcp_routes {
			for route in routes {
				old_tcp_routes.remove(&route.key);
				next_state.tcp_routes.insert(route.key.clone());
				s.insert_tcp_route(route, listener_key.clone());
			}
		}
		for p in policies {
			old_pols.remove(&p.key);
			next_state.policies.insert(p.key.clone());
			s.insert_policy(p);
		}
		for (rg_key, routes) in route_groups {
			old_route_groups.remove(&rg_key);
			next_state.route_groups.insert(rg_key.clone());
			for r in routes {
				s.insert_route_into_group(r, rg_key.clone());
			}
		}
		for remaining_bind in old_binds {
			s.remove_bind(remaining_bind);
		}
		for remaining_route in old_routes {
			s.remove_route(remaining_route);
		}
		for remaining_route in old_tcp_routes {
			s.remove_tcp_route(remaining_route);
		}
		for remaining_policy in old_pols {
			s.remove_policy(remaining_policy);
		}
		for remaining_backend in old_backends {
			s.remove_backend(remaining_backend);
		}
		for remaining_rg in old_route_groups {
			s.remove_route_group(remaining_rg);
		}
		next_state
	}
}

#[derive(Clone, Debug, Default)]
pub struct PreviousState {
	pub binds: HashSet<BindKey>,
	pub routes: HashSet<RouteKey>,
	pub tcp_routes: HashSet<RouteKey>,
	pub policies: HashSet<PolicyKey>,
	pub backends: HashSet<BackendKey>,
	pub route_groups: HashSet<RouteGroupKey>,
}

#[cfg(feature = "gateway-llm")]
fn preload_tokenizers() {
	static INIT_TOKENIZERS: std::sync::Once = std::sync::Once::new();

	tokio::task::spawn_blocking(|| {
		INIT_TOKENIZERS.call_once(|| {
			let t0 = std::time::Instant::now();
			crate::llm::preload_tokenizers();
			info!("tokenizers loaded in {}ms", t0.elapsed().as_millis());
		});
	});
}
