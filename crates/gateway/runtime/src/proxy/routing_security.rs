//! Request-local authorization gates, independent of shared load-balancer health.
use crate::{http::Request, proxy::ProxyError, store::BackendPolicies, types::agent::Target};
use security_integration_runtime::SecurityConfig;
use security_types::{ActionRequest, CheckStage, Decision, DecisionEffect};

#[cfg(feature = "gateway-llm")]
use crate::{
	RuntimeContext, llm,
	types::agent::{BackendTargetRef, ResourceName, SimpleBackend},
};
use std::sync::Arc;

#[cfg(test)]
#[path = "routing_security_tests.rs"]
mod tests;

#[derive(Clone, Copy, Default)]
pub(crate) struct Attempt(pub usize);

#[derive(Clone, Default)]
pub(crate) struct Guards(pub Vec<Arc<Guard>>);

impl Guards {
	/// A child cannot silently replace a declared async protocol contract.
	pub fn authorize_a2a_push(
		&self,
		active: &Arc<SecurityConfig>,
		actions: &[&ActionRequest],
	) -> Result<(), ProxyError> {
		let installed = active.a2a_objects.as_ref().and_then(|o| o.push.as_ref());
		for guard in &self.0 {
			let declared = guard
				.config
				.a2a_objects
				.as_ref()
				.and_then(|o| o.push.as_ref());
			if declared.is_some() && declared != installed {
				return Err(ProxyError::AuthorizationFailed);
			}
		}
		self.authorize_a2a_continuation(active, actions)
	}
	pub fn authorize_mcp_task(
		&self,
		active: &Arc<SecurityConfig>,
		actions: &[&ActionRequest],
	) -> Result<(), ProxyError> {
		let installed = active.mcp_sessions.as_ref().and_then(|s| s.tasks.as_ref());
		let reverse = active
			.mcp_sessions
			.as_ref()
			.and_then(|s| s.reverse.as_ref());
		for guard in &self.0 {
			let declared = guard
				.config
				.mcp_sessions
				.as_ref()
				.and_then(|s| s.tasks.as_ref());
			if declared.is_some() && declared != installed {
				return Err(ProxyError::AuthorizationFailed);
			}
			if installed.is_some_and(|t| t.interactive()) {
				let inherited = guard
					.config
					.mcp_sessions
					.as_ref()
					.and_then(|s| s.reverse.as_ref());
				if inherited.is_some() && inherited != reverse {
					return Err(ProxyError::AuthorizationFailed);
				}
			}
		}
		self.authorize_a2a_continuation(active, actions)
	}
	/// Supplemental form data is not covered by a capability bound to the original Tool args.
	pub fn check_mcp_elicitation_approval(&self, business: &ActionRequest) -> Result<(), ProxyError> {
		if self
			.0
			.iter()
			.any(|g| g.config.pipeline.requires_tool_approval(business))
		{
			return Err(ProxyError::AuthorizationFailed);
		}
		Ok(())
	}
	/// Context identities installed by this request's inherited gates, never grants.
	pub fn context_bindings(&self) -> Result<Vec<String>, ProxyError> {
		self
			.0
			.iter()
			.filter_map(|guard| guard.flow.as_ref())
			.map(|flow| flow.recovery_binding())
			.collect()
	}

	/// Stable lineage, not a credential. A leaf cannot remove a parent from recovered events.
	pub fn a2a_recovery_binding(&self) -> Result<String, ProxyError> {
		let declarations = self
			.0
			.iter()
			.map(|g| {
				Ok((
					&g.config,
					g.flow.as_ref().map(|f| f.recovery_binding()).transpose()?,
				))
			})
			.collect::<Result<Vec<_>, ProxyError>>()?;
		serde_json::to_string(&declarations)
			.map(|v| crate::security::digest(&v))
			.map_err(|_| ProxyError::AuthorizationFailed)
	}
	/// Recheck the inherited necessary conditions for an existing A2A stream/local replay.
	pub fn authorize_a2a_continuation(
		&self,
		active: &Arc<SecurityConfig>,
		actions: &[&ActionRequest],
	) -> Result<(), ProxyError> {
		for guard in &self.0 {
			if Arc::ptr_eq(&guard.config, active) {
				continue;
			}
			let current = || {
				!guard
					.expires
					.is_some_and(|e| e <= chrono::Utc::now().timestamp())
					&& !guard.revision.as_ref().is_some_and(|r| !r.is_current())
			};
			if !current() {
				return Err(ProxyError::AuthorizationFailed);
			}
			for action in actions {
				crate::security::evaluate(&guard.config, action)
					.map_err(|_| ProxyError::AuthorizationFailed)?;
			}
			if let Some(flow) = &guard.flow {
				flow.current()?;
			}
			if !current() {
				return Err(ProxyError::AuthorizationFailed);
			}
		}
		Ok(())
	}
	/// A gateway-issued Artifact GET must not escape a parent's necessary conditions.
	/// Different declared download contracts are not silently overridden by the leaf.
	pub fn authorize_artifact_download(
		&self,
		active: &Arc<SecurityConfig>,
		actions: &[&ActionRequest],
		download: &ActionRequest,
		destination: &str,
	) -> Result<(), ProxyError> {
		for guard in &self.0 {
			if Arc::ptr_eq(&guard.config, active) {
				continue;
			}
			let result = (|| {
				if guard
					.expires
					.is_some_and(|e| e <= chrono::Utc::now().timestamp())
					|| guard.revision.as_ref().is_some_and(|r| !r.is_current())
				{
					return Err(ProxyError::AuthorizationFailed);
				}
				let parent = guard
					.config
					.a2a_objects
					.as_ref()
					.and_then(|o| o.artifact_downloads.as_ref());
				let installed = active
					.a2a_objects
					.as_ref()
					.and_then(|o| o.artifact_downloads.as_ref());
				if parent.is_some() && parent != installed {
					return Err(ProxyError::AuthorizationFailed);
				}
				for action in actions {
					crate::security::evaluate(&guard.config, action)
						.map_err(|_| ProxyError::AuthorizationFailed)?;
				}
				if let Some(egress) = &guard.config.data_egress {
					security_integration_runtime::check_data_egress(
						egress,
						download,
						destination,
						&crate::security_events::UiSecurityAuditSink,
					)
					.map_err(|_| ProxyError::AuthorizationFailed)?;
				}
				if let Some(flow) = &guard.flow {
					flow.check(download, destination)?;
				}
				if guard
					.expires
					.is_some_and(|e| e <= chrono::Utc::now().timestamp())
					|| guard.revision.as_ref().is_some_and(|r| !r.is_current())
				{
					return Err(ProxyError::AuthorizationFailed);
				}
				Ok(())
			})();
			security_integration_runtime::a2a_objects::audit_object_check(
				download,
				result
					.as_ref()
					.map(|_| ())
					.map_err(|_| security_integration_runtime::a2a_objects::ObjectError::StreamAuthorization),
				&crate::security_events::UiSecurityAuditSink,
			);
			result?;
		}
		Ok(())
	}

	/// Guard both raw provider bytes and the final adapted output. Dropping either body
	/// releases its upstream; no background reader outlives downstream demand.
	pub fn protect_response(
		&self,
		response: crate::http::Response,
		target: &Target,
	) -> Result<crate::http::Response, ProxyError> {
		let guards = Self(
			self
				.0
				.iter()
				.filter(|g| {
					g.config.mode == security_integration_runtime::SecurityMode::Enforce
						&& (g.model.is_some() || g.inference)
				})
				.cloned()
				.collect(),
		);
		if guards.0.is_empty() {
			return Ok(response);
		}
		for guard in &guards.0 {
			guard.current()?;
		}
		Ok(response.map(|body| {
			crate::http::Body::new(ResponseBody {
				body: Some(body),
				guards,
				target: target.clone(),
				reauthorize: tokio::time::sleep(REAUTHORIZE_INTERVAL),
			})
		}))
	}

	pub fn covers(&self, config: &Arc<SecurityConfig>) -> bool {
		self
			.0
			.iter()
			.any(|guard| Arc::ptr_eq(&guard.config, config))
	}

	pub fn ensure(
		&mut self,
		policies: &BackendPolicies,
		request: &Request,
	) -> Result<(), ProxyError> {
		if policies
			.security_audit
			.as_ref()
			.is_some_and(|config| self.covers(config))
		{
			return Ok(());
		}
		if let Some(guard) = Guard::new(policies, request)? {
			self.0.push(guard);
		}
		Ok(())
	}
}

#[derive(Clone, Default)]
pub(crate) struct InheritedConfigs(pub Vec<Arc<SecurityConfig>>);

pub(crate) struct Guard {
	config: Arc<SecurityConfig>,
	flow: Option<crate::security_flow::FlowAccess>,
	identity: security_pipeline::GatewayIdentity,
	request_id: String,
	model: Option<String>,
	inference: bool,
	agent: bool,
	expires: Option<i64>,
	revision: Option<gateway_contracts::ConfigLease>,
	attempt: usize,
}
impl Guard {
	#[cfg(feature = "security-pii")]
	pub(crate) fn pii_config(&self) -> &Arc<SecurityConfig> {
		&self.config
	}
	pub fn new(
		policies: &BackendPolicies,
		request: &Request,
	) -> Result<Option<Arc<Self>>, ProxyError> {
		let Some(config) = &policies.security_audit else {
			return Ok(None);
		};
		if policies.model_name().is_none()
			&& policies.inference_routing.is_none()
			&& policies.a2a.is_none()
		{
			return Ok(None);
		}
		let mut extensions = request.extensions().clone();
		Ok(Some(Arc::new(Self {
			config: config.clone(),
			flow: crate::security_flow::prepare(config, request.headers(), request.extensions())?,
			identity: crate::security::identity_from_extensions(request.extensions()),
			request_id: crate::security::request_id(&mut extensions),
			model: policies.model_name().map(str::to_owned),
			inference: policies.inference_routing.is_some(),
			agent: policies.a2a.is_some(),
			expires: request
				.extensions()
				.get::<crate::http::jwt::Claims>()
				.and_then(|c| c.inner.get("exp"))
				.and_then(|v| v.as_i64()),
			revision: request
				.extensions()
				.get::<gateway_contracts::ConfigLease>()
				.cloned(),
			attempt: request
				.extensions()
				.get::<Attempt>()
				.copied()
				.unwrap_or_default()
				.0,
		})))
	}
	pub fn prefilter(&self, target: Option<&Target>) -> Result<(), ProxyError> {
		self.check(target, CheckStage::Candidate)
	}
	pub fn dispatch(&self, target: &Target) -> Result<(), ProxyError> {
		self.check(Some(target), CheckStage::Dispatch)
	}
	fn check_response_current(&self, target: &Target) -> Result<(), ProxyError> {
		self.current().inspect_err(|_| {
			let action = security_pipeline::inference_route_for_identity(
				&self.request_id,
				self.identity.clone(),
				target.to_string(),
			);
			self.record_check(&action, CheckStage::Continuation, false);
		})
	}

	fn current(&self) -> Result<(), ProxyError> {
		if self
			.expires
			.is_some_and(|e| e <= chrono::Utc::now().timestamp())
			|| self.revision.as_ref().is_some_and(|r| !r.is_current())
		{
			return Err(ProxyError::AuthorizationFailed);
		}
		if let Some(flow) = &self.flow {
			flow.current()?;
		}
		Ok(())
	}

	fn check(&self, target: Option<&Target>, stage: CheckStage) -> Result<(), ProxyError> {
		let destination = target
			.map(ToString::to_string)
			.unwrap_or_else(|| "unresolved-endpoint".into());
		let route = security_pipeline::inference_route_for_identity(
			self.request_id.clone(),
			self.identity.clone(),
			destination.clone(),
		);
		let result = (|| {
			self.current()?;
			let check = |action: ActionRequest, authorize: bool| {
				if authorize {
					security_integration_runtime::evaluate_at_stage(
						&self.config,
						stage,
						&action,
						None,
						&crate::security_events::UiSecurityAuditSink,
					)
					.map_err(|_| ProxyError::AuthorizationFailed)?;
				}
				if target.is_some() {
					if let Some(egress) = &self.config.data_egress {
						if !egress.permits(&action, &destination) {
							return Err(ProxyError::AuthorizationFailed);
						}
					}
					if let Some(flow) = &self.flow {
						if stage != CheckStage::Candidate {
							flow.check(&action, &destination)?;
						} else if !flow.permits(&action, &destination)? {
							return Err(ProxyError::AuthorizationFailed);
						}
					}
				}
				Ok::<_, ProxyError>(())
			};
			if let Some(model) = &self.model {
				check(
					security_pipeline::model_invoke_for_identity(
						self.request_id.clone(),
						self.identity.clone(),
						model,
					),
					true,
				)?;
			}
			if self.inference && target.is_some() {
				check(route.clone(), true)?;
			}
			// Agent method-specific authorization is performed after JSON-RPC decoding, not
			// replaced by a made-up generic action during candidate inspection.
			if self.agent && target.is_some() {
				check(
					security_pipeline::agent_invoke_for_identity(
						self.request_id.clone(),
						self.identity.clone(),
						&destination,
					),
					false,
				)?;
			}
			self.current()
		})();
		self.record_check(&route, stage, result.is_ok());
		result
	}
	fn record_check(&self, route: &ActionRequest, stage: CheckStage, allowed: bool) {
		use security_audit::AuditSink;
		let phase = stage.as_str();
		let decision = Decision {
			request_id: self.request_id.clone(),
			effect: if allowed {
				DecisionEffect::Allow
			} else {
				DecisionEffect::Deny
			},
			policy_id: Some(format!("routing:{phase}:attempt:{}", self.attempt)),
			policy_version: None,
			expires_at: None,
		};
		crate::security_events::UiSecurityAuditSink.record(security_audit::event_from_decision(
			uuid::Uuid::new_v4().to_string(),
			route,
			&decision,
		));
	}
}

/// Resolve only configuration, not a connection or a health handle. Unknown service endpoints
/// are filtered later with their concrete workload destination, not against a service alias.
#[cfg(feature = "gateway-llm")]
pub(crate) fn provider(
	inputs: &RuntimeContext,
	name: &ResourceName,
	provider: &Arc<llm::NamedAIProvider>,
	base: &BackendPolicies,
	route: &Arc<crate::store::LLMRequestPolicies>,
	request: &Request,
) -> Result<(Vec<Arc<Guard>>, Option<Target>), ProxyError> {
	let sub = inputs.stores.read_binds().sub_backend_policies(
		BackendTargetRef::Backend {
			name: &name.name,
			namespace: &name.namespace,
			section: Some(&provider.name),
		},
		Some(&provider.inline_policies),
	);
	let defaults = BackendPolicies {
		llm_provider: Some(provider.clone()),
		..Default::default()
	};
	let mut effective = defaults.clone().merge(base.clone()).merge(sub);
	let target = if let Some(reference) = &provider.provider_backend {
		let resolved = super::resolve_simple_backend_with_policies(reference, inputs)?;
		let extra = inputs
			.stores
			.read_binds()
			.sub_backend_policies(resolved.backend.target(), Some(&resolved.inline_policies));
		effective = effective.merge(extra);
		match resolved.backend {
			SimpleBackend::Opaque(_, target) => Some(target),
			SimpleBackend::Aws(_, config) => Some(Target::Hostname(config.get_host().into(), 443)),
			SimpleBackend::Service(_, _) => None,
			SimpleBackend::Invalid => return Err(ProxyError::BackendDoesNotExist),
		}
	} else {
		let route_type = route
			.clone()
			.merge_backend_policies(effective.llm.clone())
			.llm
			.as_ref()
			.map(|p| p.resolve_route(request.uri().path()))
			.unwrap_or(llm::RouteType::Completions);
		provider
			.host_override
			.clone()
			.or_else(|| provider.provider.default_connector_target(route_type))
	};
	let mut guards = Vec::new();
	// Keep the system-level gate even when provider-local policies override effective config.
	let mut inherited = request
		.extensions()
		.get::<InheritedConfigs>()
		.cloned()
		.unwrap_or_default()
		.0;
	if let Some(config) = &base.security_audit {
		inherited.push(config.clone());
	}
	let mut unique = Vec::new();
	for config in inherited {
		if unique.iter().any(|old| Arc::ptr_eq(old, &config)) {
			continue;
		}
		unique.push(config.clone());
		let mut parent = defaults.clone().merge(base.clone());
		parent.security_audit = Some(config);
		// Constraints follow the actual channel even if a provider introduces routing locally.
		parent.inference_routing = effective.inference_routing.clone();
		parent.a2a = effective.a2a.clone();
		if let Some(guard) = Guard::new(&parent, request)? {
			guards.push(guard);
		}
	}
	if effective
		.security_audit
		.as_ref()
		.is_some_and(|config| !unique.iter().any(|parent| Arc::ptr_eq(config, parent)))
	{
		if let Some(guard) = Guard::new(&effective, request)? {
			guards.push(guard);
		}
	}
	// An EPP destination is not known yet. Check it immediately after the picker returns,
	// before sending model data; do not reject a legitimate endpoint using a placeholder alias.
	let target = if effective.inference_routing.is_some() {
		None
	} else {
		target
	};
	Ok((guards, target))
}

const REAUTHORIZE_INTERVAL: std::time::Duration = std::time::Duration::from_secs(5);

pin_project_lite::pin_project! {
		struct ResponseBody {
				#[pin] body: Option<crate::http::Body>,
				guards: Guards,
				target: Target,
				#[pin] reauthorize: tokio::time::Sleep,
		}
}
impl http_body::Body for ResponseBody {
	type Data = bytes::Bytes;
	type Error = axum_core::BoxError;
	fn poll_frame(
		self: std::pin::Pin<&mut Self>,
		cx: &mut std::task::Context<'_>,
	) -> std::task::Poll<Option<Result<http_body::Frame<Self::Data>, Self::Error>>> {
		use std::{future::Future, task::Poll};
		let mut this = self.project();
		if this.body.is_none() {
			return Poll::Ready(None);
		}
		let result = (|| {
			for guard in &this.guards.0 {
				guard.check_response_current(this.target)?;
			}

			if this.reauthorize.as_mut().poll(cx).is_ready() {
				for guard in &this.guards.0 {
					guard.check(Some(this.target), CheckStage::Continuation)?;
				}
				this
					.reauthorize
					.as_mut()
					.reset(tokio::time::Instant::now() + REAUTHORIZE_INTERVAL);
			}
			Ok::<_, ProxyError>(())
		})();
		if let Err(error) = result {
			this.body.set(None);
			return Poll::Ready(Some(Err(error.into())));
		}
		match this
			.body
			.as_mut()
			.as_pin_mut()
			.expect("active response body")
			.poll_frame(cx)
		{
			Poll::Ready(None) => {
				this.body.set(None);
				Poll::Ready(None)
			},
			Poll::Ready(Some(Err(error))) => {
				this.body.set(None);
				Poll::Ready(Some(Err(error.into())))
			},
			Poll::Ready(Some(Ok(frame))) => {
				// A provider/adapter may invalidate the lease while producing this frame.
				for guard in &this.guards.0 {
					if let Err(error) = guard.check_response_current(this.target) {
						this.body.set(None);
						return Poll::Ready(Some(Err(error.into())));
					}
				}
				Poll::Ready(Some(Ok(frame)))
			},
			Poll::Pending => Poll::Pending,
		}
	}
	fn is_end_stream(&self) -> bool {
		self.body.is_none()
	}
	fn size_hint(&self) -> http_body::SizeHint {
		self
			.body
			.as_ref()
			.map_or_else(http_body::SizeHint::default, http_body::Body::size_hint)
	}
}
