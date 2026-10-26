//! Narrow calling capabilities. Runtime resolution and final dispatch remain Host-owned.
use crate::{
	http::{Request, Response},
	proxy::ProxyError,
	store::BackendPolicies,
	telemetry::metrics::{
		GuardrailAction, GuardrailLabels, GuardrailPhase, Metrics, OutboundCallKind,
		OutboundCallLabels, OutboundCallSubtype,
	},
	types::agent::{
		Backend, BackendTrafficPolicy, ResourceName, SimpleBackend, SimpleBackendReference,
		SimpleBackendWithPolicies,
	},
};
use gateway_protocol_core::execution::{BoundHttpExecution, ExecutionFuture};
use std::sync::Arc;

/// Only network backends can be invoked without a protocol RequestLog.
#[derive(Clone, Debug)]
pub(super) enum NetworkBackend {
	Simple(SimpleBackend),
	Dynamic(ResourceName),
}
impl TryFrom<Backend> for NetworkBackend {
	type Error = ProxyError;
	fn try_from(backend: Backend) -> Result<Self, Self::Error> {
		Ok(match backend {
			Backend::Service(s, p) => Self::Simple(SimpleBackend::Service(s, p)),
			Backend::Opaque(n, t) => Self::Simple(SimpleBackend::Opaque(n, t)),
			Backend::Aws(n, c) => Self::Simple(SimpleBackend::Aws(n, c)),
			Backend::Dynamic(n, ()) => Self::Dynamic(n),
			Backend::Invalid => Self::Simple(SimpleBackend::Invalid),
			_ => return Err(ProxyError::InvalidBackendType),
		})
	}
}
impl From<NetworkBackend> for Backend {
	fn from(backend: NetworkBackend) -> Self {
		match backend {
			NetworkBackend::Simple(simple) => simple.into(),
			NetworkBackend::Dynamic(name) => Self::Dynamic(name, ()),
		}
	}
}

// Transitional Host-local selectors; never exported to the shared contract crate.
#[derive(Debug)]
pub(super) enum PolicyCall {
	Reference(SimpleBackendReference, Vec<BackendTrafficPolicy>),
	Resolved(SimpleBackendWithPolicies),
	Explicit(SimpleBackend, BackendPolicies),
	Inline(NetworkBackend, Vec<BackendTrafficPolicy>),
	Direct,
}
pub(super) trait PolicyExecution: Send + Sync + std::fmt::Debug {
	fn execute(
		&self,
		request: Request,
		call: PolicyCall,
		outbound: Option<OutboundCallLabels>,
	) -> ExecutionFuture<'_, Response, ProxyError>;
}

#[derive(Clone)]
pub struct PolicyClient {
	state: Arc<PolicyClientState>,
	pub outbound: Option<OutboundCallLabels>,
}

struct PolicyClientState {
	execution: Arc<dyn PolicyExecution>,
	metrics: Arc<Metrics>,
	guardrails: Option<Arc<dyn crate::guardrails::VehicleGuardrails>>,
	vehicle_state: crate::guardrails::VehicleState,
	admin_runtime: Option<tokio::runtime::Handle>,
}

impl std::fmt::Debug for PolicyClient {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.debug_struct("PolicyClient")
			.field("outbound", &self.outbound)
			.finish_non_exhaustive()
	}
}

impl PolicyClient {
	pub fn new(inputs: impl crate::IntoRuntimeContext) -> Self {
		let inputs = inputs.into_runtime_context();
		Self {
			state: Arc::new(PolicyClientState {
				metrics: inputs.metrics.clone(),
				guardrails: inputs.guardrails.clone(),
				vehicle_state: inputs.vehicle_state.clone(),
				admin_runtime: inputs.cfg.admin_runtime_handle.clone(),
				execution: super::httpproxy::policy_executor(inputs),
			}),
			outbound: None,
		}
	}
	pub fn with_outbound(&self, kind: OutboundCallKind, subtype: OutboundCallSubtype) -> Self {
		Self {
			outbound: Some(OutboundCallLabels { kind, subtype }),
			..self.clone()
		}
	}
	pub fn guardrails(&self) -> Option<&Arc<dyn crate::guardrails::VehicleGuardrails>> {
		self.state.guardrails.as_ref()
	}
	pub fn vehicle_state(&self) -> &crate::guardrails::VehicleState {
		&self.state.vehicle_state
	}
	pub(crate) fn exporter_runtime(&self) -> tokio::runtime::Handle {
		self
			.state
			.admin_runtime
			.clone()
			.unwrap_or_else(tokio::runtime::Handle::current)
	}
	pub(crate) fn record_guardrail_check(&self, phase: GuardrailPhase, action: GuardrailAction) {
		self
			.state
			.metrics
			.guardrail_checks
			.get_or_create(&GuardrailLabels { phase, action })
			.inc();
	}
	pub async fn call_reference(
		&self,
		req: Request,
		backend: &SimpleBackendReference,
	) -> Result<Response, ProxyError> {
		self.call_reference_with_policies(req, backend, &[]).await
	}
	pub async fn call_reference_with_policies(
		&self,
		req: Request,
		backend: &SimpleBackendReference,
		policies: &[BackendTrafficPolicy],
	) -> Result<Response, ProxyError> {
		self
			.state
			.execution
			.execute(
				req,
				PolicyCall::Reference(backend.clone(), policies.to_vec()),
				self.outbound.clone(),
			)
			.await
	}
	pub async fn call(
		&self,
		req: Request,
		backend: SimpleBackendWithPolicies,
	) -> Result<Response, ProxyError> {
		self
			.state
			.execution
			.execute(req, PolicyCall::Resolved(backend), self.outbound.clone())
			.await
	}
	pub async fn call_with_explicit_policies(
		&self,
		req: Request,
		backend: &SimpleBackend,
		policies: BackendPolicies,
	) -> Result<Response, ProxyError> {
		self
			.state
			.execution
			.execute(
				req,
				PolicyCall::Explicit(backend.clone(), policies),
				self.outbound.clone(),
			)
			.await
	}
	pub async fn call_with_explicit_policies_list(
		&self,
		req: Request,
		backend: Backend,
		policies: Vec<BackendTrafficPolicy>,
	) -> Result<Response, ProxyError> {
		self
			.state
			.execution
			.execute(
				req,
				PolicyCall::Inline(backend.try_into()?, policies),
				self.outbound.clone(),
			)
			.await
	}
	pub async fn simple_call(&self, req: Request) -> Result<Response, ProxyError> {
		self
			.state
			.execution
			.execute(req, PolicyCall::Direct, self.outbound.clone())
			.await
	}
	/// Bind selection, policies and call category. Each execute still resolves current policy.
	pub fn bind_reference(
		&self,
		target: &SimpleBackendReference,
		policies: &[BackendTrafficPolicy],
	) -> BoundDependency {
		BoundDependency {
			client: self.clone(),
			target: target.clone(),
			policies: policies.to_vec(),
		}
	}
}

#[derive(Clone, Debug)]
pub struct BoundDependency {
	client: PolicyClient,
	target: SimpleBackendReference,
	policies: Vec<BackendTrafficPolicy>,
}
impl BoundHttpExecution for BoundDependency {
	type RequestBody = crate::http::Body;
	type ResponseBody = crate::http::Body;
	type Error = ProxyError;
	fn execute(&self, request: Request) -> ExecutionFuture<'_, Response, ProxyError> {
		Box::pin(
			self
				.client
				.call_reference_with_policies(request, &self.target, &self.policies),
		)
	}
}
