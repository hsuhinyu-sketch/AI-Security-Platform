use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};

use audit_core::{AuditSink, event_from_decision};
use chrono::{DateTime, Duration, Utc};
use security_contracts::{ActionRequest, ActionType, Decision, DecisionEffect};
use security_engine::decide;
use security_policy::Policy;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::{Capability, CapabilityBroker, CapabilityError};

/// A normalized authorization decision provider. It can be backed by local policies,
/// an external PDP, or a signed policy cache without changing the pipeline.
pub trait Authorizer: Send + Sync {
	fn decide(&self, request: &ActionRequest) -> Decision;
}

/// A dynamic policy decision point. Implementations may consult local state, a remote PDP, or a
/// signed decision feed. Errors are deliberately distinct from a deny so the adapter can apply
/// an explicit fail-closed failure policy.
pub trait DynamicPdp: Send + Sync {
	fn decide(&self, request: &ActionRequest) -> Result<Decision, DynamicPdpError>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DynamicPdpError {
	pub reason: String,
}

impl DynamicPdpError {
	pub fn unavailable(reason: impl Into<String>) -> Self {
		Self {
			reason: reason.into(),
		}
	}
}

/// Versioned request sent to a remote PDP. It contains normalized, verified gateway context,
/// never an upstream bearer token or raw Tool argument payload.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RemotePdpRequest {
	pub protocol_version: String,
	pub request: ActionRequest,
}

/// A remote PDP decision must be bound to one request and expire. This prevents replaying a
/// response for another action and limits the lifetime of an allow held in the gateway cache.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RemotePdpResponse {
	pub request_id: String,
	pub effect: DecisionEffect,
	pub policy_id: String,
	pub policy_version: String,
	pub expires_at: DateTime<Utc>,
}

/// Runtime transport for a trusted remote PDP. The Gateway runtime can implement this through
/// HTTP/mTLS without coupling the security core to a blocking client or a particular protocol.
pub trait RemotePdpTransport: Send + Sync {
	fn decide(&self, request: RemotePdpRequest) -> Result<RemotePdpResponse, DynamicPdpError>;
}

/// Validates remote PDP responses before returning them to the authorization pipeline.
pub struct RemoteDynamicPdp<T> {
	transport: T,
	expected_policy_version: Option<String>,
}

impl<T> RemoteDynamicPdp<T> {
	pub fn new(transport: T, expected_policy_version: Option<String>) -> Self {
		Self {
			transport,
			expected_policy_version,
		}
	}
}

impl<T: RemotePdpTransport> DynamicPdp for RemoteDynamicPdp<T> {
	fn decide(&self, request: &ActionRequest) -> Result<Decision, DynamicPdpError> {
		let response = self.transport.decide(RemotePdpRequest {
			protocol_version: "v1".into(),
			request: request.clone(),
		})?;
		if response.request_id != request.request_id {
			return Err(DynamicPdpError::unavailable(
				"remote PDP response requestId does not match",
			));
		}
		if self
			.expected_policy_version
			.as_deref()
			.is_some_and(|version| version != response.policy_version)
		{
			return Err(DynamicPdpError::unavailable(
				"remote PDP response policyVersion does not match",
			));
		}
		if response.expires_at <= Utc::now() {
			return Err(DynamicPdpError::unavailable(
				"remote PDP response is expired",
			));
		}
		Ok(Decision {
			request_id: response.request_id,
			effect: response.effect,
			policy_id: Some(response.policy_id),
			policy_version: Some(response.policy_version),
			expires_at: Some(response.expires_at),
		})
	}
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DelegationRevocationError {
	pub reason: String,
}

/// Provider for real-time delegation revocation. A provider failure is handled fail-closed by
/// `DelegationRevocationCheck`; it cannot silently preserve a previously delegated privilege.
pub trait DelegationRevocationProvider: Send + Sync {
	fn is_revoked(&self, delegation_id: &str) -> Result<bool, DelegationRevocationError>;
}

impl<T: DelegationRevocationProvider + ?Sized> DelegationRevocationProvider for Arc<T> {
	fn is_revoked(&self, delegation_id: &str) -> Result<bool, DelegationRevocationError> {
		(**self).is_revoked(delegation_id)
	}
}

/// In-process implementation for the PoC and tests. A production implementation can back the
/// same trait with a shared revocation index or the external PDP.
#[derive(Debug, Default)]
pub struct DelegationRevocationRegistry {
	revoked: Mutex<HashSet<String>>,
}

impl DelegationRevocationRegistry {
	pub fn revoke(&self, delegation_id: impl Into<String>) {
		self
			.revoked
			.lock()
			.expect("delegation revocation registry lock poisoned")
			.insert(delegation_id.into());
	}

	pub fn unrevoke(&self, delegation_id: &str) {
		self
			.revoked
			.lock()
			.expect("delegation revocation registry lock poisoned")
			.remove(delegation_id);
	}
}

impl DelegationRevocationProvider for DelegationRevocationRegistry {
	fn is_revoked(&self, delegation_id: &str) -> Result<bool, DelegationRevocationError> {
		Ok(
			self
				.revoked
				.lock()
				.expect("delegation revocation registry lock poisoned")
				.contains(delegation_id),
		)
	}
}

/// The default PoC authorizer: local policy evaluation with deny-by-default semantics.
pub struct PolicyAuthorizer {
	policies: Vec<Policy>,
}

impl PolicyAuthorizer {
	pub fn new(policies: Vec<Policy>) -> Self {
		Self { policies }
	}
}

impl Authorizer for PolicyAuthorizer {
	fn decide(&self, request: &ActionRequest) -> Decision {
		decide(&self.policies, request)
	}
}

/// Defines what happens when the dynamic PDP cannot produce a decision.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum DynamicPdpFailureMode {
	/// Call the PDP for every request. A PDP failure denies the request.
	#[default]
	FailClosed,
	/// Reuse only a still-valid cached decision; if absent, call the PDP and deny on failure.
	/// This is appropriate only for explicitly low-risk, read-only operations.
	UseCachedDecision,
}

/// Dynamic restrictions layered over the normal identity/action/resource policy vocabulary.
/// All fields of `policy` still apply; session, client, and time restrictions are additional.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DynamicPolicy {
	#[serde(flatten)]
	pub policy: Policy,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub session_id: Option<String>,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub client_id: Option<String>,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub not_before: Option<DateTime<Utc>>,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub expires_at: Option<DateTime<Utc>>,
}

impl DynamicPolicy {
	fn matches(&self, request: &ActionRequest, now: DateTime<Utc>) -> bool {
		self.policy.matches(request)
			&& self
				.session_id
				.as_deref()
				.is_none_or(|session| request.authorization_context.session_id.as_deref() == Some(session))
			&& self
				.client_id
				.as_deref()
				.is_none_or(|client| request.authorization_context.client_id.as_deref() == Some(client))
			&& self.not_before.is_none_or(|not_before| now >= not_before)
			&& self.expires_at.is_none_or(|expires_at| now < expires_at)
	}
}

/// In-process PDP used by the PoC. It has the same interface as a remote PDP and gives the
/// configuration a safe way to express time- and session-bound restrictions today.
#[derive(Debug, Clone)]
pub struct LocalDynamicPdp {
	policies: Vec<DynamicPolicy>,
	policy_version: String,
}

impl LocalDynamicPdp {
	pub fn new(policies: Vec<DynamicPolicy>, policy_version: impl Into<String>) -> Self {
		Self {
			policies,
			policy_version: policy_version.into(),
		}
	}
}

impl DynamicPdp for LocalDynamicPdp {
	fn decide(&self, request: &ActionRequest) -> Result<Decision, DynamicPdpError> {
		let now = Utc::now();
		let select = |effect| {
			self
				.policies
				.iter()
				.filter(|policy| policy.policy.effect == effect && policy.matches(request, now))
				.fold(None::<&DynamicPolicy>, |selected, policy| match selected {
					Some(current) if current.policy.priority >= policy.policy.priority => Some(current),
					_ => Some(policy),
				})
		};
		let selected = select(DecisionEffect::Deny).or_else(|| select(DecisionEffect::Allow));
		Ok(Decision {
			request_id: request.request_id.clone(),
			effect: selected
				.map(|policy| policy.policy.effect)
				.unwrap_or(DecisionEffect::Deny),
			policy_id: selected
				.map(|policy| policy.policy.id.clone())
				.or_else(|| Some("dynamic-pdp:no-matching-policy".into())),
			policy_version: Some(self.policy_version.clone()),
			expires_at: selected.and_then(|policy| policy.expires_at),
		})
	}
}

#[derive(Debug, Clone)]
struct CachedDecision {
	decision: Decision,
	expires_at: DateTime<Utc>,
}

/// Process-local, bounded-by-TTL decision cache. It is deliberately not a source of authority:
/// cache misses and expired entries always go back to the PDP, and PDP failures deny by default.
#[derive(Debug, Clone, Default)]
pub struct DecisionCache {
	entries: Arc<Mutex<HashMap<String, CachedDecision>>>,
}

impl DecisionCache {
	fn get(&self, key: &str, now: DateTime<Utc>) -> Option<Decision> {
		let mut entries = self.entries.lock().expect("decision cache lock poisoned");
		let entry = entries.get(key)?;
		if now >= entry.expires_at {
			entries.remove(key);
			return None;
		}
		Some(entry.decision.clone())
	}

	fn insert(&self, key: String, decision: Decision, ttl: Duration) {
		if ttl <= Duration::zero() {
			return;
		}
		let expires_at = decision
			.expires_at
			.map(|expires_at| expires_at.min(Utc::now() + ttl))
			.unwrap_or_else(|| Utc::now() + ttl);
		if expires_at <= Utc::now() {
			return;
		}
		self
			.entries
			.lock()
			.expect("decision cache lock poisoned")
			.insert(
				key,
				CachedDecision {
					decision,
					expires_at,
				},
			);
	}
}

/// Adds a cache boundary and fail-closed error translation to any dynamic PDP.
pub struct CachedDynamicPdp<P> {
	pdp: P,
	cache: DecisionCache,
	policy_version: String,
	cache_ttl: Duration,
	failure_mode: DynamicPdpFailureMode,
}

impl<P> CachedDynamicPdp<P> {
	pub fn new(
		pdp: P,
		cache: DecisionCache,
		policy_version: impl Into<String>,
		cache_ttl: Duration,
		failure_mode: DynamicPdpFailureMode,
	) -> Self {
		Self {
			pdp,
			cache,
			policy_version: policy_version.into(),
			cache_ttl,
			failure_mode,
		}
	}

	fn cache_key(&self, request: &ActionRequest) -> String {
		let material = serde_json::json!({
			"policyVersion": self.policy_version,
			"subject": request.subject,
			"action": request.action,
			"resource": request.resource,
			"authorizationContext": request.authorization_context,
		});
		let encoded = serde_json::to_vec(&material).expect("authorization cache key is serializable");
		Sha256::digest(encoded)
			.iter()
			.map(|byte| format!("{byte:02x}"))
			.collect()
	}
}

impl<P: DynamicPdp> DynamicPdp for CachedDynamicPdp<P> {
	fn decide(&self, request: &ActionRequest) -> Result<Decision, DynamicPdpError> {
		let key = self.cache_key(request);
		if self.failure_mode == DynamicPdpFailureMode::UseCachedDecision {
			if let Some(decision) = self.cache.get(&key, Utc::now()) {
				return Ok(decision);
			}
		}
		let decision = self.pdp.decide(request)?;
		self.cache.insert(key, decision.clone(), self.cache_ttl);
		Ok(decision)
	}
}

/// Configuration for the built-in dynamic PDP. Its runtime cache is intentionally excluded from
/// YAML/JSON, while clones of a loaded configuration share that cache.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DynamicAuthorizationConfig {
	pub policy_version: String,
	#[serde(default)]
	pub policies: Vec<DynamicPolicy>,
	#[serde(default)]
	pub cache_ttl_seconds: u64,
	#[serde(default)]
	pub failure_mode: DynamicPdpFailureMode,
	#[serde(skip, default)]
	cache: DecisionCache,
}

impl DynamicAuthorizationConfig {
	fn build_pdp(&self) -> CachedDynamicPdp<LocalDynamicPdp> {
		self.cache_pdp(LocalDynamicPdp::new(
			self.policies.clone(),
			self.policy_version.clone(),
		))
	}

	fn cache_pdp<P>(&self, pdp: P) -> CachedDynamicPdp<P> {
		CachedDynamicPdp::new(
			pdp,
			self.cache.clone(),
			self.policy_version.clone(),
			Duration::seconds(self.cache_ttl_seconds.try_into().unwrap_or(i64::MAX)),
			self.failure_mode,
		)
	}
}

/// Requires both a static allow and a dynamic PDP allow. A dynamic failure is represented as a
/// deny decision rather than silently falling back to the static policy.
pub struct StaticAndDynamicAuthorizer<P = LocalDynamicPdp> {
	static_authorizer: PolicyAuthorizer,
	dynamic_pdp: Option<CachedDynamicPdp<P>>,
}

impl StaticAndDynamicAuthorizer<LocalDynamicPdp> {
	pub fn from_config(policies: Vec<Policy>, dynamic: Option<&DynamicAuthorizationConfig>) -> Self {
		Self {
			static_authorizer: PolicyAuthorizer::new(policies),
			dynamic_pdp: dynamic.map(DynamicAuthorizationConfig::build_pdp),
		}
	}
}

impl<P> StaticAndDynamicAuthorizer<P> {
	pub fn new(
		static_authorizer: PolicyAuthorizer,
		dynamic_pdp: Option<CachedDynamicPdp<P>>,
	) -> Self {
		Self {
			static_authorizer,
			dynamic_pdp,
		}
	}
}

impl<P: DynamicPdp> Authorizer for StaticAndDynamicAuthorizer<P> {
	fn decide(&self, request: &ActionRequest) -> Decision {
		let static_decision = self.static_authorizer.decide(request);
		if static_decision.effect == DecisionEffect::Deny {
			return static_decision;
		}
		let Some(dynamic_pdp) = &self.dynamic_pdp else {
			return static_decision;
		};
		match dynamic_pdp.decide(request) {
			Ok(decision) => decision,
			Err(error) => Decision {
				request_id: request.request_id.clone(),
				effect: DecisionEffect::Deny,
				policy_id: Some(format!("dynamic-pdp:unavailable:{}", error.reason)),
				policy_version: None,
				expires_at: None,
			},
		}
	}
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ControlDenial {
	pub control_id: String,
	pub reason: String,
}

/// A composable policy-enforcement stage. Controls are deterministic: they operate on
/// normalized identity, action, resource, and optional Tool arguments, never model output.
pub trait SecurityControl: Send + Sync {
	fn id(&self) -> &str;

	fn check(
		&self,
		request: &ActionRequest,
		arguments: Option<&serde_json::Value>,
	) -> Result<(), ControlDenial>;
}

/// Identity-stage brick that blocks a revoked delegation before static or dynamic authorization.
pub struct DelegationRevocationCheck<P> {
	provider: P,
}

impl<P> DelegationRevocationCheck<P> {
	pub fn new(provider: P) -> Self {
		Self { provider }
	}
}

impl<P: DelegationRevocationProvider> SecurityControl for DelegationRevocationCheck<P> {
	fn id(&self) -> &str {
		"delegation-revocation"
	}

	fn check(
		&self,
		request: &ActionRequest,
		_arguments: Option<&serde_json::Value>,
	) -> Result<(), ControlDenial> {
		let Some(delegation_id) = request.subject.delegation_id.as_deref() else {
			return Ok(());
		};
		match self.provider.is_revoked(delegation_id) {
			Ok(false) => Ok(()),
			Ok(true) => Err(ControlDenial {
				control_id: self.id().into(),
				reason: format!("delegation '{}' has been revoked", delegation_id),
			}),
			Err(error) => Err(ControlDenial {
				control_id: self.id().into(),
				reason: format!("delegation revocation check unavailable: {}", error.reason),
			}),
		}
	}
}

/// Ensures that the AI request retains the identities required by the deployment.
#[derive(Debug, Clone, Copy, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RequiredIdentity {
	pub user: bool,
	pub agent: bool,
	pub tenant: bool,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RequiredToolArgumentsConfig {
	pub tool_name: String,
	#[serde(default)]
	pub required_fields: Vec<String>,
}

/// Declares a Tool as high risk. Until an external approval provider is installed, this is a
/// fail-closed gate rather than an implicit approval.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RequiredToolApprovalConfig {
	pub tool_name: String,
}

/// A direct, user-to-Agent delegation grant. Its identifier must be present in verified
/// request identity, so a caller cannot select a broader configured grant by itself.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentDelegationConfig {
	pub id: String,
	pub user_id: String,
	pub agent_id: String,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub tenant_id: Option<String>,
	/// An empty list grants no operations.
	#[serde(default)]
	pub scopes: Vec<DelegationScope>,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub not_before: Option<chrono::DateTime<chrono::Utc>>,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
}

/// One permitted operation inside a delegation grant. Omitted match fields are wildcards;
/// a grant still needs at least one scope to permit anything.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DelegationScope {
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub action_type: Option<ActionType>,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub action_name: Option<String>,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub resource_id: Option<String>,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub resource_type: Option<security_contracts::ResourceType>,
}

/// YAML/JSON-friendly composition of the built-in PoC bricks. The presence of this
/// configuration enables the pipeline; an empty policy list is intentionally fail-closed.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct SecurityPipelineConfig {
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub required_identity: Option<RequiredIdentity>,
	#[serde(default, skip_serializing_if = "Vec::is_empty")]
	pub policies: Vec<Policy>,
	#[serde(default, skip_serializing_if = "Vec::is_empty")]
	pub required_tool_arguments: Vec<RequiredToolArgumentsConfig>,
	#[serde(default, skip_serializing_if = "Vec::is_empty")]
	pub required_tool_approvals: Vec<RequiredToolApprovalConfig>,
	/// Enables direct user-to-Agent delegation validation for requests carrying an Agent.
	#[serde(default, skip_serializing_if = "Vec::is_empty")]
	pub delegations: Vec<AgentDelegationConfig>,
	/// Optional second authorization stage that narrows static permissions with verified context.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub dynamic_authorization: Option<DynamicAuthorizationConfig>,
}

/// Runtime-installed controls that stay independent from the YAML policy shape. Applications use
/// this composition seam to bind trusted external systems without coupling the security core to
/// HTTP, a UI, or a specific approval product.
#[derive(Default)]
pub struct RuntimeSecurityControls {
	identity_controls: Vec<Box<dyn SecurityControl>>,
	action_controls: Vec<Box<dyn SecurityControl>>,
	approval_provider: Option<Arc<dyn ApprovalProvider>>,
}

impl RuntimeSecurityControls {
	pub fn add_identity_control(mut self, control: impl SecurityControl + 'static) -> Self {
		self.identity_controls.push(Box::new(control));
		self
	}

	pub fn add_action_control(mut self, control: impl SecurityControl + 'static) -> Self {
		self.action_controls.push(Box::new(control));
		self
	}

	pub fn with_approval_provider(mut self, provider: impl ApprovalProvider + 'static) -> Self {
		self.approval_provider = Some(Arc::new(provider));
		self
	}
}

impl SecurityPipelineConfig {
	pub fn build<S: AuditSink>(&self, audit: S) -> SecurityPipeline<StaticAndDynamicAuthorizer, S> {
		let authorizer = StaticAndDynamicAuthorizer::from_config(
			self.policies.clone(),
			self.dynamic_authorization.as_ref(),
		);
		self.build_with_authorizer(audit, authorizer, RuntimeSecurityControls::default())
	}

	/// Builds local authorization together with application-supplied identity and action controls.
	pub fn build_with_runtime_controls<S: AuditSink>(
		&self,
		audit: S,
		controls: RuntimeSecurityControls,
	) -> SecurityPipeline<StaticAndDynamicAuthorizer, S> {
		let authorizer = StaticAndDynamicAuthorizer::from_config(
			self.policies.clone(),
			self.dynamic_authorization.as_ref(),
		);
		self.build_with_authorizer(audit, authorizer, controls)
	}

	/// Adds a real-time delegation revocation check to the configured local authorization pipeline.
	/// The provider is queried only for requests that carry a verified delegation identifier.
	pub fn build_with_revocation<S: AuditSink, P: DelegationRevocationProvider + 'static>(
		&self,
		audit: S,
		provider: P,
	) -> SecurityPipeline<StaticAndDynamicAuthorizer, S> {
		let authorizer = StaticAndDynamicAuthorizer::from_config(
			self.policies.clone(),
			self.dynamic_authorization.as_ref(),
		);
		self.build_with_authorizer(
			audit,
			authorizer,
			RuntimeSecurityControls::default()
				.add_identity_control(DelegationRevocationCheck::new(provider)),
		)
	}

	/// Builds the configured controls around a remote PDP. A remote PDP is only meaningful with
	/// `dynamicAuthorization`, whose policy version, cache, and failure mode bind the response.
	pub fn build_with_remote_pdp<S: AuditSink, T: RemotePdpTransport>(
		&self,
		audit: S,
		transport: T,
	) -> Result<SecurityPipeline<StaticAndDynamicAuthorizer<RemoteDynamicPdp<T>>, S>, DynamicPdpError>
	{
		let dynamic = self.dynamic_authorization.as_ref().ok_or_else(|| {
			DynamicPdpError::unavailable("remote PDP requires dynamicAuthorization configuration")
		})?;
		let remote_pdp = RemoteDynamicPdp::new(transport, Some(dynamic.policy_version.clone()));
		let authorizer = StaticAndDynamicAuthorizer::new(
			PolicyAuthorizer::new(self.policies.clone()),
			Some(dynamic.cache_pdp(remote_pdp)),
		);
		Ok(self.build_with_authorizer(audit, authorizer, RuntimeSecurityControls::default()))
	}

	/// Builds remote-PDP authorization together with application-supplied security bricks.
	pub fn build_with_remote_pdp_and_runtime_controls<S: AuditSink, T: RemotePdpTransport>(
		&self,
		audit: S,
		transport: T,
		controls: RuntimeSecurityControls,
	) -> Result<SecurityPipeline<StaticAndDynamicAuthorizer<RemoteDynamicPdp<T>>, S>, DynamicPdpError>
	{
		let dynamic = self.dynamic_authorization.as_ref().ok_or_else(|| {
			DynamicPdpError::unavailable("remote PDP requires dynamicAuthorization configuration")
		})?;
		let remote_pdp = RemoteDynamicPdp::new(transport, Some(dynamic.policy_version.clone()));
		let authorizer = StaticAndDynamicAuthorizer::new(
			PolicyAuthorizer::new(self.policies.clone()),
			Some(dynamic.cache_pdp(remote_pdp)),
		);
		Ok(self.build_with_authorizer(audit, authorizer, controls))
	}

	/// Builds the remote-PDP variant with an additional real-time delegation revocation stage.
	pub fn build_with_remote_pdp_and_revocation<
		S: AuditSink,
		T: RemotePdpTransport,
		P: DelegationRevocationProvider + 'static,
	>(
		&self,
		audit: S,
		transport: T,
		provider: P,
	) -> Result<SecurityPipeline<StaticAndDynamicAuthorizer<RemoteDynamicPdp<T>>, S>, DynamicPdpError>
	{
		let dynamic = self.dynamic_authorization.as_ref().ok_or_else(|| {
			DynamicPdpError::unavailable("remote PDP requires dynamicAuthorization configuration")
		})?;
		let remote_pdp = RemoteDynamicPdp::new(transport, Some(dynamic.policy_version.clone()));
		let authorizer = StaticAndDynamicAuthorizer::new(
			PolicyAuthorizer::new(self.policies.clone()),
			Some(dynamic.cache_pdp(remote_pdp)),
		);
		Ok(
			self.build_with_authorizer(
				audit,
				authorizer,
				RuntimeSecurityControls::default()
					.add_identity_control(DelegationRevocationCheck::new(provider)),
			),
		)
	}

	fn build_with_authorizer<S: AuditSink, A: Authorizer>(
		&self,
		audit: S,
		authorizer: A,
		mut controls: RuntimeSecurityControls,
	) -> SecurityPipeline<A, S> {
		let mut pipeline = SecurityPipeline::new(authorizer, audit);
		if let Some(identity) = self.required_identity {
			pipeline = pipeline.add_identity_control(identity);
		}
		pipeline
			.identity_controls
			.append(&mut controls.identity_controls);
		for requirement in &self.required_tool_arguments {
			pipeline = pipeline.add_action_control(RequiredToolArguments::new(
				requirement.tool_name.clone(),
				requirement.required_fields.clone(),
			));
		}
		for requirement in &self.required_tool_approvals {
			pipeline = match &controls.approval_provider {
				Some(provider) => pipeline.add_action_control(ToolApproval::new(
					requirement.tool_name.clone(),
					provider.clone(),
				)),
				None => {
					pipeline.add_action_control(RequiredToolApproval::new(requirement.tool_name.clone()))
				},
			};
		}
		pipeline
			.action_controls
			.append(&mut controls.action_controls);
		if !self.delegations.is_empty() {
			pipeline = pipeline.add_identity_control(AgentDelegation::new(self.delegations.clone()));
		}
		pipeline
	}
}

impl RequiredIdentity {
	pub const fn user_agent_tenant() -> Self {
		Self {
			user: true,
			agent: true,
			tenant: true,
		}
	}
}

/// Validates a direct delegation from the authenticated user to the authenticated Agent.
/// Authorization remains a separate mandatory stage: a delegation only narrows the
/// operations an already-authorized Agent may perform for that user.
#[derive(Debug, Clone)]
pub struct AgentDelegation {
	delegations: Vec<AgentDelegationConfig>,
}

impl AgentDelegation {
	pub fn new(delegations: Vec<AgentDelegationConfig>) -> Self {
		Self { delegations }
	}

	fn matches_grant(
		grant: &AgentDelegationConfig,
		request: &ActionRequest,
		now: chrono::DateTime<chrono::Utc>,
	) -> bool {
		let subject = &request.subject;
		grant.id == subject.delegation_id.as_deref().unwrap_or_default()
			&& grant.user_id == subject.user_id.as_deref().unwrap_or_default()
			&& grant.agent_id == subject.agent_id.as_deref().unwrap_or_default()
			&& grant
				.tenant_id
				.as_deref()
				.is_none_or(|tenant| subject.tenant_id.as_deref() == Some(tenant))
			&& grant.not_before.is_none_or(|not_before| now >= not_before)
			&& grant.expires_at.is_none_or(|expires_at| now < expires_at)
			&& grant.scopes.iter().any(|scope| scope.matches(request))
	}
}

impl DelegationScope {
	fn matches(&self, request: &ActionRequest) -> bool {
		self
			.action_type
			.is_none_or(|action_type| action_type == request.action.action_type)
			&& self
				.action_name
				.as_deref()
				.is_none_or(|name| name == request.action.name)
			&& self
				.resource_id
				.as_deref()
				.is_none_or(|id| id == request.resource.id)
			&& self
				.resource_type
				.is_none_or(|resource_type| resource_type == request.resource.resource_type)
	}
}

impl SecurityControl for AgentDelegation {
	fn id(&self) -> &str {
		"agent-delegation"
	}

	fn check(
		&self,
		request: &ActionRequest,
		_arguments: Option<&serde_json::Value>,
	) -> Result<(), ControlDenial> {
		if request.subject.agent_id.is_none() {
			return Ok(());
		}
		if request.subject.user_id.is_none() {
			return Err(ControlDenial {
				control_id: self.id().into(),
				reason: "an Agent action requires a delegating user identity".into(),
			});
		}
		if request.subject.delegation_id.is_none() {
			return Err(ControlDenial {
				control_id: self.id().into(),
				reason: "an Agent action requires a verified delegationId".into(),
			});
		}
		if self
			.delegations
			.iter()
			.any(|grant| Self::matches_grant(grant, request, chrono::Utc::now()))
		{
			Ok(())
		} else {
			Err(ControlDenial {
				control_id: self.id().into(),
				reason: "no active delegation grant permits this Agent operation".into(),
			})
		}
	}
}

impl SecurityControl for RequiredIdentity {
	fn id(&self) -> &str {
		"required-identity"
	}

	fn check(
		&self,
		request: &ActionRequest,
		_arguments: Option<&serde_json::Value>,
	) -> Result<(), ControlDenial> {
		let missing = [
			(self.user && request.subject.user_id.is_none(), "userId"),
			(self.agent && request.subject.agent_id.is_none(), "agentId"),
			(
				self.tenant && request.subject.tenant_id.is_none(),
				"tenantId",
			),
		]
		.into_iter()
		.filter_map(|(missing, name)| missing.then_some(name))
		.collect::<Vec<_>>();

		if missing.is_empty() {
			Ok(())
		} else {
			Err(ControlDenial {
				control_id: self.id().into(),
				reason: format!(
					"missing required identity attributes: {}",
					missing.join(", ")
				),
			})
		}
	}
}

/// Requires named arguments for a particular Tool. This is intentionally a small,
/// reusable PoC validator; production implementations can replace it with JSON Schema
/// and domain-specific resource ownership checks.
#[derive(Debug, Clone)]
pub struct RequiredToolArguments {
	tool_name: String,
	required_fields: Vec<String>,
}

impl RequiredToolArguments {
	pub fn new(
		tool_name: impl Into<String>,
		required_fields: impl IntoIterator<Item = impl Into<String>>,
	) -> Self {
		Self {
			tool_name: tool_name.into(),
			required_fields: required_fields.into_iter().map(Into::into).collect(),
		}
	}
}

impl SecurityControl for RequiredToolArguments {
	fn id(&self) -> &str {
		"required-tool-arguments"
	}

	fn check(
		&self,
		request: &ActionRequest,
		arguments: Option<&serde_json::Value>,
	) -> Result<(), ControlDenial> {
		if request.action.action_type != ActionType::ToolInvoke || request.action.name != self.tool_name
		{
			return Ok(());
		}
		let Some(arguments) = arguments.and_then(serde_json::Value::as_object) else {
			return Err(ControlDenial {
				control_id: self.id().into(),
				reason: format!(
					"tool '{}' requires an object argument payload",
					self.tool_name
				),
			});
		};
		let missing = self
			.required_fields
			.iter()
			.filter(|field| {
				arguments
					.get(field.as_str())
					.is_none_or(serde_json::Value::is_null)
			})
			.map(String::as_str)
			.collect::<Vec<_>>();
		if missing.is_empty() {
			Ok(())
		} else {
			Err(ControlDenial {
				control_id: self.id().into(),
				reason: format!(
					"tool '{}' is missing required arguments: {}",
					self.tool_name,
					missing.join(", ")
				),
			})
		}
	}
}

/// A high-risk Tool gate used when the deployment has not yet connected an approval authority.
///
/// This is intentionally fail-closed: declaring a Tool as high risk must never silently grant
/// permission merely because an approval integration is absent.
#[derive(Debug, Clone)]
pub struct RequiredToolApproval {
	tool_name: String,
}

impl RequiredToolApproval {
	pub fn new(tool_name: impl Into<String>) -> Self {
		Self {
			tool_name: tool_name.into(),
		}
	}
}

impl SecurityControl for RequiredToolApproval {
	fn id(&self) -> &str {
		"required-tool-approval"
	}

	fn check(
		&self,
		request: &ActionRequest,
		_arguments: Option<&serde_json::Value>,
	) -> Result<(), ControlDenial> {
		if request.action.action_type != ActionType::ToolInvoke || request.action.name != self.tool_name
		{
			return Ok(());
		}
		Err(ControlDenial {
			control_id: self.id().into(),
			reason: format!(
				"high-risk tool '{}' requires an external approval grant",
				self.tool_name
			),
		})
	}
}

/// External approval is another replaceable brick: an implementation may call a human
/// workflow, a vehicle interlock, or a business transaction service.
pub trait ApprovalProvider: Send + Sync {
	fn approved(
		&self,
		request: &ActionRequest,
		arguments: &serde_json::Value,
	) -> Result<bool, ApprovalError>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovalError {
	pub reason: String,
}

impl ApprovalError {
	pub fn unavailable(reason: impl Into<String>) -> Self {
		Self {
			reason: reason.into(),
		}
	}
}

impl<T: ApprovalProvider + ?Sized> ApprovalProvider for Arc<T> {
	fn approved(
		&self,
		request: &ActionRequest,
		arguments: &serde_json::Value,
	) -> Result<bool, ApprovalError> {
		(**self).approved(request, arguments)
	}
}

#[derive(Debug, Clone, Copy)]
pub struct StaticApproval(pub bool);

impl ApprovalProvider for StaticApproval {
	fn approved(
		&self,
		_request: &ActionRequest,
		_arguments: &serde_json::Value,
	) -> Result<bool, ApprovalError> {
		Ok(self.0)
	}
}

pub struct ToolApproval<P> {
	tool_name: String,
	provider: P,
}

impl<P> ToolApproval<P> {
	pub fn new(tool_name: impl Into<String>, provider: P) -> Self {
		Self {
			tool_name: tool_name.into(),
			provider,
		}
	}
}

impl<P: ApprovalProvider> SecurityControl for ToolApproval<P> {
	fn id(&self) -> &str {
		"tool-approval"
	}

	fn check(
		&self,
		request: &ActionRequest,
		arguments: Option<&serde_json::Value>,
	) -> Result<(), ControlDenial> {
		if request.action.action_type != ActionType::ToolInvoke || request.action.name != self.tool_name
		{
			return Ok(());
		}
		let Some(arguments) = arguments else {
			return Err(ControlDenial {
				control_id: self.id().into(),
				reason: format!("tool '{}' requires approval arguments", self.tool_name),
			});
		};
		match self.provider.approved(request, arguments) {
			Ok(true) => Ok(()),
			Ok(false) => Err(ControlDenial {
				control_id: self.id().into(),
				reason: format!("tool '{}' was not approved", self.tool_name),
			}),
			Err(error) => Err(ControlDenial {
				control_id: self.id().into(),
				reason: format!("approval check unavailable: {}", error.reason),
			}),
		}
	}
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GatewayError {
	Denied(Decision),
	DeniedByControl {
		decision: Decision,
		denial: ControlDenial,
	},
	Capability(CapabilityError),
	CapabilityUnavailable,
}

/// Ordered, composable security enforcement for one normalized Gateway request.
///
/// Identity controls run first, authorization is mandatory and independent, then action
/// controls run. Capability issuance is opt-in, allowing read-only services to use the
/// same pipeline without introducing a credential broker.
pub struct SecurityPipeline<A, S> {
	identity_controls: Vec<Box<dyn SecurityControl>>,
	authorizer: A,
	action_controls: Vec<Box<dyn SecurityControl>>,
	capabilities: Option<CapabilityBroker>,
	audit: S,
}

impl<A, S> SecurityPipeline<A, S>
where
	A: Authorizer,
	S: AuditSink,
{
	pub fn new(authorizer: A, audit: S) -> Self {
		Self {
			identity_controls: Vec::new(),
			authorizer,
			action_controls: Vec::new(),
			capabilities: None,
			audit,
		}
	}

	pub fn add_identity_control(mut self, control: impl SecurityControl + 'static) -> Self {
		self.identity_controls.push(Box::new(control));
		self
	}

	pub fn add_action_control(mut self, control: impl SecurityControl + 'static) -> Self {
		self.action_controls.push(Box::new(control));
		self
	}

	pub fn with_capability_broker(mut self) -> Self {
		self.capabilities = Some(CapabilityBroker::default());
		self
	}

	pub fn authorize(
		&self,
		request: &ActionRequest,
		arguments: Option<&serde_json::Value>,
	) -> Result<Decision, GatewayError> {
		for control in &self.identity_controls {
			if let Err(denial) = control.check(request, arguments) {
				return Err(self.reject_control(request, denial));
			}
		}

		let decision = self.authorizer.decide(request);
		if decision.effect == DecisionEffect::Deny {
			self.record(request, &decision);
			return Err(GatewayError::Denied(decision));
		}

		for control in &self.action_controls {
			if let Err(denial) = control.check(request, arguments) {
				return Err(self.reject_control(request, denial));
			}
		}

		self.record(request, &decision);
		Ok(decision)
	}

	pub fn authorize_tool(
		&self,
		request: &ActionRequest,
		arguments: &serde_json::Value,
		ttl: Duration,
	) -> Result<Capability, GatewayError> {
		self.authorize(request, Some(arguments))?;
		let Some(capabilities) = &self.capabilities else {
			return Err(GatewayError::CapabilityUnavailable);
		};
		Ok(capabilities.issue(request, arguments, ttl))
	}

	pub fn consume_tool_capability(
		&self,
		token: &str,
		request: &ActionRequest,
		arguments: &serde_json::Value,
	) -> Result<Capability, GatewayError> {
		let Some(capabilities) = &self.capabilities else {
			return Err(GatewayError::CapabilityUnavailable);
		};
		capabilities
			.consume(token, request, arguments)
			.map_err(GatewayError::Capability)
	}

	fn reject_control(&self, request: &ActionRequest, denial: ControlDenial) -> GatewayError {
		let decision = Decision {
			request_id: request.request_id.clone(),
			effect: DecisionEffect::Deny,
			policy_id: Some(format!("control:{}", denial.control_id)),
			policy_version: None,
			expires_at: None,
		};
		self.record(request, &decision);
		GatewayError::DeniedByControl { decision, denial }
	}

	fn record(&self, request: &ActionRequest, decision: &Decision) {
		self.audit.record(event_from_decision(
			Uuid::new_v4().to_string(),
			request,
			decision,
		));
	}
}

#[cfg(test)]
mod tests {
	use std::sync::Arc;
	use std::sync::atomic::{AtomicUsize, Ordering};

	use audit_core::InMemoryAuditSink;
	use chrono::Duration;
	use security_contracts::{
		Action, ActionRequest, ActionType, DecisionEffect, Resource, ResourceType, Subject,
	};

	use super::*;

	fn request() -> ActionRequest {
		ActionRequest {
			request_id: "pipeline-request".into(),
			subject: Subject {
				user_id: Some("alice".into()),
				agent_id: Some("maintenance-agent".into()),
				tenant_id: Some("tenant-a".into()),
				delegation_id: None,
			},
			action: Action {
				action_type: ActionType::ToolInvoke,
				name: "db.delete".into(),
			},
			resource: Resource {
				id: "prod-db".into(),
				resource_type: ResourceType::Tool,
			},
			authorization_context: Default::default(),
		}
	}

	fn allow_policy() -> Policy {
		Policy {
			id: "allow-maintenance-delete".into(),
			priority: 0,
			tenant_id: Some("tenant-a".into()),
			user_id: Some("alice".into()),
			agent_id: Some("maintenance-agent".into()),
			action_type: Some(ActionType::ToolInvoke),
			action_name: Some("db.delete".into()),
			resource_id: Some("prod-db".into()),
			resource_type: Some(ResourceType::Tool),
			effect: DecisionEffect::Allow,
			enabled: true,
		}
	}

	#[test]
	fn pipeline_composes_identity_validation_authorization_and_capabilities() {
		let audit = InMemoryAuditSink::default();
		let pipeline = SecurityPipeline::new(PolicyAuthorizer::new(vec![allow_policy()]), &audit)
			.add_identity_control(RequiredIdentity::user_agent_tenant())
			.add_action_control(RequiredToolArguments::new("db.delete", ["recordId"]))
			.add_action_control(ToolApproval::new("db.delete", StaticApproval(true)))
			.with_capability_broker();
		let request = request();
		let arguments = serde_json::json!({ "recordId": "42" });

		let capability = pipeline
			.authorize_tool(&request, &arguments, Duration::seconds(30))
			.unwrap();
		assert!(
			pipeline
				.consume_tool_capability(&capability.token, &request, &arguments)
				.is_ok()
		);
		assert_eq!(audit.events()[0].decision, DecisionEffect::Allow);
	}

	#[test]
	fn pipeline_audits_an_action_control_denial() {
		let audit = InMemoryAuditSink::default();
		let pipeline = SecurityPipeline::new(PolicyAuthorizer::new(vec![allow_policy()]), &audit)
			.add_identity_control(RequiredIdentity::user_agent_tenant())
			.add_action_control(RequiredToolArguments::new("db.delete", ["recordId"]));
		let request = request();

		let error = pipeline
			.authorize(&request, Some(&serde_json::json!({})))
			.unwrap_err();
		assert!(matches!(
			error,
			GatewayError::DeniedByControl { ref denial, .. }
				if denial.control_id == "required-tool-arguments"
		));
		let event = audit.events().pop().unwrap();
		assert_eq!(event.decision, DecisionEffect::Deny);
		assert_eq!(
			event.policy_id.as_deref(),
			Some("control:required-tool-arguments")
		);
	}

	#[test]
	fn yaml_facing_config_builds_the_expected_security_bricks() {
		let config: SecurityPipelineConfig = serde_json::from_value(serde_json::json!({
			"requiredIdentity": { "user": true, "agent": true, "tenant": true },
			"policies": [{
				"id": "allow-maintenance-delete",
				"tenantId": "tenant-a",
				"userId": "alice",
				"agentId": "maintenance-agent",
				"actionType": "toolInvoke",
				"actionName": "db.delete",
				"resourceId": "prod-db",
				"resourceType": "tool",
				"effect": "allow",
				"enabled": true
			}],
			"requiredToolArguments": [{
				"toolName": "db.delete",
				"requiredFields": ["recordId"]
			}],
			"dynamicAuthorization": {
				"policyVersion": "s4-v1",
				"failureMode": "failClosed",
				"policies": [{
					"id": "allow-active-maintenance-session",
					"tenantId": "tenant-a",
					"userId": "alice",
					"agentId": "maintenance-agent",
					"actionType": "toolInvoke",
					"actionName": "db.delete",
					"resourceId": "prod-db",
					"resourceType": "tool",
					"sessionId": "session-42",
					"effect": "allow",
					"enabled": true
				}]
			}
		}))
		.unwrap();
		let audit = InMemoryAuditSink::default();
		let pipeline = config.build(&audit);
		let mut request = request();
		request.authorization_context.session_id = Some("session-42".into());

		assert!(
			pipeline
				.authorize(&request, Some(&serde_json::json!({ "recordId": "42" })))
				.is_ok()
		);
	}

	#[test]
	fn dynamic_policy_narrows_a_static_allow_using_verified_context() {
		let config = SecurityPipelineConfig {
			policies: vec![allow_policy()],
			dynamic_authorization: Some(DynamicAuthorizationConfig {
				policy_version: "s4-v1".into(),
				policies: vec![DynamicPolicy {
					policy: allow_policy(),
					session_id: Some("session-42".into()),
					client_id: Some("support-console".into()),
					not_before: None,
					expires_at: None,
				}],
				cache_ttl_seconds: 0,
				failure_mode: DynamicPdpFailureMode::FailClosed,
				cache: DecisionCache::default(),
			}),
			..Default::default()
		};
		let audit = InMemoryAuditSink::default();
		let pipeline = config.build(&audit);
		let mut authorized = request();
		authorized.authorization_context.session_id = Some("session-42".into());
		authorized.authorization_context.client_id = Some("support-console".into());
		assert!(pipeline.authorize(&authorized, None).is_ok());

		let mut wrong_session = authorized;
		wrong_session.authorization_context.session_id = Some("session-other".into());
		assert!(matches!(
			pipeline.authorize(&wrong_session, None),
			Err(GatewayError::Denied(decision))
				if decision.policy_id.as_deref() == Some("dynamic-pdp:no-matching-policy")
		));
	}

	struct UnavailablePdp;

	impl DynamicPdp for UnavailablePdp {
		fn decide(&self, _request: &ActionRequest) -> Result<Decision, DynamicPdpError> {
			Err(DynamicPdpError::unavailable("connection refused"))
		}
	}

	#[test]
	fn dynamic_pdp_failure_never_falls_back_to_a_static_allow() {
		let audit = InMemoryAuditSink::default();
		let dynamic = CachedDynamicPdp::new(
			UnavailablePdp,
			DecisionCache::default(),
			"s4-v1",
			Duration::seconds(30),
			DynamicPdpFailureMode::FailClosed,
		);
		let pipeline = SecurityPipeline::new(
			StaticAndDynamicAuthorizer::new(PolicyAuthorizer::new(vec![allow_policy()]), Some(dynamic)),
			&audit,
		);
		assert!(matches!(
			pipeline.authorize(&request(), None),
			Err(GatewayError::Denied(decision))
				if decision.policy_id.as_deref() == Some("dynamic-pdp:unavailable:connection refused")
		));
	}

	struct CountingPdp {
		calls: Arc<AtomicUsize>,
	}

	impl DynamicPdp for CountingPdp {
		fn decide(&self, request: &ActionRequest) -> Result<Decision, DynamicPdpError> {
			self.calls.fetch_add(1, Ordering::SeqCst);
			Ok(Decision {
				request_id: request.request_id.clone(),
				effect: DecisionEffect::Allow,
				policy_id: Some("dynamic-allow".into()),
				policy_version: None,
				expires_at: None,
			})
		}
	}

	#[test]
	fn explicit_fresh_cache_reuses_only_the_same_dynamic_context() {
		let calls = Arc::new(AtomicUsize::new(0));
		let dynamic = CachedDynamicPdp::new(
			CountingPdp {
				calls: calls.clone(),
			},
			DecisionCache::default(),
			"s4-v1",
			Duration::seconds(30),
			DynamicPdpFailureMode::UseCachedDecision,
		);
		let audit = InMemoryAuditSink::default();
		let pipeline = SecurityPipeline::new(
			StaticAndDynamicAuthorizer::new(PolicyAuthorizer::new(vec![allow_policy()]), Some(dynamic)),
			&audit,
		);
		let mut first = request();
		first.authorization_context.session_id = Some("session-42".into());
		let mut same_context = first.clone();
		same_context.request_id = "another-request".into();
		let mut different_context = first.clone();
		different_context.authorization_context.session_id = Some("session-43".into());

		assert!(pipeline.authorize(&first, None).is_ok());
		assert!(pipeline.authorize(&same_context, None).is_ok());
		assert!(pipeline.authorize(&different_context, None).is_ok());
		assert_eq!(calls.load(Ordering::SeqCst), 2);
	}

	#[derive(Clone)]
	struct FixedRemoteTransport(RemotePdpResponse);

	impl RemotePdpTransport for FixedRemoteTransport {
		fn decide(&self, _request: RemotePdpRequest) -> Result<RemotePdpResponse, DynamicPdpError> {
			Ok(self.0.clone())
		}
	}

	struct FixedRevocation(bool);

	impl DelegationRevocationProvider for FixedRevocation {
		fn is_revoked(&self, _delegation_id: &str) -> Result<bool, DelegationRevocationError> {
			Ok(self.0)
		}
	}

	#[test]
	fn remote_pdp_binds_response_to_request_version_and_expiry() {
		let request = request();
		let expires_at = Utc::now() + Duration::seconds(30);
		let pdp = RemoteDynamicPdp::new(
			FixedRemoteTransport(RemotePdpResponse {
				request_id: request.request_id.clone(),
				effect: DecisionEffect::Allow,
				policy_id: "pdp-allow-delete".into(),
				policy_version: "2026-09-14".into(),
				expires_at,
			}),
			Some("2026-09-14".into()),
		);
		let decision = pdp.decide(&request).unwrap();
		assert_eq!(decision.effect, DecisionEffect::Allow);
		assert_eq!(decision.policy_version.as_deref(), Some("2026-09-14"));
		assert_eq!(decision.expires_at, Some(expires_at));

		let mismatched = RemoteDynamicPdp::new(
			FixedRemoteTransport(RemotePdpResponse {
				request_id: "another-request".into(),
				effect: DecisionEffect::Allow,
				policy_id: "pdp-allow-delete".into(),
				policy_version: "2026-09-14".into(),
				expires_at,
			}),
			Some("2026-09-14".into()),
		);
		assert!(mismatched.decide(&request).is_err());
	}

	#[test]
	fn configured_pipeline_uses_remote_pdp_after_static_allow() {
		let request = request();
		let config = SecurityPipelineConfig {
			policies: vec![allow_policy()],
			dynamic_authorization: Some(DynamicAuthorizationConfig {
				policy_version: "2026-09-14".into(),
				policies: Vec::new(),
				cache_ttl_seconds: 0,
				failure_mode: DynamicPdpFailureMode::FailClosed,
				cache: DecisionCache::default(),
			}),
			..Default::default()
		};
		let audit = InMemoryAuditSink::default();
		let pipeline = config
			.build_with_remote_pdp(
				&audit,
				FixedRemoteTransport(RemotePdpResponse {
					request_id: request.request_id.clone(),
					effect: DecisionEffect::Allow,
					policy_id: "remote-allow-delete".into(),
					policy_version: "2026-09-14".into(),
					expires_at: Utc::now() + Duration::seconds(30),
				}),
			)
			.unwrap();

		assert!(pipeline.authorize(&request, None).is_ok());
		assert_eq!(
			audit.events()[0].policy_id.as_deref(),
			Some("remote-allow-delete")
		);
	}

	#[test]
	fn configured_revocation_stage_blocks_a_revoked_delegation_before_authorization() {
		let config = SecurityPipelineConfig {
			policies: vec![allow_policy()],
			..Default::default()
		};
		let audit = InMemoryAuditSink::default();
		let pipeline = config.build_with_revocation(&audit, FixedRevocation(true));
		let mut request = request();
		request.subject.delegation_id = Some("delegation-alice-maintenance".into());

		assert!(matches!(
			pipeline.authorize(&request, None),
			Err(GatewayError::DeniedByControl { ref denial, .. })
				if denial.control_id == "delegation-revocation"
		));
		assert_eq!(audit.events()[0].decision, DecisionEffect::Deny);
	}

	#[test]
	fn trusted_runtime_approval_replaces_the_fail_closed_high_risk_gate() {
		let config = SecurityPipelineConfig {
			policies: vec![allow_policy()],
			required_tool_approvals: vec![RequiredToolApprovalConfig {
				tool_name: "db.delete".into(),
			}],
			..Default::default()
		};
		let audit = InMemoryAuditSink::default();
		let pipeline = config.build_with_runtime_controls(
			&audit,
			RuntimeSecurityControls::default().with_approval_provider(StaticApproval(true)),
		);
		assert!(
			pipeline
				.authorize(&request(), Some(&serde_json::json!({ "recordId": "42" })))
				.is_ok()
		);

		let denied = config.build_with_runtime_controls(
			InMemoryAuditSink::default(),
			RuntimeSecurityControls::default().with_approval_provider(StaticApproval(false)),
		);
		assert!(
			denied
				.authorize(&request(), Some(&serde_json::json!({})))
				.is_err()
		);
	}

	#[test]
	fn decision_cache_never_outlives_the_pdp_expiry() {
		let cache = DecisionCache::default();
		let decision = Decision {
			request_id: "request".into(),
			effect: DecisionEffect::Allow,
			policy_id: Some("pdp-allow".into()),
			policy_version: Some("v1".into()),
			expires_at: Some(Utc::now() + Duration::seconds(2)),
		};
		cache.insert("key".into(), decision, Duration::seconds(60));
		assert!(
			cache
				.get("key", Utc::now() + Duration::seconds(3))
				.is_none()
		);
	}

	#[test]
	fn revoking_a_delegation_blocks_the_next_agent_action() {
		let registry = Arc::new(DelegationRevocationRegistry::default());
		let audit = InMemoryAuditSink::default();
		let pipeline = SecurityPipeline::new(PolicyAuthorizer::new(vec![allow_policy()]), &audit)
			.add_identity_control(DelegationRevocationCheck::new(registry.clone()));
		let mut request = request();
		request.subject.delegation_id = Some("delegation-alice-maintenance".into());
		assert!(pipeline.authorize(&request, None).is_ok());

		registry.revoke("delegation-alice-maintenance");
		assert!(matches!(
			pipeline.authorize(&request, None),
			Err(GatewayError::DeniedByControl { ref denial, .. })
				if denial.control_id == "delegation-revocation"
		));
	}
}
