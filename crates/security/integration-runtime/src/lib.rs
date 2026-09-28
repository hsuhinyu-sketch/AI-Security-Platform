use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use security_audit::{AuditSink, event_from_decision};
use security_pipeline::{
	AgentIdentityRegistry, AgentIdentityRegistryConfig, Authorizer, DelegationRevocationCheck,
	ExternalAgentIdentityCheck, GatewayError, RuntimeSecurityControls, SecurityPipelineConfig,
};
use security_types::{ActionRequest, Decision, DecisionEffect, SecurityEvent};

mod blocking_client_cache;
mod data_egress;
pub use data_egress::{DataEgressConfig, check_data_egress};
pub use security_types::DataClassification;
pub mod remote_agent_identity;
pub mod remote_approval;
pub mod remote_capability;
pub mod remote_pdp;
pub mod remote_revocation;
mod trusted_https;

pub use remote_agent_identity::RemoteAgentIdentityConfig;
pub use remote_approval::RemoteApprovalConfig;
pub use remote_capability::{CapabilityGrant, RemoteCapabilityBrokerConfig};
pub use remote_pdp::RemotePdpConfig;
pub use remote_revocation::RemoteDelegationRevocationConfig;

/// Runtime-neutral structured audit sink for gateway security decisions.
#[derive(Clone, Copy, Default)]
pub struct TracingAuditSink;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum SecurityMode {
	/// Record decisions without changing request processing.
	#[default]
	Audit,
	/// Record decisions and warn whenever the same policy would deny in enforce mode.
	Shadow,
	/// Return policy and control denials to the gateway adapter for request rejection.
	Enforce,
}

/// System-level common security configuration. Protocol-specific controls remain separate.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SecurityConfig {
	#[serde(default)]
	pub mode: SecurityMode,
	/// Optional trusted HTTPS PDP used instead of the in-process dynamic PDP.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub remote_pdp: Option<RemotePdpConfig>,
	/// Optional shared source for immediate, cross-instance delegation revocation.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub delegation_revocation: Option<RemoteDelegationRevocationConfig>,
	/// Optional trusted authority for configured high-risk Tool approval gates.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub approval: Option<RemoteApprovalConfig>,
	/// Optional shared broker issuing one-time capabilities for approved high-risk Tool calls.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub capability_broker: Option<RemoteCapabilityBrokerConfig>,
	/// Optional registered Agent identity source. It binds a verified JWT Agent claim to an enabled
	/// tenant-scoped Agent principal and an allowed OAuth client/workload identity.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub agent_identity: Option<AgentIdentityRegistryConfig>,
	/// Optional authoritative HTTPS/mTLS Agent Directory. This cannot be combined with the local
	/// static `agentIdentity` registry because two sources could disagree about a principal.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub remote_agent_identity: Option<RemoteAgentIdentityConfig>,
	/// Administrator-assigned data classification and exact outbound allowlists.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub data_egress: Option<DataEgressConfig>,
	#[serde(flatten)]
	pub pipeline: SecurityPipelineConfig,
}

impl SecurityConfig {
	/// Reject combinations that cannot enforce the declared security controls.
	/// An approval gate without a provider remains valid: it intentionally denies by default.
	pub fn validate_composition(&self) -> Result<(), String> {
		if let Some(egress) = &self.data_egress {
			if self.mode != SecurityMode::Enforce {
				return Err("dataEgress requires security.mode: enforce".into());
			}
			egress.validate()?;
		}
		if self.agent_identity.is_some() && self.remote_agent_identity.is_some() {
			return Err("configure either agentIdentity or remoteAgentIdentity, not both".into());
		}
		if self.remote_pdp.is_some() && self.pipeline.dynamic_authorization.is_none() {
			return Err("remotePdp requires dynamicAuthorization".into());
		}
		if self.approval.is_some() && self.pipeline.required_tool_approvals.is_empty() {
			return Err("approval requires at least one requiredToolApprovals entry".into());
		}
		if self.capability_broker.is_some() {
			if self.mode != SecurityMode::Enforce {
				return Err("capabilityBroker requires security.mode: enforce".into());
			}
			if self.pipeline.required_tool_approvals.is_empty() {
				return Err("capabilityBroker requires requiredToolApprovals".into());
			}
			if self.approval.is_none() {
				return Err("capabilityBroker requires a trusted approval provider".into());
			}
		}
		Ok(())
	}
}

/// Adapts the full gateway security configuration to a protocol-specific security pipeline.
///
/// RAG uses this at each of its three action boundaries. It deliberately delegates to
/// [`evaluate_with_arguments`] instead of reconstructing policies, so SecurityMode, remote PDP,
/// agent-directory binding, and delegation-revocation controls behave consistently across gateway
/// protocols.
#[derive(Clone)]
pub struct SecurityConfigAuthorizer {
	config: Arc<SecurityConfig>,
	audit: Arc<dyn AuditSink>,
}

impl SecurityConfigAuthorizer {
	pub fn new(config: Arc<SecurityConfig>) -> Self {
		Self::with_audit(config, TracingAuditSink)
	}

	pub fn with_audit(config: Arc<SecurityConfig>, audit: impl AuditSink + 'static) -> Self {
		Self {
			config,
			audit: Arc::new(audit),
		}
	}
}

impl Authorizer for SecurityConfigAuthorizer {
	fn decide(&self, request: &ActionRequest) -> Decision {
		match evaluate_with_audit(&self.config, request, None, self.audit.as_ref()) {
			Ok(()) => Decision {
				request_id: request.request_id.clone(),
				effect: DecisionEffect::Allow,
				policy_id: Some("security:runtime".into()),
				policy_version: None,
				expires_at: None,
			},
			Err(GatewayError::Denied(decision) | GatewayError::DeniedByControl { decision, .. }) => {
				decision
			},
			Err(GatewayError::Capability(_) | GatewayError::CapabilityUnavailable) => Decision {
				request_id: request.request_id.clone(),
				effect: DecisionEffect::Deny,
				policy_id: Some("security:runtime-unavailable".into()),
				policy_version: None,
				expires_at: None,
			},
		}
	}
}

impl AuditSink for TracingAuditSink {
	fn record(&self, event: SecurityEvent) {
		tracing::info!(
			target: "security_audit",
			event_id = %event.event_id,
			request_id = %event.request_id,
			user_id = ?event.subject.user_id,
			agent_id = ?event.subject.agent_id,
			tenant_id = ?event.subject.tenant_id,
			delegation_id = ?event.subject.delegation_id,
			session_id = ?event.authorization_context.session_id,
			client_id = ?event.authorization_context.client_id,
			action = ?event.action.action_type,
			resource = %event.resource.id,
			decision = ?event.decision,
			policy_id = ?event.policy_id,
			policy_version = ?event.policy_version,
			decision_expires_at = ?event.decision_expires_at,
			"security audit decision"
		);
	}
}

/// Evaluate and record a decision. Only enforce mode changes caller control flow.
pub fn evaluate(config: &SecurityConfig, action: &ActionRequest) -> Result<(), GatewayError> {
	evaluate_with_arguments(config, action, None)
}

/// Evaluate a protocol action with optional structured arguments.
///
/// Tool adapters use this to apply shared argument controls in addition to policy matching.
pub fn evaluate_with_arguments(
	config: &SecurityConfig,
	action: &ActionRequest,
	arguments: Option<&serde_json::Value>,
) -> Result<(), GatewayError> {
	evaluate_with_audit(config, action, arguments, &TracingAuditSink)
}

/// Evaluates a protocol action and writes its redacted decision to the caller-selected audit
/// destination. This lets a runtime fan the same authoritative decision out to tracing and an
/// administrative event feed without duplicating policy evaluation.
pub fn evaluate_with_audit(
	config: &SecurityConfig,
	action: &ActionRequest,
	arguments: Option<&serde_json::Value>,
	audit: &dyn AuditSink,
) -> Result<(), GatewayError> {
	if config.remote_pdp.is_some()
		|| config.remote_agent_identity.is_some()
		|| config.delegation_revocation.is_some()
		|| config.approval.is_some()
	{
		let result = on_blocking_security_thread(action, audit, || {
			evaluate_with_audit_inner(config, action, arguments, audit)
		});
		return if config.mode == SecurityMode::Enforce {
			result
		} else {
			// Worker saturation is still audited, but observe-only modes do not interrupt traffic.
			Ok(())
		};
	}
	evaluate_with_audit_inner(config, action, arguments, audit)
}

fn evaluate_with_audit_inner(
	config: &SecurityConfig,
	action: &ActionRequest,
	arguments: Option<&serde_json::Value>,
	audit: &dyn AuditSink,
) -> Result<(), GatewayError> {
	let decision = match runtime_security_controls(config) {
		Err(reason) => Err(configuration_denial(action, reason, audit)),
		Ok(controls) => match &config.remote_pdp {
			Some(remote_pdp) => remote_pdp
				.transport()
				.map_err(|error| configuration_denial(action, error.reason, audit))
				.and_then(|transport| {
					config
						.pipeline
						.build_with_remote_pdp_and_runtime_controls(audit, transport, controls)
						.map_err(|error| configuration_denial(action, error.reason, audit))
				})
				.and_then(|pipeline| pipeline.authorize(action, arguments)),
			None => config
				.pipeline
				.build_with_runtime_controls(audit, controls)
				.authorize(action, arguments),
		},
	};
	match decision {
		Ok(_) => Ok(()),
		Err(error) => match config.mode {
			SecurityMode::Audit => Ok(()),
			SecurityMode::Shadow => {
				tracing::warn!(
					target: "security_audit",
					request_id = %action.request_id,
					error = ?error,
					"security shadow policy would deny request"
				);
				Ok(())
			},
			SecurityMode::Enforce => Err(error),
		},
	}
}

/// Enforces a Tool call, then issues an opaque capability only for a configured high-risk Tool in
/// enforce mode. Audit and shadow modes never mint a credential that could reach a protected API.
pub fn authorize_tool_with_capability(
	config: &SecurityConfig,
	action: &ActionRequest,
	arguments: &serde_json::Value,
) -> Result<Option<CapabilityGrant>, GatewayError> {
	authorize_tool_with_capability_with_audit(config, action, arguments, &TracingAuditSink)
}

/// Tool authorization variant that writes its authoritative policy decision to a caller-selected
/// audit sink. The capability itself is intentionally never included in audit data.
pub fn authorize_tool_with_capability_with_audit(
	config: &SecurityConfig,
	action: &ActionRequest,
	arguments: &serde_json::Value,
	audit: &dyn AuditSink,
) -> Result<Option<CapabilityGrant>, GatewayError> {
	evaluate_with_audit(config, action, Some(arguments), audit)?;
	if config.mode != SecurityMode::Enforce || !config.pipeline.requires_tool_approval(action) {
		return Ok(None);
	}
	let Some(broker) = &config.capability_broker else {
		return Ok(None);
	};
	on_blocking_security_thread(action, audit, || {
		let issuer = broker
			.issuer()
			.map_err(|error| capability_denial(action, error.reason, audit))?;
		issuer
			.issue(action, arguments)
			.map(Some)
			.map_err(|error| capability_denial(action, error.reason, audit))
	})
}

const MAX_CONCURRENT_REMOTE_DECISIONS: usize = 32;
static ACTIVE_REMOTE_DECISIONS: AtomicUsize = AtomicUsize::new(0);

/// Keep synchronous remote-provider traits usable from every protocol adapter, including RAG.
/// Requests beyond the bounded bridge are denied rather than spawning unbounded OS threads.
fn on_blocking_security_thread<T: Send>(
	action: &ActionRequest,
	audit: &dyn AuditSink,
	work: impl FnOnce() -> Result<T, GatewayError> + Send,
) -> Result<T, GatewayError> {
	if tokio::runtime::Handle::try_current().is_err() {
		return work();
	}
	if ACTIVE_REMOTE_DECISIONS
		.fetch_update(Ordering::AcqRel, Ordering::Acquire, |active| {
			(active < MAX_CONCURRENT_REMOTE_DECISIONS).then_some(active + 1)
		})
		.is_err()
	{
		return Err(configuration_denial(
			action,
			"remote security worker limit reached".into(),
			audit,
		));
	}
	let run = || std::thread::scope(|scope| scope.spawn(work).join());
	let result = if tokio::runtime::Handle::current().runtime_flavor()
		== tokio::runtime::RuntimeFlavor::MultiThread
	{
		tokio::task::block_in_place(run)
	} else {
		run()
	};
	ACTIVE_REMOTE_DECISIONS.fetch_sub(1, Ordering::AcqRel);
	result.unwrap_or_else(|_| {
		Err(configuration_denial(
			action,
			"remote security worker failed".into(),
			audit,
		))
	})
}

fn runtime_security_controls(config: &SecurityConfig) -> Result<RuntimeSecurityControls, String> {
	let mut controls = RuntimeSecurityControls::default();
	if config.agent_identity.is_some() && config.remote_agent_identity.is_some() {
		return Err("configure either agentIdentity or remoteAgentIdentity, not both".into());
	}
	if let Some(agent_identity) = &config.agent_identity {
		let registry = AgentIdentityRegistry::from_config(agent_identity.clone())?;
		controls = controls.add_identity_control(registry);
	}
	if let Some(remote_agent_identity) = &config.remote_agent_identity {
		let provider = remote_agent_identity
			.provider()
			.map_err(|error| error.reason)?;
		controls = controls.add_identity_control(ExternalAgentIdentityCheck::new(
			remote_agent_identity.required,
			provider,
		));
	}
	if let Some(revocation) = &config.delegation_revocation {
		let provider = revocation.provider().map_err(|error| error.reason)?;
		controls = controls.add_identity_control(DelegationRevocationCheck::new(provider));
	}
	if let Some(approval) = &config.approval {
		let provider = approval.provider().map_err(|error| error.reason)?;
		controls = controls.with_approval_provider(provider);
	}
	Ok(controls)
}

fn configuration_denial(
	action: &ActionRequest,
	reason: String,
	audit: &dyn AuditSink,
) -> GatewayError {
	tracing::error!(
		target: "security_audit",
		request_id = %action.request_id,
		error = %reason,
		"external security configuration is invalid"
	);
	let decision = Decision {
		request_id: action.request_id.clone(),
		effect: DecisionEffect::Deny,
		policy_id: Some("security:configuration".into()),
		policy_version: None,
		expires_at: None,
	};
	audit.record(event_from_decision(
		format!("{}:security-configuration", action.request_id),
		action,
		&decision,
	));
	GatewayError::Denied(decision)
}

fn capability_denial(
	action: &ActionRequest,
	reason: String,
	audit: &dyn AuditSink,
) -> GatewayError {
	tracing::error!(
		target: "security_audit",
		request_id = %action.request_id,
		error = %reason,
		"capability broker could not issue a required Tool capability"
	);
	let decision = Decision {
		request_id: action.request_id.clone(),
		effect: DecisionEffect::Deny,
		policy_id: Some("security:capability-broker".into()),
		policy_version: None,
		expires_at: None,
	};
	audit.record(event_from_decision(
		format!("{}:capability-broker", action.request_id),
		action,
		&decision,
	));
	GatewayError::Denied(decision)
}

#[cfg(test)]
mod tests {
	use std::sync::Arc;

	use super::{
		SecurityConfig, SecurityConfigAuthorizer, SecurityMode, evaluate, evaluate_with_arguments,
	};
	use chrono::{Duration, Utc};
	use security_pipeline::{
		AgentDelegationConfig, AgentIdentityRegistryConfig, Authorizer, DelegationScope,
		GatewayIdentity, RegisteredAgentConfig, RequiredIdentity, SecurityPipelineConfig,
		agent_action_for_identity, model_invoke_for_identity, tool_invoke_for_identity,
	};
	use security_policy::Policy;
	use security_types::{ActionType, DecisionEffect, ResourceType};

	#[tokio::test(flavor = "current_thread")]
	async fn remote_client_can_be_created_and_disposed_inside_an_async_request() {
		let config: SecurityConfig = serde_json::from_value(serde_json::json!({
			"mode": "enforce",
			"remotePdp": {"endpoint": "https://127.0.0.1:1/decisions"}
		}))
		.expect("remote PDP configuration should deserialize");
		let action = security_pipeline::model_invoke("request", None, None, "model");
		assert!(evaluate(&config, &action).is_err());
		// Dropping the cached blocking client here used to panic inside Tokio.
		drop(config);
	}

	#[tokio::test(flavor = "current_thread")]
	async fn remote_identity_unavailable_denies_without_panicking_on_async_worker() {
		let config: SecurityConfig = serde_json::from_value(serde_json::json!({
			"mode": "enforce",
			"remoteAgentIdentity": {
				"endpoint": "https://127.0.0.1:1/v1/identities/check",
				"required": true,
				"timeoutMillis": 100
			}
		}))
		.expect("remote Agent Directory configuration should deserialize");
		let action = model_invoke_for_identity(
			"request",
			GatewayIdentity {
				user_id: Some("alice".into()),
				agent_id: Some("agent".into()),
				tenant_id: Some("tenant".into()),
				client_id: Some("agent-client".into()),
				..Default::default()
			},
			"model",
		);
		assert!(evaluate(&config, &action).is_err());
		drop(config);
	}

	#[test]
	fn composition_rejects_broker_without_a_trusted_approval_source() {
		let config: SecurityConfig = serde_json::from_value(serde_json::json!({
			"mode": "enforce",
			"requiredToolApprovals": [{"toolName": "records.delete"}],
			"capabilityBroker": {
				"issueEndpoint": "https://broker.example.test/v1/capabilities/issue"
			}
		}))
		.expect("composition should deserialize");
		assert!(
			config
				.validate_composition()
				.unwrap_err()
				.contains("approval provider")
		);
	}

	#[test]
	fn composition_rejects_remote_pdp_without_dynamic_authorization() {
		let config: SecurityConfig = serde_json::from_value(serde_json::json!({
			"remotePdp": {"endpoint": "https://pdp.example.test/v1/decisions"}
		}))
		.expect("composition should deserialize");
		assert_eq!(
			config.validate_composition().unwrap_err(),
			"remotePdp requires dynamicAuthorization"
		);
	}

	#[test]
	fn audit_and_shadow_do_not_interrupt_but_enforce_does() {
		let action = security_pipeline::model_invoke("request", None, None, "model");
		assert!(evaluate(&SecurityConfig::default(), &action).is_ok());
		assert!(
			evaluate(
				&SecurityConfig {
					mode: SecurityMode::Shadow,
					..Default::default()
				},
				&action,
			)
			.is_ok()
		);
		assert!(
			evaluate(
				&SecurityConfig {
					mode: SecurityMode::Enforce,
					..Default::default()
				},
				&action,
			)
			.is_err()
		);
	}

	#[test]
	fn config_authorizer_preserves_enforced_deny_by_default() {
		let authorizer = SecurityConfigAuthorizer::new(Arc::new(SecurityConfig {
			mode: SecurityMode::Enforce,
			..Default::default()
		}));
		let action = security_pipeline::knowledge_retrieve_for_identity(
			"request",
			GatewayIdentity {
				tenant_id: Some("tenant-a".into()),
				..Default::default()
			},
			"support",
		);
		assert_eq!(authorizer.decide(&action).effect, DecisionEffect::Deny);
	}

	#[test]
	fn enforce_applies_tenant_scoped_least_privilege() {
		let config = SecurityConfig {
			mode: SecurityMode::Enforce,
			remote_pdp: None,
			delegation_revocation: None,
			approval: None,
			capability_broker: None,
			agent_identity: None,
			remote_agent_identity: None,
			data_egress: None,
			pipeline: SecurityPipelineConfig {
				required_identity: Some(RequiredIdentity::user_agent_tenant()),
				policies: vec![Policy {
					id: "tenant-a-support-chat".into(),
					priority: 0,
					tenant_id: Some("tenant-a".into()),
					user_id: Some("alice".into()),
					agent_id: Some("support-agent".into()),
					action_type: Some(ActionType::ModelInvoke),
					action_name: Some("invoke".into()),
					resource_id: Some("support-chat".into()),
					resource_type: Some(ResourceType::Model),
					effect: DecisionEffect::Allow,
					enabled: true,
				}],
				..Default::default()
			},
		};
		let allowed_identity = GatewayIdentity {
			user_id: Some("alice".into()),
			agent_id: Some("support-agent".into()),
			tenant_id: Some("tenant-a".into()),
			delegation_id: None,
			session_id: None,
			client_id: None,
		};
		let allowed = model_invoke_for_identity("request-allowed", allowed_identity, "support-chat");
		assert!(evaluate(&config, &allowed).is_ok());

		let other_tenant = model_invoke_for_identity(
			"request-other-tenant",
			GatewayIdentity {
				user_id: Some("alice".into()),
				agent_id: Some("support-agent".into()),
				tenant_id: Some("tenant-b".into()),
				delegation_id: None,
				session_id: None,
				client_id: None,
			},
			"support-chat",
		);
		assert!(evaluate(&config, &other_tenant).is_err());
	}

	#[test]
	fn enforce_accepts_only_a_registered_agent_client_binding() {
		let config = SecurityConfig {
			mode: SecurityMode::Enforce,
			remote_pdp: None,
			delegation_revocation: None,
			approval: None,
			capability_broker: None,
			agent_identity: Some(AgentIdentityRegistryConfig {
				required: true,
				agents: vec![RegisteredAgentConfig {
					agent_id: "support-agent".into(),
					tenant_id: "tenant-a".into(),
					client_ids: vec!["support-agent-workload".into()],
					enabled: true,
					not_before: None,
					expires_at: None,
				}],
			}),
			remote_agent_identity: None,
			data_egress: None,
			pipeline: SecurityPipelineConfig {
				policies: vec![Policy {
					id: "allow-support-agent".into(),
					priority: 0,
					tenant_id: Some("tenant-a".into()),
					user_id: Some("alice".into()),
					agent_id: Some("support-agent".into()),
					action_type: Some(ActionType::ModelInvoke),
					action_name: Some("invoke".into()),
					resource_id: Some("support-chat".into()),
					resource_type: Some(ResourceType::Model),
					effect: DecisionEffect::Allow,
					enabled: true,
				}],
				..Default::default()
			},
		};
		let trusted = GatewayIdentity {
			user_id: Some("alice".into()),
			agent_id: Some("support-agent".into()),
			tenant_id: Some("tenant-a".into()),
			delegation_id: None,
			session_id: None,
			client_id: Some("support-agent-workload".into()),
		};
		assert!(
			evaluate(
				&config,
				&model_invoke_for_identity("registered-agent", trusted.clone(), "support-chat")
			)
			.is_ok()
		);
		assert!(
			evaluate(
				&config,
				&model_invoke_for_identity(
					"untrusted-client",
					GatewayIdentity {
						client_id: Some("other-client".into()),
						..trusted
					},
					"support-chat"
				)
			)
			.is_err()
		);
	}

	#[test]
	fn enforce_distinguishes_protocol_actions_and_applies_tool_arguments() {
		let config = SecurityConfig {
			mode: SecurityMode::Enforce,
			remote_pdp: None,
			delegation_revocation: None,
			approval: None,
			capability_broker: None,
			agent_identity: None,
			remote_agent_identity: None,
			data_egress: None,
			pipeline: SecurityPipelineConfig {
				policies: vec![
					Policy {
						id: "allow-task-send".into(),
						priority: 0,
						tenant_id: None,
						user_id: None,
						agent_id: None,
						action_type: Some(ActionType::AgentInvoke),
						action_name: Some("tasks/send".into()),
						resource_id: Some("support-agent".into()),
						resource_type: Some(ResourceType::Agent),
						effect: DecisionEffect::Allow,
						enabled: true,
					},
					Policy {
						id: "allow-ticket-tool".into(),
						priority: 0,
						tenant_id: None,
						user_id: None,
						agent_id: None,
						action_type: Some(ActionType::ToolInvoke),
						action_name: Some("tickets.create".into()),
						resource_id: Some("tickets.create".into()),
						resource_type: Some(ResourceType::Tool),
						effect: DecisionEffect::Allow,
						enabled: true,
					},
				],
				required_tool_arguments: vec![security_pipeline::RequiredToolArgumentsConfig {
					tool_name: "tickets.create".into(),
					required_fields: vec!["customerId".into()],
				}],
				..Default::default()
			},
		};
		assert!(
			evaluate(
				&config,
				&agent_action_for_identity(
					"a2a-send",
					GatewayIdentity::default(),
					"support-agent",
					"tasks/send",
				),
			)
			.is_ok()
		);
		assert!(
			evaluate(
				&config,
				&agent_action_for_identity(
					"a2a-cancel",
					GatewayIdentity::default(),
					"support-agent",
					"tasks/cancel",
				),
			)
			.is_err()
		);

		let tool =
			tool_invoke_for_identity("tool-create", GatewayIdentity::default(), "tickets.create");
		assert!(
			evaluate_with_arguments(
				&config,
				&tool,
				Some(&serde_json::json!({ "customerId": "c-1" }))
			)
			.is_ok()
		);
		assert!(evaluate_with_arguments(&config, &tool, Some(&serde_json::json!({}))).is_err());
	}

	#[test]
	fn high_risk_tool_is_fail_closed_until_an_approval_provider_is_installed() {
		let tool =
			tool_invoke_for_identity("tool-delete", GatewayIdentity::default(), "records.delete");
		let pipeline = SecurityPipelineConfig {
			policies: vec![Policy {
				id: "allow-delete".into(),
				priority: 0,
				tenant_id: None,
				user_id: None,
				agent_id: None,
				action_type: Some(ActionType::ToolInvoke),
				action_name: Some("records.delete".into()),
				resource_id: Some("records.delete".into()),
				resource_type: Some(ResourceType::Tool),
				effect: DecisionEffect::Allow,
				enabled: true,
			}],
			required_tool_approvals: vec![security_pipeline::RequiredToolApprovalConfig {
				tool_name: "records.delete".into(),
			}],
			..Default::default()
		};
		assert!(
			evaluate(
				&SecurityConfig {
					mode: SecurityMode::Enforce,
					remote_pdp: None,
					delegation_revocation: None,
					approval: None,
					capability_broker: None,
					agent_identity: None,
					remote_agent_identity: None,
					data_egress: None,
					pipeline: pipeline.clone(),
				},
				&tool,
			)
			.is_err()
		);
		assert!(
			evaluate(
				&SecurityConfig {
					mode: SecurityMode::Shadow,
					remote_pdp: None,
					delegation_revocation: None,
					approval: None,
					capability_broker: None,
					agent_identity: None,
					remote_agent_identity: None,
					data_egress: None,
					pipeline,
				},
				&tool,
			)
			.is_ok()
		);
	}

	#[test]
	fn enforce_requires_a_verified_scoped_agent_delegation() {
		let config = SecurityConfig {
			mode: SecurityMode::Enforce,
			remote_pdp: None,
			delegation_revocation: None,
			approval: None,
			capability_broker: None,
			agent_identity: None,
			remote_agent_identity: None,
			data_egress: None,
			pipeline: SecurityPipelineConfig {
				policies: vec![Policy {
					id: "allow-support-agent".into(),
					priority: 0,
					tenant_id: Some("tenant-a".into()),
					user_id: Some("alice".into()),
					agent_id: Some("support-agent".into()),
					action_type: None,
					action_name: None,
					resource_id: None,
					resource_type: None,
					effect: DecisionEffect::Allow,
					enabled: true,
				}],
				delegations: vec![AgentDelegationConfig {
					id: "delegation-alice-support-01".into(),
					user_id: "alice".into(),
					agent_id: "support-agent".into(),
					tenant_id: Some("tenant-a".into()),
					scopes: vec![DelegationScope {
						action_type: Some(ActionType::ToolInvoke),
						action_name: Some("tickets.create".into()),
						resource_id: Some("tickets.create".into()),
						resource_type: Some(ResourceType::Tool),
					}],
					not_before: Some(Utc::now() - Duration::minutes(1)),
					expires_at: Some(Utc::now() + Duration::minutes(30)),
				}],
				..Default::default()
			},
		};
		let delegated = GatewayIdentity {
			user_id: Some("alice".into()),
			agent_id: Some("support-agent".into()),
			tenant_id: Some("tenant-a".into()),
			delegation_id: Some("delegation-alice-support-01".into()),
			session_id: None,
			client_id: None,
		};
		assert!(
			evaluate_with_arguments(
				&config,
				&tool_invoke_for_identity("delegated-tool", delegated.clone(), "tickets.create"),
				Some(&serde_json::json!({ "customerId": "c-1" })),
			)
			.is_ok()
		);

		let without_grant = GatewayIdentity {
			delegation_id: None,
			..delegated.clone()
		};
		assert!(
			evaluate(
				&config,
				&tool_invoke_for_identity("missing-grant", without_grant, "tickets.create"),
			)
			.is_err()
		);
		assert!(
			evaluate(
				&config,
				&model_invoke_for_identity("out-of-scope", delegated, "support-chat"),
			)
			.is_err()
		);
	}

	#[test]
	fn invalid_remote_pdp_configuration_is_denied_in_enforce_mode() {
		let remote_pdp = serde_json::from_value(serde_json::json!({
			"endpoint": "http://pdp.internal/v1/decisions"
		}))
		.expect("remote PDP test configuration should deserialize");
		let action = security_pipeline::model_invoke("request", None, None, "model");
		let result = evaluate(
			&SecurityConfig {
				mode: SecurityMode::Enforce,
				remote_pdp: Some(remote_pdp),
				delegation_revocation: None,
				approval: None,
				capability_broker: None,
				agent_identity: None,
				remote_agent_identity: None,
				data_egress: None,
				pipeline: SecurityPipelineConfig::default(),
			},
			&action,
		);
		assert!(matches!(
			result,
			Err(security_pipeline::GatewayError::Denied(decision))
				if decision.policy_id.as_deref() == Some("security:configuration")
		));
	}

	#[test]
	fn invalid_remote_revocation_configuration_is_denied_in_enforce_mode() {
		let delegation_revocation = serde_json::from_value(serde_json::json!({
			"endpoint": "http://revocations.internal/v1/check"
		}))
		.expect("revocation test configuration should deserialize");
		let action = security_pipeline::model_invoke("request", None, None, "model");
		let result = evaluate(
			&SecurityConfig {
				mode: SecurityMode::Enforce,
				remote_pdp: None,
				delegation_revocation: Some(delegation_revocation),
				approval: None,
				capability_broker: None,
				agent_identity: None,
				remote_agent_identity: None,
				data_egress: None,
				pipeline: SecurityPipelineConfig::default(),
			},
			&action,
		);
		assert!(matches!(
			result,
			Err(security_pipeline::GatewayError::Denied(decision))
				if decision.policy_id.as_deref() == Some("security:configuration")
		));
	}

	#[test]
	fn invalid_remote_approval_configuration_is_denied_in_enforce_mode() {
		let approval = serde_json::from_value(serde_json::json!({
			"endpoint": "http://approval.internal/v1/check"
		}))
		.expect("approval test configuration should deserialize");
		let action = security_pipeline::model_invoke("request", None, None, "model");
		let result = evaluate(
			&SecurityConfig {
				mode: SecurityMode::Enforce,
				remote_pdp: None,
				delegation_revocation: None,
				approval: Some(approval),
				capability_broker: None,
				agent_identity: None,
				remote_agent_identity: None,
				data_egress: None,
				pipeline: SecurityPipelineConfig::default(),
			},
			&action,
		);
		assert!(matches!(
			result,
			Err(security_pipeline::GatewayError::Denied(decision))
				if decision.policy_id.as_deref() == Some("security:configuration")
		));
	}

	#[test]
	fn invalid_remote_agent_directory_configuration_is_denied_in_enforce_mode() {
		let remote_agent_identity = serde_json::from_value(serde_json::json!({
			"endpoint": "http://agents.internal/v1/identities/check",
			"required": true
		}))
		.expect("remote Agent Directory test configuration should deserialize");
		let action = security_pipeline::model_invoke("request", None, None, "model");
		let result = evaluate(
			&SecurityConfig {
				mode: SecurityMode::Enforce,
				remote_pdp: None,
				delegation_revocation: None,
				approval: None,
				capability_broker: None,
				agent_identity: None,
				remote_agent_identity: Some(remote_agent_identity),
				data_egress: None,
				pipeline: SecurityPipelineConfig::default(),
			},
			&action,
		);
		assert!(matches!(
			result,
			Err(security_pipeline::GatewayError::Denied(decision))
				if decision.policy_id.as_deref() == Some("security:configuration")
		));
	}
}
