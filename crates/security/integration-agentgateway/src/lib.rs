use audit_core::{AuditSink, event_from_decision};
use gateway_adapter::{GatewayError, SecurityPipelineConfig};
use security_contracts::{ActionRequest, Decision, DecisionEffect, SecurityEvent};

pub mod remote_pdp;

pub use remote_pdp::RemotePdpConfig;

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
	#[serde(flatten)]
	pub pipeline: SecurityPipelineConfig,
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
	let decision = match &config.remote_pdp {
		Some(remote_pdp) => remote_pdp
			.transport()
			.map_err(|error| error.reason)
			.and_then(|transport| {
				config
					.pipeline
					.build_with_remote_pdp(TracingAuditSink, transport)
					.map_err(|error| error.reason)
			})
			.map_err(|reason| configuration_denial(action, reason))
			.and_then(|pipeline| pipeline.authorize(action, arguments)),
		None => config
			.pipeline
			.build(TracingAuditSink)
			.authorize(action, arguments),
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

fn configuration_denial(action: &ActionRequest, reason: String) -> GatewayError {
	tracing::error!(
		target: "security_audit",
		request_id = %action.request_id,
		error = %reason,
		"remote PDP security configuration is invalid"
	);
	let decision = Decision {
		request_id: action.request_id.clone(),
		effect: DecisionEffect::Deny,
		policy_id: Some("dynamic-pdp:configuration".into()),
		policy_version: None,
		expires_at: None,
	};
	TracingAuditSink.record(event_from_decision(
		format!("{}:dynamic-pdp-configuration", action.request_id),
		action,
		&decision,
	));
	GatewayError::Denied(decision)
}

#[cfg(test)]
mod tests {
	use super::{SecurityConfig, SecurityMode, evaluate, evaluate_with_arguments};
	use chrono::{Duration, Utc};
	use gateway_adapter::{
		AgentDelegationConfig, DelegationScope, GatewayIdentity, RequiredIdentity,
		SecurityPipelineConfig, agent_action_for_identity, model_invoke_for_identity,
		tool_invoke_for_identity,
	};
	use security_contracts::{ActionType, DecisionEffect, ResourceType};
	use security_policy::Policy;

	#[test]
	fn audit_and_shadow_do_not_interrupt_but_enforce_does() {
		let action = gateway_adapter::model_invoke("request", None, None, "model");
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
	fn enforce_applies_tenant_scoped_least_privilege() {
		let config = SecurityConfig {
			mode: SecurityMode::Enforce,
			remote_pdp: None,
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
	fn enforce_distinguishes_protocol_actions_and_applies_tool_arguments() {
		let config = SecurityConfig {
			mode: SecurityMode::Enforce,
			remote_pdp: None,
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
				required_tool_arguments: vec![gateway_adapter::RequiredToolArgumentsConfig {
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
			required_tool_approvals: vec![gateway_adapter::RequiredToolApprovalConfig {
				tool_name: "records.delete".into(),
			}],
			..Default::default()
		};
		assert!(
			evaluate(
				&SecurityConfig {
					mode: SecurityMode::Enforce,
					remote_pdp: None,
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
		let action = gateway_adapter::model_invoke("request", None, None, "model");
		let result = evaluate(
			&SecurityConfig {
				mode: SecurityMode::Enforce,
				remote_pdp: Some(remote_pdp),
				pipeline: SecurityPipelineConfig::default(),
			},
			&action,
		);
		assert!(matches!(
			result,
			Err(gateway_adapter::GatewayError::Denied(decision))
				if decision.policy_id.as_deref() == Some("dynamic-pdp:configuration")
		));
	}
}
