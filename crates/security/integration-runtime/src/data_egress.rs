use security_audit::{AuditSink, event_from_decision};
use security_pipeline::GatewayError;
use security_types::{ActionRequest, ActionType, DataClassification, Decision, DecisionEffect};

/// Administrator-owned labels and exact destinations. HTTP values are the actual outbound
/// `host:port` or `unix:path`; Tool values are `server-id/tool-name`.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DataEgressConfig {
	pub classification: DataClassification,
	#[serde(default)]
	pub model_destinations: Vec<String>,
	#[serde(default)]
	pub inference_destinations: Vec<String>,
	#[serde(default)]
	pub agent_destinations: Vec<String>,
	#[serde(default)]
	pub tool_destinations: Vec<String>,
}

impl DataEgressConfig {
	pub fn validate(&self) -> Result<(), String> {
		for destination in self
			.model_destinations
			.iter()
			.chain(&self.inference_destinations)
			.chain(&self.agent_destinations)
			.chain(&self.tool_destinations)
		{
			if destination.is_empty() || destination.trim() != destination {
				return Err("dataEgress destinations must be nonempty exact identifiers without surrounding whitespace".into());
			}
		}
		Ok(())
	}

	fn allows(&self, kind: ActionType, destination: &str) -> bool {
		let list = match kind {
			ActionType::ModelInvoke => &self.model_destinations,
			ActionType::InferenceRoute => &self.inference_destinations,
			ActionType::AgentInvoke => &self.agent_destinations,
			ActionType::ToolInvoke => &self.tool_destinations,
			_ => return false,
		};
		list.iter().any(|entry| entry == destination)
	}
}

/// Audits the chosen destination without recording request content or Tool arguments.
pub fn check_data_egress(
	config: &DataEgressConfig,
	action: &ActionRequest,
	destination: &str,
	audit: &dyn AuditSink,
) -> Result<(), GatewayError> {
	let allowed = config.allows(action.action.action_type, destination);
	let decision = Decision {
		request_id: action.request_id.clone(),
		effect: if allowed {
			DecisionEffect::Allow
		} else {
			DecisionEffect::Deny
		},
		policy_id: Some(format!("data-egress:{:?}", config.classification).to_ascii_lowercase()),
		policy_version: None,
		expires_at: None,
	};
	let mut audit_action = action.clone();
	audit_action.resource.id = destination.to_owned();
	audit.record(event_from_decision(
		format!(
			"{}:egress:{:?}:{}",
			action.request_id, action.action.action_type, destination
		),
		&audit_action,
		&decision,
	));
	if allowed {
		Ok(())
	} else {
		Err(GatewayError::Denied(decision))
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use security_audit::InMemoryAuditSink;
	use security_pipeline::{
		GatewayIdentity, inference_route_for_identity, model_invoke_for_identity,
		tool_invoke_for_identity,
	};

	#[test]
	fn exact_destination_and_audit() {
		let policy = DataEgressConfig {
			classification: DataClassification::Restricted,
			model_destinations: vec!["private.example:443".into()],
			inference_destinations: vec![],
			agent_destinations: vec![],
			tool_destinations: vec![],
		};
		let action = model_invoke_for_identity("req-1", GatewayIdentity::default(), "model-1");
		let audit = InMemoryAuditSink::default();
		assert!(check_data_egress(&policy, &action, "private.example:443", &audit).is_ok());
		assert!(check_data_egress(&policy, &action, "public.example:443", &audit).is_err());
		assert_eq!(audit.events()[1].resource.id, "public.example:443");
		assert_eq!(audit.events()[1].decision, DecisionEffect::Deny);
		// A permitted model destination is not automatically eligible for fallback routing.
		let route = inference_route_for_identity("req-1", GatewayIdentity::default(), "picker");
		assert!(check_data_egress(&policy, &route, "private.example:443", &audit).is_err());
		let tool = tool_invoke_for_identity("req-1", GatewayIdentity::default(), "ticket.create");
		assert!(check_data_egress(&policy, &tool, "tools/ticket.create", &audit).is_err());
	}

	#[test]
	fn configuration_requires_enforcement_and_rejects_inexact_targets() {
		let mut config: crate::SecurityConfig = serde_json::from_value(serde_json::json!({
			"dataEgress": {
				"classification": "restricted",
				"modelDestinations": ["private.example:443"]
			}
		}))
		.expect("valid data egress configuration");
		assert!(config.validate_composition().is_err());
		config.mode = crate::SecurityMode::Enforce;
		assert!(config.validate_composition().is_ok());
		config.data_egress.as_mut().unwrap().model_destinations = vec![" private.example:443".into()];
		assert!(config.validate_composition().is_err());
	}
}
