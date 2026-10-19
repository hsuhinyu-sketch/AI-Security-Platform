use security_audit::AuditSink;
use security_pipeline::GatewayError;
use security_types::{ActionRequest, ActionType, Decision, DecisionEffect};
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RequiredAuditConfig {
	pub action_types: Vec<ActionType>,
}
impl RequiredAuditConfig {
	pub fn validate(&self) -> Result<(), String> {
		if self.action_types.is_empty() || self.action_types.len() > 64 {
			return Err("requiredAudit needs 1..=64 actionTypes".into());
		}
		Ok(())
	}
}
pub(crate) fn acknowledge(
	config: &RequiredAuditConfig,
	action: &ActionRequest,
	decision: &Decision,
	audit: &dyn AuditSink,
) -> Result<(), GatewayError> {
	if !config.action_types.contains(&action.action.action_type) {
		return Ok(());
	}
	let mut event =
		security_audit::event_from_decision(uuid::Uuid::new_v4().to_string(), action, decision);
	event.policy_id = Some(format!(
		"audit:required:{}",
		decision.policy_id.as_deref().unwrap_or("allow")
	));
	if audit.record_required(event).is_ok() {
		return Ok(());
	}
	let denied = Decision {
		request_id: action.request_id.clone(),
		effect: DecisionEffect::Deny,
		policy_id: Some("security:required-audit-unavailable".into()),
		policy_version: decision.policy_version.clone(),
		expires_at: None,
	};
	audit.record(security_audit::event_from_decision(
		uuid::Uuid::new_v4().to_string(),
		action,
		&denied,
	));
	Err(GatewayError::Denied(denied))
}
