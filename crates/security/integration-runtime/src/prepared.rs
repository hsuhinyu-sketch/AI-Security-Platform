//! Prepared static rules and local identity data; provider calls and decisions remain live.
use super::{AgentIdentityRegistry, SecurityConfig};
use security_pipeline::PreparedSecurityPipeline;
use std::sync::Arc;

pub(super) struct PreparedSecurity {
	pub pipeline: PreparedSecurityPipeline,
	pub registry: Option<AgentIdentityRegistry>,
}

impl SecurityConfig {
	/// Prepare static execution inputs before publication, without constructing remote clients.
	pub fn prepare_execution(&self) -> Result<(), String> {
		self.validate_composition()?;
		self.prepared_security()?;
		Ok(())
	}

	pub(super) fn prepared_security(&self) -> Result<&PreparedSecurity, String> {
		if let Some(prepared) = self.prepared.get() {
			return Ok(prepared);
		}
		if self.agent_identity.is_some() && self.remote_agent_identity.is_some() {
			return Err("configure either agentIdentity or remoteAgentIdentity, not both".into());
		}
		let registry = self
			.agent_identity
			.as_ref()
			.map(|config| AgentIdentityRegistry::from_config(config.clone()))
			.transpose()?;
		let pipeline = self.pipeline.prepare();
		let _ = self
			.prepared
			.set(Arc::new(PreparedSecurity { pipeline, registry }));
		Ok(
			self
				.prepared
				.get()
				.expect("static preparation initialized by this caller or another reader"),
		)
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use security_audit::InMemoryAuditSink;
	use security_pipeline::GatewayIdentity;
	use serde_json::json;
	fn config() -> SecurityConfig {
		serde_json::from_value(
			json!({"mode":"enforce","policies":[{"id":"allow","enabled":true,
			"effect":"allow","actionType":"modelInvoke","tenantId":"tenant-a"}]}),
		)
		.unwrap()
	}
	fn action() -> security_types::ActionRequest {
		security_pipeline::model_invoke_for_identity(
			"request",
			GatewayIdentity {
				user_id: Some("alice".into()),
				tenant_id: Some("tenant-a".into()),
				..Default::default()
			},
			"model",
		)
	}
	#[test]
	fn prepared_rules_are_shared_and_mutation_rebuilds_without_changing_old_owners() {
		let mut config = config();
		config.prepare_execution().unwrap();
		let previous = config.clone();
		let prepared = config.prepared.get().unwrap().clone();
		let audit = InMemoryAuditSink::default();
		for _ in 0..3 {
			crate::evaluate_with_audit(&config, &action(), None, &audit).unwrap();
		}
		assert!(Arc::ptr_eq(&prepared, config.prepared.get().unwrap()));
		assert!(Arc::ptr_eq(&prepared, previous.prepared.get().unwrap()));
		config.pipeline.policies[0].effect = security_types::DecisionEffect::Deny;
		assert!(config.prepared.get().is_none());
		assert!(crate::evaluate_with_audit(&config, &action(), None, &audit).is_err());
		assert!(crate::evaluate_with_audit(&previous, &action(), None, &audit).is_ok());
		assert!(!Arc::ptr_eq(&prepared, config.prepared.get().unwrap()));
		assert_eq!(audit.events().len(), 5);
		assert!(serde_json::from_value::<SecurityConfig>(json!({"prepared":{}})).is_err());
	}
	#[test]
	fn candidate_prefilter_does_not_prepare_or_validate_identity_sources() {
		let mut config = config();
		config.agent_identity = Some(
			serde_json::from_value(json!({"required":true,"agents":[{
				"agentId":"agent","tenantId":"tenant-a","clientIds":[]
			}]}))
			.unwrap(),
		);
		let audit = InMemoryAuditSink::default();
		assert!(crate::prefilter_with_audit(&config, &action(), &audit).is_ok());
		assert!(config.prepared.get().is_none());
		assert!(crate::evaluate_with_audit(&config, &action(), None, &audit).is_err());
		assert!(config.prepare_execution().is_err());
	}
	#[test]
	fn shared_local_registry_rechecks_current_identity_and_expiry() {
		let mut config = config();
		config.agent_identity = Some(
			serde_json::from_value(json!({"required":true,"agents":[{
				"agentId":"agent","tenantId":"tenant-a","clientIds":["client"],
				"expiresAt":chrono::Utc::now()+chrono::Duration::seconds(1)
			}]}))
			.unwrap(),
		);
		config.prepare_execution().unwrap();
		let audit = InMemoryAuditSink::default();
		let mut action = action();
		action.subject.agent_id = Some("agent".into());
		action.authorization_context.client_id = Some("client".into());
		assert!(crate::evaluate_with_audit(&config, &action, None, &audit).is_ok());
		let mut foreign = action.clone();
		foreign.authorization_context.client_id = Some("other".into());
		assert!(crate::evaluate_with_audit(&config, &foreign, None, &audit).is_err());
		std::thread::sleep(std::time::Duration::from_millis(1100));
		assert!(crate::evaluate_with_audit(&config, &action, None, &audit).is_err());
	}
}
