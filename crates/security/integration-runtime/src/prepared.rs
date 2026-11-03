//! Prepared static rules and local identity data; provider calls and decisions remain live.
use super::{AgentIdentityRegistry, SecurityConfig};
use security_pipeline::PreparedSecurityPipeline;
use std::sync::Arc;

pub(super) struct PreparedSecurity {
	pub pipeline: PreparedSecurityPipeline,
	pub registry: Option<AgentIdentityRegistry>,
}

impl SecurityConfig {
	/// Prepare execution inputs and validate remote transports without sending requests.
	/// Run on a blocking thread when called from a Tokio runtime.
	pub fn prepare_execution(&self) -> Result<(), String> {
		self.validate_composition()?;
		// Reuse the real constructors; temporary clients do not populate the live request cache.
		if let Some(config) = &self.remote_pdp {
			super::remote_pdp::HttpRemotePdpTransport::from_config(config).map_err(|e| e.reason)?;
		}
		if let Some(config) = &self.approval {
			super::remote_approval::HttpApprovalProvider::from_config(config).map_err(|e| e.reason)?;
		}
		if let Some(config) = &self.capability_broker {
			super::remote_capability::HttpCapabilityIssuer::from_config(config).map_err(|e| e.reason)?;
		}
		if let Some(config) = &self.delegation_revocation {
			super::remote_revocation::HttpDelegationRevocationProvider::from_config(config)
				.map_err(|e| e.reason)?;
		}
		if let Some(config) = &self.remote_agent_identity {
			super::remote_agent_identity::HttpAgentIdentityProvider::from_config(config)
				.map_err(|e| e.reason)?;
		}
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

	fn remote_config(field: &str, mode: &str, provider: serde_json::Value) -> SecurityConfig {
		let mut value =
			json!({"mode":mode,"policies":[{"id":"allow","enabled":true,"effect":"allow"}]});
		if field == "remotePdp" {
			value["dynamicAuthorization"] = json!({"policyVersion":"v1"});
		}
		if matches!(field, "approval" | "capabilityBroker") {
			value["requiredToolApprovals"] = json!([{"toolName":"echo"}]);
		}
		if field == "capabilityBroker" {
			value["approval"] = json!({"endpoint":"https://127.0.0.1:9/approve"});
		}
		value[field] = provider;
		serde_json::from_value(value).unwrap()
	}

	#[test]
	fn preparation_rejects_invalid_remote_url_and_timeout_in_every_applicable_mode() {
		for field in [
			"remotePdp",
			"approval",
			"capabilityBroker",
			"delegationRevocation",
			"remoteAgentIdentity",
		] {
			let endpoint = if field == "capabilityBroker" {
				"issueEndpoint"
			} else {
				"endpoint"
			};
			for mode in ["enforce", "audit", "shadow"] {
				if field == "capabilityBroker" && mode != "enforce" {
					continue;
				}
				for url in [
					"http://127.0.0.1:9",
					"https://user:secret@example.test/",
					"https://example.test/#fragment",
					"not-a-url",
				] {
					let error = remote_config(field, mode, json!({endpoint:url}))
						.prepare_execution()
						.unwrap_err();
					assert!(error.contains("endpoint"), "{field}/{mode}: {error}");
					assert!(!error.contains("secret"));
				}
				let error = remote_config(
					field,
					mode,
					json!({endpoint:"https://127.0.0.1:9", "timeoutMillis":0}),
				)
				.prepare_execution()
				.unwrap_err();
				assert!(error.contains("timeoutMillis"), "{field}/{mode}: {error}");
			}
		}
	}

	#[test]
	fn preparation_rejects_missing_and_malformed_tls_material() {
		let directory = std::env::temp_dir().join(format!("aisp-preflight-{}", uuid::Uuid::new_v4()));
		std::fs::create_dir(&directory).unwrap();
		let invalid = directory.join("invalid.pem");
		let non_certificate = directory.join("invalid-der.pem");
		std::fs::write(&invalid, "not a PEM").unwrap();
		std::fs::write(
			&non_certificate,
			"-----BEGIN CERTIFICATE-----\nZm9v\n-----END CERTIFICATE-----\n",
		)
		.unwrap();
		for field in [
			"remotePdp",
			"approval",
			"capabilityBroker",
			"delegationRevocation",
			"remoteAgentIdentity",
		] {
			let endpoint = if field == "capabilityBroker" {
				"issueEndpoint"
			} else {
				"endpoint"
			};
			for material in ["rootCaPemFile", "identityPemFile"] {
				for path in [&invalid, &non_certificate, &directory.join("missing.pem")] {
					assert!(
						remote_config(
							field,
							"enforce",
							json!({endpoint:"https://127.0.0.1:9", material:path})
						)
						.prepare_execution()
						.is_err(),
						"{field}/{material}: {}",
						path.display()
					);
				}
			}
		}
		std::fs::remove_dir_all(directory).unwrap();
	}

	#[test]
	fn valid_preflight_does_not_contact_services_or_hide_mutated_config() {
		let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
		listener.set_nonblocking(true).unwrap();
		let url = format!("https://{}/unused", listener.local_addr().unwrap());
		for field in [
			"remotePdp",
			"approval",
			"capabilityBroker",
			"delegationRevocation",
			"remoteAgentIdentity",
		] {
			let endpoint = if field == "capabilityBroker" {
				"issueEndpoint"
			} else {
				"endpoint"
			};
			remote_config(field, "enforce", json!({endpoint:url}))
				.prepare_execution()
				.unwrap();
		}
		assert_eq!(
			listener.accept().unwrap_err().kind(),
			std::io::ErrorKind::WouldBlock
		);
		let original = remote_config("remotePdp", "enforce", json!({"endpoint":url}));
		original.prepare_execution().unwrap();
		let mut changed = original.clone();
		changed.remote_pdp.as_mut().unwrap().endpoint = "http://invalid.example".into();
		assert!(changed.prepare_execution().is_err());
		original.prepare_execution().unwrap();
	}

	#[test]
	fn unrepresentable_capability_ttl_is_a_configuration_error() {
		for ttl in [0, u64::MAX, i64::MAX as u64, 10_000_000_000_000_000] {
			let error = remote_config(
				"capabilityBroker",
				"enforce",
				json!({"issueEndpoint":"https://127.0.0.1:9", "ttlSeconds":ttl}),
			)
			.prepare_execution()
			.unwrap_err();
			assert!(error.contains("ttlSeconds"), "{error}");
		}
	}
}
