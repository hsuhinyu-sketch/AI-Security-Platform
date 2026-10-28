//! Configuration identity excludes runtime handles and never represents an authorization grant.
use super::{SecurityConfig, SecurityConfigData};
use sha2::{Digest, Sha256};
use std::{
	ops::{Deref, DerefMut},
	sync::Arc,
};

pub(super) struct ConfigurationIdentity {
	json: String,
	value: serde_json::Value,
	digest: [u8; 32],
}

impl std::fmt::Debug for SecurityConfig {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		self.data.fmt(f)
	}
}
impl From<SecurityConfigData> for SecurityConfig {
	fn from(data: SecurityConfigData) -> Self {
		Self {
			data,
			validated: Default::default(),
			identity: Default::default(),
			prepared: Default::default(),
		}
	}
}
impl Deref for SecurityConfig {
	type Target = SecurityConfigData;
	fn deref(&self) -> &Self::Target {
		&self.data
	}
}
impl DerefMut for SecurityConfig {
	fn deref_mut(&mut self) -> &mut Self::Target {
		self.validated.take();
		self.identity.take();
		self.prepared.take();
		&mut self.data
	}
}

impl SecurityConfig {
	pub fn into_data(self) -> SecurityConfigData {
		self.data
	}

	fn configuration_identity(&self) -> Result<&ConfigurationIdentity, serde_json::Error> {
		if let Some(identity) = self.identity.get() {
			return Ok(identity);
		}
		let json = serde_json::to_string(self)?;
		let value = serde_json::to_value(self)?;
		let digest = Sha256::digest(json.as_bytes()).into();
		let _ = self.identity.set(Arc::new(ConfigurationIdentity {
			json,
			value,
			digest,
		}));
		Ok(
			self
				.identity
				.get()
				.expect("identity initialized by this caller or another reader"),
		)
	}

	/// Reuses the original serialized binding digest. This is configuration identity, not a grant.
	pub fn configuration_digest(&self) -> Result<[u8; 32], String> {
		self.validate_composition()?;
		self
			.configuration_identity()
			.map(|identity| identity.digest)
			.map_err(|error| error.to_string())
	}

	/// Preserve the existing serialized bytes used by Context and execution-budget bindings.
	/// Successful static validation and identity are reused until mutable access.
	pub fn validated_configuration_json(&self) -> Result<String, String> {
		self.validate_composition()?;
		self
			.configuration_identity()
			.map(|identity| identity.json.clone())
			.map_err(|error| error.to_string())
	}

	/// Compare declared configuration as JSON values, preserving object-order-independent equality.
	/// This does not validate composition or compare live stores, decisions, or configuration leases.
	pub fn same_configuration(&self, other: &Self) -> Result<bool, serde_json::Error> {
		Ok(self.configuration_identity()?.value == other.configuration_identity()?.value)
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use serde_json::json;
	use std::sync::Arc;

	#[test]
	fn prepared_identity_survives_clone_but_not_nested_mutation_or_copy_on_write() {
		let mut config: SecurityConfig = serde_json::from_value(json!({
			"mode":"enforce","policies":[{"id":"allow","enabled":true,"effect":"allow","tenantId":"tenant-a"}]
		})).unwrap();
		let original = config.configuration_digest().unwrap();
		let identity = config.identity.get().unwrap().clone();
		let clone = config.clone();
		assert!(Arc::ptr_eq(&identity, clone.identity.get().unwrap()));
		config.pipeline.policies[0].tenant_id = Some("tenant-b".into());
		assert!(config.identity.get().is_none());
		assert!(config.validated.get().is_none());
		assert_ne!(original, config.configuration_digest().unwrap());
		assert_eq!(original, clone.configuration_digest().unwrap());
		let mut owner = Arc::new(clone);
		let previous = owner.clone();
		Arc::make_mut(&mut owner).mode = super::super::SecurityMode::Shadow;
		assert_ne!(
			previous.configuration_digest().unwrap(),
			owner.configuration_digest().unwrap()
		);
		assert_eq!(original, previous.configuration_digest().unwrap());
	}

	#[test]
	fn runtime_store_preparation_keeps_declaration_identity_and_concurrent_reads() {
		let mut config: SecurityConfig = serde_json::from_value(json!({
			"mode":"enforce","executionBudget":{"namespace":"cache-test", "maxModelCalls":2,
				"maxToolCalls":2,"maxAttempts":4,"maxConcurrent":2}
		}))
		.unwrap();
		let digest = config.configuration_digest().unwrap();
		let identity = config.identity.get().unwrap().clone();
		config.prepare_runtime_stores().unwrap();
		assert!(Arc::ptr_eq(&identity, config.identity.get().unwrap()));
		let owner = Arc::new(config);
		std::thread::scope(|scope| {
			for _ in 0..8 {
				let owner = owner.clone();
				scope.spawn(move || {
					for _ in 0..64 {
						assert_eq!(owner.configuration_digest().unwrap(), digest);
					}
				});
			}
		});
		assert!(Arc::ptr_eq(&identity, owner.identity.get().unwrap()));
	}

	#[test]
	fn failed_validation_is_retryable_and_private_state_is_never_configuration_input() {
		let mut config: SecurityConfig = serde_json::from_value(json!({
			"requiredAudit":{"actionTypes":["modelInvoke"]}
		}))
		.unwrap();
		assert!(config.configuration_digest().is_err());
		assert!(config.validated.get().is_none());
		config.mode = super::super::SecurityMode::Enforce;
		assert!(config.configuration_digest().is_ok());
		let wire = serde_json::to_value(&config).unwrap();
		for key in ["data", "validated", "identity"] {
			assert!(wire.get(key).is_none());
			assert!(serde_json::from_value::<SecurityConfig>(json!({key:{}})).is_err());
		}
		let loaded: SecurityConfig = serde_json::from_value(wire).unwrap();
		assert!(loaded.identity.get().is_none());
		assert!(loaded.same_configuration(&config).unwrap());
	}

	#[test]
	fn existing_wire_bytes_and_distinct_owners_are_preserved() {
		let left = Arc::new(SecurityConfig::default());
		let right = Arc::new(SecurityConfig::default());
		assert!(!Arc::ptr_eq(&left, &right));
		assert_eq!(
			left.validated_configuration_json().unwrap(),
			r#"{"mode":"audit"}"#
		);
		assert!(left.same_configuration(&right).unwrap());
		let mut changed = (*right).clone();
		changed.mode = super::super::SecurityMode::Enforce;
		assert!(!left.same_configuration(&changed).unwrap());
		assert_eq!(
			changed.validated_configuration_json().unwrap(),
			r#"{"mode":"enforce"}"#
		);
	}

	#[test]
	fn policy_changes_are_not_hidden_by_cloning_or_previous_serialization() {
		let original: SecurityConfig = serde_json::from_value(json!({
			"mode":"enforce","dynamicAuthorization":{"policyVersion":"v1"},
			"policies":[{"id":"allow","enabled":true,"effect":"allow","tenantId":"tenant-a"}]
		}))
		.unwrap();
		let before = original.validated_configuration_json().unwrap();
		for (path, value) in [
			("/policies/0/tenantId", json!("tenant-b")),
			("/policies/0/effect", json!("deny")),
			("/dynamicAuthorization/policyVersion", json!("v2")),
		] {
			let mut wire = serde_json::to_value(&original).unwrap();
			*wire.pointer_mut(path).unwrap() = value;
			let changed: SecurityConfig = serde_json::from_value(wire).unwrap();
			assert!(!original.same_configuration(&changed).unwrap(), "{path}");
			assert_ne!(
				before,
				changed.validated_configuration_json().unwrap(),
				"{path}"
			);
		}
		let mut changed = original.clone();
		changed.mode = super::super::SecurityMode::Shadow;
		assert_ne!(before, changed.validated_configuration_json().unwrap());
		assert_eq!(original.validated_configuration_json().unwrap(), before);
	}

	#[test]
	fn configuration_comparison_does_not_replace_composition_validation() {
		let invalid: SecurityConfig = serde_json::from_value(json!({
			"mode":"audit","requiredAudit":{"actionTypes":["modelInvoke"]}
		}))
		.unwrap();
		assert!(invalid.same_configuration(&invalid.clone()).unwrap());
		assert!(
			invalid
				.validated_configuration_json()
				.unwrap_err()
				.contains("enforce")
		);
		let mut changed = SecurityConfig::default();
		assert!(changed.validated_configuration_json().is_ok());
		changed.required_audit = invalid.into_data().required_audit;
		assert!(changed.validated_configuration_json().is_err());
	}

	#[cfg(not(feature = "pii"))]
	#[test]
	fn json_object_order_remains_distinct_from_binding_byte_order() {
		let left: SecurityConfig =
			serde_json::from_str(r#"{"pii":{"enabled":false,"customRules":{"A":"a","B":"b"}}}"#).unwrap();
		let right: SecurityConfig =
			serde_json::from_str(r#"{"pii":{"customRules":{"B":"b","A":"a"},"enabled":false}}"#).unwrap();
		assert!(left.same_configuration(&right).unwrap());
		assert_ne!(
			left.validated_configuration_json().unwrap(),
			right.validated_configuration_json().unwrap()
		);
	}

	#[cfg(unix)]
	#[test]
	fn serialization_failure_is_not_configuration_equality() {
		use std::os::unix::ffi::OsStringExt;
		let path = std::ffi::OsString::from_vec(b"/tmp/security-\xff.db".to_vec());
		let config = SecurityConfig::from(super::super::SecurityConfigData {
			a2a_objects: Some(crate::a2a_objects::A2aObjectConfig {
				storage: crate::a2a_objects::TaskStoreConfig::Sqlite {
					path: path.into(),
					namespace: "test".into(),
					busy_timeout_millis: 100,
				},
				..Default::default()
			}),
			..Default::default()
		});
		assert!(serde_json::to_value(&config).is_err());
		assert!(config.same_configuration(&config.clone()).is_err());
		assert!(!config.same_configuration(&config).unwrap_or(false));
	}

	#[cfg(feature = "pii")]
	#[tokio::test]
	async fn prepared_runtime_handles_are_excluded_but_pii_policy_is_not() {
		let left: SecurityConfig = serde_json::from_value(json!({"pii":{}})).unwrap();
		let before = left.validated_configuration_json().unwrap();
		let right: SecurityConfig = serde_json::from_value(json!({"pii":{}})).unwrap();
		right
			.pii_runtime
			.prepare(right.pii.as_ref().unwrap())
			.await
			.unwrap();
		assert!(left.same_configuration(&right).unwrap());
		assert_eq!(before, right.validated_configuration_json().unwrap());
		let mut changed = right.clone();
		changed.pii.as_mut().unwrap().mode = security_pii::PiiMode::Shadow;
		assert!(!right.same_configuration(&changed).unwrap());
		assert_ne!(before, changed.validated_configuration_json().unwrap());
	}
}
