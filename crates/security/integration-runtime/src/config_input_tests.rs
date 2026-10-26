use super::*;
use serde_json::{Value, json};

fn policy() -> Value {
	json!({"id":"allow","effect":"allow","enabled":true,"tenantId":"tenant-a"})
}

#[test]
fn unknown_security_keys_never_remove_mode_or_policy_conditions() {
	for field in ["Mode", "requiredIdentitty", "a2aTaskStore", "unknown"] {
		let error = serde_json::from_value::<SecurityConfig>(json!({field:true}))
			.unwrap_err()
			.to_string();
		assert!(error.contains(field), "{error}");
	}
	for field in ["tenantID", "userID", "agentID", "resourceID", "actionNmae"] {
		let mut p = policy();
		p[field] = json!("typo");
		let error = serde_json::from_value::<SecurityConfig>(json!({"mode":"enforce","policies":[p]}))
			.unwrap_err()
			.to_string();
		assert!(
			error.contains(field) && error.contains("policies[0]"),
			"{error}"
		);
	}
}

#[test]
fn flattened_dynamic_policy_accepts_known_extensions_and_rejects_unknown_conditions() {
	let input = json!({"mode":"enforce","dynamicAuthorization":{"policyVersion":"v1","policies":[{"id":"p","enabled":true,"effect":"allow","tenantId":"tenant-a","sessionId":"s","clientId":"c","notBefore":"2020-01-01T00:00:00Z","expiresAt":"2099-01-01T00:00:00Z"}]}});
	let valid: SecurityConfig = serde_json::from_value(input.clone()).unwrap();
	let roundtrip: SecurityConfig =
		serde_json::from_value(serde_json::to_value(&valid).unwrap()).unwrap();
	assert!(matches!(
		roundtrip.mode,
		super::super::SecurityMode::Enforce
	));
	for key in ["tenantID", "expiresAT", "clientID"] {
		let mut bad = input.clone();
		bad["dynamicAuthorization"]["policies"][0][key] = json!("typo");
		let error = serde_json::from_value::<SecurityConfig>(bad)
			.unwrap_err()
			.to_string();
		assert!(error.contains(key), "{error}");
	}
}

#[test]
fn nested_security_objects_are_strict_and_explicit_audit_remains_legal() {
	for input in [
		json!({"requiredIdentity":{"user":true,"agent":false,"tenant":true,"tennat":false}}),
		json!({"remotePdp":{"endpoint":"https://pdp.example","timeoutMills":1}}),
		json!({"delegations":[{"id":"d","userId":"u","agentId":"a","scopes":[{"resourceID":"wrong"}]}]}),
		json!({"agentIdentity":{"agents":[{"agentId":"a","tenantId":"t","clientIds":["c"],"Enabled":true}]}}),
	] {
		assert!(serde_json::from_value::<SecurityConfig>(input).is_err());
	}
	let audit: SecurityConfig =
		serde_json::from_value(json!({"mode":"audit","policies":[policy()]})).unwrap();
	assert_eq!(audit.mode, super::super::SecurityMode::Audit);
	let legacy: SecurityConfig = serde_json::from_value(json!({})).unwrap();
	assert_eq!(legacy.mode, super::super::SecurityMode::Audit);
}

#[test]
fn duplicate_security_keys_are_rejected_before_defaulting() {
	assert!(serde_json::from_str::<SecurityConfig>(r#"{"mode":"enforce","mode":"audit"}"#).is_err());
}
