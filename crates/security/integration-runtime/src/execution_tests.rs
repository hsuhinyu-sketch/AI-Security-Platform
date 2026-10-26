use super::*;
use security_audit::InMemoryAuditSink;
use security_types::CheckStage;

fn allowed() -> SecurityConfig {
	serde_json::from_value(serde_json::json!({"mode":"enforce", "policies":[
		{"id":"allow-model", "enabled":true,"effect":"allow","actionType":"modelInvoke"}
	]}))
	.unwrap()
}

#[test]
fn candidate_does_not_contact_or_construct_remote_pdp_but_dispatch_fails_closed() {
	let mut config = allowed();
	config.remote_pdp = Some(
		serde_json::from_value(serde_json::json!({"endpoint":"http://invalid.example/pdp"})).unwrap(),
	);
	let action =
		security_pipeline::model_invoke_for_identity("internal", Default::default(), "local-model");
	let sink = InMemoryAuditSink::default();
	assert!(evaluate_at_stage(&config, CheckStage::Candidate, &action, None, &sink).is_ok());
	assert!(evaluate_at_stage(&config, CheckStage::Dispatch, &action, None, &sink).is_err());
	let events = sink.events();
	assert_eq!(events[0].decision, DecisionEffect::Allow);
	assert!(
		events[0]
			.policy_id
			.as_ref()
			.unwrap()
			.starts_with("prefilter:")
	);
	assert_eq!(events.last().unwrap().decision, DecisionEffect::Deny);
}

#[test]
fn candidate_pass_does_not_replace_durable_audit_admission() {
	let mut config = allowed();
	config.required_audit = Some(required_audit::RequiredAuditConfig {
		action_types: vec![security_types::ActionType::ModelInvoke],
	});
	let action =
		security_pipeline::model_invoke_for_identity("internal", Default::default(), "local-model");
	let sink = InMemoryAuditSink::default();
	assert!(evaluate_at_stage(&config, CheckStage::Candidate, &action, None, &sink).is_ok());
	assert!(evaluate_at_stage(&config, CheckStage::Dispatch, &action, None, &sink).is_err());
	config.required_audit = None;
	assert!(evaluate_at_stage(&config, CheckStage::Dispatch, &action, None, &sink).is_ok());
}

#[test]
fn normalized_tool_list_keeps_transport_egress_constraints() {
	let egress: DataEgressConfig = serde_json::from_value(serde_json::json!({
		"classification":"restricted", "toolDestinations":["db/read"]
	}))
	.unwrap();
	let action = security_pipeline::tool_list("internal", Default::default(), "db");
	assert!(egress.permits(&action, "db"));
	assert!(!egress.permits(&action, "foreign-db"));
	let invoke =
		security_pipeline::tool_invoke_for_identity("internal", Default::default(), "delete");
	assert!(!egress.permits(&invoke, "db/delete"));
}

#[test]
fn retry_charges_one_logical_call_but_each_attempt_and_releases_concurrency() {
	use execution_budget::{
		BudgetError, CallKind, ExecutionBudgetConfig, ExecutionBudgetStore,
		InMemoryExecutionBudgetStore, LogicalCharge,
	};
	let config: ExecutionBudgetConfig = serde_json::from_value(serde_json::json!({
		"namespace":uuid::Uuid::new_v4().to_string(), "maxModelCalls":1,"maxToolCalls":1,
		"maxAgentCalls":1,"maxAttempts":2,"maxConcurrent":1
	}))
	.unwrap();
	let identity = security_pipeline::GatewayIdentity {
		user_id: Some("alice".into()),
		tenant_id: Some("tenant-a".into()),
		..Default::default()
	};
	let owner =
		identity_binding::VerifiedOwner::from_identity(&identity, "https://issuer.example").unwrap();
	let store = InMemoryExecutionBudgetStore::default();
	let ledger = store
		.create(&config, owner, "configuration".into())
		.unwrap();
	let logical = LogicalCharge::default();
	let first = ledger.reserve(CallKind::Model, &logical).unwrap();
	assert!(matches!(
		ledger.reserve(CallKind::Model, &logical),
		Err(BudgetError::Concurrency)
	));
	assert_eq!(ledger.usage().unwrap().attempts, 1);
	drop(first);
	let retry = ledger.reserve(CallKind::Model, &logical).unwrap();
	let usage = ledger.usage().unwrap();
	assert_eq!(
		(usage.model_calls, usage.attempts, usage.concurrent),
		(1, 2, 1)
	);
	drop(retry);
	assert_eq!(ledger.usage().unwrap().concurrent, 0);
	assert!(matches!(
		ledger.reserve(CallKind::Model, &logical),
		Err(BudgetError::Attempts)
	));
	assert_eq!(ledger.usage().unwrap().model_calls, 1);
}
