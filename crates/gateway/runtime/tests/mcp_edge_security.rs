//! Public protocol/security API integration under the actual Cargo-selected MCP profile.
//! No production hooks, model execution or remote credentials are installed here.
#![cfg(feature = "gateway-mcp")]

use security_audit::InMemoryAuditSink;
use security_capability_broker::{
	CapabilityBroker, ConsumeCapabilityRequest, InMemoryCapabilityStore, IssueCapabilityRequest,
};
use security_pipeline::GatewayIdentity;
use security_types::DecisionEffect;
use serde_json::json;
use std::sync::{Arc, Barrier};

fn operation() -> gateway_mcp::NormalizedOperation {
	assert!(
		ai_security_platform_runtime::capabilities::compiled_profile()
			.supports(ai_security_platform_runtime::capabilities::GatewayCapability::Mcp)
	);
	let request = serde_json::from_value(json!({"jsonrpc":"2.0","id":7,"method":"tools/call",
		"params":{"name":"delete","arguments":{"record":42}}}))
	.unwrap();
	gateway_mcp::normalize(
		&request,
		"trusted-request",
		GatewayIdentity {
			user_id: Some("alice".into()),
			tenant_id: Some("tenant-a".into()),
			..Default::default()
		},
		"db",
	)
}

fn capability() -> (CapabilityBroker, ConsumeCapabilityRequest) {
	let op = operation();
	let broker = CapabilityBroker::new(
		Arc::new(InMemoryCapabilityStore::default()),
		chrono::Duration::seconds(60),
	)
	.unwrap();
	let arguments_hash = security_pipeline::arguments_hash(op.arguments.as_ref().unwrap());
	let grant = broker
		.issue(IssueCapabilityRequest {
			protocol_version: "v1".into(),
			request: op.action.clone(),
			arguments_hash: arguments_hash.clone(),
			ttl_seconds: 30,
		})
		.unwrap();
	let request = ConsumeCapabilityRequest {
		protocol_version: "v1".into(),
		token: grant.token,
		request: op.action,
		arguments_hash,
	};
	(broker, request)
}

#[test]
fn high_risk_mcp_tool_without_trusted_approval_cannot_issue_a_grant() {
	let op = operation();
	let config: security_integration_runtime::SecurityConfig = serde_json::from_value(json!({
		"mode":"enforce", "requiredToolApprovals":[{"toolName":"delete"}],
		"policies":[{"id":"allow-delete","enabled":true,"effect":"allow","actionType":"toolInvoke","resourceId":"delete","tenantId":"tenant-a"}]
	})).unwrap();
	let sink = InMemoryAuditSink::default();
	assert!(
		security_integration_runtime::authorize_tool_with_capability_with_audit(
			&config,
			&op.action,
			op.arguments.as_ref().unwrap(),
			&sink
		)
		.is_err()
	);
	assert_eq!(sink.events().last().unwrap().decision, DecisionEffect::Deny);
	let mut ordinary = config;
	ordinary.pipeline.required_tool_approvals.clear();
	assert!(
		security_integration_runtime::authorize_tool_with_capability_with_audit(
			&ordinary,
			&op.action,
			op.arguments.as_ref().unwrap(),
			&sink
		)
		.unwrap()
		.is_none()
	);
}

#[test]
fn capability_binding_rejects_foreign_tenant_request_and_arguments() {
	for mutation in 0..3 {
		let (broker, request) = capability();
		let mut foreign = request.clone();
		match mutation {
			0 => foreign.request.subject.tenant_id = Some("tenant-b".into()),
			1 => foreign.request.request_id = "another-request".into(),
			_ => foreign.arguments_hash = security_pipeline::arguments_hash(&json!({"record":43})),
		}
		assert!(broker.consume(foreign).is_err());
		// A binding mismatch burns the credential rather than allowing probing/replay.
		assert!(broker.consume(request).is_err());
	}
}

#[test]
fn concurrent_capability_consumption_admits_exactly_one_operation() {
	let (broker, request) = capability();
	let barrier = Arc::new(Barrier::new(8));
	let successes = std::thread::scope(|scope| {
		let pending: Vec<_> = (0..8)
			.map(|_| {
				let (broker, request, barrier) = (broker.clone(), request.clone(), barrier.clone());
				scope.spawn(move || {
					barrier.wait();
					broker.consume(request).is_ok()
				})
			})
			.collect();
		pending
			.into_iter()
			.map(|thread| thread.join().unwrap())
			.filter(|success| *success)
			.count()
	});
	assert_eq!(successes, 1);
	assert!(broker.consume(request).is_err());
}
