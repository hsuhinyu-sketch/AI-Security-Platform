use super::*;

fn request(body: Value) -> Request<Body> {
	Request::builder()
		.method("POST")
		.uri("/agent")
		.header("content-type", "application/json")
		.body(json::to_body(body).unwrap())
		.unwrap()
}

#[tokio::test]
async fn classification_preserves_valid_body_and_rejects_invalid_envelopes() {
	let valid = serde_json::json!({"jsonrpc":"2.0","id":1,"method":"message/send","params":{}});
	let mut req = request(valid.clone());
	assert!(matches!(classify_request(&mut req).await, RequestType::Call(m) if m == "message/send"));
	let restored: Value = json::from_request_body(req).await.unwrap();
	assert_eq!(restored, valid);
	for invalid in [
		serde_json::json!({"method":"message/send"}),
		serde_json::json!({"jsonrpc":"1.0","id":1,"method":"message/send","params":{}}),
		serde_json::json!({"jsonrpc":"2.0","id":null,"method":"message/send","params":{}}),
		serde_json::json!({"jsonrpc":"2.0","id":1.5,"method":"message/send","params":{}}),
		serde_json::json!({"jsonrpc":"2.0","id":1,"method":"message/send","params":{},"result":null}),
		serde_json::json!([valid.clone()]),
	] {
		assert!(matches!(
			classify_request(&mut request(invalid)).await,
			RequestType::Invalid
		));
	}
}

#[tokio::test]
async fn unsupported_binding_method_and_media_type_are_not_calls() {
	let mut req =
		request(serde_json::json!({"jsonrpc":"2.0","id":1,"method":"custom/execute","params":{}}));
	assert!(matches!(
		classify_request(&mut req).await,
		RequestType::Unknown
	));
	req
		.headers_mut()
		.insert("content-type", "text/plain".parse().unwrap());
	assert!(matches!(
		classify_request(&mut req).await,
		RequestType::Invalid
	));
	let mut card = Request::builder()
		.uri("/.well-known/agent-card.json")
		.body(Body::empty())
		.unwrap();
	assert!(matches!(
		classify_request(&mut card).await,
		RequestType::AgentCard(_)
	));
}

#[tokio::test]
async fn invalid_operation_cannot_be_allowed_by_broad_policy() {
	use security_audit::InMemoryAuditSink;
	use security_integration_runtime::{SecurityConfig, SecurityMode};
	let mut config = SecurityConfig::from(security_integration_runtime::SecurityConfigData {
		mode: SecurityMode::Enforce,
		..Default::default()
	});
	config.pipeline.policies = serde_json::from_value(serde_json::json!([
		{"id":"broad","enabled":true,"effect":"allow"}
	]))
	.unwrap();
	let sink = InMemoryAuditSink::default();
	let mut req = request(serde_json::json!({"method":"message/send"}));
	assert!(matches!(
		classify_request(&mut req).await,
		RequestType::Invalid
	));
	let action = security_pipeline::agent_action_for_identity(
		"internal",
		Default::default(),
		"agent",
		"invalid-jsonrpc",
	);
	let mut dispatched = 0;
	if security_integration_runtime::unsupported_operation_with_audit(&config, &action, "a2a", &sink)
		.is_ok()
	{
		dispatched += 1;
	}
	assert_eq!(dispatched, 0);
	assert_eq!(sink.events().len(), 1);
	assert_eq!(
		sink.events()[0].decision,
		security_types::DecisionEffect::Deny
	);
}

#[test]
fn legacy_and_component_task_types_have_one_canonical_identity() {
	use security_integration_runtime::a2a_objects::{TaskOperation, TaskState};
	use std::any::TypeId;
	assert_eq!(
		TypeId::of::<TaskState>(),
		TypeId::of::<security_types::a2a::TaskState>()
	);
	assert_eq!(
		TypeId::of::<TaskOperation>(),
		TypeId::of::<security_types::a2a::TaskOperation>()
	);
	assert_eq!(
		security_integration_runtime::a2a_objects::events::valid_cursor(
			"01234567-89ab-4def-8123-456789abcdef"
		),
		security_types::a2a::valid_event_cursor("01234567-89ab-4def-8123-456789abcdef")
	);
}
