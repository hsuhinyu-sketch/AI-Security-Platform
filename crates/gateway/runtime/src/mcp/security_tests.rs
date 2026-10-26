use super::*;
use serde_json::json;

fn call(method: &str, params: serde_json::Value) -> JsonRpcRequest<ClientRequest> {
	serde_json::from_value(json!({"jsonrpc":"2.0", "id":7, "method":method, "params":params}))
		.unwrap()
}

fn context() -> IncomingRequestContext {
	let (parts, _) = ::http::Request::builder()
		.header("x-request-id", "caller-controlled")
		.body(())
		.unwrap()
		.into_parts();
	IncomingRequestContext::new(&parts)
}

#[test]
fn wire_ids_are_preserved_but_never_used_for_authorization_or_egress() {
	let rpc = call(
		"tools/call",
		json!({"name":"db.read","arguments":{"id":42}}),
	);
	let mut first = context();
	let second = context();
	assert_ne!(first.security_request_id(), second.security_request_id());
	assert_ne!(first.security_request_id(), "caller-controlled");
	let cloned = first.clone();
	assert_eq!(first.security_request_id(), cloned.security_request_id());
	let expected = normalize(&rpc, first.security_request_id(), Default::default(), "db");
	mark_egress(Some(&rpc), "db", "", &mut first);
	let http = first.as_request();
	let egress = http.extensions().get::<McpEgressContext>().unwrap();
	assert_eq!(egress.action, expected.action);
	assert!(egress.supported);
	assert_ne!(egress.action.request_id, rpc.id.to_string());
	assert_eq!(rpc.id.to_string(), "7");
	assert_eq!(expected.arguments, Some(json!({"id":42})));
}

#[test]
fn legacy_and_common_authorizers_enforce_list_permissions() {
	let rpc = call("tools/list", json!({}));
	let ctx = context();
	let denied = SecurityPipelineConfig::default();
	assert!(matches!(
		enforce_request(&denied, &rpc, &ctx, "db"),
		Err(UpstreamError::Security(_))
	));
	let mut allowed = denied;
	allowed.policies = serde_json::from_value(json!([
		{"id":"list-db", "enabled":true,"effect":"allow","actionType":"toolList","resourceId":"db"}
	]))
	.unwrap();
	assert!(enforce_request(&allowed, &rpc, &ctx, "db").is_ok());
	assert!(enforce_request(&allowed, &rpc, &ctx, "other-db").is_err());
	let config = security_integration_runtime::SecurityConfig {
		mode: security_integration_runtime::SecurityMode::Enforce,
		pipeline: allowed,
		..Default::default()
	};
	assert!(audit_request(&config, &rpc, &mut ctx.clone(), "db").is_ok());
	assert!(audit_request(&config, &rpc, &mut ctx.clone(), "other-db").is_err());
}

#[test]
fn security_error_response_preserves_wire_id_and_redacts_policy_details() {
	let error = crate::mcp::Error::Security(
		Some(serde_json::from_value(json!(7)).unwrap()),
		security_types::SecurityFailureKind::Denied,
	);
	let body: serde_json::Value = serde_json::from_str(&error.jsonrpc_error_body().unwrap()).unwrap();
	assert_eq!(body["id"], 7);
	assert_eq!(body["error"]["data"]["code"], "security_denied");
	assert!(
		crate::mcp::Error::Security(None, security_types::SecurityFailureKind::Denied)
			.jsonrpc_error_body()
			.is_none()
	);
}

#[test]
fn unsupported_method_cannot_be_granted_by_a_broad_allow_policy() {
	let rpc = call("custom/execute", json!({}));
	let mut ctx = context();
	let config: security_integration_runtime::SecurityConfig = serde_json::from_value(json!({
			"mode":"enforce", "policies":[{"id":"private-policy-name", "enabled":true, "effect":"allow"}]
	}))
	.unwrap();
	let failure = audit_request(&config, &rpc, &mut ctx, "db").unwrap_err();
	assert!(matches!(failure, UpstreamError::Security(_)));
	assert!(!failure.to_string().contains("private-policy-name"));
	assert!(enforce_request(&config.pipeline, &rpc, &ctx, "db").is_err());
	let shadow = security_integration_runtime::SecurityConfig {
		mode: security_integration_runtime::SecurityMode::Shadow,
		..config
	};
	assert!(audit_request(&shadow, &rpc, &mut ctx, "db").is_ok());
}
