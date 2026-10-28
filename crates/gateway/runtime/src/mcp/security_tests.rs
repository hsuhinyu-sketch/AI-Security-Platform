use super::*;
use security_pipeline::SecurityPipelineConfig;
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
	let denied: LegacySecurityPipeline = SecurityPipelineConfig::default().into();
	assert!(matches!(
		McpSecurity::new(None, Some(&denied)).authorize_request(&rpc, &mut ctx.clone(), "db"),
		Err(UpstreamError::Security(_))
	));
	let allowed: SecurityPipelineConfig = serde_json::from_value(json!({"policies":[
			{"id":"list-db", "enabled":true,"effect":"allow","actionType":"toolList","resourceId":"db"}
	]}))
	.unwrap();
	let legacy: LegacySecurityPipeline = allowed.clone().into();
	assert!(
		McpSecurity::new(None, Some(&legacy))
			.authorize_request(&rpc, &mut ctx.clone(), "db")
			.is_ok()
	);
	assert!(
		McpSecurity::new(None, Some(&legacy))
			.authorize_request(&rpc, &mut ctx.clone(), "other-db")
			.is_err()
	);
	let config = security_integration_runtime::SecurityConfig::from(
		security_integration_runtime::SecurityConfigData {
			mode: security_integration_runtime::SecurityMode::Enforce,
			pipeline: allowed,
			..Default::default()
		},
	);
	let security = McpSecurity::new(Some(&config), Some(&legacy));
	assert!(
		security
			.authorize_request(&rpc, &mut ctx.clone(), "db")
			.is_ok()
	);
	assert!(
		security
			.authorize_request(&rpc, &mut ctx.clone(), "other-db")
			.is_err()
	);
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
	let failure = McpSecurity::new(Some(&config), None)
		.authorize_request(&rpc, &mut ctx, "db")
		.unwrap_err();
	assert!(matches!(failure, UpstreamError::Security(_)));
	assert!(!failure.to_string().contains("private-policy-name"));
	let legacy: LegacySecurityPipeline = config.pipeline.clone().into();
	assert!(
		McpSecurity::new(None, Some(&legacy))
			.authorize_request(&rpc, &mut ctx, "db")
			.is_err()
	);
	let shadow = security_integration_runtime::SecurityConfig::from(
		security_integration_runtime::SecurityConfigData {
			mode: security_integration_runtime::SecurityMode::Shadow,
			..config.into_data()
		},
	);
	assert!(
		McpSecurity::new(Some(&shadow), None)
			.authorize_request(&rpc, &mut ctx, "db")
			.is_ok()
	);
}

fn declaration(mode: &str, effect: &str) -> SecurityConfig {
	serde_json::from_value(json!({"mode":mode,"policies":[{
			"id":"same-id","enabled":true,"effect":effect
	}]}))
	.unwrap()
}

#[test]
fn declarations_remain_an_intersection_with_independent_modes_and_default_deny() {
	let rpc = call("tools/call", json!({"name":"echo","arguments":{}}));
	for mode in ["enforce", "audit", "shadow"] {
		for common_effect in ["allow", "deny"] {
			for legacy_effect in ["allow", "deny"] {
				let common = declaration(mode, common_effect);
				let legacy: LegacySecurityPipeline = declaration("enforce", legacy_effect)
					.pipeline
					.clone()
					.into();
				let expected = legacy_effect == "allow" && (common_effect == "allow" || mode != "enforce");
				assert_eq!(
					McpSecurity::new(Some(&common), Some(&legacy))
						.authorize_request(&rpc, &mut context(), "db")
						.is_ok(),
					expected,
					"{mode}/{common_effect}/{legacy_effect}"
				);
			}
		}
	}
	let empty: LegacySecurityPipeline = SecurityPipelineConfig::default().into();
	let observe = declaration("audit", "allow");
	assert!(
		McpSecurity::new(Some(&observe), Some(&empty))
			.authorize_request(&rpc, &mut context(), "db")
			.is_err()
	);
	assert!(
		McpSecurity::new(None, None)
			.authorize_request(&call("custom/execute", json!({})), &mut context(), "db")
			.is_ok()
	);
	assert!(
		McpSecurity::new(Some(&observe), Some(&empty))
			.authorize_request(&call("custom/execute", json!({})), &mut context(), "db")
			.is_err()
	);
}

#[test]
fn each_declarations_arguments_and_approval_constraints_are_preserved() {
	let mut common = declaration("enforce", "allow");
	common.pipeline.required_tool_arguments =
		serde_json::from_value(json!([{"toolName":"echo","requiredFields":["query"]}])).unwrap();
	let mut pipeline = declaration("enforce", "allow").pipeline.clone();
	pipeline.required_tool_arguments =
		serde_json::from_value(json!([{"toolName":"echo","requiredFields":["recordId"]}])).unwrap();
	let legacy: LegacySecurityPipeline = pipeline.clone().into();
	let security = McpSecurity::new(Some(&common), Some(&legacy));
	for (args, permitted) in [
		(json!({"query":"safe"}), false),
		(json!({"recordId":42}), false),
		(json!({"query":"safe","recordId":42}), true),
	] {
		let rpc = call("tools/call", json!({"name":"echo","arguments":args}));
		let mut ctx = context();
		assert_eq!(
			security.authorize_request(&rpc, &mut ctx, "db").is_ok(),
			permitted
		);
		assert!(
			ctx
				.as_request()
				.extensions()
				.get::<IssuedCapability>()
				.is_none()
		);
	}
	pipeline.required_tool_approvals = serde_json::from_value(json!([{"toolName":"echo"}])).unwrap();
	let approval: LegacySecurityPipeline = pipeline.into();
	let rpc = call(
		"tools/call",
		json!({"name":"echo","arguments":{"query":"safe","recordId":42}}),
	);
	let security = McpSecurity::new(Some(&common), Some(&approval));
	let op = normalize(&rpc, "request", GatewayIdentity::default(), "db");
	assert!(security.requires_tool_approval(&op.action));
	assert!(
		security
			.authorize_request(&rpc, &mut context(), "db")
			.is_err()
	);
}

#[test]
fn normalized_legacy_declaration_retains_wire_shape_and_shared_owner() {
	let pipeline: SecurityPipelineConfig = serde_json::from_value(json!({
		"requiredIdentity":{"user":true,"agent":false,"tenant":false},"policies":[{"id":"allow","effect":"allow","enabled":true}],
			"dynamicAuthorization":{"policyVersion":"v1","cacheTtlSeconds":0}
	}))
	.unwrap();
	let expected = serde_json::to_value(&pipeline).unwrap();
	let legacy: LegacySecurityPipeline = pipeline.into();
	let cloned = legacy.clone();
	assert!(std::sync::Arc::ptr_eq(
		legacy.configuration(),
		cloned.configuration()
	));
	assert_eq!(
		legacy.configuration().mode,
		security_integration_runtime::SecurityMode::Enforce
	);
	assert_eq!(serde_json::to_value(&legacy).unwrap(), expected);
	let policy = crate::types::agent::BackendTrafficPolicy::SecurityPipeline(legacy.clone());
	assert_eq!(
		serde_json::to_value(policy).unwrap(),
		json!({"securityPipeline":expected})
	);
	let policies = crate::store::BackendPolicies {
		security_pipeline: Some(legacy),
		..Default::default()
	};
	assert_eq!(
		serde_json::to_value(policies).unwrap()["securityPipeline"],
		expected
	);
}
