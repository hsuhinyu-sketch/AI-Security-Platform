use gateway_adapter::{
	GatewayError, GatewayIdentity, SecurityPipelineConfig, tool_invoke_for_identity, tool_list,
};
use rmcp::model::{ClientRequest, JsonRpcRequest};

use crate::mcp::upstream::{IncomingRequestContext, UpstreamError};

/// Enforce the configured security pipeline for a real MCP Tool invocation.
/// Identity is derived only from previously validated JWT claims carried in the request context.
pub fn enforce_tool_call(
	config: &SecurityPipelineConfig,
	request: &JsonRpcRequest<ClientRequest>,
	context: &IncomingRequestContext,
) -> Result<(), UpstreamError> {
	let ClientRequest::CallToolRequest(call) = &request.request else {
		return Ok(());
	};
	let identity = identity_from_context(context);
	let action = tool_invoke_for_identity(
		request.id.to_string(),
		identity,
		call.params.name.to_string(),
	);
	let arguments = serde_json::Value::Object(call.params.arguments.clone().unwrap_or_default());
	config
		.build(security_integration_agentgateway::TracingAuditSink)
		.authorize(&action, Some(&arguments))
		.map(|_| ())
		.map_err(|error| UpstreamError::InvalidRequest(error_message(error)))
}

/// Applies common S1/S2 security controls to MCP Tool discovery and invocation.
pub fn audit_request(
	config: &security_integration_agentgateway::SecurityConfig,
	request: &JsonRpcRequest<ClientRequest>,
	context: &IncomingRequestContext,
	mcp_server_id: &str,
) -> Result<(), UpstreamError> {
	let identity = identity_from_context(context);
	let (action, arguments) = match &request.request {
		ClientRequest::CallToolRequest(call) => (
			tool_invoke_for_identity(
				request.id.to_string(),
				identity,
				call.params.name.to_string(),
			),
			Some(serde_json::Value::Object(
				call.params.arguments.clone().unwrap_or_default(),
			)),
		),
		ClientRequest::ListToolsRequest(_) => (
			tool_list(request.id.to_string(), identity, mcp_server_id),
			None,
		),
		_ => return Ok(()),
	};
	security_integration_agentgateway::evaluate_with_arguments(config, &action, arguments.as_ref())
		.map_err(|error| UpstreamError::InvalidRequest(error_message(error)))
}

pub(crate) fn identity_from_context(context: &IncomingRequestContext) -> GatewayIdentity {
	let request = context.as_request();
	let Some(claims) = request.extensions().get::<crate::http::jwt::Claims>() else {
		return GatewayIdentity::default();
	};
	GatewayIdentity {
		user_id: string_claim(&claims.inner, &["sub", "user_id", "userId"]),
		agent_id: string_claim(&claims.inner, &["agent_id", "agentId"]),
		tenant_id: string_claim(&claims.inner, &["tenant_id", "tenantId"]),
		delegation_id: string_claim(&claims.inner, &["delegation_id", "delegationId"]),
		session_id: string_claim(&claims.inner, &["sid", "session_id", "sessionId"]),
		client_id: string_claim(&claims.inner, &["azp", "client_id", "clientId"]),
	}
}

fn string_claim(
	claims: &serde_json::Map<String, serde_json::Value>,
	names: &[&str],
) -> Option<String> {
	names.iter().find_map(|name| {
		claims
			.get(*name)
			.and_then(serde_json::Value::as_str)
			.map(ToOwned::to_owned)
	})
}

fn error_message(error: GatewayError) -> String {
	match error {
		GatewayError::Denied(decision) => format!(
			"security policy denied request{}",
			decision
				.policy_id
				.as_deref()
				.map(|id| format!(" by '{id}'"))
				.unwrap_or_default()
		),
		GatewayError::DeniedByControl { denial, .. } => {
			format!(
				"security control '{}' denied request: {}",
				denial.control_id, denial.reason
			)
		},
		GatewayError::Capability(error) => format!("capability validation failed: {error:?}"),
		GatewayError::CapabilityUnavailable => "capability broker is not configured".to_string(),
	}
}
