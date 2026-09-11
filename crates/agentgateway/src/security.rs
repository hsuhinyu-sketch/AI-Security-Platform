use gateway_adapter::{GatewayError, GatewayIdentity};
use security_contracts::ActionRequest;
use security_integration_agentgateway::SecurityConfig;

pub(crate) fn identity_from_extensions(extensions: &::http::Extensions) -> GatewayIdentity {
	let Some(claims) = extensions.get::<crate::http::jwt::Claims>() else {
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

pub(crate) fn evaluate(
	config: &SecurityConfig,
	action: &ActionRequest,
) -> Result<(), GatewayError> {
	security_integration_agentgateway::evaluate(config, action)
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
