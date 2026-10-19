use security_integration_runtime::SecurityConfig;
use security_pipeline::{GatewayError, GatewayIdentity};
use security_types::ActionRequest;

/// Internal identifier/configuration fingerprint. A digest is not an authentication proof.
pub(crate) fn digest(value: &str) -> String {
	use sha2::Digest;
	base64::Engine::encode(
		&base64::engine::general_purpose::URL_SAFE_NO_PAD,
		sha2::Sha256::digest(value.as_bytes()),
	)
}

#[derive(Clone)]
struct SecurityRequestId(String);

/// Gateway-generated identity, independent of caller headers and URL query contents.
/// Request extensions keep retries and authorization/egress checks on the same ID.
pub(crate) fn request_id(extensions: &mut ::http::Extensions) -> String {
	if let Some(id) = extensions.get::<SecurityRequestId>() {
		return id.0.clone();
	}
	let id = uuid::Uuid::new_v4().to_string();
	extensions.insert(SecurityRequestId(id.clone()));
	id
}

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
	security_integration_runtime::evaluate_with_audit(
		config,
		action,
		None,
		&crate::security_events::UiSecurityAuditSink,
	)
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
