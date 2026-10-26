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

/// Gateway-generated identity, independent of caller headers and URL query contents.
/// Request extensions keep retries and authorization/egress checks on the same ID.
pub(crate) fn request_id(extensions: &mut ::http::Extensions) -> String {
	if let Some(context) = extensions.get::<security_types::RequestContext>() {
		return context.request_id().to_owned();
	}
	let context = security_types::RequestContext::default();
	let id = context.request_id().to_owned();
	extensions.insert(context);
	id
}

pub(crate) fn identity_from_extensions(extensions: &::http::Extensions) -> GatewayIdentity {
	let Some(claims) = extensions.get::<crate::http::jwt::Claims>() else {
		return GatewayIdentity::default();
	};
	identity_from_claims(&claims.inner)
}

pub(crate) fn identity_from_claims(
	claims: &serde_json::Map<String, serde_json::Value>,
) -> GatewayIdentity {
	GatewayIdentity {
		user_id: string_claim(claims, &["sub", "user_id", "userId"]),
		agent_id: string_claim(claims, &["agent_id", "agentId"]),
		tenant_id: string_claim(claims, &["tenant_id", "tenantId"]),
		delegation_id: string_claim(claims, &["delegation_id", "delegationId"]),
		session_id: string_claim(claims, &["sid", "session_id", "sessionId"]),
		client_id: string_claim(claims, &["azp", "client_id", "clientId"]),
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
