//! Audit the configuration write boundary, including JSON extraction failures.
//! This is observability, not authentication or administrator authorization.
use std::collections::BTreeMap;

use axum::extract::{Request, State};
use axum::middleware::Next;
use axum::response::Response;
use chrono::Utc;
use security_pipeline::GatewayIdentity;
use serde_json::json;

use crate::security_events::{SecurityEventKind, SecurityEventStore, SecurityTimelineEvent};

fn event(
	id: &str,
	actor: &GatewayIdentity,
	phase: &str,
	status: Option<u16>,
) -> SecurityTimelineEvent {
	SecurityTimelineEvent {
		sequence: 0,
		kind: SecurityEventKind::ManagementChange,
		request_id: id.into(),
		timestamp: Utc::now(),
		user_id: actor.user_id.clone(),
		agent_id: actor.agent_id.clone(),
		tenant_id: actor.tenant_id.clone(),
		delegation_id: actor.delegation_id.clone(),
		action: "ConfigurationWrite".into(),
		resource_type: "RuntimeConfiguration".into(),
		resource_id: "local".into(),
		// Operation success is not an authorization decision.
		decision: None,
		policy_id: None,
		policy_version: None,
		details: BTreeMap::from([
			("phase".into(), json!(phase)),
			("httpStatus".into(), json!(status)),
			(
				"actorAttribution".into(),
				json!(if actor.user_id.is_some() {
					"verifiedClaims"
				} else {
					"unverified"
				}),
			),
			(
				"outcome".into(),
				json!(match status {
					Some(200..=299) => "saved",
					Some(_) => "failed",
					None => "attempted",
				}),
			),
		]),
	}
}

pub(crate) async fn audit_config_write(
	State(store): State<SecurityEventStore>,
	mut request: Request,
	next: Next,
) -> Response {
	if request.method() != http::Method::POST {
		return next.run(request).await;
	}
	let id = crate::security::request_id(request.extensions_mut());
	// Only server-side validated Claims extensions are accepted. Never read identity headers
	// or decode the Authorization header here. An unprotected admin port remains unverified.
	let actor = crate::security::identity_from_extensions(request.extensions());
	store.record(event(&id, &actor, "started", None));
	let mut response = next.run(request).await;
	store.record(event(
		&id,
		&actor,
		"completed",
		Some(response.status().as_u16()),
	));
	response.headers_mut().insert(
		"x-ai-security-request-id",
		id.parse()
			.expect("gateway-generated UUID is a valid header"),
	);
	response
}
