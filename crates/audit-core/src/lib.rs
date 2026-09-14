use std::sync::Mutex;

use chrono::Utc;
use security_contracts::{ActionRequest, Decision, SecurityEvent};

pub fn event_from_decision(
	event_id: impl Into<String>,
	request: &ActionRequest,
	decision: &Decision,
) -> SecurityEvent {
	SecurityEvent {
		event_id: event_id.into(),
		request_id: request.request_id.clone(),
		subject: request.subject.clone(),
		action: request.action.clone(),
		resource: request.resource.clone(),
		authorization_context: request.authorization_context.clone(),
		decision: decision.effect,
		policy_id: decision.policy_id.clone(),
		policy_version: decision.policy_version.clone(),
		decision_expires_at: decision.expires_at,
		timestamp: Utc::now(),
	}
}

/// Destination for authorization audit events. Production deployments can implement this
/// for an event stream or durable store; the PoC uses the in-memory implementation below.
pub trait AuditSink: Send + Sync {
	fn record(&self, event: SecurityEvent);
}

impl<T: AuditSink + ?Sized> AuditSink for &T {
	fn record(&self, event: SecurityEvent) {
		(*self).record(event);
	}
}

#[derive(Default)]
pub struct InMemoryAuditSink {
	events: Mutex<Vec<SecurityEvent>>,
}

impl InMemoryAuditSink {
	pub fn events(&self) -> Vec<SecurityEvent> {
		self
			.events
			.lock()
			.expect("audit sink lock poisoned")
			.clone()
	}
}

impl AuditSink for InMemoryAuditSink {
	fn record(&self, event: SecurityEvent) {
		self
			.events
			.lock()
			.expect("audit sink lock poisoned")
			.push(event);
	}
}
