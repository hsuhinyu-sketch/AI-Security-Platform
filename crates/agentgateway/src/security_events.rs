//! Bounded, redacted security-event feed for the administrative UI.
//!
//! This is intentionally an observability projection, not a policy store or authorization
//! control plane. Events retain identities, normalized actions, resources, decisions, hashes and
//! stable rule IDs, but never JWTs, prompts, document content, ACL lists or capability tokens.

use std::collections::{BTreeMap, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

use audit_core::AuditSink;
use chrono::{DateTime, Utc};
use security_contracts::{DecisionEffect, SecurityEvent};
use serde::Serialize;
use serde_json::{Value, json};
use tokio::sync::broadcast;

const DEFAULT_CAPACITY: usize = 10_000;

static STORE: OnceLock<SecurityEventStore> = OnceLock::new();

#[derive(Clone)]
pub struct SecurityEventStore {
	inner: Arc<Inner>,
}

struct Inner {
	capacity: usize,
	next_sequence: AtomicU64,
	events: Mutex<VecDeque<SecurityTimelineEvent>>,
	live: broadcast::Sender<SecurityTimelineEvent>,
}

/// Event classes exposed by the UI. Values describe control-flow stages, never request content.
#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum SecurityEventKind {
	Authorization,
	RagIngestion,
	RagRetrieval,
	RagContextAssembly,
}

/// A sanitized event suitable for an authenticated administrative UI and SSE clients.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SecurityTimelineEvent {
	pub sequence: u64,
	pub kind: SecurityEventKind,
	pub request_id: String,
	pub timestamp: DateTime<Utc>,
	pub user_id: Option<String>,
	pub agent_id: Option<String>,
	pub tenant_id: Option<String>,
	pub delegation_id: Option<String>,
	pub action: String,
	pub resource_type: String,
	pub resource_id: String,
	pub decision: Option<DecisionEffect>,
	pub policy_id: Option<String>,
	pub policy_version: Option<String>,
	pub details: BTreeMap<String, Value>,
}

/// Aggregate values used by the Security Overview page.
#[cfg(any(test, feature = "ui"))]
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SecurityOverview {
	pub capacity: usize,
	pub retained_events: usize,
	pub total_recorded: u64,
	pub allowed: u64,
	pub denied: u64,
	pub by_action: BTreeMap<String, SecurityDecisionCounts>,
}

#[cfg(any(test, feature = "ui"))]
#[derive(Debug, Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SecurityDecisionCounts {
	pub allowed: u64,
	pub denied: u64,
	pub other: u64,
}

impl SecurityEventStore {
	pub fn new(capacity: usize) -> Self {
		let capacity = capacity.max(1);
		let (live, _) = broadcast::channel(capacity.min(1_024));
		Self {
			inner: Arc::new(Inner {
				capacity,
				next_sequence: AtomicU64::new(0),
				events: Mutex::new(VecDeque::with_capacity(capacity)),
				live,
			}),
		}
	}

	pub fn record(&self, event: SecurityTimelineEvent) {
		let mut event = event;
		event.sequence = self.inner.next_sequence.fetch_add(1, Ordering::Relaxed) + 1;
		{
			let mut events = self
				.inner
				.events
				.lock()
				.expect("security event store lock poisoned");
			if events.len() == self.inner.capacity {
				events.pop_front();
			}
			events.push_back(event.clone());
		}
		let _ = self.inner.live.send(event);
	}

	pub fn record_authorization(&self, event: SecurityEvent) {
		self.record(SecurityTimelineEvent {
			sequence: 0,
			kind: SecurityEventKind::Authorization,
			request_id: event.request_id,
			timestamp: event.timestamp,
			user_id: event.subject.user_id,
			agent_id: event.subject.agent_id,
			tenant_id: event.subject.tenant_id,
			delegation_id: event.subject.delegation_id,
			action: format!("{:?}:{}", event.action.action_type, event.action.name),
			resource_type: format!("{:?}", event.resource.resource_type),
			resource_id: event.resource.id,
			decision: Some(event.decision),
			policy_id: event.policy_id,
			policy_version: event.policy_version,
			details: BTreeMap::from([(
				"decisionExpiresAt".into(),
				json!(event.decision_expires_at.map(|value| value.to_rfc3339())),
			)]),
		});
	}

	pub fn record_rag_stage(
		&self,
		kind: SecurityEventKind,
		request_id: String,
		timestamp: DateTime<Utc>,
		tenant_id: Option<String>,
		action: &str,
		resource_type: &str,
		resource_id: String,
		decision: Option<DecisionEffect>,
		details: BTreeMap<String, Value>,
	) {
		self.record(SecurityTimelineEvent {
			sequence: 0,
			kind,
			request_id,
			timestamp,
			user_id: None,
			agent_id: None,
			tenant_id,
			delegation_id: None,
			action: action.into(),
			resource_type: resource_type.into(),
			resource_id,
			decision,
			policy_id: None,
			policy_version: None,
			details,
		});
	}

	#[cfg(any(test, feature = "ui"))]
	pub fn events(&self, request_id: Option<&str>, limit: usize) -> Vec<SecurityTimelineEvent> {
		let limit = limit.clamp(1, self.inner.capacity);
		self
			.inner
			.events
			.lock()
			.expect("security event store lock poisoned")
			.iter()
			.rev()
			.filter(|event| request_id.is_none_or(|request_id| event.request_id == request_id))
			.take(limit)
			.cloned()
			.collect()
	}

	#[cfg(any(test, feature = "ui"))]
	pub fn overview(&self) -> SecurityOverview {
		let events = self
			.inner
			.events
			.lock()
			.expect("security event store lock poisoned");
		let mut overview = SecurityOverview {
			capacity: self.inner.capacity,
			retained_events: events.len(),
			total_recorded: self.inner.next_sequence.load(Ordering::Relaxed),
			allowed: 0,
			denied: 0,
			by_action: BTreeMap::new(),
		};
		for event in events.iter() {
			let counts = overview.by_action.entry(event.action.clone()).or_default();
			match event.decision {
				Some(DecisionEffect::Allow) => {
					overview.allowed += 1;
					counts.allowed += 1;
				},
				Some(DecisionEffect::Deny) => {
					overview.denied += 1;
					counts.denied += 1;
				},
				None => counts.other += 1,
			}
		}
		overview
	}

	#[cfg(any(test, feature = "ui"))]
	pub fn subscribe(&self) -> broadcast::Receiver<SecurityTimelineEvent> {
		self.inner.live.subscribe()
	}
}

/// Initializes the process-wide event store. The first application initialization wins; this is
/// intentional because the compatibility runtime runs one administrative control plane per process.
pub fn initialize(capacity: usize) -> SecurityEventStore {
	STORE
		.get_or_init(|| SecurityEventStore::new(capacity))
		.clone()
}

pub fn store() -> SecurityEventStore {
	initialize(DEFAULT_CAPACITY)
}

/// Fan-out sink used by security pipelines: tracing remains the operational record while the
/// bounded projection makes sanitized events available to the UI.
#[derive(Clone, Copy, Default)]
pub struct UiSecurityAuditSink;

impl AuditSink for UiSecurityAuditSink {
	fn record(&self, event: SecurityEvent) {
		security_integration_agentgateway::TracingAuditSink.record(event.clone());
		store().record_authorization(event);
	}
}

#[cfg(test)]
mod tests {
	use chrono::Utc;

	use super::*;

	fn event(request_id: &str, decision: DecisionEffect) -> SecurityTimelineEvent {
		SecurityTimelineEvent {
			sequence: 0,
			kind: SecurityEventKind::Authorization,
			request_id: request_id.into(),
			timestamp: Utc::now(),
			user_id: Some("alice".into()),
			agent_id: None,
			tenant_id: Some("tenant-a".into()),
			delegation_id: None,
			action: "KnowledgeRetrieve:retrieve".into(),
			resource_type: "KnowledgeBase".into(),
			resource_id: "support".into(),
			decision: Some(decision),
			policy_id: Some("allow".into()),
			policy_version: None,
			details: BTreeMap::new(),
		}
	}

	#[test]
	fn bounded_store_keeps_the_latest_events_and_filters_by_request() {
		let store = SecurityEventStore::new(2);
		store.record(event("first", DecisionEffect::Allow));
		store.record(event("second", DecisionEffect::Deny));
		store.record(event("third", DecisionEffect::Allow));
		assert_eq!(store.events(None, 10).len(), 2);
		assert_eq!(store.events(Some("second"), 10)[0].request_id, "second");
		let overview = store.overview();
		assert_eq!(overview.total_recorded, 3);
		assert_eq!(overview.allowed, 1);
		assert_eq!(overview.denied, 1);
	}
}
