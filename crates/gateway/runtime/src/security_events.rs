//! Bounded, redacted security-event feed for the administrative UI.
//!
//! This is intentionally an observability projection, not a policy store or authorization
//! control plane. Events retain identities, normalized actions, resources, decisions, hashes and
//! stable rule IDs, but never JWTs, prompts, document content, ACL lists or capability tokens.

use std::collections::{BTreeMap, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

use chrono::{DateTime, Utc};
use security_audit::AuditSink;
use security_types::{DecisionEffect, SecurityEvent};
use serde::{Deserialize, Serialize};
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
	journal: Mutex<Option<EventJournal>>,
	retention_seconds: Option<u64>,
	persistence_enabled: bool,
	persistence_failures: AtomicU64,
}
enum EventJournal {
	Legacy(security_audit::JsonlJournal),
	Managed(security_audit::RotatingAuditJournal<SecurityTimelineEvent>),
}
impl EventJournal {
	fn append(&mut self, event: &SecurityTimelineEvent) -> std::io::Result<()> {
		match self {
			Self::Legacy(j) => j.append(event),
			Self::Managed(j) => j.append(event),
		}
	}
}

/// Event classes exposed by the UI. Values describe control-flow stages, never request content.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum SecurityEventKind {
	ManagementChange,
	Authorization,
	RagIngestion,
	RagRetrieval,
	RagContextAssembly,
	PiiInspection,
}

/// A sanitized event suitable for an authenticated administrative UI and SSE clients.
#[derive(Debug, Clone, Serialize, Deserialize)]
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
#[cfg(feature = "ui")]
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SecurityOverview {
	pub persistence_enabled: bool,
	pub persistence_healthy: bool,
	pub persistence_failures: u64,
	pub capacity: usize,
	pub retained_events: usize,
	pub total_recorded: u64,
	pub allowed: u64,
	pub denied: u64,
	pub by_action: BTreeMap<String, SecurityDecisionCounts>,
}

#[cfg(feature = "ui")]
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
				journal: Mutex::new(None),
				retention_seconds: None,
				persistence_enabled: false,
				persistence_failures: AtomicU64::new(0),
			}),
		}
	}

	pub fn open(capacity: usize, path: &std::path::Path) -> std::io::Result<Self> {
		let (journal, events) =
			security_audit::JsonlJournal::open::<SecurityTimelineEvent>(path, capacity)?;
		let mut previous = 0;
		for event in &events {
			if event.sequence <= previous {
				return Err(std::io::Error::other("non-monotonic audit sequence"));
			}
			previous = event.sequence;
		}
		let mut store = Self::new(capacity);
		let inner = Arc::get_mut(&mut store.inner).expect("new store is exclusively owned");
		inner.next_sequence.store(previous, Ordering::Relaxed);
		inner.events = Mutex::new(events);
		inner.journal = Mutex::new(Some(EventJournal::Legacy(journal)));
		inner.persistence_enabled = true;
		Ok(store)
	}

	pub fn record(&self, event: SecurityTimelineEvent) {
		if let Err(error) = self.record_checked(event, false) {
			self
				.inner
				.persistence_failures
				.fetch_add(1, Ordering::Relaxed);
			tracing::error!(%error,"security audit record unavailable");
		}
	}
	pub fn open_managed(
		capacity: usize,
		config: security_audit::AuditJournalConfig,
	) -> std::io::Result<Self> {
		let (journal, events) = security_audit::RotatingAuditJournal::open(config.clone(), capacity)?;
		let mut store = Self::new(capacity);
		let inner = Arc::get_mut(&mut store.inner).expect("new store");
		inner
			.next_sequence
			.store(journal.next_sequence() - 1, Ordering::Relaxed);
		inner.events = Mutex::new(events);
		inner.journal = Mutex::new(Some(EventJournal::Managed(journal)));
		inner.persistence_enabled = true;
		inner.retention_seconds = Some(config.retention_seconds);
		Ok(store)
	}
	#[cfg(feature = "ui")]
	pub fn history(
		&self,
		before: Option<u64>,
		limit: usize,
	) -> Result<Vec<SecurityTimelineEvent>, String> {
		let mut journal = self.inner.journal.lock().map_err(|_| "audit unavailable")?;
		match journal.as_mut() {
			Some(EventJournal::Managed(j)) => j
				.history(before, limit)
				.map(|events| events.into_iter().collect())
				.map_err(|_| "audit history unavailable".into()),
			_ => Err("managed audit history unavailable".into()),
		}
	}
	fn record_checked(&self, event: SecurityTimelineEvent, required: bool) -> Result<(), String> {
		security_audit::StateJournal::encoded_len(&event, 16000)
			.map_err(|_| "audit event exceeds byte budget")?;
		// Serialize assignment, append and publication so concurrent writers cannot reorder IDs.
		let mut journal = self
			.inner
			.journal
			.lock()
			.map_err(|_| "audit journal lock poisoned")?;
		if required && !matches!(journal.as_ref(), Some(EventJournal::Managed(_))) {
			return Err("managed durable audit required".into());
		}
		let mut event = event;
		event.sequence = self.inner.next_sequence.fetch_add(1, Ordering::Relaxed) + 1;
		if let Some(writer) = journal.as_mut() {
			if let Err(error) = writer.append(&event) {
				self
					.inner
					.persistence_failures
					.fetch_add(1, Ordering::Relaxed);
				tracing::error!(%error, "security audit persistence failed; journal disabled until restart");
				// A partial write must never be followed by another record in the same journal.
				*journal = None;
				if required {
					return Err("required audit commit failed".into());
				}
			}
		} else if self.inner.persistence_enabled {
			self
				.inner
				.persistence_failures
				.fetch_add(1, Ordering::Relaxed);
		}
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
		Ok(())
	}

	pub fn record_authorization(&self, event: SecurityEvent) {
		self.record(Self::authorization_event(event));
	}
	pub fn record_authorization_required(&self, event: SecurityEvent) -> Result<(), String> {
		self.record_checked(Self::authorization_event(event), true)
	}
	#[cfg(feature = "security-pii")]
	pub(crate) fn record_content_required(&self, event: SecurityTimelineEvent) -> Result<(), String> {
		self.record_checked(event, true)
	}
	fn authorization_event(event: SecurityEvent) -> SecurityTimelineEvent {
		SecurityTimelineEvent {
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
		}
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

	#[cfg(feature = "ui")]
	pub fn events(&self, request_id: Option<&str>, limit: usize) -> Vec<SecurityTimelineEvent> {
		let limit = limit.clamp(1, self.inner.capacity);
		self
			.inner
			.events
			.lock()
			.expect("security event store lock poisoned")
			.iter()
			.rev()
			.filter(|event| {
				self.inner.retention_seconds.is_none_or(|ttl| {
					event.timestamp.timestamp_millis()
						>= Utc::now()
							.timestamp_millis()
							.saturating_sub(ttl as i64 * 1000)
				})
			})
			.filter(|event| request_id.is_none_or(|request_id| event.request_id == request_id))
			.take(limit)
			.cloned()
			.collect()
	}

	#[cfg(feature = "ui")]
	pub fn overview(&self) -> SecurityOverview {
		let events = self
			.inner
			.events
			.lock()
			.expect("security event store lock poisoned");
		let mut overview = SecurityOverview {
			persistence_enabled: self.inner.persistence_enabled,
			persistence_healthy: self.inner.persistence_enabled
				&& self.inner.persistence_failures.load(Ordering::Relaxed) == 0,
			persistence_failures: self.inner.persistence_failures.load(Ordering::Relaxed),
			capacity: self.inner.capacity,
			retained_events: 0,
			total_recorded: self.inner.next_sequence.load(Ordering::Relaxed),
			allowed: 0,
			denied: 0,
			by_action: BTreeMap::new(),
		};
		let cutoff = self.inner.retention_seconds.map(|ttl| {
			Utc::now()
				.timestamp_millis()
				.saturating_sub(ttl as i64 * 1000)
		});
		for event in events
			.iter()
			.filter(|event| cutoff.is_none_or(|cutoff| event.timestamp.timestamp_millis() >= cutoff))
		{
			overview.retained_events += 1;
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

	#[cfg(feature = "ui")]
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

pub fn initialize_persistent(
	capacity: usize,
	path: Option<&std::path::Path>,
) -> anyhow::Result<()> {
	if let Some(path) = path {
		let store = SecurityEventStore::open(capacity, path)?;
		STORE
			.set(store)
			.map_err(|_| anyhow::anyhow!("security store already initialized"))?;
	} else {
		initialize(capacity);
	}
	Ok(())
}
pub fn initialize_managed(
	capacity: usize,
	config: security_audit::AuditJournalConfig,
) -> anyhow::Result<()> {
	STORE
		.set(SecurityEventStore::open_managed(capacity, config)?)
		.map_err(|_| anyhow::anyhow!("security store already initialized"))?;
	Ok(())
}

pub fn store() -> SecurityEventStore {
	initialize(DEFAULT_CAPACITY)
}

/// Fan-out sink used by security pipelines: tracing remains the operational record while the
/// bounded projection makes sanitized events available to the UI.
#[derive(Clone, Copy, Default)]
pub struct UiSecurityAuditSink;

impl AuditSink for UiSecurityAuditSink {
	fn record_required(&self, event: SecurityEvent) -> Result<(), String> {
		store().record_authorization_required(event)
	}
	fn record(&self, event: SecurityEvent) {
		security_integration_runtime::TracingAuditSink.record(event.clone());
		store().record_authorization(event);
	}
}
