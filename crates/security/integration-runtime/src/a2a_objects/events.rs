//! Bounded local replay of already projected A2A events, not an upstream replay guarantee.
//! Private storage is a deployment trust boundary, NOT a MAC or rollback-proof log.
use super::{ObjectError, TaskPermit};
use crate::identity_binding::VerifiedOwner;
use security_audit::{StateJournal, StateJournalConfig};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
	collections::{HashMap, VecDeque},
	sync::{Arc, Mutex, OnceLock, Weak},
};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EventRecoveryConfig {
	pub storage: StateJournalConfig,
	pub namespace: String,
	#[serde(default = "max_events")]
	pub max_events: usize,
	#[serde(default = "max_memory")]
	pub max_memory_bytes: usize,
	#[serde(default = "max_event")]
	pub max_event_bytes: usize,
	#[serde(default = "retention")]
	pub retention_seconds: u64,
	#[serde(default = "batch")]
	pub max_batch_events: usize,
	#[serde(default = "batch_bytes")]
	pub max_batch_bytes: usize,
	#[serde(skip)]
	store: StoreSlot,
}
fn max_events() -> usize {
	1024
}
fn max_memory() -> usize {
	8_388_608
}
fn max_event() -> usize {
	262_144
}
fn retention() -> u64 {
	3600
}
fn batch() -> usize {
	16
}
fn batch_bytes() -> usize {
	1_048_576
}

#[derive(Clone, Default)]
struct StoreSlot(Option<Arc<EventStore>>);
impl std::fmt::Debug for StoreSlot {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.debug_tuple("EventStoreSlot")
			.field(&self.0.is_some())
			.finish()
	}
}
impl EventRecoveryConfig {
	pub fn validate(&self) -> Result<(), String> {
		self.storage.validate()?;
		if self.namespace.is_empty()
			|| self.namespace.trim() != self.namespace
			|| self.namespace.len() > 128
			|| !(1..=4096).contains(&self.max_events)
			|| !(1024..=262_144).contains(&self.max_event_bytes)
			|| !(1024..=16_777_216).contains(&self.max_memory_bytes)
			|| self.max_memory_bytes < self.max_event_bytes
			|| !(1..=86_400).contains(&self.retention_seconds)
			|| !(1..=64).contains(&self.max_batch_events)
			|| !(1024..=1_048_576).contains(&self.max_batch_bytes)
			|| self.max_batch_bytes < self.max_event_bytes
		{
			return Err(
				"eventRecovery requires bounded namespace, retention, event, memory and batch limits"
					.into(),
			);
		}
		Ok(())
	}
	fn spec(&self) -> Result<String, ObjectError> {
		serde_json::to_string(self).map_err(|_| ObjectError::EventStorage)
	}
	pub fn prepare_store(&mut self) -> Result<(), String> {
		self.validate()?;
		self.store = StoreSlot(Some(EventStore::open(self)?));
		Ok(())
	}
	pub fn store(&self) -> Result<Arc<EventStore>, ObjectError> {
		let store = self.store.0.as_ref().ok_or(ObjectError::EventStorage)?;
		if self.spec()? != store.spec {
			return Err(ObjectError::EventStorage);
		}
		Ok(store.clone())
	}
}

/// Construct only from an authorized permit and live lineage. Cursor possession is not authority.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EventBinding {
	owner: VerifiedOwner,
	task_generation: String,
	context: String,
	execution: Option<String>,
	lineage: String,
}
impl EventBinding {
	pub(super) fn matches_permit(&self, permit: &TaskPermit) -> Result<(), ObjectError> {
		if Self::from_permit(permit, self.lineage.clone())? != *self {
			return Err(ObjectError::ResponseBinding);
		}
		Ok(())
	}
	pub fn from_permit(permit: &TaskPermit, lineage: String) -> Result<Self, ObjectError> {
		let value = Self {
			owner: permit.owner.clone(),
			task_generation: permit.cleanup_key()?,
			context: permit
				.context_id
				.clone()
				.ok_or(ObjectError::ResponseBinding)?,
			execution: permit.execution_binding.clone(),
			lineage,
		};
		value.validate()?;
		Ok(value)
	}
	fn validate(&self) -> Result<(), ObjectError> {
		if !super::valid_execution_binding(&self.lineage)
			|| self.context.is_empty()
			|| self.context.len() > 512
			|| StateJournal::encoded_len(self, 16_384).is_err()
		{
			return Err(ObjectError::EventStorage);
		}
		Ok(())
	}
	fn validate_result(&self, result: &Value) -> Result<(), ObjectError> {
		let (_, task, generation): (String, String, u64) =
			serde_json::from_str(&self.task_generation).map_err(|_| ObjectError::ResponseBinding)?;
		let id = if result["kind"] == "task" {
			&result["id"]
		} else {
			&result["taskId"]
		};
		if generation == 0
			|| task.is_empty()
			|| task.len() > 512
			|| id.as_str() != Some(&task)
			|| result["contextId"].as_str() != Some(&self.context)
			|| !matches!(
				result["kind"].as_str(),
				Some("task" | "artifact-update" | "status-update")
			) {
			return Err(ObjectError::ResponseBinding);
		}
		Ok(())
	}
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoredEvent {
	pub cursor: String,
	pub sequence: u64,
	millis: i64,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	observed_millis: Option<i64>,
	binding: EventBinding,
	pub result: Value,
}
/// Already authorized/projected Push data, atomically committed with Task state in SQLite.
/// No callback secret, user credential, RPC ID or raw unprojected notification is retained.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PushDelivery {
	pub source: String,
	pub serial: u64,
	pub cursor: String,
	pub millis: i64,
	pub binding: EventBinding,
	pub result: Value,
}
impl PushDelivery {
	pub(super) fn validate(&self) -> Result<(), ObjectError> {
		if !valid_cursor(&self.source)
			|| !valid_cursor(&self.cursor)
			|| self.serial == 0
			|| self.millis < 0
		{
			return Err(ObjectError::EventStorage);
		}
		self.binding.validate()?;
		self.binding.validate_result(&self.result)
	}
	fn fingerprint(&self) -> Result<String, ObjectError> {
		Ok(security_pipeline::arguments_hash(
			&serde_json::to_value(self).map_err(|_| ObjectError::EventStorage)?,
		))
	}
}
struct PushReceipt {
	source: String,
	serial: u64,
	cursor: String,
	fingerprint: String,
}
#[derive(Serialize, Deserialize)]
#[serde(tag = "kind", deny_unknown_fields)]
enum Record {
	Init {
		version: u32,
		namespace: String,
		millis: i64,
	},
	Event {
		event: StoredEvent,
	},
	PushEvent {
		source: String,
		serial: u64,
		event: StoredEvent,
	},
}
struct State {
	journal: StateJournal,
	events: VecDeque<(Arc<StoredEvent>, usize)>,
	bytes: usize,
	sequence: u64,
	highwater: i64,
	healthy: bool,
	push: Option<PushReceipt>,
}
pub struct EventStore {
	// Config owns the store, store owns only serialized settings: no Arc ownership cycle.
	spec: String,
	limits: EventRecoveryConfig,
	state: Mutex<State>,
}
pub struct EventBatch {
	pub events: Vec<Arc<StoredEvent>>,
	pub next_cursor: String,
	pub has_more: bool,
}
impl EventStore {
	pub(super) fn check_push_checkpoint(&self, source: &str, serial: u64) -> Result<(), ObjectError> {
		let mut state = self.state.lock().map_err(|_| ObjectError::EventStorage)?;
		self.check(&mut state)?;
		if state
			.push
			.as_ref()
			.map_or(serial != 0, |p| p.source != source || p.serial != serial)
		{
			return Err(ObjectError::EventStorage);
		}
		Ok(())
	}
	pub(super) fn check_push_size(&self, delivery: &PushDelivery) -> Result<(), ObjectError> {
		let event = StoredEvent {
			cursor: delivery.cursor.clone(),
			sequence: u64::MAX,
			millis: i64::MAX,
			observed_millis: Some(delivery.millis),
			binding: delivery.binding.clone(),
			result: delivery.result.clone(),
		};
		StateJournal::encoded_len(&event, self.limits.max_event_bytes)
			.map_err(|_| ObjectError::EventStorage)?;
		Ok(())
	}
	fn open(config: &EventRecoveryConfig) -> Result<Arc<Self>, String> {
		static STORES: OnceLock<Mutex<HashMap<std::path::PathBuf, Weak<EventStore>>>> = OnceLock::new();
		let path = config.storage.canonical_path().map_err(|e| e.to_string())?;
		let mut stores = STORES
			.get_or_init(Default::default)
			.lock()
			.map_err(|_| "event registry poisoned")?;
		stores.retain(|_, store| store.strong_count() > 0);
		let spec = config.spec().map_err(|_| "event spec")?;
		if let Some(store) = stores.get(&path).and_then(Weak::upgrade) {
			if store.spec != spec {
				return Err("event journal already opened with different settings".into());
			}
			return Ok(store);
		}
		if stores.len() >= 64 {
			return Err("event store registry capacity".into());
		}
		let mut events = VecDeque::new();
		let mut bytes = 0;
		let mut sequence = 0;
		let mut highwater = 0;
		let mut initialized = false;
		let mut push: Option<PushReceipt> = None;
		let now = chrono::Utc::now().timestamp_millis();
		let mut journal = StateJournal::open(&config.storage, |record: Record| {
			match record {
				Record::Init {
					version,
					namespace,
					millis,
				} => {
					if initialized
						|| version != 1
						|| namespace != config.namespace
						|| millis < 0
						|| millis > now
					{
						return Err(std::io::Error::other("invalid event journal header/clock"));
					}
					initialized = true;
					highwater = millis;
				},
				record @ (Record::Event { .. } | Record::PushEvent { .. }) => {
					let (event, delivery) = match record {
						Record::Event { event } => (event, None),
						Record::PushEvent {
							source,
							serial,
							event,
						} => {
							let delivery = PushDelivery {
								source,
								serial,
								cursor: event.cursor.clone(),
								millis: event
									.observed_millis
									.ok_or_else(|| std::io::Error::other("missing Push observation time"))?,
								binding: event.binding.clone(),
								result: event.result.clone(),
							};
							(event, Some(delivery))
						},
						_ => unreachable!(),
					};
					if !initialized
						|| event.sequence != sequence + 1
						|| event.millis < highwater
						|| event.millis > now
						|| event
							.observed_millis
							.is_some_and(|m| m < 0 || m > event.millis)
						|| !valid_cursor(&event.cursor)
						|| event.binding.validate().is_err()
						|| event.binding.validate_result(&event.result).is_err()
					{
						return Err(std::io::Error::other("invalid event journal entry"));
					}
					if let Some(delivery) = delivery {
						validate_push_order(push.as_ref(), &delivery)
							.map_err(|_| std::io::Error::other("invalid Push journal order"))?;
						push = Some(
							push_receipt(&delivery).map_err(|_| std::io::Error::other("invalid Push receipt"))?,
						);
					}
					let size = StateJournal::encoded_len(&event, config.max_event_bytes)?;
					sequence = event.sequence;
					highwater = event.millis;
					events.push_back((Arc::new(event), size));
					bytes += size;
					prune(&mut events, &mut bytes, config, now);
				},
			}
			Ok(())
		})
		.map_err(|e| e.to_string())?;
		if !initialized {
			if !journal.is_fresh() {
				return Err("missing event journal header".into());
			}
			journal
				.append(&Record::Init {
					version: 1,
					namespace: config.namespace.clone(),
					millis: now,
				})
				.map_err(|e| e.to_string())?;
			highwater = now;
		}
		let mut limits = config.clone();
		limits.store = StoreSlot::default();
		let store = Arc::new(Self {
			spec,
			limits,
			state: Mutex::new(State {
				journal,
				events,
				bytes,
				sequence,
				highwater,
				healthy: true,
				push,
			}),
		});
		stores.insert(path, Arc::downgrade(&store));
		Ok(store)
	}
	fn check(&self, state: &mut State) -> Result<i64, ObjectError> {
		let now = chrono::Utc::now().timestamp_millis();
		if !state.healthy || now < state.highwater || state.journal.check().is_err() {
			state.healthy = false;
			return Err(ObjectError::EventStorage);
		}
		state.highwater = now;
		let State { events, bytes, .. } = state;
		prune(events, bytes, &self.limits, now);
		Ok(now)
	}
	/// fsync completes before the cursor may be disclosed. Never stores RPC IDs or credentials.
	pub fn append(&self, binding: EventBinding, result: Value) -> Result<String, ObjectError> {
		self.append_inner(binding, result, None)
	}
	/// One persistent producer per journal. The last serial/fingerprint survives ring eviction.
	/// Replaying a committed outbox record never appends a second event or refreshes retention.
	pub fn append_push(&self, delivery: PushDelivery) -> Result<String, ObjectError> {
		delivery.validate()?;
		self.append_inner(
			delivery.binding.clone(),
			delivery.result.clone(),
			Some(delivery),
		)
	}
	fn append_inner(
		&self,
		binding: EventBinding,
		result: Value,
		delivery: Option<PushDelivery>,
	) -> Result<String, ObjectError> {
		binding.validate()?;
		binding.validate_result(&result)?;
		let mut state = self.state.lock().map_err(|_| ObjectError::EventStorage)?;
		let now = self.check(&mut state)?;
		if let Some(delivery) = &delivery {
			if delivery.millis > now {
				return Err(ObjectError::ClockRollback);
			}
			if let Some(last) = &state.push {
				if last.source == delivery.source && last.serial == delivery.serial {
					if last.cursor != delivery.cursor || last.fingerprint != delivery.fingerprint()? {
						return Err(ObjectError::EventStorage);
					}
					return Ok(last.cursor.clone());
				}
			}
			validate_push_order(state.push.as_ref(), delivery)?;
		}
		let event = StoredEvent {
			cursor: delivery
				.as_ref()
				.map(|d| d.cursor.clone())
				.unwrap_or_else(|| uuid::Uuid::new_v4().to_string()),
			sequence: state
				.sequence
				.checked_add(1)
				.ok_or(ObjectError::EventStorage)?,
			millis: now,
			observed_millis: delivery.as_ref().map(|d| d.millis),
			binding,
			result,
		};
		let size = StateJournal::encoded_len(&event, self.limits.max_event_bytes)
			.map_err(|_| ObjectError::EventStorage)?;
		let cursor = event.cursor.clone();
		let receipt = delivery.as_ref().map(push_receipt).transpose()?;
		let record = match delivery {
			Some(d) => Record::PushEvent {
				source: d.source,
				serial: d.serial,
				event,
			},
			None => Record::Event { event },
		};
		if state.journal.append(&record).is_err() {
			state.healthy = false;
			return Err(ObjectError::EventStorage);
		}
		let event = match record {
			Record::Event { event } | Record::PushEvent { event, .. } => event,
			_ => unreachable!(),
		};
		if let Some(receipt) = receipt {
			state.push = Some(receipt);
		}
		state.sequence = event.sequence;
		state.events.push_back((Arc::new(event), size));
		state.bytes += size;
		let State { events, bytes, .. } = &mut *state;
		prune(events, bytes, &self.limits, now);
		Ok(cursor)
	}
	/// A missing, expired or evicted cursor is a gap, never silently restarted at "now".
	pub fn read(
		&self,
		binding: &EventBinding,
		after: &str,
		limit: usize,
	) -> Result<EventBatch, ObjectError> {
		if !valid_cursor(after) || limit == 0 || limit > self.limits.max_batch_events {
			return Err(ObjectError::EventCursor);
		}
		let mut state = self.state.lock().map_err(|_| ObjectError::EventStorage)?;
		self.check(&mut state)?;
		let index = state
			.events
			.iter()
			.position(|(e, _)| e.cursor == after && &e.binding == binding)
			.ok_or(ObjectError::EventCursor)?;
		let mut events = Vec::new();
		let mut bytes = 0;
		let mut next_cursor = after.to_owned();
		let mut has_more = false;
		for (event, size) in state
			.events
			.iter()
			.skip(index + 1)
			.filter(|(e, _)| &e.binding == binding)
		{
			if events.len() == limit || bytes + size > self.limits.max_batch_bytes {
				has_more = true;
				break;
			}
			bytes += size;
			next_cursor = event.cursor.clone();
			events.push(event.clone());
		}
		Ok(EventBatch {
			events,
			next_cursor,
			has_more,
		})
	}
}
fn validate_push_order(
	last: Option<&PushReceipt>,
	delivery: &PushDelivery,
) -> Result<(), ObjectError> {
	delivery.validate()?;
	if last.map_or(delivery.serial != 1, |p| {
		p.source != delivery.source || p.serial.checked_add(1) != Some(delivery.serial)
	}) {
		return Err(ObjectError::EventStorage);
	}
	Ok(())
}
fn push_receipt(delivery: &PushDelivery) -> Result<PushReceipt, ObjectError> {
	Ok(PushReceipt {
		source: delivery.source.clone(),
		serial: delivery.serial,
		cursor: delivery.cursor.clone(),
		fingerprint: delivery.fingerprint()?,
	})
}
fn prune(
	events: &mut VecDeque<(Arc<StoredEvent>, usize)>,
	bytes: &mut usize,
	limits: &EventRecoveryConfig,
	now: i64,
) {
	// A recovered Push can be older than events already present. Expiry is not ordered
	// by append sequence, so do not let a fresh front retain an expired recovered suffix.
	events.retain(|(event, size)| {
		let keep = now.saturating_sub(event.observed_millis.unwrap_or(event.millis))
			< limits.retention_seconds as i64 * 1000;
		if !keep {
			*bytes -= size;
		}
		keep
	});
	while events.len() > limits.max_events || *bytes > limits.max_memory_bytes {
		let (_, size) = events.pop_front().expect("front");
		*bytes -= size;
	}
}
pub fn valid_cursor(cursor: &str) -> bool {
	uuid::Uuid::parse_str(cursor)
		.is_ok_and(|id| id.get_version_num() == 4 && id.to_string() == cursor)
}
