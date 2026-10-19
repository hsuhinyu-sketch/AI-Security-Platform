//! Identity-bound context state. No network allow-cache, prompts, JWTs or chunk bodies are stored.
use crate::identity_binding::VerifiedOwner;
use security_audit::{StateJournal, StateJournalConfig};
use security_types::{DataClassification, DocumentVersion, DocumentVersionValidator};
use serde::{Deserialize, Serialize};
use std::{
	collections::HashMap,
	sync::{Arc, Mutex, OnceLock, Weak},
	time::{Duration, Instant},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContextError {
	Denied,
	Unavailable,
	Capacity,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContextBinding {
	pub owner: VerifiedOwner,
	pub namespace: String,
	pub fingerprint: String,
}
pub trait SecurityContextStore: Send + Sync {
	fn register_document_validator(
		&self,
		_namespace: &str,
		_validator: Arc<dyn DocumentVersionValidator>,
	) -> Result<(), ContextError> {
		Err(ContextError::Unavailable)
	}
	fn issue_documents(
		&self,
		binding: ContextBinding,
		ttl: u64,
		capacity: usize,
		class: DataClassification,
		documents: Vec<DocumentVersion>,
	) -> Result<String, ContextError> {
		if !documents.is_empty() {
			return Err(ContextError::Denied);
		}
		self.issue(binding, ttl, capacity, class)
	}
	fn elevate_documents(
		&self,
		id: &str,
		binding: &ContextBinding,
		class: DataClassification,
		documents: Vec<DocumentVersion>,
	) -> Result<(), ContextError> {
		if !documents.is_empty() {
			return Err(ContextError::Denied);
		}
		self.elevate(id, binding, class)
	}
	fn issue(
		&self,
		binding: ContextBinding,
		ttl_seconds: u64,
		max_contexts: usize,
		class: DataClassification,
	) -> Result<String, ContextError>;
	fn classification(
		&self,
		id: &str,
		binding: &ContextBinding,
	) -> Result<DataClassification, ContextError>;
	fn elevate(
		&self,
		id: &str,
		binding: &ContextBinding,
		class: DataClassification,
	) -> Result<(), ContextError>;
	fn revoke(&self, id: &str, binding: &ContextBinding) -> Result<(), ContextError>;
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Snapshot {
	#[serde(default)]
	document_authority: Option<String>,
	#[serde(default)]
	documents: Vec<DocumentVersion>,
	id: String,
	binding: ContextBinding,
	created_ms: i64,
	expires_ms: i64,
	ttl_seconds: u64,
	classification: DataClassification,
	revoked: bool,
}
struct Record {
	snapshot: Snapshot,
	deadline: Instant,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Event {
	version: u32,
	sequence: u64,
	millis: i64,
	change: Change,
}
#[derive(Serialize, Deserialize)]
#[serde(tag = "kind", deny_unknown_fields)]
enum Change {
	DocumentAuthority { namespace: String, identity: String },
	Init { namespace: String },
	Put { snapshot: Snapshot },
	Checkpoint,
}
struct State {
	authorities: HashMap<String, String>,
	validators: HashMap<String, Weak<dyn DocumentVersionValidator>>,
	records: HashMap<String, Record>,
	journal: Option<StateJournal>,
	sequence: u64,
	highwater: i64,
	healthy: bool,
}
impl Default for State {
	fn default() -> Self {
		Self {
			authorities: HashMap::new(),
			validators: HashMap::new(),
			records: HashMap::new(),
			journal: None,
			sequence: 0,
			highwater: 0,
			healthy: true,
		}
	}
}
impl State {
	fn validate_snapshot_documents(&self, snapshot: &Snapshot) -> Result<(), ContextError> {
		let validator = self
			.validators
			.get(&snapshot.binding.namespace)
			.and_then(Weak::upgrade);
		let current = self
			.authorities
			.get(&snapshot.binding.namespace)
			.map(String::as_str);
		if snapshot.document_authority.as_deref() != current {
			return Err(ContextError::Denied);
		}
		if current.is_some() && validator.as_ref().and_then(|v| v.authority_id()) != current {
			return Err(ContextError::Denied);
		}
		self.validate_documents(&snapshot.binding, &snapshot.documents)
	}
	fn check(&mut self) -> Result<i64, ContextError> {
		let now = chrono::Utc::now().timestamp_millis();
		if !self.healthy
			|| (self.journal.is_some() && now < self.highwater)
			|| self.journal.as_mut().is_some_and(|j| j.check().is_err())
		{
			self.healthy = false;
			return Err(ContextError::Unavailable);
		}
		Ok(now)
	}
	fn commit(&mut self, change: Change) -> Result<(), ContextError> {
		let now = self.check()?;
		if let Some(journal) = &mut self.journal {
			let sequence = self
				.sequence
				.checked_add(1)
				.ok_or(ContextError::Unavailable)?;
			if journal
				.append(&Event {
					version: 1,
					sequence,
					millis: now,
					change,
				})
				.is_err()
			{
				self.healthy = false;
				return Err(ContextError::Unavailable);
			}
			self.sequence = sequence;
			self.highwater = now;
		}
		Ok(())
	}
	fn snapshot(
		&mut self,
		id: &str,
		binding: &ContextBinding,
		allow_revoked: bool,
	) -> Result<Snapshot, ContextError> {
		self.check()?;
		let record = self.records.get(id).ok_or(ContextError::Denied)?;
		if record.snapshot.binding != *binding
			|| Instant::now() >= record.deadline
			|| (!allow_revoked && record.snapshot.revoked)
		{
			return Err(ContextError::Denied);
		}
		Ok(record.snapshot.clone())
	}
	fn validate_documents(
		&self,
		binding: &ContextBinding,
		documents: &[DocumentVersion],
	) -> Result<(), ContextError> {
		if documents.is_empty() {
			return Ok(());
		}
		self
			.validators
			.get(&binding.namespace)
			.and_then(Weak::upgrade)
			.ok_or(ContextError::Denied)?
			.validate_documents(&binding.owner.identity().into(), documents)
			.map_err(|_| ContextError::Denied)
	}
}
pub struct LocalSecurityContextStore {
	state: Mutex<State>,
	namespace: Option<String>,
	spec: Option<StateJournalConfig>,
}
impl Default for LocalSecurityContextStore {
	fn default() -> Self {
		Self {
			state: Mutex::new(State::default()),
			namespace: None,
			spec: None,
		}
	}
}
type OpenStores = HashMap<std::path::PathBuf, Weak<LocalSecurityContextStore>>;
static STORES: OnceLock<Mutex<OpenStores>> = OnceLock::new();
impl LocalSecurityContextStore {
	pub fn open(spec: StateJournalConfig, namespace: &str) -> Result<Arc<Self>, String> {
		validate_namespace(namespace)?;
		let path = spec
			.canonical_path()
			.map_err(|_| "context journal directory unavailable or not private")?;
		let mut registry = STORES
			.get_or_init(Default::default)
			.lock()
			.map_err(|_| "context store registry unavailable")?;
		registry.retain(|_, store| store.strong_count() > 0);
		if let Some(store) = registry.get(&path).and_then(Weak::upgrade) {
			if store.namespace.as_deref() != Some(namespace) || store.spec.as_ref() != Some(&spec) {
				return Err("context journal already open with another declaration".into());
			}
			store
				.state
				.lock()
				.map_err(|_| "context store unavailable")?
				.check()
				.map_err(|_| "context store unavailable")?;
			return Ok(store);
		}
		let mut state = State::default();
		let mut snapshots: HashMap<String, Snapshot> = HashMap::new();
		let now = chrono::Utc::now().timestamp_millis();
		let journal = StateJournal::open::<Event>(&spec, |event| {
			let invalid = || std::io::Error::other("invalid context journal transition/version/clock");
			if event.version != 1
				|| Some(event.sequence) != state.sequence.checked_add(1)
				|| event.millis < state.highwater
				|| event.millis > now
			{
				return Err(invalid());
			}
			match event.change {
				Change::DocumentAuthority {
					namespace: found,
					identity,
				} if state.sequence > 0
					&& found == namespace
					&& uuid::Uuid::parse_str(&identity).is_ok() =>
				{
					state.authorities.insert(found, identity);
				},
				Change::Init { namespace: found } if state.sequence == 0 && found == namespace => {},
				Change::Checkpoint if state.sequence > 0 => {},
				Change::Put { snapshot } if state.sequence > 0 => {
					validate_snapshot(&snapshot, namespace).map_err(std::io::Error::other)?;
					if snapshot.created_ms > event.millis {
						return Err(invalid());
					}
					if let Some(old) = snapshots.get(&snapshot.id) {
						if old.binding != snapshot.binding
							|| old.created_ms != snapshot.created_ms
							|| old.expires_ms != snapshot.expires_ms
							|| old.ttl_seconds != snapshot.ttl_seconds
							|| old.classification > snapshot.classification
							|| (old.revoked && !snapshot.revoked)
							|| old
								.documents
								.iter()
								.any(|doc| !snapshot.documents.contains(doc))
							|| old.document_authority != snapshot.document_authority
						{
							return Err(invalid());
						}
					} else if snapshot.created_ms < state.highwater {
						return Err(invalid());
					}
					// TTL is at most one day. Discard expired entries without weakening live ones.
					snapshots.retain(|_, old| old.expires_ms > event.millis);
					if snapshot.expires_ms > event.millis {
						snapshots.insert(snapshot.id.clone(), snapshot);
					}
					if snapshots.len() > 16384 {
						return Err(invalid());
					}
				},
				_ => return Err(invalid()),
			}
			state.sequence = event.sequence;
			state.highwater = event.millis;
			Ok(())
		})
		.map_err(|e| format!("cannot open context journal: {e}"))?;
		let fresh = journal.is_fresh();
		state.journal = Some(journal);
		let monotonic = Instant::now();
		for (id, snapshot) in snapshots {
			if snapshot.expires_ms > now {
				let deadline = monotonic
					.checked_add(Duration::from_millis((snapshot.expires_ms - now) as u64))
					.ok_or("invalid context deadline")?;
				state.records.insert(id, Record { snapshot, deadline });
			}
		}
		state
			.commit(if fresh {
				Change::Init {
					namespace: namespace.into(),
				}
			} else {
				Change::Checkpoint
			})
			.map_err(|_| "cannot initialize context journal")?;
		let store = Arc::new(Self {
			state: Mutex::new(state),
			namespace: Some(namespace.into()),
			spec: Some(spec),
		});
		registry.insert(path, Arc::downgrade(&store));
		Ok(store)
	}
}
fn validate_namespace(namespace: &str) -> Result<(), String> {
	if namespace.is_empty() || namespace.trim() != namespace || namespace.len() > 128 {
		return Err("invalid context namespace".into());
	}
	Ok(())
}
fn validate_binding(binding: &ContextBinding) -> Result<(), String> {
	validate_namespace(&binding.namespace)?;
	// Entry-count bounds alone do not bound heap usage: verified claims can still be large.
	// Bound individual identifiers and the combined raw payload before cloning the identity.
	let principals = [
		Some(binding.owner.tenant.as_str()),
		binding.owner.user.as_deref(),
		binding.owner.agent.as_deref(),
		binding.owner.client.as_deref(),
		binding.owner.delegation.as_deref(),
	];
	let binding_bytes = principals.iter().flatten().fold(
		binding
			.owner
			.issuer
			.len()
			.saturating_add(binding.namespace.len())
			.saturating_add(binding.fingerprint.len()),
		|size, value| size.saturating_add(value.len()),
	);
	if principals.iter().flatten().any(|value| value.len() > 1024)
		|| binding.owner.issuer.len() > 2048
		|| binding_bytes > 4096
	{
		return Err("context identity metadata exceeds bounded storage limits".into());
	}
	if binding.fingerprint.is_empty()
		|| binding.fingerprint.len() > 256
		|| VerifiedOwner::from_identity(&binding.owner.identity(), &binding.owner.issuer).as_ref()
			!= Ok(&binding.owner)
	{
		return Err("invalid context binding".into());
	}
	Ok(())
}
fn validate_snapshot(snapshot: &Snapshot, namespace: &str) -> Result<(), String> {
	if snapshot
		.document_authority
		.as_ref()
		.is_some_and(|id| uuid::Uuid::parse_str(id).is_err())
	{
		return Err("invalid document authority".into());
	}
	validate_binding(&snapshot.binding)?;
	validate_references(&snapshot.documents)
		.map_err(|_| "context document references exceed limits")?;
	if snapshot.binding.namespace != namespace
		|| uuid::Uuid::parse_str(&snapshot.id).is_err()
		|| !(1..=86400).contains(&snapshot.ttl_seconds)
		|| snapshot.created_ms <= 0
		|| snapshot.expires_ms.checked_sub(snapshot.created_ms)
			!= Some(snapshot.ttl_seconds as i64 * 1000)
	{
		return Err("invalid context snapshot".into());
	}
	Ok(())
}
impl SecurityContextStore for LocalSecurityContextStore {
	fn register_document_validator(
		&self,
		namespace: &str,
		validator: Arc<dyn DocumentVersionValidator>,
	) -> Result<(), ContextError> {
		validate_namespace(namespace).map_err(|_| ContextError::Denied)?;
		let mut state = self.state.lock().map_err(|_| ContextError::Unavailable)?;
		state.check()?;
		state.validators.retain(|_, v| v.strong_count() > 0);
		if !state.validators.contains_key(namespace) && state.validators.len() >= 16384 {
			return Err(ContextError::Capacity);
		}
		if let Some(existing) = state.validators.get(namespace).and_then(Weak::upgrade) {
			if !Arc::ptr_eq(&existing, &validator) {
				return Err(ContextError::Denied);
			}
		}
		if let Some(identity) = validator.authority_id() {
			if uuid::Uuid::parse_str(identity).is_err()
				|| !state.authorities.contains_key(namespace) && state.authorities.len() >= 16384
			{
				return Err(ContextError::Capacity);
			}
			if state.authorities.get(namespace).map(String::as_str) != Some(identity) {
				state.commit(Change::DocumentAuthority {
					namespace: namespace.into(),
					identity: identity.into(),
				})?;
				state.authorities.insert(namespace.into(), identity.into());
			}
		}
		state
			.validators
			.insert(namespace.into(), Arc::downgrade(&validator));
		Ok(())
	}
	fn issue(
		&self,
		binding: ContextBinding,
		ttl_seconds: u64,
		max_contexts: usize,
		classification: DataClassification,
	) -> Result<String, ContextError> {
		self.issue_documents(
			binding,
			ttl_seconds,
			max_contexts,
			classification,
			Vec::new(),
		)
	}
	fn issue_documents(
		&self,
		binding: ContextBinding,
		ttl_seconds: u64,
		max_contexts: usize,
		classification: DataClassification,
		mut documents: Vec<DocumentVersion>,
	) -> Result<String, ContextError> {
		validate_references(&documents)?;
		documents.sort();
		documents.dedup();
		validate_binding(&binding).map_err(|_| ContextError::Denied)?;
		if !(1..=86400).contains(&ttl_seconds)
			|| !(1..=16384).contains(&max_contexts)
			|| self
				.namespace
				.as_ref()
				.is_some_and(|n| n != &binding.namespace)
		{
			return Err(ContextError::Denied);
		}
		let mut state = self.state.lock().map_err(|_| ContextError::Unavailable)?;
		let now = state.check()?;
		state.validate_documents(&binding, &documents)?;
		state.records.retain(|_, r| Instant::now() < r.deadline);
		if state.records.len() >= 16384
			|| state
				.records
				.values()
				.filter(|r| r.snapshot.binding.namespace == binding.namespace)
				.count()
				>= max_contexts
		{
			return Err(ContextError::Capacity);
		}
		let id = uuid::Uuid::new_v4().to_string();
		let expires_ms = now
			.checked_add(ttl_seconds as i64 * 1000)
			.ok_or(ContextError::Denied)?;
		let deadline = Instant::now() + Duration::from_secs(ttl_seconds);
		let snapshot = Snapshot {
			document_authority: state
				.validators
				.get(&binding.namespace)
				.and_then(Weak::upgrade)
				.and_then(|v| v.authority_id().map(str::to_string)),
			documents,
			id: id.clone(),
			binding,
			created_ms: now,
			expires_ms,
			ttl_seconds,
			classification,
			revoked: false,
		};
		state.commit(Change::Put {
			snapshot: snapshot.clone(),
		})?;
		state
			.records
			.insert(id.clone(), Record { snapshot, deadline });
		if Instant::now() >= deadline {
			return Err(ContextError::Denied);
		}
		state.validate_snapshot_documents(&state.records[&id].snapshot)?;
		Ok(id)
	}
	fn classification(
		&self,
		id: &str,
		binding: &ContextBinding,
	) -> Result<DataClassification, ContextError> {
		let mut state = self.state.lock().map_err(|_| ContextError::Unavailable)?;
		let snapshot = state.snapshot(id, binding, false)?;
		state.validate_snapshot_documents(&snapshot)?;
		// Persist a clock highwater before disclosing use, not an authorization cache.
		state.commit(Change::Checkpoint)?;
		state.snapshot(id, binding, false)?;
		state.validate_snapshot_documents(&snapshot)?;
		Ok(snapshot.classification)
	}
	fn elevate(
		&self,
		id: &str,
		binding: &ContextBinding,
		class: DataClassification,
	) -> Result<(), ContextError> {
		self.elevate_documents(id, binding, class, Vec::new())
	}
	fn elevate_documents(
		&self,
		id: &str,
		binding: &ContextBinding,
		class: DataClassification,
		documents: Vec<DocumentVersion>,
	) -> Result<(), ContextError> {
		validate_references(&documents)?;
		let mut state = self.state.lock().map_err(|_| ContextError::Unavailable)?;
		let mut snapshot = state.snapshot(id, binding, false)?;
		state.validate_snapshot_documents(&snapshot)?;
		snapshot.documents.extend(documents);
		snapshot.documents.sort();
		snapshot.documents.dedup();
		validate_references(&snapshot.documents)?;
		state.validate_documents(binding, &snapshot.documents)?;
		snapshot.classification = snapshot.classification.max(class);
		state.commit(Change::Put {
			snapshot: snapshot.clone(),
		})?;
		state
			.records
			.get_mut(id)
			.ok_or(ContextError::Denied)?
			.snapshot = snapshot;
		state.snapshot(id, binding, false)?;
		state.validate_snapshot_documents(&state.records[id].snapshot)?;
		Ok(())
	}
	fn revoke(&self, id: &str, binding: &ContextBinding) -> Result<(), ContextError> {
		let mut state = self.state.lock().map_err(|_| ContextError::Unavailable)?;
		let mut snapshot = state.snapshot(id, binding, true)?;
		snapshot.revoked = true;
		state.commit(Change::Put {
			snapshot: snapshot.clone(),
		})?;
		state
			.records
			.get_mut(id)
			.ok_or(ContextError::Denied)?
			.snapshot = snapshot;
		Ok(())
	}
}

fn validate_references(documents: &[DocumentVersion]) -> Result<(), ContextError> {
	if documents.len() > 64
		|| documents.iter().any(|d| {
			d.revision == 0 || uuid::Uuid::parse_str(&d.authority).is_err() || d.key.validate().is_err()
		}) || documents
		.iter()
		.map(|d| {
			d.key.tenant_id.len()
				+ d.key.corpus_id.len()
				+ d.key.document_id.len()
				+ d.authority.len()
				+ 8
		})
		.sum::<usize>()
		> 8192
	{
		return Err(ContextError::Capacity);
	}
	Ok(())
}

#[derive(Clone, Default)]
pub struct ContextStoreSlot(Arc<OnceLock<Arc<dyn SecurityContextStore>>>);
impl ContextStoreSlot {
	/// Trusted embedding hook. Install after configuration initialization, never from HTTP/YAML.
	pub fn new(store: Arc<dyn SecurityContextStore>) -> Self {
		let slot = OnceLock::new();
		let _ = slot.set(store);
		Self(Arc::new(slot))
	}
	pub fn get(&self) -> Option<Arc<dyn SecurityContextStore>> {
		self.0.get().cloned()
	}
}
impl std::fmt::Debug for ContextStoreSlot {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.debug_struct("ContextStoreSlot")
			.field("initialized", &self.0.get().is_some())
			.finish()
	}
}
impl crate::cross_component::CrossComponentConfig {
	pub fn prepare_store(&mut self) -> Result<(), String> {
		self.validate()?;
		if let Some(storage) = &self.storage {
			let store = LocalSecurityContextStore::open(storage.clone(), &self.namespace)?;
			let slot = OnceLock::new();
			let _ = slot.set(store as Arc<dyn SecurityContextStore>);
			self.store = ContextStoreSlot(Arc::new(slot));
		} else {
			self.store = Default::default();
		}
		Ok(())
	}
	pub fn context_store(&self) -> Result<Arc<dyn SecurityContextStore>, ContextError> {
		if let Some(store) = self.store.get() {
			return Ok(store);
		}
		match self.storage {
			Some(_) => self.store.0.get().cloned().ok_or(ContextError::Unavailable),
			None => Ok(shared_memory_store()),
		}
	}
}

pub fn shared_memory_store() -> Arc<LocalSecurityContextStore> {
	static MEMORY: OnceLock<Arc<LocalSecurityContextStore>> = OnceLock::new();
	MEMORY.get_or_init(Default::default).clone()
}
