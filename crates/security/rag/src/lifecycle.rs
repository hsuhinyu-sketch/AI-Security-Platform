//! Authoritative document lifecycle. The vector index is never the ACL/version authority.
use crate::{
	DataClassification, DocumentIngestBackend, IndexedDocument, KnowledgeChunk, QuarantinedDocument,
	RetrievalBackend, RetrievalFilter, RetrievalQuery, SourceOrigin, TrustedChunkAccess,
};
use security_audit::{StateJournal, StateJournalConfig};
use security_types::{DocumentKey, DocumentVersion, DocumentVersionValidator, Subject};
use serde::{Deserialize, Serialize};
use std::{
	collections::HashMap,
	sync::{Arc, Mutex, OnceLock, Weak},
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DocumentLifecycleConfig {
	pub namespace: String,
	pub storage: StateJournalConfig,
	#[serde(default = "max_documents")]
	pub max_documents: usize,
}
fn max_documents() -> usize {
	4096
}
impl DocumentLifecycleConfig {
	pub fn validate(&self) -> Result<(), String> {
		self.storage.validate()?;
		if self.namespace.is_empty()
			|| self.namespace.trim() != self.namespace
			|| self.namespace.len() > 128
			|| !(1..=4096).contains(&self.max_documents)
		{
			return Err("invalid document lifecycle namespace/capacity".into());
		}
		Ok(())
	}
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum DocumentState {
	Pending,
	Active,
	Revoked,
	Deleted,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DocumentMetadata {
	pub authority: String,
	pub key: DocumentKey,
	pub revision: u64,
	pub version: u64,
	pub state: DocumentState,
	pub source_hash: String,
	pub classification: DataClassification,
	pub classification_source: String,
	pub labels: Vec<String>,
	pub access: TrustedChunkAccess,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "camelCase", deny_unknown_fields)]
pub enum DocumentMutation {
	Acl { access: TrustedChunkAccess },
	Revoke,
	Delete,
}
impl DocumentMutation {
	pub fn action(&self) -> &'static str {
		match self {
			Self::Acl { .. } => "document/update-acl",
			Self::Revoke => "document/revoke",
			Self::Delete => "document/delete",
		}
	}
}
fn validate_access(access: &TrustedChunkAccess) -> Result<(), String> {
	if access.allowed_users.len() + access.allowed_agents.len() > 64
		|| access
			.allowed_users
			.iter()
			.chain(&access.allowed_agents)
			.any(|v| v.is_empty() || v.trim() != v || v.len() > 256)
		|| access
			.allowed_users
			.iter()
			.chain(&access.allowed_agents)
			.map(String::len)
			.sum::<usize>()
			> 4096
	{
		return Err("document ACL exceeds byte/count limits".into());
	}
	Ok(())
}
fn validate_metadata(meta: &DocumentMetadata) -> Result<(), String> {
	meta.key.validate()?;
	validate_access(&meta.access)?;
	if uuid::Uuid::parse_str(&meta.authority).is_err() {
		return Err("invalid document authority identity".into());
	}
	if meta.version == 0
		|| meta.revision < meta.version
		|| meta.source_hash.len() != 64
		|| !meta.source_hash.bytes().all(|b| b.is_ascii_hexdigit())
		|| meta.classification_source.is_empty()
		|| meta.classification_source.len() > 256
		|| meta.labels.len() > 64
		|| meta.labels.iter().any(|v| v.len() > 256)
		|| meta.labels.iter().map(String::len).sum::<usize>() > 4096
	{
		return Err("invalid document lifecycle metadata".into());
	}
	Ok(())
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
	Header {
		namespace: String,
		capacity: usize,
		authority: String,
	},
	Put {
		metadata: DocumentMetadata,
	},
	Checkpoint,
}
struct State {
	journal: StateJournal,
	records: HashMap<DocumentKey, DocumentMetadata>,
	sequence: u64,
	highwater: i64,
	healthy: bool,
}
impl State {
	fn check(&mut self) -> Result<i64, String> {
		let now = chrono::Utc::now().timestamp_millis();
		if !self.healthy || now < self.highwater || self.journal.check().is_err() {
			self.healthy = false;
			return Err("document authority unavailable".into());
		}
		Ok(now)
	}
	fn commit(&mut self, change: Change) -> Result<(), String> {
		let millis = self.check()?;
		let sequence = self
			.sequence
			.checked_add(1)
			.ok_or("document sequence exhausted")?;
		if self
			.journal
			.append(&Event {
				version: 1,
				sequence,
				millis,
				change,
			})
			.is_err()
		{
			self.healthy = false;
			return Err("document authority commit failed".into());
		}
		self.sequence = sequence;
		self.highwater = millis;
		Ok(())
	}
	fn put(&mut self, meta: DocumentMetadata) -> Result<(), String> {
		validate_metadata(&meta)?;
		self.commit(Change::Put {
			metadata: meta.clone(),
		})?;
		self.records.insert(meta.key.clone(), meta);
		Ok(())
	}
}
pub struct DocumentLifecycleStore {
	config: DocumentLifecycleConfig,
	authority: String,
	state: Mutex<State>,
}
type Registry = HashMap<std::path::PathBuf, Weak<DocumentLifecycleStore>>;
static STORES: OnceLock<Mutex<Registry>> = OnceLock::new();
impl DocumentLifecycleStore {
	pub fn open(config: DocumentLifecycleConfig) -> Result<Arc<Self>, String> {
		config.validate()?;
		let path = config.storage.canonical_path().map_err(|e| e.to_string())?;
		let mut registry = STORES
			.get_or_init(Default::default)
			.lock()
			.map_err(|_| "document registry unavailable")?;
		registry.retain(|_, v| v.strong_count() > 0);
		if let Some(existing) = registry.get(&path).and_then(Weak::upgrade) {
			if existing.config != config {
				return Err("document journal already open with another declaration".into());
			}
			existing
				.state
				.lock()
				.map_err(|_| "document authority unavailable")?
				.check()?;
			return Ok(existing);
		}
		let mut sequence = 0_u64;
		let mut highwater = 0;
		let mut authority = uuid::Uuid::new_v4().to_string();
		let now = chrono::Utc::now().timestamp_millis();
		let mut records: HashMap<DocumentKey, DocumentMetadata> = HashMap::new();
		let journal = StateJournal::open::<Event>(&config.storage, |event| {
			let invalid = || std::io::Error::other("invalid document journal transition/version/clock");
			if event.version != 1
				|| Some(event.sequence) != sequence.checked_add(1)
				|| event.millis < highwater
				|| event.millis > now
			{
				return Err(invalid());
			}
			match event.change {
				Change::Header {
					namespace,
					capacity,
					authority: found,
				} if sequence == 0
					&& namespace == config.namespace
					&& capacity == config.max_documents
					&& uuid::Uuid::parse_str(&found).is_ok() =>
				{
					authority = found;
				},
				Change::Checkpoint if sequence > 0 => {},
				Change::Put { metadata } if sequence > 0 => {
					validate_metadata(&metadata).map_err(std::io::Error::other)?;
					if metadata.authority != authority {
						return Err(invalid());
					}
					if let Some(old) = records.get(&metadata.key) {
						validate_transition(old, &metadata).map_err(std::io::Error::other)?;
					} else if metadata.revision != 1
						|| metadata.version != 1
						|| metadata.state != DocumentState::Pending
					{
						return Err(invalid());
					}
					records.insert(metadata.key.clone(), metadata);
					if records.len() > config.max_documents {
						return Err(invalid());
					}
				},
				_ => return Err(invalid()),
			}
			sequence = event.sequence;
			highwater = event.millis;
			Ok(())
		})
		.map_err(|e| format!("cannot open document authority: {e}"))?;
		let fresh = journal.is_fresh();
		let mut state = State {
			journal,
			records,
			sequence,
			highwater,
			healthy: true,
		};
		state.commit(if fresh {
			Change::Header {
				namespace: config.namespace.clone(),
				capacity: config.max_documents,
				authority: authority.clone(),
			}
		} else {
			Change::Checkpoint
		})?;
		let store = Arc::new(Self {
			config,
			authority,
			state: Mutex::new(state),
		});
		registry.insert(path, Arc::downgrade(&store));
		Ok(store)
	}
	pub fn get(&self, key: &DocumentKey) -> Result<DocumentMetadata, String> {
		key.validate()?;
		let mut state = self
			.state
			.lock()
			.map_err(|_| "document authority unavailable")?;
		state.check()?;
		let result = state.records.get(key).cloned().ok_or("unknown document")?;
		state.commit(Change::Checkpoint)?;
		Ok(result)
	}
	pub fn begin_index(
		&self,
		document: &IndexedDocument,
		access: TrustedChunkAccess,
	) -> Result<DocumentMetadata, String> {
		if matches!(document.source_origin, SourceOrigin::Lifecycle { .. }) {
			return Err("nested lifecycle origin rejected".into());
		}
		let key = DocumentKey {
			tenant_id: document.tenant_id.clone(),
			corpus_id: document.corpus_id.clone(),
			document_id: document.document_id.clone(),
		};
		key.validate()?;
		let mut state = self
			.state
			.lock()
			.map_err(|_| "document authority unavailable")?;
		state.check()?;
		let revision = match state.records.get(&key) {
			Some(old) if matches!(old.state, DocumentState::Revoked | DocumentState::Deleted) => {
				return Err("withdrawn document cannot be resurrected by ingestion".into());
			},
			Some(old) => old
				.revision
				.checked_add(1)
				.ok_or("document revision exhausted")?,
			None if state.records.len() >= self.config.max_documents => {
				return Err("document authority capacity exhausted".into());
			},
			None => 1,
		};
		let meta = DocumentMetadata {
			authority: self.authority.clone(),
			key,
			revision,
			version: revision,
			state: DocumentState::Pending,
			source_hash: document.source_hash.clone(),
			classification: document.classification,
			classification_source: document.classification_source.clone(),
			labels: document.labels.clone(),
			access,
		};
		state.put(meta.clone())?;
		Ok(meta)
	}
	pub fn activate(&self, key: &DocumentKey, revision: u64) -> Result<(), String> {
		let mut state = self
			.state
			.lock()
			.map_err(|_| "document authority unavailable")?;
		state.check()?;
		let mut meta = state.records.get(key).cloned().ok_or("unknown document")?;
		if meta.revision != revision || meta.state != DocumentState::Pending {
			return Err("stale document activation".into());
		}
		meta.state = DocumentState::Active;
		state.put(meta)
	}
	pub fn mutate(
		&self,
		key: &DocumentKey,
		expected_revision: u64,
		mutation: DocumentMutation,
	) -> Result<DocumentMetadata, String> {
		key.validate()?;
		let mut state = self
			.state
			.lock()
			.map_err(|_| "document authority unavailable")?;
		state.check()?;
		let mut meta = state.records.get(key).cloned().ok_or("unknown document")?;
		if meta.revision != expected_revision {
			return Err("document revision conflict".into());
		}
		match mutation {
			DocumentMutation::Acl { access } if meta.state == DocumentState::Active => {
				validate_access(&access)?;
				meta.access = access;
			},
			DocumentMutation::Revoke if !matches!(meta.state, DocumentState::Deleted) => {
				meta.state = DocumentState::Revoked
			},
			DocumentMutation::Delete => meta.state = DocumentState::Deleted,
			_ => return Err("document operation not allowed in current state".into()),
		}
		meta.revision = meta
			.revision
			.checked_add(1)
			.ok_or("document revision exhausted")?;
		state.put(meta.clone())?;
		Ok(meta)
	}
	pub fn check_chunk(
		&self,
		chunk: &KnowledgeChunk,
		subject: &Subject,
	) -> Result<KnowledgeChunk, String> {
		let SourceOrigin::Lifecycle {
			authority,
			version,
			origin,
			..
		} = &chunk.source_origin
		else {
			return Err("unversioned index entry".into());
		};
		let key = DocumentKey {
			tenant_id: chunk.tenant_id.clone(),
			corpus_id: chunk.corpus_id.clone(),
			document_id: chunk.document_id.clone(),
		};
		let meta = self.get(&key)?;
		check_access(&meta, subject)?;
		if *authority != meta.authority
			|| *version != meta.version
			|| chunk.source_hash != meta.source_hash
		{
			return Err("stale document content version".into());
		}
		let mut chunk = chunk.clone();
		chunk.allowed_users = meta.access.allowed_users.clone();
		chunk.allowed_agents = meta.access.allowed_agents.clone();
		chunk.allow_tenant_authenticated = meta.access.allow_tenant_authenticated;
		chunk.expires_at = meta.access.expires_at;
		chunk.classification = meta.classification;
		chunk.classification_source = meta.classification_source;
		chunk.labels = meta.labels;
		chunk.source_origin = SourceOrigin::Lifecycle {
			authority: meta.authority,
			version: *version,
			revision: meta.revision,
			origin: origin.clone(),
		};
		Ok(chunk)
	}
}
fn validate_transition(old: &DocumentMetadata, new: &DocumentMetadata) -> Result<(), String> {
	let mut activated = old.clone();
	activated.state = DocumentState::Active;
	if old.state == DocumentState::Pending && *new == activated {
		return Ok(());
	}
	if Some(new.revision) != old.revision.checked_add(1)
		|| old.state == DocumentState::Deleted && new.state != DocumentState::Deleted
		|| old.state == DocumentState::Revoked
			&& !matches!(new.state, DocumentState::Revoked | DocumentState::Deleted)
	{
		return Err("document state/revision regression".into());
	}
	if new.state == DocumentState::Pending {
		if new.version != new.revision {
			return Err("invalid new content version".into());
		}
	} else {
		let mut expected = old.clone();
		expected.revision = new.revision;
		expected.state = new.state;
		expected.access = new.access.clone();
		if *new != expected || new.state == DocumentState::Active && old.state != DocumentState::Active
		{
			return Err("invalid metadata transition".into());
		}
	}
	Ok(())
}
fn check_access(meta: &DocumentMetadata, subject: &Subject) -> Result<(), String> {
	if meta.state != DocumentState::Active
		|| subject.tenant_id.as_deref() != Some(meta.key.tenant_id.as_str())
		|| meta
			.access
			.expires_at
			.is_some_and(|t| t <= chrono::Utc::now())
		|| !(subject
			.user_id
			.as_ref()
			.is_some_and(|id| meta.access.allowed_users.contains(id))
			|| subject
				.agent_id
				.as_ref()
				.is_some_and(|id| meta.access.allowed_agents.contains(id))
			|| meta.access.allow_tenant_authenticated
				&& (subject.user_id.is_some() || subject.agent_id.is_some()))
	{
		return Err("document version or ACL denied".into());
	}
	Ok(())
}
impl DocumentVersionValidator for DocumentLifecycleStore {
	fn authority_id(&self) -> Option<&str> {
		Some(&self.authority)
	}
	fn validate_documents(
		&self,
		subject: &Subject,
		documents: &[DocumentVersion],
	) -> Result<(), String> {
		let mut state = self
			.state
			.lock()
			.map_err(|_| "document authority unavailable")?;
		state.check()?;
		for reference in documents {
			let meta = state
				.records
				.get(&reference.key)
				.ok_or("unknown document")?;
			check_access(meta, subject)?;
			if meta.authority != reference.authority || meta.revision != reference.revision {
				return Err("document security revision changed".into());
			}
		}
		state.commit(Change::Checkpoint)
	}
}
pub fn document_reference(chunk: &KnowledgeChunk) -> Option<DocumentVersion> {
	let SourceOrigin::Lifecycle {
		authority,
		revision,
		..
	} = &chunk.source_origin
	else {
		return None;
	};
	Some(DocumentVersion {
		authority: authority.clone(),
		key: DocumentKey {
			tenant_id: chunk.tenant_id.clone(),
			corpus_id: chunk.corpus_id.clone(),
			document_id: chunk.document_id.clone(),
		},
		revision: *revision,
	})
}

#[async_trait::async_trait]
pub trait DocumentPurger: Send + Sync {
	async fn purge_document(&self, key: &DocumentKey) -> Result<(), String>;
}
#[async_trait::async_trait]
impl<T: DocumentPurger + ?Sized> DocumentPurger for Arc<T> {
	async fn purge_document(&self, key: &DocumentKey) -> Result<(), String> {
		(**self).purge_document(key).await
	}
}
pub struct LifecycleBackend<B> {
	pub backend: B,
	pub store: Option<Arc<DocumentLifecycleStore>>,
	pub default_access: TrustedChunkAccess,
}

#[async_trait::async_trait]
impl<B: DocumentIngestBackend> DocumentIngestBackend for LifecycleBackend<B> {
	async fn index(&self, mut document: IndexedDocument) -> Result<(), String> {
		let Some(store) = &self.store else {
			return self.backend.index(document).await;
		};
		let meta = store.begin_index(&document, self.default_access.clone())?;
		document.source_origin = SourceOrigin::Lifecycle {
			authority: meta.authority,
			version: meta.version,
			revision: meta.revision,
			origin: Box::new(document.source_origin),
		};
		self.backend.index(document).await?;
		store.activate(&meta.key, meta.revision)
	}
	async fn quarantine(&self, document: QuarantinedDocument) -> Result<(), String> {
		if let Some(store) = &self.store {
			store.begin_index(&document.document, self.default_access.clone())?;
		}
		self.backend.quarantine(document).await
	}
}
#[async_trait::async_trait]
impl<B: RetrievalBackend> RetrievalBackend for LifecycleBackend<B> {
	async fn retrieve(
		&self,
		query: &RetrievalQuery,
		filter: &RetrievalFilter,
	) -> Result<Vec<KnowledgeChunk>, String> {
		let mut filter = filter.clone();
		if self.store.is_some() {
			filter.authoritative_acl = true;
		}
		let chunks = self.backend.retrieve(query, &filter).await?;
		let Some(store) = &self.store else {
			return Ok(chunks);
		};
		let subject = Subject {
			tenant_id: Some(filter.tenant_id),
			user_id: filter.user_id,
			agent_id: filter.agent_id,
			delegation_id: None,
		};
		// Authority failure rejects the entire request, not an empty successful context.
		store
			.state
			.lock()
			.map_err(|_| "document authority unavailable")?
			.check()?;
		let accepted = chunks
			.iter()
			.filter_map(|chunk| store.check_chunk(chunk, &subject).ok())
			.collect();
		store
			.state
			.lock()
			.map_err(|_| "document authority unavailable")?
			.check()?;
		Ok(accepted)
	}
}
