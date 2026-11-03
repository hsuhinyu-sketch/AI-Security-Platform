//! Optional transactional Context + document state. Async embedding API; no execution grants.
//! A file belongs to one deployment namespace. JSONL is never imported or overwritten here.
mod files;
use crate::context_store::{
	ContextBinding, ContextError, Snapshot, validate_binding, validate_namespace,
	validate_references, validate_snapshot,
};
use files::Files;
use security_rag::{
	IndexedDocument, KnowledgeChunk, TrustedChunkAccess,
	lifecycle::{DocumentMetadata, DocumentMutation},
};
use security_types::{DataClassification, DocumentKey, DocumentVersion, Subject};
use sqlx::{
	Connection, Row, Sqlite, SqliteConnection, Transaction,
	sqlite::{SqliteConnectOptions, SqliteSynchronous},
};
use std::{
	collections::HashMap,
	path::PathBuf,
	time::{Duration, Instant},
};

const APPLICATION: i64 = 0x41535052;
const WAL_RECLAIM_BYTES: u64 = 1_048_576;

/// Explicit Rust configuration until Host selection and JSONL migration are implemented.
/// max_database_bytes limits database pages, not total disk usage. WAL reclamation is separate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SqliteRagConfig {
	pub path: PathBuf,
	pub namespace: String,
	pub max_documents: usize,
	pub max_contexts: usize,
	pub max_database_bytes: u64,
	pub busy_timeout_millis: u64,
}
impl SqliteRagConfig {
	pub fn validate(&self) -> Result<(), String> {
		validate_namespace(&self.namespace)?;
		if !self.path.is_absolute()
			|| self.path.file_name().is_none()
			|| !(1..=4096).contains(&self.max_documents)
			|| !(1..=16384).contains(&self.max_contexts)
			|| !(1_048_576..=67_108_864).contains(&self.max_database_bytes)
			|| !(1..=5000).contains(&self.busy_timeout_millis)
		{
			return Err("invalid SQLite RAG path/capacity/busy timeout".into());
		}
		Ok(())
	}
}
pub struct SqliteRagStore {
	config: SqliteRagConfig,
	authority: String,
	db: tokio::sync::Mutex<Db>,
}
struct Db {
	connection: SqliteConnection,
	deadlines: HashMap<String, Instant>,
	healthy: bool,
	files: Files,
}
fn unavailable<E>(_: E) -> ContextError {
	ContextError::Unavailable
}
fn denied<E>(_: E) -> ContextError {
	ContextError::Denied
}
impl SqliteRagStore {
	pub fn authority_id(&self) -> &str {
		&self.authority
	}
	pub async fn open(config: SqliteRagConfig) -> Result<Self, String> {
		config.validate()?;
		let path = config.path.clone();
		let files = tokio::task::spawn_blocking(move || Files::open(&path))
			.await
			.map_err(|_| "SQLite file preparation unavailable")??;
		let options = SqliteConnectOptions::new()
			.filename(&files.path)
			.create_if_missing(false)
			.synchronous(SqliteSynchronous::Full)
			.busy_timeout(Duration::from_millis(config.busy_timeout_millis));
		let mut connection = SqliteConnection::connect_with(&options)
			.await
			.map_err(|_| "cannot open RAG SQLite database")?;
		// Identify existing files before changing their journal mode or schema.
		let app: i64 = sqlx::query_scalar("PRAGMA application_id")
			.fetch_one(&mut connection)
			.await
			.map_err(|_| "invalid SQLite database")?;
		let version: i64 = sqlx::query_scalar("PRAGMA user_version")
			.fetch_one(&mut connection)
			.await
			.map_err(|_| "invalid SQLite database")?;
		if !files.fresh && (app != APPLICATION || version != 1) {
			return Err("unrecognized RAG SQLite database/version; explicit migration required".into());
		}
		let integrity: String = sqlx::query_scalar("PRAGMA quick_check")
			.fetch_one(&mut connection)
			.await
			.map_err(|_| "SQLite integrity check failed")?;
		if integrity != "ok" {
			return Err("SQLite integrity check failed".into());
		}
		let page_size: i64 = sqlx::query_scalar("PRAGMA page_size")
			.fetch_one(&mut connection)
			.await
			.map_err(|_| "SQLite page size unavailable")?;
		if page_size <= 0 {
			return Err("invalid SQLite page size".into());
		}
		let max_pages = config.max_database_bytes / page_size as u64;
		let actual: i64 = sqlx::query_scalar(sqlx::AssertSqlSafe(format!(
			"PRAGMA max_page_count={max_pages}"
		)))
		.fetch_one(&mut connection)
		.await
		.map_err(|_| "cannot set database page limit")?;
		if actual != max_pages as i64 {
			return Err("SQLite database exceeds configured page budget".into());
		}
		let mode: String = sqlx::query_scalar("PRAGMA journal_mode=WAL")
			.fetch_one(&mut connection)
			.await
			.map_err(|_| "cannot enable WAL")?;
		if mode != "wal" {
			return Err("SQLite WAL unavailable".into());
		}
		sqlx::raw_sql("PRAGMA wal_autocheckpoint=64; PRAGMA journal_size_limit=262144;")
			.execute(&mut connection)
			.await
			.map_err(|_| "cannot configure WAL reclamation")?;
		let mut tx = connection
			.begin_with("BEGIN IMMEDIATE")
			.await
			.map_err(|_| "SQLite recovery busy/unavailable")?;
		if files.fresh {
			sqlx::raw_sql(include_str!("rag_sqlite/schema.sql"))
				.execute(&mut *tx)
				.await
				.map_err(|_| "cannot initialize RAG schema")?;
			sqlx::query("INSERT INTO asp_rag_meta VALUES(1,?,?,?,?,?,?)")
				.bind(&config.namespace)
				.bind(uuid::Uuid::new_v4().to_string())
				.bind(config.max_documents as i64)
				.bind(config.max_contexts as i64)
				.bind(config.max_database_bytes as i64)
				.bind(chrono::Utc::now().timestamp_millis())
				.execute(&mut *tx)
				.await
				.map_err(|_| "cannot initialize RAG metadata")?;
		}
		let (authority, deadlines) = recover(&mut tx, &config).await?;
		let now = chrono::Utc::now().timestamp_millis();
		sqlx::query("DELETE FROM asp_rag_contexts WHERE expires_ms<=?")
			.bind(now)
			.execute(&mut *tx)
			.await
			.map_err(|_| "cannot prune recovered contexts")?;
		let water = commit(tx).await.map_err(|_| "cannot commit RAG recovery")?;
		if chrono::Utc::now().timestamp_millis() < water {
			return Err("RAG clock moved backwards during recovery".into());
		}
		let files = tokio::task::spawn_blocking(move || files.seal())
			.await
			.map_err(|_| "SQLite directory sync unavailable")??;
		Ok(Self {
			config,
			authority,
			db: tokio::sync::Mutex::new(Db {
				connection,
				deadlines,
				healthy: true,
				files,
			}),
		})
	}
	/// Stop operations before releasing the file owner. Cancellation can leave an unknown commit;
	/// the next opener obtains BEGIN IMMEDIATE before validating recovered rows.
	pub async fn close(self) -> Result<(), ContextError> {
		let Db {
			connection, files, ..
		} = self.db.into_inner();
		let result = connection.close().await.map_err(unavailable);
		drop(files);
		result
	}
	pub async fn begin_index(
		&self,
		document: &IndexedDocument,
		access: TrustedChunkAccess,
	) -> Result<DocumentMetadata, ContextError> {
		let key = DocumentKey {
			tenant_id: document.tenant_id.clone(),
			corpus_id: document.corpus_id.clone(),
			document_id: document.document_id.clone(),
		};
		key.validate().map_err(denied)?;
		let mut db = self.db.lock().await;
		let result = async {
			let mut tx = db.begin().await?;
			let old = read_document(&mut tx, &key).await?;
			if old.is_none()
				&& count(&mut tx, "asp_rag_documents").await? >= self.config.max_documents as i64
			{
				return Err(ContextError::Capacity);
			}
			let meta = DocumentMetadata::begin_index(&self.authority, document, access, old.as_ref())
				.map_err(denied)?;
			put_document(&mut tx, &meta).await?;
			let committed = commit(tx).await;
			db.after_commit(committed).await?;
			Ok(meta)
		}
		.await;
		db.complete(result)
	}
	pub async fn activate(&self, key: &DocumentKey, revision: u64) -> Result<(), ContextError> {
		key.validate().map_err(denied)?;
		let mut db = self.db.lock().await;
		let result = async {
			let mut tx = db.begin().await?;
			let meta = read_document(&mut tx, key)
				.await?
				.ok_or(ContextError::Denied)?
				.activate(revision)
				.map_err(denied)?;
			put_document(&mut tx, &meta).await?;
			let committed = commit(tx).await;
			db.after_commit(committed).await
		}
		.await;
		db.complete(result)
	}
	pub async fn mutate(
		&self,
		key: &DocumentKey,
		expected_revision: u64,
		mutation: DocumentMutation,
	) -> Result<DocumentMetadata, ContextError> {
		key.validate().map_err(denied)?;
		let mut db = self.db.lock().await;
		let result = async {
			let mut tx = db.begin().await?;
			let meta = read_document(&mut tx, key)
				.await?
				.ok_or(ContextError::Denied)?
				.mutate(expected_revision, mutation)
				.map_err(denied)?;
			put_document(&mut tx, &meta).await?;
			let committed = commit(tx).await;
			db.after_commit(committed).await?;
			Ok(meta)
		}
		.await;
		db.complete(result)
	}
	pub async fn get_document(&self, key: &DocumentKey) -> Result<DocumentMetadata, ContextError> {
		key.validate().map_err(denied)?;
		let mut db = self.db.lock().await;
		let result = async {
			let mut tx = db.begin().await?;
			let meta = read_document(&mut tx, key)
				.await?
				.ok_or(ContextError::Denied)?;
			let committed = commit(tx).await;
			db.after_commit(committed).await?;
			Ok(meta)
		}
		.await;
		db.complete(result)
	}
	pub async fn filter_chunks(
		&self,
		chunks: &[KnowledgeChunk],
		subject: &Subject,
	) -> Result<Vec<KnowledgeChunk>, ContextError> {
		let mut db = self.db.lock().await;
		let result = async {
			let mut tx = db.begin().await?;
			let mut accepted = Vec::new();
			for chunk in chunks {
				let key = DocumentKey {
					tenant_id: chunk.tenant_id.clone(),
					corpus_id: chunk.corpus_id.clone(),
					document_id: chunk.document_id.clone(),
				};
				if key.validate().is_err() {
					continue;
				}
				if let Some(meta) = read_document(&mut tx, &key).await? {
					if let Ok(chunk) = meta.check_chunk(chunk, subject) {
						accepted.push(chunk);
					}
				}
			}
			let committed = commit(tx).await;
			db.after_commit(committed).await?;
			// ACL expiry can pass while the durable commit is in flight.
			accepted.retain(|chunk| {
				chunk
					.expires_at
					.is_none_or(|expires| expires > chrono::Utc::now())
			});
			Ok(accepted)
		}
		.await;
		db.complete(result)
	}
	pub async fn issue_documents(
		&self,
		binding: ContextBinding,
		ttl_seconds: u64,
		classification: DataClassification,
		mut documents: Vec<DocumentVersion>,
	) -> Result<String, ContextError> {
		validate_binding(&binding).map_err(denied)?;
		validate_references(&documents)?;
		if binding.namespace != self.config.namespace || !(1..=86400).contains(&ttl_seconds) {
			return Err(ContextError::Denied);
		}
		documents.sort();
		documents.dedup();
		let mut db = self.db.lock().await;
		let result = async {
			let live: std::collections::HashSet<_> = db
				.deadlines
				.iter()
				.filter(|(_, deadline)| Instant::now() < **deadline)
				.map(|(id, _)| id.clone())
				.collect();
			let mut tx = db.begin().await?;
			// A cancelled issuance may have committed without installing its in-memory deadline.
			let ids: Vec<String> = sqlx::query_scalar("SELECT id FROM asp_rag_contexts")
				.fetch_all(&mut *tx)
				.await
				.map_err(unavailable)?;
			for id in ids {
				if !live.contains(&id) {
					sqlx::query("DELETE FROM asp_rag_contexts WHERE id=?")
						.bind(id)
						.execute(&mut *tx)
						.await
						.map_err(unavailable)?;
				}
			}
			if count(&mut tx, "asp_rag_contexts").await? >= self.config.max_contexts as i64 {
				return Err(ContextError::Capacity);
			}
			let now = chrono::Utc::now().timestamp_millis();
			let id = uuid::Uuid::new_v4().to_string();
			let deadline = Instant::now() + Duration::from_secs(ttl_seconds);
			let snapshot = Snapshot {
				id: id.clone(),
				binding,
				document_authority: Some(self.authority.clone()),
				documents,
				created_ms: now,
				expires_ms: now
					.checked_add(ttl_seconds as i64 * 1000)
					.ok_or(ContextError::Denied)?,
				ttl_seconds,
				classification,
				revoked: false,
			};
			let expiry = check_documents(&mut tx, &snapshot).await?;
			put_context(&mut tx, &snapshot).await?;
			let committed = commit(tx).await;
			db.after_commit(committed).await?;
			db.deadlines.retain(|_, d| Instant::now() < *d);
			db.deadlines.insert(id.clone(), deadline);
			if Instant::now() >= deadline {
				return Err(ContextError::Denied);
			}
			check_expiry(expiry)?;
			Ok(id)
		}
		.await;
		db.complete(result)
	}
	pub async fn classification(
		&self,
		id: &str,
		binding: &ContextBinding,
	) -> Result<DataClassification, ContextError> {
		let mut db = self.db.lock().await;
		let result = async {
			db.live(id)?;
			let mut tx = db.begin().await?;
			let snapshot = read_context(&mut tx, id, binding, false).await?;
			let expiry = check_documents(&mut tx, &snapshot).await?;
			let committed = commit(tx).await;
			db.after_commit(committed).await?;
			db.live(id)?;
			check_expiry(expiry)?;
			Ok(snapshot.classification)
		}
		.await;
		db.complete(result)
	}
	pub async fn elevate_documents(
		&self,
		id: &str,
		binding: &ContextBinding,
		class: DataClassification,
		documents: Vec<DocumentVersion>,
	) -> Result<(), ContextError> {
		validate_references(&documents)?;
		let mut db = self.db.lock().await;
		let result = async {
			db.live(id)?;
			let mut tx = db.begin().await?;
			let mut snapshot = read_context(&mut tx, id, binding, false).await?;
			snapshot.documents.extend(documents);
			snapshot.documents.sort();
			snapshot.documents.dedup();
			validate_references(&snapshot.documents)?;
			let expiry = check_documents(&mut tx, &snapshot).await?;
			snapshot.classification = snapshot.classification.max(class);
			put_context(&mut tx, &snapshot).await?;
			let committed = commit(tx).await;
			db.after_commit(committed).await?;
			db.live(id)?;
			check_expiry(expiry)
		}
		.await;
		db.complete(result)
	}
	pub async fn revoke(&self, id: &str, binding: &ContextBinding) -> Result<(), ContextError> {
		let mut db = self.db.lock().await;
		let result = async {
			db.live(id)?;
			let mut tx = db.begin().await?;
			let mut snapshot = read_context(&mut tx, id, binding, true).await?;
			snapshot.revoked = true;
			put_context(&mut tx, &snapshot).await?;
			let committed = commit(tx).await;
			db.after_commit(committed).await
		}
		.await;
		db.complete(result)
	}
}

impl Db {
	async fn begin(&mut self) -> Result<Transaction<'_, Sqlite>, ContextError> {
		if !self.healthy {
			return Err(ContextError::Unavailable);
		}
		self.files.check().map_err(unavailable)?;
		let mut tx = self
			.connection
			.begin_with("BEGIN IMMEDIATE")
			.await
			.map_err(unavailable)?;
		let water: i64 = sqlx::query_scalar("SELECT highwater FROM asp_rag_meta WHERE id=1")
			.fetch_one(&mut *tx)
			.await
			.map_err(unavailable)?;
		if water <= 0 || chrono::Utc::now().timestamp_millis() < water {
			return Err(ContextError::Unavailable);
		}
		Ok(tx)
	}
	async fn after_commit(
		&mut self,
		committed: Result<i64, ContextError>,
	) -> Result<(), ContextError> {
		let water = committed?;
		let wal = std::fs::metadata(self.files.sidecar("-wal"))
			.map_err(unavailable)?
			.len();
		if wal > WAL_RECLAIM_BYTES {
			let result = sqlx::query("PRAGMA wal_checkpoint(TRUNCATE)")
				.fetch_one(&mut self.connection)
				.await
				.map_err(unavailable)?;
			if result.get::<i64, _>(0) != 0 {
				return Err(ContextError::Unavailable);
			}
		}
		self.files.check().map_err(unavailable)?;
		if chrono::Utc::now().timestamp_millis() < water {
			return Err(ContextError::Unavailable);
		}
		Ok(())
	}
	fn complete<T>(&mut self, result: Result<T, ContextError>) -> Result<T, ContextError> {
		if matches!(result, Err(ContextError::Unavailable)) {
			self.healthy = false;
		}
		result
	}
	fn live(&self, id: &str) -> Result<(), ContextError> {
		if !self.healthy {
			return Err(ContextError::Unavailable);
		}
		if self.deadlines.get(id).is_none_or(|d| Instant::now() >= *d) {
			return Err(ContextError::Denied);
		}
		Ok(())
	}
}
async fn commit(mut tx: Transaction<'_, Sqlite>) -> Result<i64, ContextError> {
	let water: i64 = sqlx::query_scalar("SELECT highwater FROM asp_rag_meta WHERE id=1")
		.fetch_one(&mut *tx)
		.await
		.map_err(unavailable)?;
	let now = chrono::Utc::now().timestamp_millis();
	if now < water {
		return Err(ContextError::Unavailable);
	}
	sqlx::query("UPDATE asp_rag_meta SET highwater=? WHERE id=1")
		.bind(now)
		.execute(&mut *tx)
		.await
		.map_err(unavailable)?;
	tx.commit().await.map_err(unavailable)?;
	Ok(now)
}
async fn count(tx: &mut Transaction<'_, Sqlite>, table: &str) -> Result<i64, ContextError> {
	// Private call sites select only static schema table names.
	sqlx::query_scalar(match table {
		"asp_rag_documents" => "SELECT COUNT(*) FROM asp_rag_documents",
		"asp_rag_contexts" => "SELECT COUNT(*) FROM asp_rag_contexts",
		"asp_rag_meta" => "SELECT COUNT(*) FROM asp_rag_meta",
		_ => return Err(ContextError::Unavailable),
	})
	.fetch_one(&mut **tx)
	.await
	.map_err(unavailable)
}
async fn read_document(
	tx: &mut Transaction<'_, Sqlite>,
	key: &DocumentKey,
) -> Result<Option<DocumentMetadata>, ContextError> {
	let raw: Option<String> = sqlx::query_scalar(
		"SELECT metadata FROM asp_rag_documents WHERE tenant=? AND corpus=? AND document=?",
	)
	.bind(&key.tenant_id)
	.bind(&key.corpus_id)
	.bind(&key.document_id)
	.fetch_optional(&mut **tx)
	.await
	.map_err(unavailable)?;
	raw
		.map(|raw| {
			let meta: DocumentMetadata = serde_json::from_str(&raw).map_err(unavailable)?;
			meta.validate().map_err(unavailable)?;
			if meta.key != *key {
				return Err(ContextError::Unavailable);
			}
			Ok(meta)
		})
		.transpose()
}
async fn put_document(
	tx: &mut Transaction<'_, Sqlite>,
	meta: &DocumentMetadata,
) -> Result<(), ContextError> {
	let raw = serde_json::to_string(meta).map_err(unavailable)?;
	sqlx::query("INSERT INTO asp_rag_documents VALUES(?,?,?,?) ON CONFLICT(tenant,corpus,document) DO UPDATE SET metadata=excluded.metadata")
		.bind(&meta.key.tenant_id).bind(&meta.key.corpus_id).bind(&meta.key.document_id).bind(raw).execute(&mut **tx).await.map_err(unavailable)?;
	Ok(())
}
async fn read_context(
	tx: &mut Transaction<'_, Sqlite>,
	id: &str,
	binding: &ContextBinding,
	allow_revoked: bool,
) -> Result<Snapshot, ContextError> {
	let raw: Option<String> = sqlx::query_scalar("SELECT snapshot FROM asp_rag_contexts WHERE id=?")
		.bind(id)
		.fetch_optional(&mut **tx)
		.await
		.map_err(unavailable)?;
	let snapshot: Snapshot =
		serde_json::from_str(&raw.ok_or(ContextError::Denied)?).map_err(unavailable)?;
	if snapshot.binding != *binding || (!allow_revoked && snapshot.revoked) {
		return Err(ContextError::Denied);
	}
	validate_snapshot(&snapshot, &binding.namespace).map_err(unavailable)?;
	if snapshot.id != id {
		return Err(ContextError::Unavailable);
	}
	Ok(snapshot)
}
async fn put_context(
	tx: &mut Transaction<'_, Sqlite>,
	snapshot: &Snapshot,
) -> Result<(), ContextError> {
	let raw = serde_json::to_string(snapshot).map_err(unavailable)?;
	sqlx::query("INSERT INTO asp_rag_contexts VALUES(?,?,?) ON CONFLICT(id) DO UPDATE SET snapshot=excluded.snapshot")
		.bind(&snapshot.id).bind(snapshot.expires_ms).bind(raw).execute(&mut **tx).await.map_err(unavailable)?;
	Ok(())
}
async fn check_documents(
	tx: &mut Transaction<'_, Sqlite>,
	snapshot: &Snapshot,
) -> Result<Option<chrono::DateTime<chrono::Utc>>, ContextError> {
	let mut expiry = None;
	for reference in &snapshot.documents {
		let meta = read_document(tx, &reference.key)
			.await?
			.ok_or(ContextError::Denied)?;
		if snapshot.document_authority.as_deref() != Some(meta.authority.as_str()) {
			return Err(ContextError::Denied);
		}
		meta
			.check_reference(&snapshot.binding.owner.identity().into(), reference)
			.map_err(denied)?;
		if let Some(deadline) = meta.access.expires_at {
			expiry = Some(
				expiry.map_or(deadline, |previous: chrono::DateTime<chrono::Utc>| {
					previous.min(deadline)
				}),
			);
		}
	}
	Ok(expiry)
}
fn check_expiry(expiry: Option<chrono::DateTime<chrono::Utc>>) -> Result<(), ContextError> {
	if expiry.is_some_and(|deadline| deadline <= chrono::Utc::now()) {
		return Err(ContextError::Denied);
	}
	Ok(())
}
async fn recover(
	tx: &mut Transaction<'_, Sqlite>,
	config: &SqliteRagConfig,
) -> Result<(String, HashMap<String, Instant>), String> {
	if count(tx, "asp_rag_meta")
		.await
		.map_err(|_| "invalid RAG metadata")?
		!= 1
	{
		return Err("invalid RAG header count".into());
	}
	let row = sqlx::query("SELECT namespace,authority,max_documents,max_contexts,max_database_bytes,highwater FROM asp_rag_meta WHERE id=1").fetch_one(&mut **tx).await.map_err(|_| "incompatible RAG metadata schema")?;
	let authority: String = row
		.try_get("authority")
		.map_err(|_| "invalid RAG authority")?;
	let water: i64 = row.try_get("highwater").map_err(|_| "invalid time water")?;
	let now = chrono::Utc::now().timestamp_millis();
	let instant = Instant::now();
	if row
		.try_get::<String, _>("namespace")
		.map_err(|_| "invalid namespace")?
		!= config.namespace
		|| row
			.try_get::<i64, _>("max_documents")
			.map_err(|_| "invalid document limit")?
			!= config.max_documents as i64
		|| row
			.try_get::<i64, _>("max_contexts")
			.map_err(|_| "invalid context limit")?
			!= config.max_contexts as i64
		|| row
			.try_get::<i64, _>("max_database_bytes")
			.map_err(|_| "invalid database budget")?
			!= config.max_database_bytes as i64
		|| uuid::Uuid::parse_str(&authority).is_err()
		|| water <= 0
		|| now < water
	{
		return Err("RAG declaration/authority/clock mismatch".into());
	}
	for (table, limit, column) in [
		("asp_rag_documents", config.max_documents, "metadata"),
		("asp_rag_contexts", config.max_contexts, "snapshot"),
	] {
		if count(tx, table)
			.await
			.map_err(|_| "incompatible RAG schema")?
			> limit as i64
		{
			return Err("RAG state exceeds row limit".into());
		}
		let length: i64 = sqlx::query_scalar(match column {
			"metadata" => "SELECT COALESCE(MAX(length(CAST(metadata AS BLOB))),0) FROM asp_rag_documents",
			"snapshot" => "SELECT COALESCE(MAX(length(CAST(snapshot AS BLOB))),0) FROM asp_rag_contexts",
			_ => return Err("invalid RAG payload column".into()),
		})
		.fetch_one(&mut **tx)
		.await
		.map_err(|_| "invalid RAG payload schema")?;
		if length > security_audit::StateJournal::MAX_RECORD as i64 {
			return Err("oversized RAG state row".into());
		}
	}
	let rows = sqlx::query("SELECT tenant,corpus,document,metadata FROM asp_rag_documents")
		.fetch_all(&mut **tx)
		.await
		.map_err(|_| "cannot recover documents")?;
	let mut keys = std::collections::HashSet::new();
	for row in rows {
		let raw: &str = row
			.try_get("metadata")
			.map_err(|_| "invalid document row")?;
		let meta: DocumentMetadata =
			serde_json::from_str(raw).map_err(|_| "invalid document metadata")?;
		meta.validate()?;
		if !keys.insert(meta.key.clone())
			|| meta.authority != authority
			|| row
				.try_get::<String, _>("tenant")
				.map_err(|_| "invalid tenant key")?
				!= meta.key.tenant_id
			|| row
				.try_get::<String, _>("corpus")
				.map_err(|_| "invalid corpus key")?
				!= meta.key.corpus_id
			|| row
				.try_get::<String, _>("document")
				.map_err(|_| "invalid document key")?
				!= meta.key.document_id
		{
			return Err("recovered document key/authority mismatch".into());
		}
	}
	let rows = sqlx::query("SELECT id,expires_ms,snapshot FROM asp_rag_contexts")
		.fetch_all(&mut **tx)
		.await
		.map_err(|_| "cannot recover contexts")?;
	let mut deadlines = HashMap::new();
	let mut ids = std::collections::HashSet::new();
	for row in rows {
		let raw: &str = row.try_get("snapshot").map_err(|_| "invalid context row")?;
		let snapshot: Snapshot = serde_json::from_str(raw).map_err(|_| "invalid context snapshot")?;
		validate_snapshot(&snapshot, &config.namespace)?;
		if !ids.insert(snapshot.id.clone())
			|| snapshot
				.documents
				.iter()
				.any(|reference| reference.authority != authority)
			|| snapshot.id
				!= row
					.try_get::<String, _>("id")
					.map_err(|_| "invalid context ID")?
			|| snapshot.expires_ms
				!= row
					.try_get::<i64, _>("expires_ms")
					.map_err(|_| "invalid context expiry")?
			|| snapshot.document_authority.as_deref() != Some(authority.as_str())
			|| snapshot.created_ms > water
		{
			return Err("recovered context key/authority/clock mismatch".into());
		}
		// A stale or revoked document can legitimately invalidate a persisted Context. Keep the
		// context, but validate all references on every use instead of treating recovery as Allow.
		if snapshot.expires_ms > now {
			deadlines.insert(
				snapshot.id,
				instant
					.checked_add(Duration::from_millis((snapshot.expires_ms - now) as u64))
					.ok_or("invalid context deadline")?,
			);
		}
	}
	Ok((authority, deadlines))
}
