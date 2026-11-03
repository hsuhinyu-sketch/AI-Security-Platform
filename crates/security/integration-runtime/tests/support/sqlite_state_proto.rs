//! Test-only feasibility prototype. No production configuration, migration or execution grants.
use security_integration_runtime::context_store::{ContextBinding, ContextError};
use security_rag::lifecycle::{DocumentMetadata, DocumentState};
use security_types::{DataClassification, DocumentVersion};
use serde::{Deserialize, Serialize};
use sqlx::{
	Connection, Row, Sqlite, SqliteConnection, Transaction,
	sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions, SqliteSynchronous},
};
use std::{
	collections::HashMap,
	fs::{File, OpenOptions},
	path::{Path, PathBuf},
	sync::{
		Mutex,
		atomic::{AtomicBool, AtomicU64, Ordering},
	},
	time::{Duration, Instant},
};

const APPLICATION: i64 = 0x41535053;
#[derive(Clone, Serialize, Deserialize)]
struct ContextRecord {
	binding: ContextBinding,
	class: DataClassification,
	expires_ms: i64,
	references: Vec<DocumentVersion>,
	revoked: bool,
}

pub struct Prototype {
	pub pool: sqlx::SqlitePool,
	pub path: PathBuf,
	healthy: AtomicBool,
	deadlines: Mutex<HashMap<String, Instant>>,
	pub acknowledged_commits: AtomicU64,
	_owner: File,
}
impl Prototype {
	pub async fn open(path: PathBuf, max_pages: u32) -> Result<Self, ContextError> {
		let lock_path = path.with_extension("owner");
		let mut options = OpenOptions::new();
		options.read(true).write(true).create(true).truncate(false);
		#[cfg(unix)]
		{
			use std::os::unix::fs::OpenOptionsExt;
			options.mode(0o600);
		}
		let owner = options
			.open(lock_path)
			.map_err(|_| ContextError::Unavailable)?;
		owner.try_lock().map_err(|_| ContextError::Unavailable)?;
		let fresh = match options.create_new(true).open(&path) {
			Ok(_) => true,
			Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => false,
			Err(_) => return Err(ContextError::Unavailable),
		};
		let connect = SqliteConnectOptions::new()
			.filename(&path)
			.create_if_missing(false)
			.journal_mode(SqliteJournalMode::Wal)
			.synchronous(SqliteSynchronous::Full)
			.busy_timeout(Duration::from_millis(50))
			.pragma("wal_autocheckpoint", "64")
			.pragma("journal_size_limit", "262144")
			.pragma("max_page_count", max_pages.to_string());
		let pool = SqlitePoolOptions::new()
			.max_connections(1)
			.connect_with(connect)
			.await
			.map_err(|_| ContextError::Unavailable)?;
		let identity: i64 = sqlx::query_scalar("PRAGMA application_id")
			.fetch_one(&pool)
			.await
			.map_err(|_| ContextError::Unavailable)?;
		if fresh {
			if identity != 0 {
				return Err(ContextError::Unavailable);
			}
			sqlx::raw_sql("BEGIN IMMEDIATE;
                CREATE TABLE prototype_meta(id INTEGER PRIMARY KEY CHECK(id=1), highwater INTEGER NOT NULL) STRICT;
                INSERT INTO prototype_meta VALUES(1,0);
                CREATE TABLE prototype_documents(tenant TEXT NOT NULL, corpus TEXT NOT NULL, document TEXT NOT NULL, metadata TEXT NOT NULL, PRIMARY KEY(tenant,corpus,document)) STRICT;
                CREATE TABLE prototype_contexts(id TEXT PRIMARY KEY, record TEXT NOT NULL) STRICT;
                PRAGMA application_id=1095979091;
                PRAGMA user_version=1;
                COMMIT;").execute(&pool).await.map_err(|_| ContextError::Unavailable)?;
		} else if identity != APPLICATION {
			return Err(ContextError::Unavailable);
		}
		let version: i64 = sqlx::query_scalar("PRAGMA user_version")
			.fetch_one(&pool)
			.await
			.map_err(|_| ContextError::Unavailable)?;
		if version != 1 {
			return Err(ContextError::Unavailable);
		}
		let highwater: i64 = sqlx::query_scalar("SELECT highwater FROM prototype_meta WHERE id=1")
			.fetch_one(&pool)
			.await
			.map_err(|_| ContextError::Unavailable)?;
		let now = chrono::Utc::now().timestamp_millis();
		if now < highwater {
			return Err(ContextError::Unavailable);
		}
		let mut deadlines = HashMap::new();
		for row in sqlx::query("SELECT id,record FROM prototype_contexts")
			.fetch_all(&pool)
			.await
			.map_err(|_| ContextError::Unavailable)?
		{
			let record: ContextRecord =
				serde_json::from_str(row.get("record")).map_err(|_| ContextError::Unavailable)?;
			if record.expires_ms > now {
				deadlines.insert(
					row.get::<String, _>("id"),
					Instant::now() + Duration::from_millis((record.expires_ms - now) as u64),
				);
			}
		}
		let this = Self {
			pool,
			path,
			healthy: AtomicBool::new(true),
			deadlines: Mutex::new(deadlines),
			acknowledged_commits: AtomicU64::new(0),
			_owner: owner,
		};
		let tx = this.begin().await?;
		this.commit(tx).await?;
		Ok(this)
	}
	fn unavailable(&self) -> ContextError {
		self.healthy.store(false, Ordering::Release);
		ContextError::Unavailable
	}
	async fn begin(&self) -> Result<Transaction<'_, Sqlite>, ContextError> {
		if !self.healthy.load(Ordering::Acquire) {
			return Err(ContextError::Unavailable);
		}
		let mut tx = self
			.pool
			.begin_with("BEGIN IMMEDIATE")
			.await
			.map_err(|_| self.unavailable())?;
		if !self.healthy.load(Ordering::Acquire) {
			return Err(ContextError::Unavailable);
		}
		let water: i64 = sqlx::query_scalar("SELECT highwater FROM prototype_meta WHERE id=1")
			.fetch_one(&mut *tx)
			.await
			.map_err(|_| self.unavailable())?;
		let now = chrono::Utc::now().timestamp_millis();
		if now < water {
			return Err(self.unavailable());
		}
		sqlx::query("UPDATE prototype_meta SET highwater=? WHERE id=1")
			.bind(now)
			.execute(&mut *tx)
			.await
			.map_err(|_| self.unavailable())?;
		Ok(tx)
	}
	async fn commit(&self, tx: Transaction<'_, Sqlite>) -> Result<(), ContextError> {
		tx.commit().await.map_err(|_| self.unavailable())?;
		self.acknowledged_commits.fetch_add(1, Ordering::Relaxed);
		Ok(())
	}
	pub async fn put_document(&self, meta: &DocumentMetadata) -> Result<(), ContextError> {
		meta.key.validate().map_err(|_| ContextError::Denied)?;
		if meta.revision == 0 || uuid::Uuid::parse_str(&meta.authority).is_err() {
			return Err(ContextError::Denied);
		}
		let mut tx = self.begin().await?;
		sqlx::query("INSERT INTO prototype_documents VALUES(?,?,?,?) ON CONFLICT(tenant,corpus,document) DO UPDATE SET metadata=excluded.metadata")
            .bind(&meta.key.tenant_id).bind(&meta.key.corpus_id).bind(&meta.key.document_id)
            .bind(serde_json::to_string(meta).map_err(|_|ContextError::Denied)?)
            .execute(&mut *tx).await.map_err(|_|self.unavailable())?;
		self.commit(tx).await
	}
	async fn documents(
		&self,
		tx: &mut Transaction<'_, Sqlite>,
		record: &ContextRecord,
	) -> Result<(), ContextError> {
		let identity = record.binding.owner.identity();
		for reference in &record.references {
			let row: Option<String> = sqlx::query_scalar(
				"SELECT metadata FROM prototype_documents WHERE tenant=? AND corpus=? AND document=?",
			)
			.bind(&reference.key.tenant_id)
			.bind(&reference.key.corpus_id)
			.bind(&reference.key.document_id)
			.fetch_optional(&mut **tx)
			.await
			.map_err(|_| self.unavailable())?;
			let meta: DocumentMetadata =
				serde_json::from_str(&row.ok_or(ContextError::Denied)?).map_err(|_| self.unavailable())?;
			let allowed = meta.access.allow_tenant_authenticated
				&& (identity.user_id.is_some() || identity.agent_id.is_some())
				|| identity
					.user_id
					.as_ref()
					.is_some_and(|u| meta.access.allowed_users.contains(u))
				|| identity
					.agent_id
					.as_ref()
					.is_some_and(|a| meta.access.allowed_agents.contains(a));
			if meta.state != DocumentState::Active
				|| meta.key != reference.key
				|| meta.authority != reference.authority
				|| meta.revision != reference.revision
				|| identity.tenant_id.as_deref() != Some(meta.key.tenant_id.as_str())
				|| !allowed
				|| meta
					.access
					.expires_at
					.is_some_and(|expires| expires <= chrono::Utc::now())
			{
				return Err(ContextError::Denied);
			}
		}
		Ok(())
	}
	pub async fn issue(
		&self,
		binding: ContextBinding,
		ttl: u64,
		references: Vec<DocumentVersion>,
	) -> Result<String, ContextError> {
		if !(1..=86400).contains(&ttl) || references.len() > 64 {
			return Err(ContextError::Denied);
		}
		let id = uuid::Uuid::new_v4().to_string();
		let record = ContextRecord {
			binding,
			class: DataClassification::Restricted,
			expires_ms: chrono::Utc::now().timestamp_millis() + ttl as i64 * 1000,
			references,
			revoked: false,
		};
		let deadline = Instant::now() + Duration::from_secs(ttl);
		let mut tx = self.begin().await?;
		self.documents(&mut tx, &record).await?;
		sqlx::query("INSERT INTO prototype_contexts VALUES(?,?)")
			.bind(&id)
			.bind(serde_json::to_string(&record).map_err(|_| ContextError::Denied)?)
			.execute(&mut *tx)
			.await
			.map_err(|_| self.unavailable())?;
		self.commit(tx).await?;
		self.deadlines.lock().unwrap().insert(id.clone(), deadline);
		Ok(id)
	}
	fn live(&self, id: &str) -> Result<(), ContextError> {
		if self
			.deadlines
			.lock()
			.unwrap()
			.get(id)
			.is_none_or(|deadline| Instant::now() >= *deadline)
		{
			Err(ContextError::Denied)
		} else {
			Ok(())
		}
	}
	pub async fn use_context(
		&self,
		id: &str,
		binding: &ContextBinding,
	) -> Result<DataClassification, ContextError> {
		let mut tx = self.begin().await?;
		let row: Option<String> =
			sqlx::query_scalar("SELECT record FROM prototype_contexts WHERE id=?")
				.bind(id)
				.fetch_optional(&mut *tx)
				.await
				.map_err(|_| self.unavailable())?;
		let record: ContextRecord =
			serde_json::from_str(&row.ok_or(ContextError::Denied)?).map_err(|_| self.unavailable())?;
		if record.binding != *binding || record.revoked {
			return Err(ContextError::Denied);
		}
		self.live(id)?;
		self.documents(&mut tx, &record).await?;
		self.commit(tx).await?;
		self.live(id)?;
		Ok(record.class)
	}
	pub async fn revoke(&self, id: &str, binding: &ContextBinding) -> Result<(), ContextError> {
		let mut tx = self.begin().await?;
		let raw: Option<String> =
			sqlx::query_scalar("SELECT record FROM prototype_contexts WHERE id=?")
				.bind(id)
				.fetch_optional(&mut *tx)
				.await
				.map_err(|_| self.unavailable())?;
		let mut record: ContextRecord =
			serde_json::from_str(&raw.ok_or(ContextError::Denied)?).map_err(|_| self.unavailable())?;
		if record.binding != *binding {
			return Err(ContextError::Denied);
		}
		record.revoked = true;
		sqlx::query("UPDATE prototype_contexts SET record=? WHERE id=?")
			.bind(serde_json::to_string(&record).unwrap())
			.bind(id)
			.execute(&mut *tx)
			.await
			.map_err(|_| self.unavailable())?;
		self.commit(tx).await
	}
	pub async fn sizes(&self) -> (u64, u64, u64) {
		fn size(path: &Path) -> u64 {
			std::fs::metadata(path).map_or(0, |m| m.len())
		}
		(
			size(&self.path),
			size(&PathBuf::from(format!("{}-wal", self.path.display()))),
			size(&PathBuf::from(format!("{}-shm", self.path.display()))),
		)
	}
	pub async fn checkpoint(&self) -> Result<(), ContextError> {
		let result = sqlx::query("PRAGMA wal_checkpoint(TRUNCATE)")
			.fetch_one(&self.pool)
			.await
			.map_err(|_| self.unavailable())?;
		if result.get::<i64, _>(0) != 0 {
			return Err(ContextError::Unavailable);
		}
		Ok(())
	}
	pub async fn external_connection(&self) -> SqliteConnection {
		SqliteConnection::connect_with(
			&SqliteConnectOptions::new()
				.filename(&self.path)
				.busy_timeout(Duration::from_millis(50)),
		)
		.await
		.unwrap()
	}
}
