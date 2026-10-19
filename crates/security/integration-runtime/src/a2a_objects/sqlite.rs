//! Local durable ownership metadata. One owner process per (file, namespace).
//! SQLite files and their parent directory must be protected by the deployment.
use super::*;
use std::fs::{File, OpenOptions};
use std::path::{Path, PathBuf};
use std::sync::{OnceLock, Weak, mpsc};

use sqlx::sqlite::{SqliteConnectOptions, SqliteRow, SqliteSynchronous};
use sqlx::{Connection, Row, SqliteConnection};

const APPLICATION_ID: i64 = 0x41535041;
const SCHEMA_VERSION: i64 = 3;
const PUSH_MIGRATION: &str = "BEGIN IMMEDIATE; CREATE TABLE asp_push_outbox(namespace TEXT PRIMARY KEY REFERENCES asp_namespaces(namespace), source TEXT NOT NULL, serial INTEGER NOT NULL CHECK(serial>=0), destination TEXT, pending TEXT CHECK(pending IS NULL OR length(CAST(pending AS BLOB))<=266240)) STRICT; PRAGMA user_version=3; COMMIT;";
type Registry = HashMap<(PathBuf, String), Weak<SqliteTaskStore>>;
static OPEN_STORES: OnceLock<Mutex<Registry>> = OnceLock::new();
static SESSION: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);

trait Clock: Send + Sync {
	fn millis(&self) -> i64;
}
struct WallClock;
impl Clock for WallClock {
	fn millis(&self) -> i64 {
		chrono::Utc::now().timestamp_millis()
	}
}

#[derive(Debug, Default)]
struct Live {
	pending: usize,
	streams: usize,
}

#[derive(Clone)]
struct PermitData {
	execution_binding: Option<String>,
	scope: String,
	owner: Owner,
	task: Option<String>,
	context: Option<String>,
	generation: Option<u64>,
	reserved: bool,
	operation: TaskOperation,
}
impl From<&TaskPermit> for PermitData {
	fn from(p: &TaskPermit) -> Self {
		Self {
			execution_binding: p.execution_binding.clone(),
			scope: p.scope.clone(),
			owner: p.owner.clone(),
			task: p.task_id.clone(),
			context: p.context_id.clone(),
			generation: p.generation,
			reserved: p.reservation.is_some(),
			operation: p.operation,
		}
	}
}
enum Op {
	Health(A2aObjectConfig),
	Begin(A2aObjectConfig, PermitData),
	Check(A2aObjectConfig, PermitData, bool),
	Finish(
		A2aObjectConfig,
		PermitData,
		String,
		String,
		TaskState,
		Option<(events::EventBinding, serde_json::Value)>,
	),
	DrainPush(A2aObjectConfig),
}
enum Reply {
	Unit,
	Bound(
		Option<u64>,
		Option<String>,
		Option<String>,
		Option<TaskState>,
	),
	Finished(u64),
}
struct Job {
	op: Op,
	reply: mpsc::SyncSender<Result<Reply, ObjectError>>,
}

pub struct SqliteTaskStore {
	path: PathBuf,
	declared_path: PathBuf,
	namespace: String,
	timeout: u64,
	binding: String,
	live: Arc<Mutex<Live>>,
	sender: Option<mpsc::SyncSender<Job>>,
	thread: Option<std::thread::JoinHandle<()>>,
	_lock: File,
}
impl std::fmt::Debug for SqliteTaskStore {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.debug_struct("SqliteTaskStore")
			.field("namespace", &self.namespace)
			.finish_non_exhaustive()
	}
}
impl Drop for SqliteTaskStore {
	fn drop(&mut self) {
		self.sender.take();
		if let Some(thread) = self.thread.take() {
			let _ = thread.join();
		}
	}
}

/// Reject symlinks and group/world-accessible files. Do not chmod or overwrite user files.
fn protected_file(path: &Path) -> Result<(File, bool), String> {
	let mut options = OpenOptions::new();
	options.read(true).write(true).create_new(true);
	#[cfg(unix)]
	{
		use std::os::unix::fs::OpenOptionsExt;
		options.mode(0o600);
	}
	match options.open(path) {
		Ok(file) => Ok((file, true)),
		Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
			let metadata = std::fs::symlink_metadata(path).map_err(|e| e.to_string())?;
			if !metadata.file_type().is_file() {
				return Err("TaskStore path must be a regular non-symlink file".into());
			}
			#[cfg(unix)]
			{
				use std::os::unix::fs::{MetadataExt, PermissionsExt};
				if metadata.permissions().mode() & 0o077 != 0 || metadata.nlink() != 1 {
					return Err("TaskStore files require mode 0600 and a single hard link".into());
				}
			}
			OpenOptions::new()
				.read(true)
				.write(true)
				.open(path)
				.map(|f| (f, false))
				.map_err(|e| e.to_string())
		},
		Err(e) => Err(e.to_string()),
	}
}
fn wait<T>(receiver: mpsc::Receiver<T>) -> Result<T, ObjectError> {
	let receive = || receiver.recv().map_err(|_| ObjectError::Unavailable);
	if tokio::runtime::Handle::try_current()
		.is_ok_and(|h| h.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread)
	{
		tokio::task::block_in_place(receive)
	} else {
		receive()
	}
}
impl SqliteTaskStore {
	pub fn open(spec: TaskStoreConfig) -> Result<Arc<Self>, String> {
		Self::open_clock(spec, Arc::new(WallClock))
	}
	fn open_clock(spec: TaskStoreConfig, clock: Arc<dyn Clock>) -> Result<Arc<Self>, String> {
		use sha2::Digest;
		spec.validate()?;
		let TaskStoreConfig::Sqlite {
			path,
			namespace,
			busy_timeout_millis: timeout,
		} = spec
		else {
			return Err("expected SQLite TaskStore configuration".into());
		};
		let registry = OPEN_STORES.get_or_init(Default::default);
		let mut entries = registry
			.lock()
			.map_err(|_| "TaskStore registry unavailable")?;
		entries.retain(|_, v| v.strong_count() > 0);
		if std::fs::symlink_metadata(&path).is_ok_and(|m| m.file_type().is_symlink()) {
			return Err("TaskStore database path must not be a symlink".into());
		}
		// Existing aliases resolve to the same namespace lock and cached actor.
		if let Ok(canonical) = path.canonicalize() {
			if let Some(store) = entries
				.get(&(canonical, namespace.clone()))
				.and_then(Weak::upgrade)
			{
				if store.timeout != timeout {
					return Err(
						"changing SQLite busyTimeoutMillis requires draining/restarting the existing store"
							.into(),
					);
				}
				store.call(Op::Health(A2aObjectConfig::default())).map_err(
					|_| "existing SQLite TaskStore is unavailable; drain/restart after investigation",
				)?;
				return Ok(store);
			}
		}
		let declared_path = path.clone();
		let (file, fresh) = protected_file(&path)?;
		let path = path.canonicalize().map_err(|e| e.to_string())?;
		let lock_path = path.with_file_name(format!(
			"{}.a2a-{}.lock",
			path
				.file_name()
				.ok_or("missing database file name")?
				.to_string_lossy(),
			sha2::Sha256::digest(namespace.as_bytes())
				.iter()
				.map(|b| format!("{b:02x}"))
				.collect::<String>()
		));
		let (lock, _) = protected_file(&lock_path)?;
		lock
			.try_lock()
			.map_err(|_| "SQLite TaskStore namespace is already owned by another process")?;
		let live = Arc::new(Mutex::new(Live::default()));
		let (sender, receiver) = mpsc::sync_channel::<Job>(32);
		let (ready_tx, ready_rx) = mpsc::channel();
		let (db_path, ns, counters) = (path.clone(), namespace.clone(), live.clone());
		let thread = std::thread::Builder::new()
			.name("a2a-sqlite".into())
			.spawn(move || {
				let runtime = match tokio::runtime::Builder::new_current_thread()
					.enable_all()
					.build()
				{
					Ok(rt) => rt,
					Err(_) => {
						let _ = ready_tx.send(Err("SQLite worker runtime unavailable".to_string()));
						return;
					},
				};
				let mut db =
					match runtime.block_on(Db::open(db_path, ns, timeout, fresh, file, counters, clock)) {
						Ok(db) => {
							let _ = ready_tx.send(Ok(()));
							db
						},
						Err(error) => {
							let _ = ready_tx.send(Err(error));
							return;
						},
					};
				let mut poisoned = false;
				while let Ok(job) = receiver.recv() {
					let result = if poisoned {
						Err(ObjectError::Unavailable)
					} else {
						runtime.block_on(db.execute(job.op))
					};
					if matches!(
						result,
						Err(ObjectError::Unavailable | ObjectError::ClockRollback)
					) {
						poisoned = true;
					}
					let _ = job.reply.send(result);
				}
				// Connection/runtime are destroyed on this OS thread, not a Tokio caller.
				runtime.block_on(async {
					let _ = db.connection.close().await;
				});
			})
			.map_err(|e| e.to_string())?;
		match wait(ready_rx) {
			Ok(Ok(())) => {},
			Ok(Err(error)) => {
				let _ = thread.join();
				return Err(error);
			},
			Err(_) => {
				let _ = thread.join();
				return Err("SQLite worker startup failed".into());
			},
		}
		let session = SESSION
			.fetch_update(
				std::sync::atomic::Ordering::Relaxed,
				std::sync::atomic::Ordering::Relaxed,
				|n| n.checked_add(1),
			)
			.map_err(|_| "TaskStore session counter exhausted")?;
		let binding =
			serde_json::to_string(&(&path, &namespace, session)).map_err(|e| e.to_string())?;
		let store = Arc::new(Self {
			path: path.clone(),
			declared_path,
			namespace: namespace.clone(),
			timeout,
			binding,
			live,
			sender: Some(sender),
			thread: Some(thread),
			_lock: lock,
		});
		entries.insert((path, namespace), Arc::downgrade(&store));
		Ok(store)
	}
	fn call(&self, op: Op) -> Result<Reply, ObjectError> {
		let (tx, rx) = mpsc::sync_channel(1);
		self
			.sender
			.as_ref()
			.ok_or(ObjectError::Unavailable)?
			.try_send(Job { op, reply: tx })
			.map_err(|_| ObjectError::Unavailable)?;
		wait(rx)?
	}
	fn check_permit(&self, cfg: &A2aObjectConfig, p: &TaskPermit) -> Result<(), ObjectError> {
		if !self.matches_storage(&cfg.storage) || p.store_binding.as_deref() != Some(&self.binding) {
			return Err(ObjectError::Unavailable);
		}
		if p.started.elapsed() >= Duration::from_secs(cfg.retention_seconds) {
			return Err(ObjectError::UnknownOrNotOwner);
		}
		Ok(())
	}
	fn lease(
		self: &Arc<Self>,
		cfg: &A2aObjectConfig,
		stream: bool,
	) -> Result<StoreLease, ObjectError> {
		let mut live = self.live.lock().map_err(|_| ObjectError::Unavailable)?;
		if stream {
			if live.streams >= cfg.max_streams {
				return Err(ObjectError::StreamLimit);
			}
			live.streams += 1;
		} else {
			if live.pending >= cfg.max_tasks {
				return Err(ObjectError::Capacity);
			}
			live.pending += 1;
		}
		let store = self.clone();
		Ok(StoreLease::new(move || {
			if let Ok(mut live) = store.live.lock() {
				if stream {
					live.streams = live.streams.saturating_sub(1);
				} else {
					live.pending = live.pending.saturating_sub(1);
				}
			}
		}))
	}
}
impl TaskOwnershipStore for SqliteTaskStore {
	fn commit_push(
		&self,
		cfg: &A2aObjectConfig,
		p: &TaskPermit,
		binding: events::EventBinding,
		result: serde_json::Value,
	) -> Result<(), ObjectError> {
		self.check_permit(cfg, p)?;
		binding.matches_permit(p)?;
		let task = p.task_id.clone().ok_or(ObjectError::ResponseBinding)?;
		let context = p.context_id.clone().ok_or(ObjectError::ResponseBinding)?;
		let state = serde_json::from_value(result["status"]["state"].clone())
			.map_err(|_| ObjectError::ResponseBinding)?;
		if result["kind"] != "task" || result["id"] != task || result["contextId"] != context {
			return Err(ObjectError::ResponseBinding);
		}
		self
			.call(Op::Finish(
				cfg.clone(),
				p.into(),
				task,
				context,
				state,
				Some((binding, result)),
			))
			.map(|_| ())
	}
	fn drain_push(&self, cfg: &A2aObjectConfig) -> Result<(), ObjectError> {
		if !self.matches_storage(&cfg.storage) {
			return Err(ObjectError::Unavailable);
		}
		self.call(Op::DrainPush(cfg.clone())).map(|_| ())
	}
	fn matches_storage(&self, storage: &TaskStoreConfig) -> bool {
		matches!(storage,TaskStoreConfig::Sqlite{path,namespace,busy_timeout_millis}
            if namespace==&self.namespace && busy_timeout_millis==&self.timeout
                // Match declarations even when the file vanished: execute() must observe the
                // fault and quarantine the actor, not let it recover silently if the path returns.
                && (path == &self.declared_path || path == &self.path ||
                    path.parent().and_then(|p| p.canonicalize().ok())
                        .zip(path.file_name()).is_some_and(|(p, name)| p.join(name) == self.path)))
	}
	fn begin_owned(
		self: Arc<Self>,
		cfg: &A2aObjectConfig,
		identity: &GatewayIdentity,
		issuer: &str,
		scope: &str,
		task: Option<&str>,
		operation: TaskOperation,
	) -> Result<TaskPermit, ObjectError> {
		cfg.validate().map_err(|_| ObjectError::Unavailable)?;
		if !self.matches_storage(&cfg.storage) {
			return Err(ObjectError::Unavailable);
		}
		let owner = Owner::from_identity(identity, issuer).map_err(|_| ObjectError::Identity)?;
		let started = Instant::now();
		let reservation = if operation == TaskOperation::Create {
			Some(self.lease(cfg, false)?)
		} else {
			None
		};
		let data = PermitData {
			execution_binding: None,
			scope: scope.into(),
			owner: owner.clone(),
			task: task.map(Into::into),
			context: None,
			generation: None,
			reserved: reservation.is_some(),
			operation,
		};
		let Reply::Bound(generation, context_id, execution_binding, snapshot_state) =
			self.call(Op::Begin(cfg.clone(), data))?
		else {
			return Err(ObjectError::Unavailable);
		};
		Ok(TaskPermit {
			snapshot_state,
			execution_binding,
			task_id: task.map(Into::into),
			context_id,
			operation,
			scope: scope.into(),
			owner,
			generation,
			started,
			reservation,
			store_binding: Some(self.binding.clone()),
		})
	}
	fn validate_permit(&self, cfg: &A2aObjectConfig, p: &TaskPermit) -> Result<(), ObjectError> {
		self.check_permit(cfg, p)?;
		self
			.call(Op::Check(cfg.clone(), p.into(), false))
			.map(|_| ())
	}
	fn validate_stream(&self, cfg: &A2aObjectConfig, p: &TaskPermit) -> Result<(), ObjectError> {
		self.check_permit(cfg, p)?;
		self
			.call(Op::Check(cfg.clone(), p.into(), true))
			.map(|_| ())
	}
	fn finish(
		&self,
		cfg: &A2aObjectConfig,
		p: &mut TaskPermit,
		task: &str,
		context: &str,
		state: TaskState,
	) -> Result<(), ObjectError> {
		self.check_permit(cfg, p)?;
		let Reply::Finished(generation) = self.call(Op::Finish(
			cfg.clone(),
			(&*p).into(),
			task.into(),
			context.into(),
			state,
			None,
		))?
		else {
			return Err(ObjectError::Unavailable);
		};
		p.task_id = Some(task.into());
		p.context_id = Some(context.into());
		p.generation = Some(generation);
		p.snapshot_state = Some(state);
		p.reservation.take();
		Ok(())
	}
	fn reserve_stream(self: Arc<Self>, cfg: &A2aObjectConfig) -> Result<StoreLease, ObjectError> {
		if !self.matches_storage(&cfg.storage) {
			return Err(ObjectError::Unavailable);
		}
		self.call(Op::Health(cfg.clone()))?;
		self.lease(cfg, true)
	}
}

struct Db {
	connection: SqliteConnection,
	namespace: String,
	path: PathBuf,
	file: File,
	live: Arc<Mutex<Live>>,
	clock: Arc<dyn Clock>,
}
#[derive(Debug)]
struct Record {
	execution_binding: Option<String>,
	owner: Owner,
	context: String,
	state: TaskState,
	generation: u64,
	created: i64,
	expires: i64,
}
fn unavailable<T>(_: T) -> ObjectError {
	ObjectError::Unavailable
}
fn id(value: &str) -> bool {
	!value.is_empty() && value.trim() == value && value.len() <= 512
}
impl Record {
	fn parse(row: SqliteRow) -> Result<Self, ObjectError> {
		let owner: Owner = serde_json::from_str(row.try_get::<&str, _>("owner").map_err(unavailable)?)
			.map_err(unavailable)?;
		let checked = Owner::from_identity(
			&GatewayIdentity {
				tenant_id: Some(owner.tenant.clone()),
				user_id: owner.user.clone(),
				agent_id: owner.agent.clone(),
				client_id: owner.client.clone(),
				delegation_id: owner.delegation.clone(),
				..Default::default()
			},
			&owner.issuer,
		)
		.map_err(unavailable)?;
		if owner != checked {
			return Err(ObjectError::Unavailable);
		}
		let record = Self {
			execution_binding: row.try_get("execution_binding").map_err(unavailable)?,
			owner,
			context: row.try_get("context").map_err(unavailable)?,
			state: serde_json::from_value(serde_json::Value::String(
				row.try_get("state").map_err(unavailable)?,
			))
			.map_err(unavailable)?,
			generation: u64::try_from(row.try_get::<i64, _>("generation").map_err(unavailable)?)
				.map_err(unavailable)?,
			created: row.try_get("created_ms").map_err(unavailable)?,
			expires: row.try_get("expires_ms").map_err(unavailable)?,
		};
		if record
			.execution_binding
			.as_deref()
			.is_some_and(|v| !valid_execution_binding(v))
			|| !id(&record.context)
			|| record.generation == 0
			|| record.created < 0
			|| record.expires <= record.created
			|| record.expires - record.created > 30 * 86_400_000
		{
			return Err(ObjectError::Unavailable);
		}
		Ok(record)
	}
	fn current(&self, cfg: &A2aObjectConfig, now: i64) -> Result<(), ObjectError> {
		if now < self.created
			|| now >= self.expires
			|| now - self.created >= cfg.retention_seconds as i64 * 1000
		{
			return Err(ObjectError::UnknownOrNotOwner);
		}
		Ok(())
	}
	fn bound(&self, p: &PermitData) -> Result<(), ObjectError> {
		if self.execution_binding != p.execution_binding {
			return Err(ObjectError::ExecutionBinding);
		}
		if self.owner != p.owner
			|| Some(self.generation) != p.generation
			|| p.context.as_deref() != Some(&self.context)
		{
			return Err(ObjectError::UnknownOrNotOwner);
		}
		Ok(())
	}
}
async fn read_task(
	connection: &mut SqliteConnection,
	ns: &str,
	scope: &str,
	task: &str,
) -> Result<Record, ObjectError> {
	let row=sqlx::query("SELECT owner,context,state,generation,created_ms,expires_ms,execution_binding FROM asp_tasks WHERE namespace=? AND scope=? AND task=?")
        .bind(ns).bind(scope).bind(task).fetch_optional(connection).await.map_err(unavailable)?
        .ok_or(ObjectError::UnknownOrNotOwner)?;
	Record::parse(row)
}
// Read scalar lengths first; corrupt local state must not cause an unbounded JSON allocation.
async fn push_metadata(
	connection: &mut SqliteConnection,
	ns: &str,
) -> Result<Option<(String, i64, Option<String>, Option<i64>)>, ObjectError> {
	let sizes: Option<(i64, i64, Option<i64>, Option<i64>)> = sqlx::query_as(
		"SELECT length(CAST(source AS BLOB)),serial,length(CAST(destination AS BLOB)),length(CAST(pending AS BLOB)) FROM asp_push_outbox WHERE namespace=?")
		.bind(ns).fetch_optional(&mut *connection).await.map_err(unavailable)?;
	let Some((source_len, serial, dest_len, pending_len)) = sizes else {
		return Ok(None);
	};
	if source_len != 36
		|| serial < 0
		|| dest_len.is_some_and(|l| !(1..=8192).contains(&l))
		|| pending_len.is_some_and(|l| !(1..=266240).contains(&l))
		|| (serial == 0 && (dest_len.is_some() || pending_len.is_some()))
		|| (serial > 0 && dest_len.is_none())
	{
		return Err(ObjectError::Unavailable);
	}
	let (source, destination): (String, Option<String>) =
		sqlx::query_as("SELECT source,destination FROM asp_push_outbox WHERE namespace=?")
			.bind(ns)
			.fetch_one(connection)
			.await
			.map_err(unavailable)?;
	if !events::valid_cursor(&source) {
		return Err(ObjectError::Unavailable);
	}
	Ok(Some((source, serial, destination, pending_len)))
}
impl Db {
	async fn open(
		path: PathBuf,
		namespace: String,
		timeout: u64,
		fresh: bool,
		file: File,
		live: Arc<Mutex<Live>>,
		clock: Arc<dyn Clock>,
	) -> Result<Self, String> {
		let options = SqliteConnectOptions::new()
			.filename(&path)
			.create_if_missing(false)
			.busy_timeout(Duration::from_millis(timeout))
			.synchronous(SqliteSynchronous::Full);
		let mut connection = SqliteConnection::connect_with(&options)
			.await
			.map_err(|_| "cannot open SQLite TaskStore")?;
		let application: i64 = sqlx::query_scalar("PRAGMA application_id")
			.fetch_one(&mut connection)
			.await
			.map_err(|_| "cannot read SQLite identity")?;
		let version: i64 = sqlx::query_scalar("PRAGMA user_version")
			.fetch_one(&mut connection)
			.await
			.map_err(|_| "cannot read SQLite schema")?;
		if fresh {
			let tables: i64 =
				sqlx::query_scalar("SELECT COUNT(*) FROM sqlite_master WHERE name NOT LIKE 'sqlite_%'")
					.fetch_one(&mut connection)
					.await
					.map_err(|_| "cannot inspect new SQLite file")?;
			if application != 0 || version != 0 || tables != 0 {
				return Err("refusing to initialize a nonempty database".into());
			}
			sqlx::raw_sql("BEGIN IMMEDIATE;
                CREATE TABLE asp_namespaces(namespace TEXT PRIMARY KEY, generation INTEGER NOT NULL CHECK(generation>=0), last_clock_ms INTEGER NOT NULL CHECK(last_clock_ms>=0)) STRICT;
                CREATE TABLE asp_tasks(namespace TEXT NOT NULL REFERENCES asp_namespaces(namespace), scope TEXT NOT NULL,
                    task TEXT NOT NULL, context TEXT NOT NULL, owner TEXT NOT NULL,
                    state TEXT NOT NULL CHECK(state IN ('submitted','working','input-required','auth-required','completed','canceled','failed','rejected','unknown')),
                    generation INTEGER NOT NULL CHECK(generation>0), created_ms INTEGER NOT NULL CHECK(created_ms>=0),
                    expires_ms INTEGER NOT NULL CHECK(expires_ms>created_ms), execution_binding TEXT, PRIMARY KEY(namespace,scope,task)) STRICT;
                CREATE INDEX asp_context ON asp_tasks(namespace,scope,context);
                PRAGMA application_id=1095979073;
                PRAGMA user_version=2;
                COMMIT;").execute(&mut connection).await.map_err(|_|"cannot initialize SQLite TaskStore schema")?;
		} else if application == APPLICATION_ID && version == 1 {
			// Additive migration only for the known v1 identity. No reset, ownership adoption,
			// or workflow assignment: legacy rows remain unbound and fail protected rebinding.
			sqlx::query("SELECT namespace,scope,task,owner,context,state,generation,created_ms,expires_ms FROM asp_tasks LIMIT 0")
				.fetch_all(&mut connection).await.map_err(|_| "incompatible v1 TaskStore schema")?;
			sqlx::raw_sql("BEGIN IMMEDIATE; ALTER TABLE asp_tasks ADD COLUMN execution_binding TEXT; PRAGMA user_version=2; COMMIT;")
				.execute(&mut connection).await.map_err(|_| "cannot migrate v1 TaskStore execution binding")?;
		} else if application != APPLICATION_ID || version != SCHEMA_VERSION {
			if application != APPLICATION_ID || version != 2 {
				return Err(
					"SQLite TaskStore identity/schema is incompatible; no automatic reset or migration"
						.into(),
				);
			}
		}
		// Known v1 -> v2 (above) -> v3 is additive. Do not erase or adopt unknown tables.
		let current: i64 = sqlx::query_scalar("PRAGMA user_version")
			.fetch_one(&mut connection)
			.await
			.map_err(|_| "cannot read migrated schema")?;
		if current == 2 {
			sqlx::raw_sql(PUSH_MIGRATION)
				.execute(&mut connection)
				.await
				.map_err(|_| "cannot migrate Push outbox schema")?;
		}
		sqlx::query("SELECT namespace,source,serial,destination,pending FROM asp_push_outbox LIMIT 0")
			.fetch_all(&mut connection)
			.await
			.map_err(|_| "incompatible Push outbox schema")?;
		let integrity: String = sqlx::query_scalar("PRAGMA quick_check")
			.fetch_one(&mut connection)
			.await
			.map_err(|_| "SQLite integrity check failed")?;
		if integrity != "ok" {
			return Err("SQLite integrity check failed".into());
		}
		sqlx::query("SELECT namespace,generation,last_clock_ms FROM asp_namespaces LIMIT 0")
			.fetch_all(&mut connection)
			.await
			.map_err(|_| "incompatible namespace schema")?;
		sqlx::query("PRAGMA journal_mode=WAL")
			.execute(&mut connection)
			.await
			.map_err(|_| "cannot enable SQLite WAL")?;
		let mut db = Self {
			connection,
			namespace,
			path,
			file,
			live,
			clock,
		};
		// Validate all recovered metadata in this namespace; never create ownership on first GET.
		let rows = sqlx::query(
			"SELECT owner,context,state,generation,created_ms,expires_ms,execution_binding FROM asp_tasks WHERE namespace=?",
		)
		.bind(&db.namespace)
		.fetch_all(&mut db.connection)
		.await
		.map_err(|_| "cannot recover TaskStore records")?;
		let namespace_state: Option<(i64, i64)> =
			sqlx::query_as("SELECT generation,last_clock_ms FROM asp_namespaces WHERE namespace=?")
				.bind(&db.namespace)
				.fetch_optional(&mut db.connection)
				.await
				.map_err(|_| "cannot recover generation")?;
		for row in rows {
			let record = Record::parse(row).map_err(|_| "invalid recovered TaskStore record")?;
			if namespace_state
				.is_none_or(|(g, clock)| g < 0 || record.generation > g as u64 || record.created > clock)
			{
				return Err("invalid recovered TaskStore generation".into());
			}
		}
		let cfg = A2aObjectConfig::default();
		push_metadata(&mut db.connection, &db.namespace)
			.await
			.map_err(|_| "invalid recovered Push outbox")?;
		db.execute(Op::Health(cfg))
			.await
			.map_err(|e| format!("SQLite recovery refused: {}", e.rule()))?;
		Ok(db)
	}
	fn same_file(&self) -> Result<(), ObjectError> {
		let current = std::fs::symlink_metadata(&self.path).map_err(unavailable)?;
		if !current.is_file() {
			return Err(ObjectError::Unavailable);
		}
		#[cfg(unix)]
		{
			use std::os::unix::fs::{MetadataExt, PermissionsExt};
			let original = self.file.metadata().map_err(unavailable)?;
			if (current.dev(), current.ino()) != (original.dev(), original.ino())
				|| current.permissions().mode() & 0o077 != 0
				|| current.nlink() != 1
			{
				return Err(ObjectError::Unavailable);
			}
		}
		Ok(())
	}
	async fn execute(&mut self, op: Op) -> Result<Reply, ObjectError> {
		self.same_file()?;
		let cfg = match &op {
			Op::Health(c)
			| Op::Begin(c, _)
			| Op::Check(c, _, _)
			| Op::Finish(c, ..)
			| Op::DrainPush(c) => c,
		};
		cfg.validate().map_err(unavailable)?;
		let now = self.clock.millis();
		if now < 0 {
			return Err(ObjectError::ClockRollback);
		}
		let ns = &self.namespace;
		let mut tx = self
			.connection
			.begin_with("BEGIN IMMEDIATE")
			.await
			.map_err(unavailable)?;
		sqlx::query(
			"INSERT OR IGNORE INTO asp_namespaces(namespace,generation,last_clock_ms) VALUES(?,0,0)",
		)
		.bind(ns)
		.execute(&mut *tx)
		.await
		.map_err(unavailable)?;
		let (generation, highwater): (i64, i64) =
			sqlx::query_as("SELECT generation,last_clock_ms FROM asp_namespaces WHERE namespace=?")
				.bind(ns)
				.fetch_one(&mut *tx)
				.await
				.map_err(unavailable)?;
		if generation < 0 || now < highwater {
			return Err(ObjectError::ClockRollback);
		}
		sqlx::query("UPDATE asp_namespaces SET last_clock_ms=? WHERE namespace=?")
			.bind(now)
			.bind(ns)
			.execute(&mut *tx)
			.await
			.map_err(unavailable)?;
		let reply = match &op {
			Op::Health(_) => Reply::Unit,
			Op::DrainPush(cfg) => {
				// Only one pending delivery per namespace: bounded recovery without a background queue.
				if let Some((source, serial, destination, pending_len)) = push_metadata(&mut tx, ns).await?
				{
					if let Some(settings) = &cfg.event_recovery {
						let spec = serde_json::to_string(settings).map_err(unavailable)?;
						if destination.as_deref().is_some_and(|v| v != spec) {
							return Err(ObjectError::EventStorage);
						}
						if pending_len.is_none() {
							settings
								.store()?
								.check_push_checkpoint(&source, serial as u64)?;
						}
					}
					if pending_len.is_some() {
						let encoded: String =
							sqlx::query_scalar("SELECT pending FROM asp_push_outbox WHERE namespace=?")
								.bind(ns)
								.fetch_one(&mut *tx)
								.await
								.map_err(unavailable)?;
						let settings = cfg
							.event_recovery
							.as_ref()
							.ok_or(ObjectError::EventStorage)?;
						if destination.as_deref()
							!= Some(&serde_json::to_string(settings).map_err(unavailable)?)
						{
							return Err(ObjectError::EventStorage);
						}
						let delivery: events::PushDelivery =
							serde_json::from_str(&encoded).map_err(unavailable)?;
						delivery.validate()?;
						if delivery.source != source || delivery.serial != serial as u64 {
							return Err(ObjectError::EventStorage);
						}
						// Journal fsync first; if the SQLite commit below is lost, replay is idempotent.
						settings.store()?.append_push(delivery)?;

						sqlx::query("UPDATE asp_push_outbox SET pending=NULL WHERE namespace=?")
							.bind(ns)
							.execute(&mut *tx)
							.await
							.map_err(unavailable)?;
					}
				}
				Reply::Unit
			},
			Op::Begin(cfg, p) => {
				sqlx::query("DELETE FROM asp_tasks WHERE namespace=? AND (expires_ms<=? OR created_ms<=?)")
					.bind(ns)
					.bind(now)
					.bind(now.saturating_sub(cfg.retention_seconds as i64 * 1000))
					.execute(&mut *tx)
					.await
					.map_err(unavailable)?;
				if p.operation == TaskOperation::Create {
					if p.task.is_some() || !p.reserved {
						return Err(ObjectError::ResponseBinding);
					}
					let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM asp_tasks WHERE namespace=?")
						.bind(ns)
						.fetch_one(&mut *tx)
						.await
						.map_err(unavailable)?;
					let pending = self
						.live
						.lock()
						.map_err(|_| ObjectError::Unavailable)?
						.pending;
					if count as usize >= cfg.max_tasks
						|| (count as usize).saturating_add(pending) > cfg.max_tasks
					{
						return Err(ObjectError::Capacity);
					}
					Reply::Bound(None, None, None, None)
				} else {
					let record = read_task(
						&mut tx,
						ns,
						&p.scope,
						p.task.as_deref().ok_or(ObjectError::UnknownOrNotOwner)?,
					)
					.await?;
					record.current(cfg, now)?;
					if record.owner != p.owner {
						return Err(ObjectError::UnknownOrNotOwner);
					}
					if p.operation != TaskOperation::Read
						&& (record.state.terminal() || record.state == TaskState::Unknown)
					{
						return Err(ObjectError::Terminal);
					}
					Reply::Bound(
						Some(record.generation),
						Some(record.context),
						record.execution_binding,
						Some(record.state),
					)
				}
			},
			Op::Check(cfg, p, stream) => {
				if let Some(task) = &p.task {
					let record = read_task(&mut tx, ns, &p.scope, task).await?;
					record.current(cfg, now)?;
					record.bound(p)?;
					if *stream && (record.state.terminal() || record.state == TaskState::Unknown) {
						return Err(ObjectError::Terminal);
					}
				} else if p.operation != TaskOperation::Create || !p.reserved || p.generation.is_some() {
					return Err(ObjectError::UnknownOrNotOwner);
				}
				Reply::Unit
			},
			Op::Finish(cfg, p, task, context, state, push) => {
				if !id(task) || !id(context) {
					return Err(ObjectError::ResponseBinding);
				}
				let encoded_state = serde_json::to_value(state)
					.map_err(unavailable)?
					.as_str()
					.ok_or(ObjectError::Unavailable)?
					.to_owned();
				if let Some((binding, result)) = push {
					if p.generation.is_none() || cfg.push.is_none() {
						return Err(ObjectError::Unsupported);
					}
					let settings = cfg
						.event_recovery
						.as_ref()
						.ok_or(ObjectError::EventStorage)?;
					let destination = serde_json::to_string(settings).map_err(unavailable)?;
					sqlx::query(
						"INSERT OR IGNORE INTO asp_push_outbox(namespace,source,serial) VALUES(?,?,0)",
					)
					.bind(ns)
					.bind(uuid::Uuid::new_v4().to_string())
					.execute(&mut *tx)
					.await
					.map_err(unavailable)?;
					push_metadata(&mut tx, ns).await?;
					let (source, serial, old_destination, occupied): (String, i64, Option<String>, bool) = sqlx::query_as(
						"SELECT source,serial,destination,pending IS NOT NULL FROM asp_push_outbox WHERE namespace=?")
						.bind(ns).fetch_one(&mut *tx).await.map_err(unavailable)?;
					if occupied {
						return Err(ObjectError::Capacity);
					}
					if old_destination.as_ref().is_some_and(|v| v != &destination) {
						return Err(ObjectError::EventStorage);
					}
					let serial = serial
						.checked_add(1)
						.filter(|s| *s > 0)
						.ok_or(ObjectError::Unavailable)?;
					let delivery = events::PushDelivery {
						source,
						serial: serial as u64,
						cursor: uuid::Uuid::new_v4().to_string(),
						millis: now,
						binding: binding.clone(),
						result: result.clone(),
					};
					delivery.validate()?;
					// Bound the complete durable envelope before updating either table.
					security_audit::StateJournal::encoded_len(&delivery, settings.max_event_bytes)
						.map_err(|_| ObjectError::EventStorage)?;
					settings.store()?.check_push_size(&delivery)?;
					let encoded = serde_json::to_string(&delivery).map_err(unavailable)?;
					sqlx::query(
						"UPDATE asp_push_outbox SET serial=?,destination=?,pending=? WHERE namespace=?",
					)
					.bind(serial)
					.bind(destination)
					.bind(encoded)
					.bind(ns)
					.execute(&mut *tx)
					.await
					.map_err(unavailable)?;
				}
				if p.generation.is_none() {
					if p.operation != TaskOperation::Create || !p.reserved || p.task.is_some() {
						return Err(ObjectError::ResponseBinding);
					}
					let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM asp_tasks WHERE namespace=?")
						.bind(ns)
						.fetch_one(&mut *tx)
						.await
						.map_err(unavailable)?;
					if count as usize >= cfg.max_tasks {
						return Err(ObjectError::Capacity);
					}
					let existing: i64 = sqlx::query_scalar(
						"SELECT COUNT(*) FROM asp_tasks WHERE namespace=? AND scope=? AND task=?",
					)
					.bind(ns)
					.bind(&p.scope)
					.bind(task)
					.fetch_one(&mut *tx)
					.await
					.map_err(unavailable)?;
					if existing != 0 {
						return Err(ObjectError::ResponseBinding);
					}
					let owners:Vec<String>=sqlx::query_scalar("SELECT owner FROM asp_tasks WHERE namespace=? AND scope=? AND context=? AND expires_ms>? AND created_ms>?")
                        .bind(ns).bind(&p.scope).bind(context).bind(now).bind(now.saturating_sub(cfg.retention_seconds as i64*1000))
                        .fetch_all(&mut *tx).await.map_err(unavailable)?;
					for owner in owners {
						let owner: Owner = serde_json::from_str(&owner).map_err(unavailable)?;
						if owner != p.owner {
							return Err(ObjectError::ResponseBinding);
						}
					}
					let next = generation.checked_add(1).ok_or(ObjectError::Unavailable)?;
					sqlx::query("UPDATE asp_namespaces SET generation=? WHERE namespace=?")
						.bind(next)
						.bind(ns)
						.execute(&mut *tx)
						.await
						.map_err(unavailable)?;
					sqlx::query("INSERT INTO asp_tasks(namespace,scope,task,context,owner,state,generation,created_ms,expires_ms,execution_binding) VALUES(?,?,?,?,?,?,?,?,?,?)")
                        .bind(ns).bind(&p.scope).bind(task).bind(context).bind(serde_json::to_string(&p.owner).map_err(unavailable)?)
                        .bind(encoded_state).bind(next).bind(now).bind(now.checked_add(cfg.retention_seconds as i64*1000).ok_or(ObjectError::Unavailable)?)
                        .bind(&p.execution_binding)
                        .execute(&mut *tx).await.map_err(unavailable)?;
					Reply::Finished(next as u64)
				} else {
					if p.task.as_deref() != Some(task) || p.context.as_deref() != Some(context) {
						return Err(ObjectError::ResponseBinding);
					}
					let record = read_task(&mut tx, ns, &p.scope, task).await?;
					record.current(cfg, now)?;
					record.bound(p)?;
					if record.state.terminal() && record.state != *state {
						return Err(ObjectError::Terminal);
					}
					let updated = sqlx::query(
						"UPDATE asp_tasks SET state=? WHERE namespace=? AND scope=? AND task=? AND generation=?",
					)
					.bind(encoded_state)
					.bind(ns)
					.bind(&p.scope)
					.bind(task)
					.bind(record.generation as i64)
					.execute(&mut *tx)
					.await
					.map_err(unavailable)?
					.rows_affected();
					if updated != 1 {
						return Err(ObjectError::UnknownOrNotOwner);
					}
					Reply::Finished(record.generation)
				}
			},
		};
		tx.commit().await.map_err(unavailable)?;
		Ok(reply)
	}
}
