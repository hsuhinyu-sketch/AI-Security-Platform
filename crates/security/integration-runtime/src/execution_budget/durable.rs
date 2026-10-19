//! Single-writer execution recovery. Persist admissions before acknowledging them; never replay
//! network operations. The private directory is a deployment trust boundary, not cryptographic
//! rollback protection. Disk work is synchronous because ExecutionLedger is synchronous.
use super::*;
use crate::task_cleanup::{CleanupAdmission, CleanupLease, CleanupResult, CleanupSnapshot};
use serde::{Deserialize, Serialize};
use std::{
	fs::{File, OpenOptions},
	io::{BufRead, BufReader, Write},
	path::{Path, PathBuf},
	sync::{OnceLock, Weak},
};

const VERSION: u32 = 1;
const MAX_LINE: usize = 1_048_576;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "camelCase", deny_unknown_fields)]
pub enum ExecutionStorageConfig {
	Journal {
		path: PathBuf,
		#[serde(default = "max_bytes", rename = "maxBytes")]
		max_bytes: u64,
	},
}
fn max_bytes() -> u64 {
	67_108_864
}
impl ExecutionStorageConfig {
	pub fn validate(&self) -> Result<(), String> {
		let Self::Journal { path, max_bytes } = self;
		if !path.is_absolute()
			|| path.file_name().is_none()
			|| !(1_048_576..=1_073_741_824).contains(max_bytes)
		{
			return Err(
				"execution storage requires an absolute journal path and maxBytes in 1048576..=1073741824"
					.into(),
			);
		}
		Ok(())
	}
}

#[derive(Clone, Default)]
pub struct ExecutionStoreSlot(Arc<OnceLock<Arc<dyn ExecutionBudgetStore>>>);
impl std::fmt::Debug for ExecutionStoreSlot {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.debug_struct("ExecutionStoreSlot")
			.field("initialized", &self.0.get().is_some())
			.finish()
	}
}
impl ExecutionBudgetConfig {
	pub fn prepare_store(&mut self) -> Result<(), String> {
		self.validate()?;
		if let Some(spec) = &self.storage {
			let store = DurableExecutionBudgetStore::open(spec.clone(), &self.namespace)?;
			// Reinitialization cannot keep a stale handle after a changed storage declaration.
			let slot = OnceLock::new();
			let _ = slot.set(store as Arc<dyn ExecutionBudgetStore>);
			self.store = ExecutionStoreSlot(Arc::new(slot));
		} else {
			self.store = Default::default();
		}
		Ok(())
	}
	pub fn prepared_store(&self) -> Result<Option<Arc<dyn ExecutionBudgetStore>>, BudgetError> {
		match &self.storage {
			None => Ok(None),
			Some(_) => self
				.store
				.0
				.get()
				.cloned()
				.map(Some)
				.ok_or(BudgetError::Unavailable),
		}
	}
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Entry {
	version: u32,
	sequence: u64,
	millis: i64,
	change: Change,
}
#[derive(Serialize, Deserialize)]
#[serde(tag = "kind", deny_unknown_fields)]
enum Change {
	Init { namespace: String },
	Workflow { snapshot: Snapshot },
	Checkpoint,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Snapshot {
	id: String,
	owner: VerifiedOwner,
	fingerprint: String,
	config: ExecutionBudgetConfig,
	expires_ms: i64,
	cancelled: bool,
	usage: Usage,
	invocations: HashMap<String, Invocation>,
	cleanup: Option<CleanupSnapshot>,
}

struct Journal {
	file: File,
	path: PathBuf,
	max_bytes: u64,
	sequence: u64,
	highwater: i64,
	healthy: bool,
	failure: CancellationToken,
}
impl Journal {
	fn check(&mut self) -> Result<i64, BudgetError> {
		let now = chrono::Utc::now().timestamp_millis();
		let valid = self.healthy && now >= self.highwater && same_file(&self.file, &self.path);
		if !valid {
			self.healthy = false;
			self.failure.cancel();
			return Err(BudgetError::Unavailable);
		}
		Ok(now)
	}
	fn append(&mut self, change: Change) -> Result<(), BudgetError> {
		let now = self.check()?;
		let sequence = self
			.sequence
			.checked_add(1)
			.ok_or(BudgetError::Unavailable)?;
		let mut bytes = serde_json::to_vec(&Entry {
			version: VERSION,
			sequence,
			millis: now,
			change,
		})
		.map_err(|_| BudgetError::Unavailable)?;
		bytes.push(b'\n');
		let result = (|| -> std::io::Result<()> {
			if bytes.len() > MAX_LINE
				|| self
					.file
					.metadata()?
					.len()
					.saturating_add(bytes.len() as u64)
					> self.max_bytes
			{
				return Err(std::io::Error::other("execution journal capacity exceeded"));
			}
			self.file.write_all(&bytes)?;
			self.file.sync_data()
		})();
		if result.is_err() {
			self.healthy = false;
			self.failure.cancel();
			return Err(BudgetError::Unavailable);
		}
		self.sequence = sequence;
		self.highwater = now;
		Ok(())
	}
}

struct State {
	memory: InMemoryExecutionBudgetStore,
	expirations: HashMap<String, i64>,
	journal: Journal,
}
impl State {
	fn persist(&mut self, record: &Record) -> Result<(), BudgetError> {
		let usage = *record.usage.lock().map_err(|_| BudgetError::Unavailable)?;
		let snapshot = Snapshot {
			id: record.id.clone(),
			owner: record.owner.clone(),
			fingerprint: record.fingerprint.clone(),
			config: record.config.clone(),
			expires_ms: *self
				.expirations
				.get(&record.id)
				.ok_or(BudgetError::Unavailable)?,
			cancelled: record.cancellation.is_cancelled(),
			usage: Usage {
				concurrent: 0,
				..usage
			},
			invocations: record
				.invocations
				.lock()
				.map_err(|_| BudgetError::Unavailable)?
				.clone(),
			cleanup: record.cleanup.as_ref().map(|c| c.snapshot()).transpose()?,
		};
		self.journal.append(Change::Workflow { snapshot })
	}
}

pub struct DurableExecutionBudgetStore {
	namespace: String,
	spec: ExecutionStorageConfig,
	state: Arc<Mutex<State>>,
}
type Registry = HashMap<PathBuf, Weak<DurableExecutionBudgetStore>>;
static STORES: OnceLock<Mutex<Registry>> = OnceLock::new();

impl DurableExecutionBudgetStore {
	pub fn open(spec: ExecutionStorageConfig, namespace: &str) -> Result<Arc<Self>, String> {
		spec.validate()?;
		if namespace.is_empty() || namespace.trim() != namespace || namespace.len() > 128 {
			return Err("invalid execution storage namespace".into());
		}
		let ExecutionStorageConfig::Journal { path, max_bytes } = &spec;
		let parent = path
			.parent()
			.ok_or("missing execution journal parent")?
			.canonicalize()
			.map_err(|_| "execution journal parent must exist")?;
		let canonical = parent.join(path.file_name().ok_or("missing journal name")?);
		let mut registry = STORES
			.get_or_init(Default::default)
			.lock()
			.map_err(|_| "execution store registry unavailable")?;
		registry.retain(|_, v| v.strong_count() > 0);
		if let Some(existing) = registry.get(&canonical).and_then(Weak::upgrade) {
			if existing.namespace != namespace || existing.spec != spec {
				return Err("execution journal already open with different namespace or limits".into());
			}
			existing
				.state
				.lock()
				.map_err(|_| "execution store unavailable")?
				.journal
				.check()
				.map_err(|_| "execution store unavailable")?;
			return Ok(existing);
		}
		let (mut file, fresh) = open_file(&canonical)?;
		file
			.try_lock()
			.map_err(|_| "execution journal already locked")?;
		if !same_file(&file, &canonical) {
			return Err("execution journal file identity/permissions invalid".into());
		}
		if file
			.metadata()
			.map_err(|_| "execution journal metadata unavailable")?
			.len()
			> *max_bytes
		{
			return Err("execution journal exceeds maxBytes".into());
		}
		let now_ms = chrono::Utc::now().timestamp_millis();
		let mut sequence = 0u64;
		let mut highwater = 0i64;
		let mut snapshots = HashMap::new();
		{
			let mut reader = BufReader::new(&mut file);
			loop {
				let mut line = Vec::new();
				// Bounded reads, including malformed files without newline.
				use std::io::Read;
				let count = reader
					.by_ref()
					.take((MAX_LINE + 1) as u64)
					.read_until(b'\n', &mut line)
					.map_err(|_| "execution journal read failed")?;
				if count == 0 {
					break;
				}
				if count > MAX_LINE || line.last() != Some(&b'\n') {
					return Err("truncated/oversized execution journal record".into());
				}
				let entry: Entry =
					serde_json::from_slice(&line).map_err(|_| "invalid execution journal record")?;
				if entry.version != VERSION
					|| Some(entry.sequence) != sequence.checked_add(1)
					|| entry.millis < highwater
					|| entry.millis > now_ms
				{
					return Err("execution journal version/sequence/clock mismatch".into());
				}
				match entry.change {
					Change::Init { namespace: found } if sequence == 0 && found == namespace => {},
					Change::Workflow { snapshot } if sequence > 0 => {
						validate_snapshot(&snapshot, namespace)?;
						if snapshot.expires_ms
							> entry
								.millis
								.saturating_add(snapshot.config.max_duration_seconds as i64 * 1000)
						{
							return Err("execution deadline exceeds its original budget".into());
						}
						if let Some(previous) = snapshots.get(&snapshot.id) {
							validate_transition(previous, &snapshot)?;
						}
						let until = snapshot.expires_ms.saturating_add(
							snapshot
								.config
								.task_cleanup
								.as_ref()
								.map_or(0, |c| c.grace_seconds as i64 * 1000),
						);
						if until > now_ms {
							snapshots.insert(snapshot.id.clone(), snapshot);
						} else {
							snapshots.remove(&snapshot.id);
						}
						if snapshots.len() > 16384 {
							return Err("execution journal context capacity exceeded".into());
						}
					},
					Change::Checkpoint if sequence > 0 => {},
					_ => return Err("execution journal requires a unique matching header".into()),
				}
				sequence = entry.sequence;
				highwater = entry.millis;
			}
		}
		if !fresh && sequence == 0 {
			return Err("existing execution journal has no header".into());
		}
		let memory = InMemoryExecutionBudgetStore::default();
		let mut expirations = HashMap::new();
		let now = Instant::now();
		for (_, mut snapshot) in snapshots {
			let delta = snapshot.expires_ms - now_ms;
			let deadline = if delta >= 0 {
				now.checked_add(Duration::from_millis(delta as u64))
			} else {
				now.checked_sub(Duration::from_millis(delta.unsigned_abs()))
			}
			.ok_or("invalid execution deadline")?;
			let cancellation = CancellationToken::new();
			if snapshot.cancelled {
				cancellation.cancel();
			}
			let cleanup = match (snapshot.config.task_cleanup.clone(), snapshot.cleanup) {
				(Some(config), Some(book)) => Some(Arc::new(
					crate::task_cleanup::LocalCleanupLedger::restore(config, book, memory.2.clone())
						.map_err(|_| "invalid cleanup recovery")?,
				)),
				(None, None) => None,
				_ => return Err("cleanup recovery configuration mismatch".into()),
			};
			let invocation_count = snapshot.invocations.len();
			for invocation in snapshot.invocations.values_mut() {
				if invocation.claimed
					&& (invocation.receipt.is_none()
						|| invocation
							.receipt
							.as_ref()
							.is_some_and(|r| r.state == InvocationState::Accepted))
				{
					invocation.receipt = Some(InvocationReceipt::unknown());
				}
			}
			memory.1.fetch_add(invocation_count, Ordering::AcqRel);
			if memory.1.load(Ordering::Acquire) > 65536 {
				return Err("execution invocation capacity exceeded".into());
			}
			let record = Arc::new(Record {
				cleanup,
				cancellation,
				invocations: Mutex::new(snapshot.invocations),
				invocation_slots: memory.1.clone(),
				id: snapshot.id,
				owner: snapshot.owner,
				fingerprint: snapshot.fingerprint,
				config: snapshot.config,
				deadline,
				usage: Arc::new(Mutex::new(Usage {
					concurrent: 0,
					..snapshot.usage
				})),
			});
			expirations.insert(record.id.clone(), snapshot.expires_ms);
			memory
				.0
				.lock()
				.map_err(|_| "execution table unavailable")?
				.insert(record.id.clone(), record);
		}
		let mut journal = Journal {
			file,
			path: canonical.clone(),
			max_bytes: *max_bytes,
			sequence,
			highwater,
			healthy: true,
			failure: CancellationToken::new(),
		};
		journal
			.append(if fresh {
				Change::Init {
					namespace: namespace.into(),
				}
			} else {
				Change::Checkpoint
			})
			.map_err(|_| "execution journal startup commit failed")?;
		if fresh {
			File::open(parent)
				.and_then(|f| f.sync_all())
				.map_err(|_| "execution journal directory sync failed")?;
		}
		let result = Arc::new(Self {
			namespace: namespace.into(),
			spec,
			state: Arc::new(Mutex::new(State {
				memory,
				expirations,
				journal,
			})),
		});
		registry.insert(canonical, Arc::downgrade(&result));
		Ok(result)
	}
	fn wrap(&self, inner: Arc<Record>) -> ExecutionHandle {
		Arc::new(DurableRecord {
			inner,
			state: self.state.clone(),
		})
	}
}

fn validate_snapshot(s: &Snapshot, namespace: &str) -> Result<(), String> {
	s.config.validate()?;
	if s.config.namespace != namespace
		|| uuid::Uuid::parse_str(&s.id).is_err()
		|| s.fingerprint.is_empty()
		|| s.expires_ms <= 0
		|| VerifiedOwner::from_identity(&s.owner.identity(), &s.owner.issuer).as_ref() != Ok(&s.owner)
		|| s.usage.concurrent != 0
		|| s.usage.attempts > s.config.max_attempts
		|| s.usage.model_calls > s.config.max_model_calls
		|| s.usage.tool_calls > s.config.max_tool_calls
		|| s.usage.agent_calls > s.config.max_agent_calls
		|| s.invocations.len() > s.config.max_invocations
		|| s.invocations.iter().any(|(id, v)| {
			uuid::Uuid::parse_str(id).is_err()
				|| v.target.is_empty()
				|| v.target.len() > 1024
				|| v.arguments_hash.len() != 64
				|| !v.arguments_hash.bytes().all(|b| b.is_ascii_hexdigit())
				|| v
					.task_binding
					.as_ref()
					.is_some_and(|b| !v.claimed || b.len() != 64 || !b.bytes().all(|c| c.is_ascii_hexdigit()))
				|| v
					.receipt
					.as_ref()
					.is_some_and(|r| r.state == InvocationState::Accepted && v.task_binding.is_none())
				|| v
					.receipt
					.as_ref()
					.is_some_and(|r| !v.claimed || !valid_receipt(r))
		}) {
		return Err("invalid execution snapshot bindings or counters".into());
	}
	Ok(())
}
fn valid_receipt(receipt: &InvocationReceipt) -> bool {
	match receipt.state {
		InvocationState::Accepted => receipt.result_hash.is_none() && receipt.tool_error.is_none(),
		InvocationState::Returned => {
			receipt
				.result_hash
				.as_ref()
				.is_some_and(|h| h.len() == 64 && h.bytes().all(|b| b.is_ascii_hexdigit()))
				&& receipt.tool_error.is_some()
		},
		InvocationState::Unknown => receipt.result_hash.is_none() && receipt.tool_error.is_none(),
		_ => false,
	}
}
fn validate_transition(previous: &Snapshot, next: &Snapshot) -> Result<(), String> {
	let stable = previous.owner == next.owner
		&& previous.fingerprint == next.fingerprint
		&& previous.expires_ms == next.expires_ms
		&& serde_json::to_value(&previous.config).ok() == serde_json::to_value(&next.config).ok();
	let counters = previous.usage.model_calls <= next.usage.model_calls
		&& previous.usage.tool_calls <= next.usage.tool_calls
		&& previous.usage.agent_calls <= next.usage.agent_calls
		&& previous.usage.attempts <= next.usage.attempts;
	let calls = previous.invocations.iter().all(|(id, old)| {
		next.invocations.get(id).is_some_and(|new| {
			old.target == new.target
				&& old.arguments_hash == new.arguments_hash
				&& (!old.claimed || new.claimed)
				&& old
					.task_binding
					.as_ref()
					.is_none_or(|b| Some(b) == new.task_binding.as_ref())
				&& old.receipt.as_ref().is_none_or(|r| {
					Some(r) == new.receipt.as_ref()
						|| (r.state == InvocationState::Accepted
							&& new.receipt.as_ref().is_some_and(|n| {
								matches!(
									n.state,
									InvocationState::Returned | InvocationState::Unknown
								)
							}))
				})
		})
	});
	let cleanup = match (&previous.cleanup, &next.cleanup) {
		(None, None) => true,
		(Some(old), Some(new)) => {
			old.attempts <= new.attempts
				&& old.records.iter().all(|(key, result)| {
					new.records.get(key).is_some_and(|n| {
						result == n || result.outcome == crate::task_cleanup::CleanupOutcome::InFlight
					})
				})
		},
		_ => false,
	};
	if !stable || !counters || !calls || !cleanup || (previous.cancelled && !next.cancelled) {
		return Err("execution snapshot rebind/regression".into());
	}
	Ok(())
}

fn open_file(path: &Path) -> Result<(File, bool), String> {
	let mut options = OpenOptions::new();
	options.create_new(true).read(true).append(true);
	#[cfg(unix)]
	{
		use std::os::unix::fs::OpenOptionsExt;
		options.mode(0o600);
	}
	match options.open(path) {
		Ok(file) => Ok((file, true)),
		Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
			let metadata = std::fs::symlink_metadata(path).map_err(|_| "execution file unavailable")?;
			if !metadata.file_type().is_file() {
				return Err("execution journal must be a regular non-symlink file".into());
			}
			OpenOptions::new()
				.read(true)
				.append(true)
				.open(path)
				.map(|f| (f, false))
				.map_err(|_| "execution file unavailable".into())
		},
		Err(_) => Err("cannot create execution journal; provision its private directory first".into()),
	}
}
fn same_file(file: &File, path: &Path) -> bool {
	let (Ok(open), Ok(current)) = (file.metadata(), std::fs::symlink_metadata(path)) else {
		return false;
	};
	if !current.is_file() || current.file_type().is_symlink() {
		return false;
	}
	#[cfg(unix)]
	{
		use std::os::unix::fs::MetadataExt;
		open.dev() == current.dev()
			&& open.ino() == current.ino()
			&& current.mode() & 0o077 == 0
			&& current.nlink() == 1
	}
	#[cfg(not(unix))]
	{
		let _ = open;
		true
	}
}

impl ExecutionBudgetStore for DurableExecutionBudgetStore {
	fn create(
		&self,
		config: &ExecutionBudgetConfig,
		owner: VerifiedOwner,
		fingerprint: String,
	) -> Result<ExecutionHandle, BudgetError> {
		if config.namespace != self.namespace || config.storage.as_ref() != Some(&self.spec) {
			return Err(BudgetError::InvalidContext);
		}
		let mut state = self.state.lock().map_err(|_| BudgetError::Unavailable)?;
		let now = state.journal.check()?;
		let handle = state.memory.create(config, owner, fingerprint)?;
		let record = state
			.memory
			.0
			.lock()
			.map_err(|_| BudgetError::Unavailable)?
			.get(handle.id())
			.cloned()
			.ok_or(BudgetError::Unavailable)?;
		state.expirations.insert(
			record.id.clone(),
			now + config.max_duration_seconds as i64 * 1000,
		);
		state.persist(&record)?;
		record.check_active()?;
		// Bound metadata as well as the core table; no old records can regain a new deadline.
		let live = state
			.memory
			.0
			.lock()
			.map_err(|_| BudgetError::Unavailable)?
			.keys()
			.cloned()
			.collect::<std::collections::HashSet<_>>();
		state.expirations.retain(|id, _| live.contains(id));
		Ok(self.wrap(record))
	}
	fn resolve(
		&self,
		id: &str,
		config: &ExecutionBudgetConfig,
		owner: &VerifiedOwner,
		fingerprint: &str,
	) -> Result<ExecutionHandle, BudgetError> {
		let record = self.resolve_for_control(id, config, owner, fingerprint)?;
		record.check_active()?;
		Ok(record)
	}
	fn resolve_for_control(
		&self,
		id: &str,
		config: &ExecutionBudgetConfig,
		owner: &VerifiedOwner,
		fingerprint: &str,
	) -> Result<ExecutionHandle, BudgetError> {
		if config.namespace != self.namespace || config.storage.as_ref() != Some(&self.spec) {
			return Err(BudgetError::InvalidContext);
		}
		let mut state = self.state.lock().map_err(|_| BudgetError::Unavailable)?;
		state.journal.check()?;
		state
			.memory
			.resolve_for_control(id, config, owner, fingerprint)?;
		let record = state
			.memory
			.0
			.lock()
			.map_err(|_| BudgetError::Unavailable)?
			.get(id)
			.cloned()
			.ok_or(BudgetError::InvalidContext)?;
		// Persist time progress without re-authorizing or creating anything.
		state.journal.append(Change::Checkpoint)?;
		Ok(self.wrap(record))
	}
}

struct DurableRecord {
	inner: Arc<Record>,
	state: Arc<Mutex<State>>,
}
impl DurableRecord {
	fn read<T>(&self, f: impl FnOnce(&Record) -> Result<T, BudgetError>) -> Result<T, BudgetError> {
		let mut state = self.state.lock().map_err(|_| BudgetError::Unavailable)?;
		state.journal.check()?;
		f(&self.inner)
	}
	fn mutate<T>(&self, f: impl FnOnce(&Record) -> Result<T, BudgetError>) -> Result<T, BudgetError> {
		let mut state = self.state.lock().map_err(|_| BudgetError::Unavailable)?;
		state.journal.check()?;
		let result = f(&self.inner)?;
		state.persist(&self.inner)?;
		Ok(result)
	}
}
impl ExecutionLedger for DurableRecord {
	fn accept_invocation(&self, id: &str, binding: &str) -> Result<(), BudgetError> {
		self.mutate(|r| r.accept_invocation(id, binding))?;
		self.read(|r| r.check_active())
	}
	fn invocation_receipt(&self, id: &str) -> Result<InvocationReceipt, BudgetError> {
		self.read(|r| r.invocation_receipt(id))
	}
	fn finish_invocation(&self, id: &str, receipt: InvocationReceipt) -> Result<(), BudgetError> {
		self.mutate(|r| r.finish_invocation(id, receipt))
	}
	fn id(&self) -> &str {
		self.inner.id()
	}
	fn deadline(&self) -> Instant {
		self.inner.deadline()
	}
	fn cancellation(&self) -> ExecutionCancellation {
		let original = self.inner.cancellation();
		let failure = match self.state.lock() {
			Ok(s) => s.journal.failure.clone(),
			Err(_) => return Box::pin(async {}),
		};
		Box::pin(async move {
			tokio::select! { _ = original => {}, _ = failure.cancelled_owned() => {} }
		})
	}
	fn state(&self) -> Result<ExecutionState, BudgetError> {
		self.read(|r| r.state())
	}
	fn usage(&self) -> Result<Usage, BudgetError> {
		self.read(|r| r.usage())
	}
	fn cancel(&self) -> Result<ExecutionState, BudgetError> {
		self.mutate(|r| r.cancel())
	}
	fn issue_invocation(&self, target: &str, hash: &str) -> Result<String, BudgetError> {
		let id = self.mutate(|r| r.issue_invocation(target, hash))?;
		self.read(|r| r.check_active())?;
		Ok(id)
	}
	fn claim_invocation(&self, id: &str, target: &str, hash: &str) -> Result<(), BudgetError> {
		self.mutate(|r| r.claim_invocation(id, target, hash))?;
		self.read(|r| r.check_active())
	}
	fn reserve(
		&self,
		kind: CallKind,
		logical: &LogicalCharge,
	) -> Result<Box<dyn ExecutionLease>, BudgetError> {
		let lease = self.mutate(|r| r.reserve(kind, logical))?;
		self.read(|r| r.check_active())?;
		Ok(lease)
	}
	fn cleanup_deadline(&self) -> Result<Instant, BudgetError> {
		self.read(|r| r.cleanup_deadline())
	}
	fn cleanup(&self) -> Result<Arc<dyn CleanupLedger>, BudgetError> {
		self.read(|r| {
			r.cleanup().map(|inner| {
				Arc::new(DurableCleanup {
					record: self.inner.clone(),
					state: self.state.clone(),
					inner,
				}) as Arc<dyn CleanupLedger>
			})
		})
	}
}
struct DurableCleanup {
	record: Arc<Record>,
	state: Arc<Mutex<State>>,
	inner: Arc<dyn CleanupLedger>,
}
impl CleanupLedger for DurableCleanup {
	fn active(&self) -> bool {
		self.inner.active()
	}
	fn begin(
		&self,
		key: &str,
		terminal: Option<crate::a2a_objects::TaskState>,
	) -> Result<CleanupAdmission, BudgetError> {
		let mut state = self.state.lock().map_err(|_| BudgetError::Unavailable)?;
		state.journal.check()?;
		if Instant::now() >= self.record.cleanup_deadline()? {
			return Err(BudgetError::Deadline);
		}
		let admission = self.inner.begin(key, terminal)?;
		state.persist(&self.record)?;
		Ok(match admission {
			CleanupAdmission::Existing(result) => CleanupAdmission::Existing(result),
			CleanupAdmission::New(lease) => CleanupAdmission::New(Box::new(DurableCleanupLease {
				record: self.record.clone(),
				state: self.state.clone(),
				inner: Some(lease),
			})),
		})
	}
}
struct DurableCleanupLease {
	record: Arc<Record>,
	state: Arc<Mutex<State>>,
	inner: Option<Box<dyn CleanupLease>>,
}
impl CleanupLease for DurableCleanupLease {
	fn mark_sent(&mut self) -> Result<(), BudgetError> {
		let mut state = self.state.lock().map_err(|_| BudgetError::Unavailable)?;
		state.journal.check()?;
		if Instant::now() >= self.record.cleanup_deadline()? {
			return Err(BudgetError::Deadline);
		}
		self
			.inner
			.as_mut()
			.ok_or(BudgetError::Unavailable)?
			.mark_sent()?;
		state.persist(&self.record)
	}
	fn finish(&mut self, result: CleanupResult) -> Result<(), BudgetError> {
		let mut state = self.state.lock().map_err(|_| BudgetError::Unavailable)?;
		state.journal.check()?;
		self
			.inner
			.as_mut()
			.ok_or(BudgetError::Unavailable)?
			.finish(result)?;
		state.persist(&self.record)
	}
}
impl Drop for DurableCleanupLease {
	fn drop(&mut self) {
		if let Ok(mut state) = self.state.lock() {
			drop(self.inner.take());
			if state.journal.healthy && state.persist(&self.record).is_err() {
				state.journal.healthy = false;
			}
		}
	}
}
