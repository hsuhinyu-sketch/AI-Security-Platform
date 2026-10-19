//! Bounded, one-attempt Task cleanup commands. Outcomes are not backend idempotency proofs.
use crate::{a2a_objects::TaskState, execution_budget::BudgetError};
use std::{
	collections::HashMap,
	sync::{
		Arc, Mutex,
		atomic::{AtomicUsize, Ordering},
	},
};

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(default, rename_all = "camelCase", deny_unknown_fields)]
pub struct TaskCleanupConfig {
	pub grace_seconds: u64,
	pub timeout_seconds: u64,
	pub max_tasks: usize,
	pub max_attempts: usize,
	pub max_concurrent: usize,
}
impl Default for TaskCleanupConfig {
	fn default() -> Self {
		Self {
			grace_seconds: 300,
			timeout_seconds: 5,
			max_tasks: 32,
			max_attempts: 8,
			max_concurrent: 2,
		}
	}
}
impl TaskCleanupConfig {
	pub fn validate(&self) -> Result<(), String> {
		if !(1..=3600).contains(&self.grace_seconds)
			|| !(1..=30).contains(&self.timeout_seconds)
			|| !(1..=128).contains(&self.max_tasks)
			|| !(1..=self.max_tasks).contains(&self.max_attempts)
			|| !(1..=16.min(self.max_attempts)).contains(&self.max_concurrent)
		{
			return Err(
				"taskCleanup requires bounded timeoutSeconds, maxTasks, maxAttempts and maxConcurrent"
					.into(),
			);
		}
		Ok(())
	}
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum CleanupOutcome {
	InFlight,
	Confirmed,
	AlreadyTerminal,
	Rejected,
	Unknown,
	NotSent,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CleanupResult {
	pub outcome: CleanupOutcome,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub task_state: Option<TaskState>,
}
impl CleanupResult {
	pub fn new(outcome: CleanupOutcome) -> Self {
		Self {
			outcome,
			task_state: None,
		}
	}
}
pub enum CleanupAdmission {
	Existing(CleanupResult),
	New(Box<dyn CleanupLease>),
}
pub trait CleanupLease: Send + Sync {
	fn mark_sent(&mut self) -> Result<(), BudgetError>;
	fn finish(&mut self, result: CleanupResult) -> Result<(), BudgetError>;
}
pub trait CleanupLedger: Send + Sync {
	fn begin(&self, key: &str, terminal: Option<TaskState>) -> Result<CleanupAdmission, BudgetError>;
	fn active(&self) -> bool;
}
#[derive(Default)]
struct Book {
	records: HashMap<String, CleanupResult>,
	attempts: usize,
	concurrent: usize,
}
#[derive(Clone, Default, serde::Serialize, serde::Deserialize)]
pub(crate) struct CleanupSnapshot {
	pub records: HashMap<String, CleanupResult>,
	pub attempts: usize,
}
pub struct LocalCleanupLedger {
	config: TaskCleanupConfig,
	book: Arc<Mutex<Book>>,
	global_slots: Arc<AtomicUsize>,
}
impl LocalCleanupLedger {
	pub(crate) fn snapshot(&self) -> Result<CleanupSnapshot, BudgetError> {
		let book = self.book.lock().map_err(|_| BudgetError::Unavailable)?;
		Ok(CleanupSnapshot {
			records: book.records.clone(),
			attempts: book.attempts,
		})
	}
	pub(crate) fn restore(
		config: TaskCleanupConfig,
		mut snapshot: CleanupSnapshot,
		global_slots: Arc<AtomicUsize>,
	) -> Result<Self, BudgetError> {
		if snapshot.records.len() > config.max_tasks
			|| snapshot.attempts > config.max_attempts
			|| snapshot
				.records
				.keys()
				.any(|k| k.is_empty() || k.len() > 1024)
			|| snapshot
				.records
				.values()
				.filter(|r| r.outcome != CleanupOutcome::AlreadyTerminal)
				.count()
				> snapshot.attempts
		{
			return Err(BudgetError::Unavailable);
		}
		for result in snapshot.records.values_mut() {
			match result.outcome {
				CleanupOutcome::InFlight => *result = CleanupResult::new(CleanupOutcome::Unknown),
				CleanupOutcome::Confirmed if result.task_state == Some(TaskState::Canceled) => {},
				CleanupOutcome::AlreadyTerminal if result.task_state.is_some_and(|s| s.terminal()) => {},
				CleanupOutcome::Rejected | CleanupOutcome::Unknown | CleanupOutcome::NotSent
					if result.task_state.is_none() => {},
				_ => return Err(BudgetError::Unavailable),
			}
		}
		Ok(Self {
			config,
			book: Arc::new(Mutex::new(Book {
				records: snapshot.records,
				attempts: snapshot.attempts,
				concurrent: 0,
			})),
			global_slots,
		})
	}
	pub(crate) fn new(config: TaskCleanupConfig, global_slots: Arc<AtomicUsize>) -> Self {
		Self {
			config,
			book: Default::default(),
			global_slots,
		}
	}
}
struct Lease {
	key: String,
	book: Arc<Mutex<Book>>,
	global_slots: Arc<AtomicUsize>,
	sent: bool,
	done: bool,
}
impl CleanupLease for Lease {
	fn mark_sent(&mut self) -> Result<(), BudgetError> {
		if self.done || self.sent {
			return Err(BudgetError::InvalidContext);
		}
		let _book = self.book.lock().map_err(|_| BudgetError::Unavailable)?;
		self.sent = true;
		Ok(())
	}
	fn finish(&mut self, result: CleanupResult) -> Result<(), BudgetError> {
		let valid = match result.outcome {
			CleanupOutcome::Confirmed => self.sent && result.task_state == Some(TaskState::Canceled),
			CleanupOutcome::AlreadyTerminal => result.task_state.is_some_and(|s| s.terminal()),
			CleanupOutcome::Rejected | CleanupOutcome::Unknown => {
				self.sent && result.task_state.is_none()
			},
			CleanupOutcome::NotSent => !self.sent && result.task_state.is_none(),
			CleanupOutcome::InFlight => false,
		};
		if self.done || !valid {
			return Err(BudgetError::InvalidContext);
		}
		let mut book = self.book.lock().map_err(|_| BudgetError::Unavailable)?;
		*book
			.records
			.get_mut(&self.key)
			.ok_or(BudgetError::Unavailable)? = result;
		book.concurrent = book.concurrent.saturating_sub(1);
		self.global_slots.fetch_sub(1, Ordering::AcqRel);
		self.done = true;
		Ok(())
	}
}

impl Drop for Lease {
	fn drop(&mut self) {
		if !self.done {
			let outcome = if self.sent {
				CleanupOutcome::Unknown
			} else {
				CleanupOutcome::NotSent
			};
			if self.finish(CleanupResult::new(outcome)).is_err() {
				// Poisoned local accounting remains fail closed, but does not poison other ledgers.
				self.global_slots.fetch_sub(1, Ordering::AcqRel);
			}
		}
	}
}
impl CleanupLedger for LocalCleanupLedger {
	fn active(&self) -> bool {
		self.book.lock().map_or(true, |b| b.concurrent != 0)
	}
	fn begin(&self, key: &str, terminal: Option<TaskState>) -> Result<CleanupAdmission, BudgetError> {
		self
			.config
			.validate()
			.map_err(|_| BudgetError::InvalidContext)?;
		if key.is_empty() || key.len() > 1024 || terminal.is_some_and(|s| !s.terminal()) {
			return Err(BudgetError::InvalidContext);
		}
		let mut book = self.book.lock().map_err(|_| BudgetError::Unavailable)?;
		if let Some(result) = book.records.get(key) {
			return Ok(CleanupAdmission::Existing(*result));
		}
		if book.records.len() >= self.config.max_tasks {
			return Err(BudgetError::Capacity);
		}
		if let Some(state) = terminal {
			let result = CleanupResult {
				outcome: CleanupOutcome::AlreadyTerminal,
				task_state: Some(state),
			};
			book.records.insert(key.into(), result);
			return Ok(CleanupAdmission::Existing(result));
		}
		// A prepared attempt is consumed even when a later dispatch check refuses it.
		if book.attempts >= self.config.max_attempts || book.concurrent >= self.config.max_concurrent {
			return Err(BudgetError::Capacity);
		}
		self
			.global_slots
			.fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| {
				n.checked_add(1).filter(|n| *n <= 256)
			})
			.map_err(|_| BudgetError::Capacity)?;
		book.concurrent += 1;
		book.attempts += 1;
		book
			.records
			.insert(key.into(), CleanupResult::new(CleanupOutcome::InFlight));
		Ok(CleanupAdmission::New(Box::new(Lease {
			key: key.into(),
			book: self.book.clone(),
			global_slots: self.global_slots.clone(),
			sent: false,
			done: false,
		})))
	}
}
