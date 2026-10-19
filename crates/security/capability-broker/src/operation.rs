//! Backend-side admission and receipts. Install at the real side-effect boundary, after current
//! authentication/authorization. A pending record is flushed BEFORE handing the permit to the
//! business handler. Unknown work is never automatically retried; this is not a distributed
//! transaction between the ledger and an external business database.
use security_audit::JsonlJournal;
use serde::{Deserialize, Serialize};
use std::{
	collections::HashMap,
	fs::{File, Metadata},
	path::{Path, PathBuf},
	sync::{Arc, Mutex},
};

pub struct AuthorizedToolOperation {
	key: String,
	binding: String,
}
impl AuthorizedToolOperation {
	pub fn key(&self) -> &str {
		&self.key
	}
	pub(super) fn new(key: String, binding: String) -> Self {
		Self { key, binding }
	}
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "camelCase", deny_unknown_fields)]
pub enum OperationOutcome {
	InFlight,
	Completed { result_hash: String },
	Unknown,
}
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum OperationError {
	#[error("operation binding mismatch")]
	Binding,
	#[error("operation capacity exceeded")]
	Capacity,
	#[error("operation journal unavailable")]
	Unavailable,
}
pub enum OperationAdmission {
	New(OperationPermit),
	Existing(OperationOutcome),
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Event {
	version: u32,
	sequence: usize,
	key: String,
	binding: String,
	outcome: OperationOutcome,
}
struct State {
	journal: JsonlJournal,
	path: PathBuf,
	identity: Metadata,
	records: HashMap<String, (String, OperationOutcome)>,
	sequence: usize,
	max_operations: usize,
	healthy: bool,
}
impl State {
	fn check(&mut self) -> Result<(), OperationError> {
		let valid = std::fs::symlink_metadata(&self.path)
			.is_ok_and(|metadata| protected_identity(&metadata, &self.identity));
		if !self.healthy || !valid {
			self.healthy = false;
			return Err(OperationError::Unavailable);
		}
		Ok(())
	}
	fn commit(
		&mut self,
		key: &str,
		binding: &str,
		outcome: OperationOutcome,
	) -> Result<(), OperationError> {
		self.check()?;
		if self.sequence >= self.max_operations * 2 + 1 {
			return Err(OperationError::Capacity);
		}
		let event = Event {
			version: 1,
			sequence: self.sequence + 1,
			key: key.into(),
			binding: binding.into(),
			outcome: outcome.clone(),
		};
		if self.journal.append(&event).is_err() {
			self.healthy = false;
			return Err(OperationError::Unavailable);
		}
		self.sequence += 1;
		self.records.insert(key.into(), (binding.into(), outcome));
		Ok(())
	}
}
#[derive(Clone)]
pub struct JournalOperationStore {
	state: Arc<Mutex<State>>,
}
impl JournalOperationStore {
	/// A dedicated, bounded file. No eviction/reset: provision a new store only after trusted
	/// reconciliation/retention. Keep the private parent directory; do not share the file.
	pub fn open(path: &Path, max_operations: usize) -> Result<Self, OperationError> {
		if !path.is_absolute() || !(1..=4096).contains(&max_operations) {
			return Err(OperationError::Capacity);
		}
		let existing = std::fs::symlink_metadata(path).ok();
		if existing
			.as_ref()
			.is_some_and(|m| !protected_identity(m, m) || m.len() > 8_388_608)
		{
			return Err(OperationError::Unavailable);
		}
		let (mut journal, mut events) = JsonlJournal::open::<Event>(path, max_operations * 2 + 1)
			.map_err(|_| OperationError::Unavailable)?;
		if existing.is_none() {
			let header = Event {
				version: 1,
				sequence: 1,
				key: String::new(),
				binding: format!("capacity:{max_operations}"),
				outcome: OperationOutcome::Unknown,
			};
			journal
				.append(&header)
				.map_err(|_| OperationError::Unavailable)?;
			events.push_back(header);
		}
		let identity = std::fs::symlink_metadata(path).map_err(|_| OperationError::Unavailable)?;
		if !protected_identity(&identity, &identity) {
			return Err(OperationError::Unavailable);
		}
		let mut records: HashMap<String, (String, OperationOutcome)> = HashMap::new();
		let mut sequence = 0;
		for event in events {
			if sequence == 0 {
				if event.version != 1
					|| event.sequence != 1
					|| !event.key.is_empty()
					|| event.binding != format!("capacity:{max_operations}")
					|| event.outcome != OperationOutcome::Unknown
				{
					return Err(OperationError::Unavailable);
				}
				sequence = 1;
				continue;
			}
			if event.version != 1
				|| event.sequence != sequence + 1
				|| !valid_hash(&event.key)
				|| !valid_hash(&event.binding)
			{
				return Err(OperationError::Unavailable);
			}
			let previous = records.get(&event.key);
			match (&event.outcome, previous) {
				(OperationOutcome::InFlight, None) => {},
				(
					OperationOutcome::Completed { result_hash },
					Some((binding, OperationOutcome::InFlight)),
				) if binding == &event.binding && valid_hash(result_hash) => {},
				(OperationOutcome::Unknown, Some((binding, OperationOutcome::InFlight)))
					if binding == &event.binding => {},
				_ => return Err(OperationError::Unavailable),
			}
			sequence = event.sequence;
			records.insert(event.key, (event.binding, event.outcome));
		}
		if sequence == 0 {
			return Err(OperationError::Unavailable);
		}
		if records.len() > max_operations {
			return Err(OperationError::Capacity);
		}
		for (_, outcome) in records.values_mut() {
			if *outcome == OperationOutcome::InFlight {
				*outcome = OperationOutcome::Unknown;
			}
		}
		if existing.is_none() {
			File::open(path.parent().ok_or(OperationError::Unavailable)?)
				.and_then(|f| f.sync_all())
				.map_err(|_| OperationError::Unavailable)?;
		}
		Ok(Self {
			state: Arc::new(Mutex::new(State {
				journal,
				path: path.into(),
				identity,
				records,
				sequence,
				max_operations,
				healthy: true,
			})),
		})
	}
	pub fn begin(
		&self,
		operation: &AuthorizedToolOperation,
	) -> Result<OperationAdmission, OperationError> {
		let mut state = self.state.lock().map_err(|_| OperationError::Unavailable)?;
		state.check()?;
		if let Some((binding, outcome)) = state.records.get(&operation.key) {
			if binding != &operation.binding {
				return Err(OperationError::Binding);
			}
			return Ok(OperationAdmission::Existing(outcome.clone()));
		}
		if state.records.len() >= state.max_operations {
			return Err(OperationError::Capacity);
		}
		// Each pending command needs one reserved final-event slot; no unbounded history.
		state.commit(
			&operation.key,
			&operation.binding,
			OperationOutcome::InFlight,
		)?;
		Ok(OperationAdmission::New(OperationPermit {
			state: self.state.clone(),
			key: operation.key.clone(),
			binding: operation.binding.clone(),
			finished: false,
		}))
	}
}
pub struct OperationPermit {
	state: Arc<Mutex<State>>,
	key: String,
	binding: String,
	finished: bool,
}
impl OperationPermit {
	/// Hash the actual result from the local business handler; never accept a client hash.
	/// A failed commit must be reported as uncertain, never as safe-to-retry.
	pub fn complete(mut self, result: &serde_json::Value) -> Result<(), OperationError> {
		let result_hash = super::consumer::arguments_hash(result);
		let mut state = self.state.lock().map_err(|_| OperationError::Unavailable)?;
		state.commit(
			&self.key,
			&self.binding,
			OperationOutcome::Completed { result_hash },
		)?;
		self.finished = true;
		Ok(())
	}
}
impl Drop for OperationPermit {
	fn drop(&mut self) {
		if !self.finished
			&& let Ok(mut state) = self.state.lock()
		{
			let _ = state.commit(&self.key, &self.binding, OperationOutcome::Unknown);
		}
	}
}
fn valid_hash(value: &str) -> bool {
	value.len() == 64 && value.bytes().all(|b| b.is_ascii_hexdigit())
}
fn protected_identity(current: &Metadata, original: &Metadata) -> bool {
	if !current.file_type().is_file() {
		return false;
	}
	#[cfg(unix)]
	{
		use std::os::unix::fs::MetadataExt;
		current.dev() == original.dev()
			&& current.ino() == original.ino()
			&& current.mode() & 0o077 == 0
			&& current.nlink() == 1
	}
	#[cfg(not(unix))]
	{
		let _ = original;
		true
	}
}
