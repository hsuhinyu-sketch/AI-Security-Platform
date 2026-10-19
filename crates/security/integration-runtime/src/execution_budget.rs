//! Local workflow accounting, not authorization or token billing. Failed/uncertain executions
//! never refund cumulative counters. Only the live concurrency lease is released.
use crate::identity_binding::VerifiedOwner;
use crate::task_cleanup::CleanupLedger;
use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio_util::sync::CancellationToken;

pub mod durable;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ExecutionBudgetConfig {
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub storage: Option<durable::ExecutionStorageConfig>,
	/// Initialized by the host; neither the handle nor recovered state comes from YAML.
	#[serde(skip)]
	pub store: durable::ExecutionStoreSlot,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub task_cleanup: Option<crate::task_cleanup::TaskCleanupConfig>,
	/// Server-issued business calls retained until the original workflow expires.
	#[serde(default = "invocations")]
	pub max_invocations: usize,
	pub namespace: String,
	#[serde(default = "duration")]
	pub max_duration_seconds: u64,
	#[serde(default = "contexts")]
	pub max_contexts: usize,
	#[serde(default = "per_owner")]
	pub max_contexts_per_owner: usize,
	pub max_model_calls: u64,
	pub max_tool_calls: u64,
	#[serde(default = "agent_calls")]
	pub max_agent_calls: u64,
	pub max_attempts: u64,
	pub max_concurrent: u64,
}
fn duration() -> u64 {
	300
}
fn contexts() -> usize {
	1024
}
fn per_owner() -> usize {
	16
}
fn agent_calls() -> u64 {
	32
}
fn invocations() -> usize {
	32
}
impl ExecutionBudgetConfig {
	pub fn validate(&self) -> Result<(), String> {
		if let Some(storage) = &self.storage {
			storage.validate()?;
		}
		if let Some(config) = &self.task_cleanup {
			config.validate()?;
		}
		if self.namespace.is_empty()
			|| !(1..=128).contains(&self.max_invocations)
			|| self.namespace.trim() != self.namespace
			|| self.namespace.len() > 128
			|| !(1..=86400).contains(&self.max_duration_seconds)
			|| !(1..=16384).contains(&self.max_contexts)
			|| !(1..=self.max_contexts).contains(&self.max_contexts_per_owner)
			|| self.max_attempts == 0
			|| self.max_concurrent == 0
			|| self.max_concurrent > self.max_attempts
		{
			return Err(
				"executionBudget requires bounded namespace, duration, capacity, attempts and concurrency"
					.into(),
			);
		}
		Ok(())
	}
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BudgetError {
	Cancelled,
	InvocationBinding,
	InvalidContext,
	Capacity,
	Deadline,
	ModelCalls,
	ToolCalls,
	AgentCalls,
	Attempts,
	Concurrency,
	Unavailable,
}
impl BudgetError {
	pub fn rule(self) -> &'static str {
		match self {
			Self::Cancelled => "cancelled",
			Self::InvocationBinding => "invocation-binding",
			Self::InvalidContext => "invalid-context",
			Self::Capacity => "capacity",
			Self::Deadline => "deadline",
			Self::ModelCalls => "model-calls",
			Self::ToolCalls => "tool-calls",
			Self::AgentCalls => "agent-calls",
			Self::Attempts => "attempts",
			Self::Concurrency => "concurrency",
			Self::Unavailable => "unavailable",
		}
	}
}
#[derive(Debug, Clone, Copy)]
pub enum CallKind {
	Model,
	Tool,
	Agent,
	Transport,
}
#[derive(Debug, Default)]
pub struct LogicalCharge(Mutex<[bool; 3]>);
#[derive(Debug, Clone, Copy, Default, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Usage {
	pub model_calls: u64,
	pub tool_calls: u64,
	pub agent_calls: u64,
	pub attempts: u64,
	pub concurrent: u64,
}

pub trait ExecutionLease: Send + Sync {}
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub enum ExecutionState {
	Active,
	Cancelled,
	Expired,
}
/// A read-only wake-up future, not a token that can bypass authorized cancellation.
pub type ExecutionCancellation =
	std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + 'static>>;
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum InvocationState {
	Issued,
	InFlight,
	Accepted,
	Returned,
	Unknown,
}
/// Returned means a validated Tool response was observed, not a committed business transaction.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct InvocationReceipt {
	pub state: InvocationState,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub result_hash: Option<String>,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub tool_error: Option<bool>,
}
impl InvocationReceipt {
	pub fn unknown() -> Self {
		Self {
			state: InvocationState::Unknown,
			result_hash: None,
			tool_error: None,
		}
	}
}
pub trait ExecutionLedger: Send + Sync {
	/// An asynchronous request was accepted, not completed. The binding is gateway-issued.
	fn accept_invocation(&self, _id: &str, _binding: &str) -> Result<(), BudgetError> {
		Err(BudgetError::InvocationBinding)
	}
	fn invocation_receipt(&self, _id: &str) -> Result<InvocationReceipt, BudgetError> {
		Err(BudgetError::InvocationBinding)
	}
	fn finish_invocation(&self, _id: &str, _receipt: InvocationReceipt) -> Result<(), BudgetError> {
		Err(BudgetError::InvocationBinding)
	}
	fn cleanup_deadline(&self) -> Result<Instant, BudgetError> {
		Err(BudgetError::InvalidContext)
	}
	fn cleanup(&self) -> Result<Arc<dyn crate::task_cleanup::CleanupLedger>, BudgetError> {
		Err(BudgetError::InvalidContext)
	}
	fn state(&self) -> Result<ExecutionState, BudgetError>;
	fn cancel(&self) -> Result<ExecutionState, BudgetError>;
	fn cancellation(&self) -> ExecutionCancellation;
	fn check_active(&self) -> Result<(), BudgetError> {
		match self.state()? {
			ExecutionState::Active => Ok(()),
			ExecutionState::Cancelled => Err(BudgetError::Cancelled),
			ExecutionState::Expired => Err(BudgetError::Deadline),
		}
	}
	fn issue_invocation(&self, _target: &str, _arguments_hash: &str) -> Result<String, BudgetError> {
		Err(BudgetError::InvocationBinding)
	}
	fn claim_invocation(
		&self,
		_id: &str,
		_target: &str,
		_arguments_hash: &str,
	) -> Result<(), BudgetError> {
		Err(BudgetError::InvocationBinding)
	}
	fn id(&self) -> &str;
	fn deadline(&self) -> Instant;
	fn usage(&self) -> Result<Usage, BudgetError>;
	fn reserve(
		&self,
		kind: CallKind,
		logical: &LogicalCharge,
	) -> Result<Box<dyn ExecutionLease>, BudgetError>;
}
pub type ExecutionHandle = Arc<dyn ExecutionLedger>;
pub trait ExecutionBudgetStore: Send + Sync {
	/// Called only after a trusted execution/create authorization, never on unknown IDs.
	fn create(
		&self,
		config: &ExecutionBudgetConfig,
		owner: VerifiedOwner,
		fingerprint: String,
	) -> Result<ExecutionHandle, BudgetError>;
	fn resolve(
		&self,
		id: &str,
		config: &ExecutionBudgetConfig,
		owner: &VerifiedOwner,
		fingerprint: &str,
	) -> Result<ExecutionHandle, BudgetError>;
	/// Same owner/config binding, but no active-state or remaining-budget requirement.
	/// Only use after independent lifecycle authorization. Never creates a record.
	fn resolve_for_control(
		&self,
		id: &str,
		config: &ExecutionBudgetConfig,
		owner: &VerifiedOwner,
		fingerprint: &str,
	) -> Result<ExecutionHandle, BudgetError>;
}

#[derive(Default)]
pub struct InMemoryExecutionBudgetStore(
	Mutex<HashMap<String, Arc<Record>>>,
	Arc<AtomicUsize>,
	Arc<AtomicUsize>,
);
#[derive(Clone, serde::Serialize, serde::Deserialize)]
struct Invocation {
	target: String,
	arguments_hash: String,
	claimed: bool,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	task_binding: Option<String>,
	#[serde(default)]
	receipt: Option<InvocationReceipt>,
}
struct Record {
	cleanup: Option<Arc<crate::task_cleanup::LocalCleanupLedger>>,
	cancellation: CancellationToken,
	invocations: Mutex<HashMap<String, Invocation>>,
	invocation_slots: Arc<AtomicUsize>,
	id: String,
	owner: VerifiedOwner,
	fingerprint: String,
	config: ExecutionBudgetConfig,
	deadline: Instant,
	usage: Arc<Mutex<Usage>>,
}
impl Record {
	// All lifecycle changes and admissions serialize through usage. Token is private.
	fn state_locked(&self) -> ExecutionState {
		if self.cancellation.is_cancelled() {
			ExecutionState::Cancelled
		} else if Instant::now() >= self.deadline {
			ExecutionState::Expired
		} else {
			ExecutionState::Active
		}
	}
	fn active_locked(&self) -> Result<(), BudgetError> {
		match self.state_locked() {
			ExecutionState::Active => Ok(()),
			ExecutionState::Cancelled => Err(BudgetError::Cancelled),
			ExecutionState::Expired => Err(BudgetError::Deadline),
		}
	}
}
impl Drop for Record {
	fn drop(&mut self) {
		if let Ok(calls) = self.invocations.get_mut() {
			self
				.invocation_slots
				.fetch_sub(calls.len(), Ordering::AcqRel);
		}
	}
}
struct Lease(Arc<Mutex<Usage>>);
impl ExecutionLease for Lease {}
impl Drop for Lease {
	fn drop(&mut self) {
		if let Ok(mut usage) = self.0.lock() {
			usage.concurrent = usage.concurrent.saturating_sub(1);
		}
	}
}
impl ExecutionLedger for Record {
	fn accept_invocation(&self, id: &str, binding: &str) -> Result<(), BudgetError> {
		let _usage = self.usage.lock().map_err(|_| BudgetError::Unavailable)?;
		self.active_locked()?;
		if binding.len() != 64 || !binding.bytes().all(|b| b.is_ascii_hexdigit()) {
			return Err(BudgetError::InvocationBinding);
		}
		let mut calls = self
			.invocations
			.lock()
			.map_err(|_| BudgetError::Unavailable)?;
		let call = calls.get_mut(id).ok_or(BudgetError::InvocationBinding)?;
		if !call.claimed || call.receipt.is_some() || call.task_binding.is_some() {
			return Err(BudgetError::InvocationBinding);
		}
		call.task_binding = Some(binding.into());
		call.receipt = Some(InvocationReceipt {
			state: InvocationState::Accepted,
			result_hash: None,
			tool_error: None,
		});
		Ok(())
	}
	fn invocation_receipt(&self, id: &str) -> Result<InvocationReceipt, BudgetError> {
		let calls = self
			.invocations
			.lock()
			.map_err(|_| BudgetError::Unavailable)?;
		let call = calls.get(id).ok_or(BudgetError::InvocationBinding)?;
		Ok(call.receipt.clone().unwrap_or(InvocationReceipt {
			state: if call.claimed {
				InvocationState::InFlight
			} else {
				InvocationState::Issued
			},
			result_hash: None,
			tool_error: None,
		}))
	}
	fn finish_invocation(&self, id: &str, receipt: InvocationReceipt) -> Result<(), BudgetError> {
		let _usage = self.usage.lock().map_err(|_| BudgetError::Unavailable)?;
		let mut calls = self
			.invocations
			.lock()
			.map_err(|_| BudgetError::Unavailable)?;
		let call = calls.get_mut(id).ok_or(BudgetError::InvocationBinding)?;
		if call.task_binding.is_some() && receipt.state == InvocationState::Returned {
			self.active_locked()?;
		}
		let valid = match receipt.state {
			InvocationState::Returned => {
				receipt
					.result_hash
					.as_ref()
					.is_some_and(|h| h.len() == 64 && h.bytes().all(|b| b.is_ascii_hexdigit()))
					&& receipt.tool_error.is_some()
			},
			InvocationState::Unknown => receipt.result_hash.is_none() && receipt.tool_error.is_none(),
			_ => false,
		};
		if !call.claimed
			|| !valid
			|| call
				.receipt
				.as_ref()
				.is_some_and(|r| r.state != InvocationState::Accepted)
		{
			return Err(BudgetError::InvocationBinding);
		}
		call.receipt = Some(receipt);
		Ok(())
	}
	fn cleanup_deadline(&self) -> Result<Instant, BudgetError> {
		self
			.config
			.task_cleanup
			.as_ref()
			.map(|c| self.deadline + Duration::from_secs(c.grace_seconds))
			.ok_or(BudgetError::InvalidContext)
	}
	fn cleanup(&self) -> Result<Arc<dyn crate::task_cleanup::CleanupLedger>, BudgetError> {
		if Instant::now() >= self.cleanup_deadline()? {
			return Err(BudgetError::Deadline);
		}
		self
			.cleanup
			.clone()
			.map(|c| c as Arc<dyn crate::task_cleanup::CleanupLedger>)
			.ok_or(BudgetError::InvalidContext)
	}
	fn state(&self) -> Result<ExecutionState, BudgetError> {
		let _usage = self.usage.lock().map_err(|_| BudgetError::Unavailable)?;
		Ok(self.state_locked())
	}
	fn cancel(&self) -> Result<ExecutionState, BudgetError> {
		let _usage = self.usage.lock().map_err(|_| BudgetError::Unavailable)?;
		if self.state_locked() == ExecutionState::Active {
			self.cancellation.cancel();
		}
		Ok(self.state_locked())
	}
	fn cancellation(&self) -> ExecutionCancellation {
		Box::pin(self.cancellation.clone().cancelled_owned())
	}
	fn issue_invocation(&self, target: &str, arguments_hash: &str) -> Result<String, BudgetError> {
		let _usage = self.usage.lock().map_err(|_| BudgetError::Unavailable)?;
		self.active_locked()?;
		let mut calls = self
			.invocations
			.lock()
			.map_err(|_| BudgetError::Unavailable)?;
		if target.is_empty()
			|| target.len() > 1024
			|| target.trim() != target
			|| arguments_hash.len() != 64
			|| !arguments_hash.bytes().all(|b| b.is_ascii_hexdigit())
		{
			return Err(BudgetError::InvocationBinding);
		}
		if calls.len() >= self.config.max_invocations {
			return Err(BudgetError::Capacity);
		}
		self
			.invocation_slots
			.fetch_update(Ordering::AcqRel, Ordering::Acquire, |used| {
				used.checked_add(1).filter(|n| *n <= 65536)
			})
			.map_err(|_| BudgetError::Capacity)?;
		let id = uuid::Uuid::new_v4().to_string();
		calls.insert(
			id.clone(),
			Invocation {
				target: target.into(),
				arguments_hash: arguments_hash.into(),
				claimed: false,
				task_binding: None,
				receipt: None,
			},
		);
		Ok(id)
	}
	fn claim_invocation(
		&self,
		id: &str,
		target: &str,
		arguments_hash: &str,
	) -> Result<(), BudgetError> {
		let _usage = self.usage.lock().map_err(|_| BudgetError::Unavailable)?;
		self.active_locked()?;
		let mut calls = self
			.invocations
			.lock()
			.map_err(|_| BudgetError::Unavailable)?;
		let call = calls.get_mut(id).ok_or(BudgetError::InvocationBinding)?;
		if call.claimed || call.target != target || call.arguments_hash != arguments_hash {
			return Err(BudgetError::InvocationBinding);
		}
		call.claimed = true; // Never reopen on failure, uncertain results, or changed RPC/session IDs.
		Ok(())
	}
	fn id(&self) -> &str {
		&self.id
	}
	fn deadline(&self) -> Instant {
		self.deadline
	}
	fn usage(&self) -> Result<Usage, BudgetError> {
		self
			.usage
			.lock()
			.map(|u| *u)
			.map_err(|_| BudgetError::Unavailable)
	}
	fn reserve(
		&self,
		kind: CallKind,
		logical: &LogicalCharge,
	) -> Result<Box<dyn ExecutionLease>, BudgetError> {
		let mut charged = logical.0.lock().map_err(|_| BudgetError::Unavailable)?;
		let mut usage = self.usage.lock().map_err(|_| BudgetError::Unavailable)?;
		self.active_locked()?;
		if usage.concurrent >= self.config.max_concurrent {
			return Err(BudgetError::Concurrency);
		}
		if usage.attempts >= self.config.max_attempts {
			return Err(BudgetError::Attempts);
		}
		let index = match kind {
			CallKind::Model => Some(0),
			CallKind::Tool => Some(1),
			CallKind::Agent => Some(2),
			CallKind::Transport => None,
		};
		if index.is_none_or(|i| !charged[i]) {
			match kind {
				CallKind::Model if usage.model_calls >= self.config.max_model_calls => {
					return Err(BudgetError::ModelCalls);
				},
				CallKind::Tool if usage.tool_calls >= self.config.max_tool_calls => {
					return Err(BudgetError::ToolCalls);
				},
				CallKind::Agent if usage.agent_calls >= self.config.max_agent_calls => {
					return Err(BudgetError::AgentCalls);
				},
				_ => {},
			}
			match kind {
				CallKind::Model => usage.model_calls += 1,
				CallKind::Tool => usage.tool_calls += 1,
				CallKind::Agent => usage.agent_calls += 1,
				CallKind::Transport => {},
			}
			if let Some(index) = index {
				charged[index] = true;
			}
		}
		usage.attempts += 1;
		usage.concurrent += 1;
		Ok(Box::new(Lease(self.usage.clone())))
	}
}
impl ExecutionBudgetStore for InMemoryExecutionBudgetStore {
	fn create(
		&self,
		config: &ExecutionBudgetConfig,
		owner: VerifiedOwner,
		fingerprint: String,
	) -> Result<ExecutionHandle, BudgetError> {
		config.validate().map_err(|_| BudgetError::InvalidContext)?;
		let mut records = self.0.lock().map_err(|_| BudgetError::Unavailable)?;
		let now = Instant::now();
		// Do not evict live or in-flight records, nor reset exhausted records early.
		records.retain(|_, r| {
			r.deadline > now
				|| r.cleanup_deadline().is_ok_and(|until| until > now)
				|| r.usage.lock().map_or(true, |u| u.concurrent != 0)
				|| r.cleanup.as_ref().is_some_and(|c| c.active())
		});
		let domain = records
			.values()
			.filter(|r| r.config.namespace == config.namespace)
			.collect::<Vec<_>>();
		if records.len() >= 16384
			|| domain.len() >= config.max_contexts
			|| domain.iter().filter(|r| r.owner == owner).count() >= config.max_contexts_per_owner
		{
			return Err(BudgetError::Capacity);
		}
		let mut detached_config = config.clone();
		detached_config.store = Default::default();
		let record = Arc::new(Record {
			cleanup: config.task_cleanup.as_ref().map(|c| {
				Arc::new(crate::task_cleanup::LocalCleanupLedger::new(
					c.clone(),
					self.2.clone(),
				))
			}),
			cancellation: CancellationToken::new(),
			invocations: Default::default(),
			invocation_slots: self.1.clone(),
			id: uuid::Uuid::new_v4().to_string(),
			owner,
			fingerprint,
			config: detached_config,
			deadline: now + Duration::from_secs(config.max_duration_seconds),
			usage: Default::default(),
		});
		records.insert(record.id.clone(), record.clone());
		Ok(record)
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
		let records = self.0.lock().map_err(|_| BudgetError::Unavailable)?;
		let record = records.get(id).ok_or(BudgetError::InvalidContext)?;
		if &record.owner != owner
			|| record.config.namespace != config.namespace
			|| record.fingerprint != fingerprint
		{
			return Err(BudgetError::InvalidContext);
		}
		Ok(record.clone())
	}
}
