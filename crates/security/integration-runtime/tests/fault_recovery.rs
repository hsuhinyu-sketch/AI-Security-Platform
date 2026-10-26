//! Process and filesystem faults against public production APIs. No runtime hooks.
#![cfg(target_os = "linux")]

use security_audit::StateJournalConfig;
use security_integration_runtime::{
	context_store::{ContextBinding, LocalSecurityContextStore, SecurityContextStore},
	identity_binding::VerifiedOwner,
};
use security_pipeline::GatewayIdentity;
use security_types::DataClassification;
use std::{
	fs,
	path::{Path, PathBuf},
	process::{Child, Command, Stdio},
	thread,
	time::{Duration, Instant},
};

struct Directory(PathBuf);
impl Directory {
	fn new() -> Self {
		use std::os::unix::fs::DirBuilderExt;
		let path = std::env::temp_dir().join(format!("aisp-fault-{}", uuid::Uuid::new_v4()));
		fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
		Self(path)
	}
}
impl Drop for Directory {
	fn drop(&mut self) {
		let _ = fs::remove_dir_all(&self.0);
	}
}
fn spec(dir: &Path) -> StateJournalConfig {
	StateJournalConfig {
		path: dir.join("contexts.jsonl"),
		max_bytes: 1_048_576,
	}
}
fn binding() -> ContextBinding {
	ContextBinding {
		owner: VerifiedOwner::from_identity(
			&GatewayIdentity {
				user_id: Some("alice".into()),
				tenant_id: Some("tenant-a".into()),
				client_id: Some("client-a".into()),
				..Default::default()
			},
			"https://issuer.example",
		)
		.unwrap(),
		namespace: "knowledge".into(),
		fingerprint: "config-v1".into(),
	}
}
struct Worker(Child);
impl Worker {
	fn start(dir: &Path, mode: &str) -> Self {
		Self(
			Command::new(std::env::current_exe().unwrap())
				.args(["--exact", "fault_worker", "--nocapture"])
				.env("AISP_FAULT_DIRECTORY", dir)
				.env("AISP_FAULT_MODE", mode)
				.stdout(Stdio::null())
				.spawn()
				.unwrap(),
		)
	}
	fn ready(&mut self, dir: &Path) -> String {
		let deadline = Instant::now() + Duration::from_secs(15);
		loop {
			if let Ok(value) = fs::read_to_string(dir.join("ready")) {
				return value;
			}
			assert!(
				self.0.try_wait().unwrap().is_none(),
				"worker exited before readiness"
			);
			assert!(Instant::now() < deadline, "worker readiness timeout");
			thread::sleep(Duration::from_millis(10));
		}
	}
	fn kill(&mut self) {
		use std::os::unix::process::ExitStatusExt;
		self.0.kill().unwrap();
		assert_eq!(self.0.wait().unwrap().signal(), Some(libc::SIGKILL));
	}
	fn success(&mut self) {
		let deadline = Instant::now() + Duration::from_secs(15);
		loop {
			if let Some(status) = self.0.try_wait().unwrap() {
				assert!(status.success());
				return;
			}
			assert!(Instant::now() < deadline, "worker exit timeout");
			thread::sleep(Duration::from_millis(10));
		}
	}
}
impl Drop for Worker {
	fn drop(&mut self) {
		let _ = self.0.kill();
		let _ = self.0.wait();
	}
}

#[test]
fn fault_worker() {
	let Some(directory) = std::env::var_os("AISP_FAULT_DIRECTORY") else {
		return;
	};
	let dir = PathBuf::from(directory);
	let mode = std::env::var("AISP_FAULT_MODE").unwrap();
	#[cfg(feature = "a2a-sqlite")]
	if mode == "a2a" {
		use security_integration_runtime::a2a_objects::*;
		let config = a2a_config(&dir);
		let store = TaskStoreHandle::from_config(&config).unwrap();
		let identity = GatewayIdentity {
			user_id: Some("alice".into()),
			tenant_id: Some("tenant-a".into()),
			client_id: Some("client-a".into()),
			..Default::default()
		};
		let mut permit = store
			.begin(
				&config,
				&identity,
				"https://issuer.example",
				"agent",
				None,
				TaskOperation::Create,
			)
			.unwrap();
		store
			.finish(
				&config,
				&mut permit,
				"task-a",
				"context-a",
				TaskState::Completed,
			)
			.unwrap();
		fs::write(dir.join("ready"), "task-a").unwrap();
		loop {
			thread::park();
		}
	}
	let store = LocalSecurityContextStore::open(spec(&dir), "knowledge").unwrap();
	let owner = binding();
	let id = store
		.issue(owner.clone(), 300, 16, DataClassification::Restricted)
		.unwrap();
	if mode == "write-failure" || mode == "partial-write" {
		let length = fs::metadata(spec(&dir).path).unwrap().len();
		// Restrict only this disposable child. EFBIG exercises a real failed write;
		// it is deliberately not claimed to emulate ENOSPC or power loss.
		let cap = length + if mode == "partial-write" { 8 } else { 0 };
		let limit = libc::rlimit {
			rlim_cur: cap,
			rlim_max: cap,
		};
		unsafe {
			assert_ne!(libc::signal(libc::SIGXFSZ, libc::SIG_IGN), libc::SIG_ERR);
			assert_eq!(libc::setrlimit(libc::RLIMIT_FSIZE, &limit), 0);
		}
		assert!(store.revoke(&id, &owner).is_err());
		assert_eq!(fs::metadata(spec(&dir).path).unwrap().len(), cap);
		assert!(store.classification(&id, &owner).is_err());
		assert!(
			store
				.issue(owner, 300, 16, DataClassification::Public)
				.is_err()
		);
		fs::write(dir.join("ready"), id).unwrap();
		return;
	}
	if mode == "revoked" {
		store.revoke(&id, &owner).unwrap();
	}
	let temporary = dir.join("ready.tmp");
	fs::write(&temporary, id).unwrap();
	fs::rename(temporary, dir.join("ready")).unwrap();
	loop {
		thread::park();
	}
}

#[test]
fn acknowledged_revocation_survives_sigkill() {
	let dir = Directory::new();
	let mut worker = Worker::start(&dir.0, "revoked");
	let id = worker.ready(&dir.0);
	worker.kill();
	let store = LocalSecurityContextStore::open(spec(&dir.0), "knowledge").unwrap();
	assert!(store.classification(&id, &binding()).is_err());
	assert!(
		store
			.elevate(&id, &binding(), DataClassification::Public)
			.is_err()
	);
}

#[test]
fn live_context_recovers_with_binding_and_classification_after_sigkill() {
	let dir = Directory::new();
	let mut worker = Worker::start(&dir.0, "live");
	let id = worker.ready(&dir.0);
	worker.kill();
	let store = LocalSecurityContextStore::open(spec(&dir.0), "knowledge").unwrap();
	assert_eq!(
		store.classification(&id, &binding()).unwrap(),
		DataClassification::Restricted
	);
	let mut foreign = binding();
	foreign.fingerprint = "config-v2".into();
	assert!(store.classification(&id, &foreign).is_err());
}

#[test]
fn concurrent_process_cannot_open_single_writer_state() {
	let dir = Directory::new();
	let mut worker = Worker::start(&dir.0, "live");
	worker.ready(&dir.0);
	assert!(LocalSecurityContextStore::open(spec(&dir.0), "knowledge").is_err());
	worker.kill();
	assert!(LocalSecurityContextStore::open(spec(&dir.0), "knowledge").is_ok());
}

#[test]
fn real_write_failure_quarantines_current_store() {
	let dir = Directory::new();
	Worker::start(&dir.0, "write-failure").success();
	// No bytes of the rejected mutation were written. Recovery retains the last
	// acknowledged state; a failed revoke must never be reported as committed.
	let id = fs::read_to_string(dir.0.join("ready")).unwrap();
	let recovered = LocalSecurityContextStore::open(spec(&dir.0), "knowledge").unwrap();
	assert_eq!(
		recovered.classification(&id, &binding()).unwrap(),
		DataClassification::Restricted
	);
}

#[test]
fn partial_os_write_quarantines_store_and_rejects_recovery() {
	let dir = Directory::new();
	Worker::start(&dir.0, "partial-write").success();
	assert!(LocalSecurityContextStore::open(spec(&dir.0), "knowledge").is_err());
}

#[cfg(feature = "a2a-sqlite")]
fn a2a_config(dir: &Path) -> security_integration_runtime::a2a_objects::A2aObjectConfig {
	use security_integration_runtime::a2a_objects::*;
	A2aObjectConfig {
		storage: TaskStoreConfig::Sqlite {
			path: dir.join("tasks.db"),
			namespace: "agent".into(),
			busy_timeout_millis: 100,
		},
		..Default::default()
	}
}

#[cfg(feature = "a2a-sqlite")]
#[test]
fn sqlite_terminal_state_and_owner_survive_sigkill() {
	use security_integration_runtime::a2a_objects::*;
	let dir = Directory::new();
	let mut worker = Worker::start(&dir.0, "a2a");
	let id = worker.ready(&dir.0);
	worker.kill();
	let config = a2a_config(&dir.0);
	let store = TaskStoreHandle::from_config(&config).unwrap();
	let identity = GatewayIdentity {
		user_id: Some("alice".into()),
		tenant_id: Some("tenant-a".into()),
		client_id: Some("client-a".into()),
		..Default::default()
	};
	let permit = store
		.begin(
			&config,
			&identity,
			"https://issuer.example",
			"agent",
			Some(&id),
			TaskOperation::Read,
		)
		.unwrap();
	assert_eq!(permit.snapshot_state(), Some(TaskState::Completed));
	assert!(
		store
			.begin(
				&config,
				&identity,
				"https://issuer.example",
				"agent",
				Some(&id),
				TaskOperation::Continue
			)
			.is_err()
	);
	let foreign = GatewayIdentity {
		user_id: Some("bob".into()),
		tenant_id: Some("tenant-a".into()),
		client_id: Some("client-a".into()),
		..Default::default()
	};
	assert!(
		store
			.begin(
				&config,
				&foreign,
				"https://issuer.example",
				"agent",
				Some(&id),
				TaskOperation::Read
			)
			.is_err()
	);
}

#[test]
fn torn_tail_is_rejected_without_silent_repair() {
	let dir = Directory::new();
	let mut worker = Worker::start(&dir.0, "revoked");
	worker.ready(&dir.0);
	worker.kill();
	let path = spec(&dir.0).path;
	let original = fs::read(&path).unwrap();
	// Cut inside the final acknowledged record, not at a valid record boundary.
	fs::OpenOptions::new()
		.write(true)
		.open(&path)
		.unwrap()
		.set_len((original.len() - 2) as u64)
		.unwrap();
	let torn = fs::read(&path).unwrap();
	assert!(LocalSecurityContextStore::open(spec(&dir.0), "knowledge").is_err());
	assert_eq!(fs::read(path).unwrap(), torn);
}

#[test]
fn external_truncation_permanently_quarantines_live_store() {
	let dir = Directory::new();
	let config = spec(&dir.0);
	let store = LocalSecurityContextStore::open(config.clone(), "knowledge").unwrap();
	let id = store
		.issue(binding(), 300, 16, DataClassification::Restricted)
		.unwrap();
	let bytes = fs::read(&config.path).unwrap();
	fs::OpenOptions::new()
		.write(true)
		.open(&config.path)
		.unwrap()
		.set_len(0)
		.unwrap();
	assert!(store.classification(&id, &binding()).is_err());
	fs::write(&config.path, bytes).unwrap();
	assert!(store.classification(&id, &binding()).is_err());
	assert!(
		store
			.issue(binding(), 300, 16, DataClassification::Public)
			.is_err()
	);
}
