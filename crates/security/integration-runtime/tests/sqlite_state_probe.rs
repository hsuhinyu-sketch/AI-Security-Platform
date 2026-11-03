//! Finite storage experiment, deliberately excluded from production APIs and YAML assembly.
#[path = "support/sqlite_state_proto.rs"]
mod prototype;
use prototype::Prototype;
use security_audit::StateJournalConfig;
use security_integration_runtime::{
	context_store::{ContextBinding, ContextError, LocalSecurityContextStore, SecurityContextStore},
	identity_binding::VerifiedOwner,
};
use security_pipeline::GatewayIdentity;
use security_rag::{
	IndexedDocument, SourceOrigin, TrustedChunkAccess,
	lifecycle::{DocumentLifecycleConfig, DocumentLifecycleStore, DocumentMetadata, DocumentState},
};
use security_types::{DataClassification, DocumentKey, DocumentVersion};
use sqlx::{Connection, Executor};
use std::{
	fs,
	path::{Path, PathBuf},
	sync::{
		Arc,
		atomic::{AtomicBool, Ordering},
	},
	time::{Duration, Instant},
};

struct Directory(PathBuf);
impl Directory {
	fn new() -> Self {
		let root = std::env::var_os("AISP_SQLITE_PROBE_ROOT")
			.map(PathBuf::from)
			.unwrap_or(std::env::temp_dir());
		let path = root.join(format!("sqlite-prototype-{}", uuid::Uuid::new_v4()));
		fs::create_dir(&path).unwrap();
		#[cfg(unix)]
		{
			use std::os::unix::fs::PermissionsExt;
			fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
		}
		Self(path)
	}
	fn journal(&self, name: &str) -> StateJournalConfig {
		StateJournalConfig {
			path: self.0.join(name),
			max_bytes: 67_108_864,
		}
	}
}
impl Drop for Directory {
	fn drop(&mut self) {
		if std::env::var_os("AISP_SQLITE_PROBE_KEEP").is_none() {
			let _ = fs::remove_dir_all(&self.0);
		}
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
fn metadata() -> DocumentMetadata {
	DocumentMetadata {
		authority: uuid::Uuid::new_v4().to_string(),
		key: DocumentKey {
			tenant_id: "tenant-a".into(),
			corpus_id: "docs".into(),
			document_id: "guide".into(),
		},
		revision: 1,
		version: 1,
		state: DocumentState::Active,
		source_hash: "a".repeat(64),
		classification: DataClassification::Restricted,
		classification_source: "trusted".into(),
		labels: vec![],
		access: TrustedChunkAccess {
			allowed_users: vec!["alice".into()],
			..Default::default()
		},
	}
}
fn reference(meta: &DocumentMetadata) -> DocumentVersion {
	DocumentVersion {
		authority: meta.authority.clone(),
		key: meta.key.clone(),
		revision: meta.revision,
	}
}
async fn seeded(dir: &Directory) -> (Prototype, String, DocumentMetadata) {
	let store = Prototype::open(dir.0.join("state.sqlite"), 256)
		.await
		.unwrap();
	let doc = metadata();
	store.put_document(&doc).await.unwrap();
	let id = store
		.issue(binding(), 60, vec![reference(&doc)])
		.await
		.unwrap();
	(store, id, doc)
}
async fn close(store: Prototype) {
	store.pool.close().await;
	drop(store);
}

#[tokio::test]
async fn combined_transaction_preserves_binding_document_acl_and_revision() {
	let dir = Directory::new();
	let (store, id, mut doc) = seeded(&dir).await;
	assert_eq!(
		store.use_context(&id, &binding()).await,
		Ok(DataClassification::Restricted)
	);
	let commits = store.acknowledged_commits.load(Ordering::Relaxed);
	for change in ["tenant", "owner", "namespace", "config"] {
		let mut foreign = binding();
		match change {
			"tenant" | "owner" => {
				let mut identity = foreign.owner.identity();
				if change == "tenant" {
					identity.tenant_id = Some("tenant-b".into());
				} else {
					identity.user_id = Some("bob".into());
				}
				foreign.owner = VerifiedOwner::from_identity(&identity, "https://issuer.example").unwrap();
			},
			"namespace" => foreign.namespace = "other".into(),
			_ => foreign.fingerprint = "config-v2".into(),
		}
		assert_eq!(
			store.use_context(&id, &foreign).await,
			Err(ContextError::Denied)
		);
	}
	assert_eq!(store.acknowledged_commits.load(Ordering::Relaxed), commits);
	doc.access.allowed_users = vec!["bob".into()];
	store.put_document(&doc).await.unwrap();
	assert_eq!(
		store.use_context(&id, &binding()).await,
		Err(ContextError::Denied)
	);
	doc.access.allowed_users = vec!["alice".into()];
	doc.revision += 1;
	store.put_document(&doc).await.unwrap();
	assert_eq!(
		store.use_context(&id, &binding()).await,
		Err(ContextError::Denied)
	);
	close(store).await;
}
#[tokio::test]
async fn acknowledged_revocation_and_document_authority_survive_reopen() {
	let dir = Directory::new();
	let (store, id, mut doc) = seeded(&dir).await;
	let other = store
		.issue(binding(), 60, vec![reference(&doc)])
		.await
		.unwrap();
	store.revoke(&id, &binding()).await.unwrap();
	close(store).await;
	let store = Prototype::open(dir.0.join("state.sqlite"), 256)
		.await
		.unwrap();
	assert_eq!(
		store.use_context(&id, &binding()).await,
		Err(ContextError::Denied)
	);
	assert!(store.use_context(&other, &binding()).await.is_ok());
	doc.authority = uuid::Uuid::new_v4().to_string();
	store.put_document(&doc).await.unwrap();
	assert_eq!(
		store.use_context(&other, &binding()).await,
		Err(ContextError::Denied)
	);
	close(store).await;
}
#[tokio::test]
async fn expiry_does_not_renew_on_reopen() {
	let dir = Directory::new();
	let (store, _, doc) = seeded(&dir).await;
	let short = store
		.issue(binding(), 1, vec![reference(&doc)])
		.await
		.unwrap();
	close(store).await;
	tokio::time::sleep(Duration::from_millis(1100)).await;
	let store = Prototype::open(dir.0.join("state.sqlite"), 256)
		.await
		.unwrap();
	assert_eq!(
		store.use_context(&short, &binding()).await,
		Err(ContextError::Denied)
	);
	close(store).await;
}
#[tokio::test]
async fn future_highwater_quarantines_current_store_and_refuses_recovery() {
	let dir = Directory::new();
	let (store, id, _) = seeded(&dir).await;
	let future = chrono::Utc::now().timestamp_millis() + 60000;
	sqlx::query("UPDATE prototype_meta SET highwater=?")
		.bind(future)
		.execute(&store.pool)
		.await
		.unwrap();
	assert_eq!(
		store.use_context(&id, &binding()).await,
		Err(ContextError::Unavailable)
	);
	sqlx::query("UPDATE prototype_meta SET highwater=0")
		.execute(&store.pool)
		.await
		.unwrap();
	assert_eq!(
		store.use_context(&id, &binding()).await,
		Err(ContextError::Unavailable)
	);
	sqlx::query("UPDATE prototype_meta SET highwater=?")
		.bind(future)
		.execute(&store.pool)
		.await
		.unwrap();
	close(store).await;
	assert!(
		Prototype::open(dir.0.join("state.sqlite"), 256)
			.await
			.is_err()
	);
}
#[tokio::test(flavor = "current_thread")]
async fn busy_database_does_not_block_tokio_and_failure_remains_closed() {
	let dir = Directory::new();
	let (store, id, _) = seeded(&dir).await;
	let store = Arc::new(store);
	let mut blocker = store.external_connection().await;
	blocker.execute("BEGIN IMMEDIATE").await.unwrap();
	let progress = Arc::new(AtomicBool::new(false));
	let observed = progress.clone();
	let heartbeat = tokio::spawn(async move {
		tokio::time::sleep(Duration::from_millis(5)).await;
		observed.store(true, Ordering::Release);
	});
	let call = store.use_context(&id, &binding()).await;
	assert_eq!(call, Err(ContextError::Unavailable));
	// Check before awaiting the heartbeat: awaiting it first would also pass if the call blocked Tokio.
	assert!(progress.load(Ordering::Acquire));
	heartbeat.await.unwrap();
	blocker.execute("ROLLBACK").await.unwrap();
	blocker.close().await.unwrap();
	assert_eq!(
		store.use_context(&id, &binding()).await,
		Err(ContextError::Unavailable)
	);
	store.pool.close().await;
}
#[tokio::test]
async fn uncommitted_revocation_is_atomic_and_cancelled_transaction_rolls_back() {
	let dir = Directory::new();
	let (store, id, mut doc) = seeded(&dir).await;
	let store = Arc::new(store);
	let mut tx = store.pool.begin_with("BEGIN IMMEDIATE").await.unwrap();
	doc.state = DocumentState::Revoked;
	doc.revision += 1;
	sqlx::query("UPDATE prototype_documents SET metadata=?")
		.bind(serde_json::to_string(&doc).unwrap())
		.execute(&mut *tx)
		.await
		.unwrap();
	let waiting = tokio::spawn({
		let store = store.clone();
		let id = id.clone();
		async move { store.use_context(&id, &binding()).await }
	});
	tokio::task::yield_now().await;
	assert!(!waiting.is_finished());
	tx.commit().await.unwrap();
	assert_eq!(waiting.await.unwrap(), Err(ContextError::Denied));
	let before: i64 = sqlx::query_scalar("SELECT highwater FROM prototype_meta")
		.fetch_one(&store.pool)
		.await
		.unwrap();
	let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
	let task = tokio::spawn({
		let store = store.clone();
		async move {
			let mut tx = store.pool.begin().await.unwrap();
			sqlx::query("UPDATE prototype_meta SET highwater=highwater+1")
				.execute(&mut *tx)
				.await
				.unwrap();
			ready_tx.send(()).unwrap();
			std::future::pending::<()>().await;
			drop(tx);
		}
	});
	ready_rx.await.unwrap();
	task.abort();
	assert!(task.await.unwrap_err().is_cancelled());
	let after: i64 = sqlx::query_scalar("SELECT highwater FROM prototype_meta")
		.fetch_one(&store.pool)
		.await
		.unwrap();
	assert_eq!(before, after);
	store.pool.close().await;
}
#[tokio::test]
async fn sqlite_capacity_failure_preserves_previously_acknowledged_rows() {
	let dir = Directory::new();
	let store = Prototype::open(dir.0.join("state.sqlite"), 32)
		.await
		.unwrap();
	let doc = metadata();
	store.put_document(&doc).await.unwrap();
	let id = store
		.issue(binding(), 60, vec![reference(&doc)])
		.await
		.unwrap();
	let mut failed = false;
	let mut accepted = 1;
	for n in 0..100 {
		let mut large = doc.clone();
		large.key.document_id = format!("large-{n}");
		large.labels = vec!["a".repeat(256); 16];
		if store.put_document(&large).await.is_err() {
			failed = true;
			break;
		}
		accepted += 1;
	}
	assert!(failed);
	assert_eq!(
		store.use_context(&id, &binding()).await,
		Err(ContextError::Unavailable)
	);
	close(store).await;
	let store = Prototype::open(dir.0.join("state.sqlite"), 256)
		.await
		.unwrap();
	let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM prototype_documents")
		.fetch_one(&store.pool)
		.await
		.unwrap();
	assert_eq!(count, accepted);
	assert!(store.use_context(&id, &binding()).await.is_ok());
	close(store).await;
}
#[tokio::test]
async fn sqlite_wal_recycles_without_accumulating_one_record_per_use() {
	let dir = Directory::new();
	let (store, id, _) = seeded(&dir).await;
	let mut peak = 0;
	for _ in 0..512 {
		assert!(store.use_context(&id, &binding()).await.is_ok());
		let (db, wal, shm) = store.sizes().await;
		peak = peak.max(db + wal + shm);
	}
	assert!(
		peak < 2 * 1024 * 1024,
		"observed bound for this fixed-row workload, not a general WAL quota"
	);
	store.checkpoint().await.unwrap();
	let (_, wal, _) = store.sizes().await;
	assert_eq!(wal, 0);
	close(store).await;
}

#[test]
fn sqlite_recovery_child() {
	let Some(dir) = std::env::var_os("AISP_SQLITE_CHILD_DIRECTORY") else {
		return;
	};
	let mode = std::env::var("AISP_SQLITE_CHILD_MODE").unwrap();
	let rt = tokio::runtime::Builder::new_current_thread()
		.enable_all()
		.build()
		.unwrap();
	rt.block_on(async {
		let store = Prototype::open(PathBuf::from(&dir).join("state.sqlite"), 256)
			.await
			.unwrap();
		let doc = metadata();
		store.put_document(&doc).await.unwrap();
		let id = store
			.issue(binding(), 60, vec![reference(&doc)])
			.await
			.unwrap();
		if mode == "revoked" {
			store.revoke(&id, &binding()).await.unwrap();
		}
		fs::write(PathBuf::from(&dir).join("ready"), id).unwrap();
		std::future::pending::<()>().await;
		drop(store);
	});
}
#[test]
fn sqlite_live_and_revoked_contexts_recover_after_sigkill() {
	for mode in ["live", "revoked"] {
		let dir = Directory::new();
		let mut child = std::process::Command::new(std::env::current_exe().unwrap())
			.args(["--exact", "sqlite_recovery_child", "--nocapture"])
			.env("AISP_SQLITE_CHILD_DIRECTORY", &dir.0)
			.env("AISP_SQLITE_CHILD_MODE", mode)
			.stdout(std::process::Stdio::null())
			.spawn()
			.unwrap();
		let deadline = Instant::now() + Duration::from_secs(10);
		let ready = dir.0.join("ready");
		while !ready.exists() {
			if Instant::now() >= deadline {
				let _ = child.kill();
				let _ = child.wait();
				panic!("child readiness timeout");
			}
			assert!(child.try_wait().unwrap().is_none());
			std::thread::sleep(Duration::from_millis(10));
		}
		let id = fs::read_to_string(ready).unwrap();
		child.kill().unwrap();
		child.wait().unwrap();
		tokio::runtime::Builder::new_current_thread()
			.enable_all()
			.build()
			.unwrap()
			.block_on(async {
				let store = Prototype::open(dir.0.join("state.sqlite"), 256)
					.await
					.unwrap();
				let result = store.use_context(&id, &binding()).await;
				assert_eq!(
					result,
					if mode == "live" {
						Ok(DataClassification::Restricted)
					} else {
						Err(ContextError::Denied)
					}
				);
				close(store).await;
			});
	}
}

fn jsonl_seed(
	dir: &Directory,
) -> (
	Arc<LocalSecurityContextStore>,
	Arc<DocumentLifecycleStore>,
	String,
) {
	let docs = DocumentLifecycleStore::open(DocumentLifecycleConfig {
		namespace: "knowledge".into(),
		storage: dir.journal("documents.jsonl"),
		max_documents: 16,
	})
	.unwrap();
	let doc = IndexedDocument {
		corpus_id: "docs".into(),
		document_id: "guide".into(),
		tenant_id: "tenant-a".into(),
		source_uri: "file:///guide".into(),
		source_hash: "a".repeat(64),
		source_origin: SourceOrigin::Submitted,
		content: "knowledge".into(),
		labels: vec![],
		classification: DataClassification::Restricted,
		classification_source: "trusted".into(),
	};
	let meta = docs
		.begin_index(
			&doc,
			TrustedChunkAccess {
				allowed_users: vec!["alice".into()],
				..Default::default()
			},
		)
		.unwrap();
	docs.activate(&meta.key, meta.revision).unwrap();
	let contexts =
		LocalSecurityContextStore::open(dir.journal("contexts.jsonl"), "knowledge").unwrap();
	contexts
		.register_document_validator("knowledge", docs.clone())
		.unwrap();
	let id = contexts
		.issue_documents(
			binding(),
			60,
			16,
			DataClassification::Restricted,
			vec![reference(&meta)],
		)
		.unwrap();
	(contexts, docs, id)
}
fn bytes(path: &Path) -> u64 {
	fs::metadata(path).map_or(0, |m| m.len())
}
fn checkpoints(path: &Path) -> u64 {
	fs::read_to_string(path)
		.unwrap()
		.lines()
		.filter(|line| {
			let value: serde_json::Value = serde_json::from_str(line).unwrap();
			value["change"]["kind"] == "Checkpoint"
		})
		.count() as u64
}
fn p(sorted: &[u128], percent: usize) -> f64 {
	sorted[(sorted.len() - 1) * percent / 100] as f64 / 1000.0
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "bounded release comparison; run explicitly with AISP_SQLITE_PROBE_ROOT on ext4"]
async fn measure_jsonl_and_sqlite_context_use() {
	let out =
		PathBuf::from(std::env::var_os("AISP_SQLITE_PROBE_ROOT").expect("explicit output directory"));
	let mut results = Vec::new();
	for trial in 1..=3 {
		for workers in [1, 2, 4, 8] {
			for sqlite in [false, true] {
				let dir = Directory::new();
				let mut docs = None;
				let mut jsonl = None;
				let mut db = None;
				let id = if sqlite {
					let (store, id, _) = seeded(&dir).await;
					db = Some(Arc::new(store));
					id
				} else {
					let (store, document, id) = jsonl_seed(&dir);
					docs = Some(document);
					jsonl = Some(store);
					id
				};
				for _ in 0..5 {
					if let Some(store) = &db {
						store.use_context(&id, &binding()).await.unwrap();
					} else {
						jsonl
							.as_ref()
							.unwrap()
							.classification(&id, &binding())
							.unwrap();
					}
				}
				let before = if sqlite {
					let (a, b, c) = db.as_ref().unwrap().sizes().await;
					a + b + c
				} else {
					bytes(&dir.0.join("contexts.jsonl")) + bytes(&dir.0.join("documents.jsonl"))
				};
				let committed = db
					.as_ref()
					.map(|store| store.acknowledged_commits.load(Ordering::Relaxed));
				let journal_checkpoints = if sqlite {
					0
				} else {
					checkpoints(&dir.0.join("contexts.jsonl")) + checkpoints(&dir.0.join("documents.jsonl"))
				};
				let start = Instant::now();
				let barrier = Arc::new(tokio::sync::Barrier::new(workers));
				let mut tasks = tokio::task::JoinSet::new();
				for _ in 0..workers {
					let (db, jsonl, id, barrier) = (db.clone(), jsonl.clone(), id.clone(), barrier.clone());
					tasks.spawn(async move {
						let mut durations = Vec::new();
						barrier.wait().await;
						for _ in 0..116 {
							let now = Instant::now();
							if let Some(store) = &db {
								store.use_context(&id, &binding()).await.unwrap();
							} else {
								let store = jsonl.as_ref().unwrap().clone();
								let id = id.clone();
								tokio::task::spawn_blocking(move || store.classification(&id, &binding()))
									.await
									.unwrap()
									.unwrap();
							}
							durations.push(now.elapsed().as_nanos());
						}
						durations
					});
				}
				let mut samples = Vec::new();
				while let Some(task) = tasks.join_next().await {
					samples.extend(task.unwrap());
				}
				let elapsed = start.elapsed().as_secs_f64();
				samples.sort_unstable();
				let after = if sqlite {
					let (a, b, c) = db.as_ref().unwrap().sizes().await;
					a + b + c
				} else {
					bytes(&dir.0.join("contexts.jsonl")) + bytes(&dir.0.join("documents.jsonl"))
				};
				let commits = if let Some(store) = &db {
					store.acknowledged_commits.load(Ordering::Relaxed) - committed.unwrap()
				} else {
					checkpoints(&dir.0.join("contexts.jsonl")) + checkpoints(&dir.0.join("documents.jsonl"))
						- journal_checkpoints
				};
				assert_eq!(commits, samples.len() as u64 * if sqlite { 1 } else { 3 });
				let result = serde_json::json!({"backend":if sqlite{"sqlite-prototype"}else{"production-jsonl"},"trial":trial,"workers":workers,"operations":samples.len(),"seconds":elapsed,"opsPerSecond":samples.len() as f64/elapsed,"p50Us":p(&samples,50),"p95Us":p(&samples,95),"p99Us":p(&samples,99),"maxUs":*samples.last().unwrap() as f64/1000.0,"bytesBefore":before,"bytesAfter":after,"acknowledgedTransactionsOrAppends":commits});
				println!("{result}");
				results.push(result);
				if let Some(store) = db {
					store.pool.close().await;
				}
				drop(jsonl);
				drop(docs);
			}
		}
	}
	fs::write(
		out.join("comparison.json"),
		serde_json::to_vec_pretty(&results).unwrap(),
	)
	.unwrap();
}

#[tokio::test]
async fn cancelled_context_use_waiter_does_not_acknowledge_a_commit() {
	let dir = Directory::new();
	let (store, id, _) = seeded(&dir).await;
	let store = Arc::new(store);
	let transaction = store.pool.begin_with("BEGIN IMMEDIATE").await.unwrap();
	let before = store.acknowledged_commits.load(Ordering::Relaxed);
	let waiter = tokio::spawn({
		let store = store.clone();
		let id = id.clone();
		async move { store.use_context(&id, &binding()).await }
	});
	tokio::time::sleep(Duration::from_millis(5)).await;
	assert!(!waiter.is_finished());
	waiter.abort();
	assert!(waiter.await.unwrap_err().is_cancelled());
	transaction.rollback().await.unwrap();
	assert_eq!(store.acknowledged_commits.load(Ordering::Relaxed), before);
	assert!(store.use_context(&id, &binding()).await.is_ok());
	store.pool.close().await;
}

#[tokio::test]
async fn malformed_database_is_rejected_without_reinitialization() {
	let dir = Directory::new();
	let file = dir.0.join("state.sqlite");
	fs::write(&file, b"not a SQLite database").unwrap();
	assert!(Prototype::open(file.clone(), 256).await.is_err());
	assert_eq!(fs::read(file).unwrap(), b"not a SQLite database");
}

#[tokio::test]
async fn second_store_cannot_acquire_live_owner() {
	let dir = Directory::new();
	let (store, id, _) = seeded(&dir).await;
	assert!(Prototype::open(store.path.clone(), 256).await.is_err());
	assert!(store.use_context(&id, &binding()).await.is_ok());
	close(store).await;
}

#[tokio::test]
#[ignore = "bounded fixed-state WAL measurement; run explicitly on ext4"]
async fn measure_sqlite_fixed_state_growth() {
	let out =
		PathBuf::from(std::env::var_os("AISP_SQLITE_PROBE_ROOT").expect("explicit output directory"));
	let dir = Directory::new();
	let (store, id, _) = seeded(&dir).await;
	let start = Instant::now();
	let mut peak = 0;
	let before = store.acknowledged_commits.load(Ordering::Relaxed);
	for _ in 0..8192 {
		store.use_context(&id, &binding()).await.unwrap();
		let (db, wal, shm) = store.sizes().await;
		peak = peak.max(db + wal + shm);
	}
	let seconds = start.elapsed().as_secs_f64();
	let commits = store.acknowledged_commits.load(Ordering::Relaxed) - before;
	assert_eq!(commits, 8192);
	assert!(
		peak < 2 * 1024 * 1024,
		"fixed-row workload, not a general disk quota"
	);
	store.checkpoint().await.unwrap();
	let (db, wal, shm) = store.sizes().await;
	assert_eq!(wal, 0);
	let result = serde_json::json!({"operations":8192,"acknowledgedTransactions":commits,"seconds":seconds,"peakDatabaseWalShmBytes":peak,"afterTruncate":{"database":db,"wal":wal,"shm":shm}});
	println!("{result}");
	fs::write(
		out.join("fixed-state-growth.json"),
		serde_json::to_vec_pretty(&result).unwrap(),
	)
	.unwrap();
	close(store).await;
}
