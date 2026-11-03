#![cfg(feature = "rag-sqlite")]
use security_integration_runtime::{
	context_store::{ContextBinding, ContextError},
	identity_binding::VerifiedOwner,
	rag_sqlite::{SqliteRagConfig, SqliteRagStore},
};
use security_pipeline::GatewayIdentity;
use security_rag::{
	IndexedDocument, SourceOrigin, TrustedChunkAccess,
	lifecycle::{
		DocumentLifecycleConfig, DocumentLifecycleStore, DocumentMetadata, DocumentMutation,
		DocumentState,
	},
};
use security_types::{DataClassification, DocumentVersion};
use sqlx::{Connection, Executor};
use std::{
	fs,
	path::PathBuf,
	sync::{
		Arc,
		atomic::{AtomicBool, Ordering},
	},
	time::Duration,
};

struct Directory(PathBuf);
impl Directory {
	fn new() -> Self {
		let path = std::env::temp_dir().join(format!("rag-sqlite-backend-{}", uuid::Uuid::new_v4()));
		let mut builder = fs::DirBuilder::new();
		#[cfg(unix)]
		{
			use std::os::unix::fs::DirBuilderExt;
			builder.mode(0o700);
		}
		builder.create(&path).unwrap();
		Self(path)
	}
	fn config(&self) -> SqliteRagConfig {
		SqliteRagConfig {
			path: self.0.join("state.sqlite"),
			namespace: "knowledge".into(),
			max_documents: 16,
			max_contexts: 16,
			max_database_bytes: 1_048_576,
			busy_timeout_millis: 100,
		}
	}
	fn journal(&self, name: &str) -> security_audit::StateJournalConfig {
		security_audit::StateJournalConfig {
			path: self.0.join(name),
			max_bytes: 1_048_576,
		}
	}
}
impl Drop for Directory {
	fn drop(&mut self) {
		let _ = fs::remove_dir_all(&self.0);
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
fn document() -> IndexedDocument {
	IndexedDocument {
		tenant_id: "tenant-a".into(),
		corpus_id: "docs".into(),
		document_id: "guide".into(),
		source_uri: "file:///guide".into(),
		source_hash: "a".repeat(64),
		source_origin: SourceOrigin::Submitted,
		content: "private knowledge".into(),
		labels: vec![],
		classification: DataClassification::Restricted,
		classification_source: "trusted".into(),
	}
}
fn access() -> TrustedChunkAccess {
	TrustedChunkAccess {
		allowed_users: vec!["alice".into()],
		..Default::default()
	}
}
fn reference(meta: &DocumentMetadata) -> DocumentVersion {
	DocumentVersion {
		key: meta.key.clone(),
		authority: meta.authority.clone(),
		revision: meta.revision,
	}
}
async fn seeded(config: SqliteRagConfig) -> (SqliteRagStore, String, DocumentMetadata) {
	let store = SqliteRagStore::open(config).await.unwrap();
	let mut meta = store.begin_index(&document(), access()).await.unwrap();
	assert!(
		store
			.issue_documents(
				binding(),
				60,
				DataClassification::Restricted,
				vec![reference(&meta)]
			)
			.await
			.is_err()
	);
	store.activate(&meta.key, meta.revision).await.unwrap();
	meta.state = DocumentState::Active;
	let id = store
		.issue_documents(
			binding(),
			60,
			DataClassification::Restricted,
			vec![reference(&meta)],
		)
		.await
		.unwrap();
	(store, id, meta)
}
async fn external(path: &std::path::Path) -> sqlx::SqliteConnection {
	sqlx::SqliteConnection::connect_with(&sqlx::sqlite::SqliteConnectOptions::new().filename(path))
		.await
		.unwrap()
}
fn equivalent(mut jsonl: DocumentMetadata, sqlite: &DocumentMetadata) {
	jsonl.authority = sqlite.authority.clone();
	assert_eq!(jsonl, *sqlite);
}

#[tokio::test]
async fn document_transitions_match_existing_journal_and_never_resurrect() {
	let dir = Directory::new();
	let sql = SqliteRagStore::open(dir.config()).await.unwrap();
	let journal = DocumentLifecycleStore::open(DocumentLifecycleConfig {
		namespace: "knowledge".into(),
		storage: dir.journal("documents.jsonl"),
		max_documents: 16,
	})
	.unwrap();
	let mut a = journal.begin_index(&document(), access()).unwrap();
	let mut b = sql.begin_index(&document(), access()).await.unwrap();
	equivalent(a.clone(), &b);
	// Re-indexing supersedes the pending content and makes the previous activation stale.
	let stale = b.revision;
	a = journal.begin_index(&document(), access()).unwrap();
	b = sql.begin_index(&document(), access()).await.unwrap();
	equivalent(a.clone(), &b);
	assert!(journal.activate(&a.key, stale).is_err());
	assert_eq!(sql.activate(&b.key, stale).await, Err(ContextError::Denied));
	journal.activate(&a.key, a.revision).unwrap();
	sql.activate(&b.key, b.revision).await.unwrap();
	for mutation in [
		DocumentMutation::Acl {
			access: TrustedChunkAccess {
				allowed_users: vec!["bob".into()],
				..Default::default()
			},
		},
		DocumentMutation::Revoke,
		DocumentMutation::Delete,
		DocumentMutation::Delete,
	] {
		a = journal
			.mutate(&a.key, a.revision, mutation.clone())
			.unwrap();
		b = sql.mutate(&b.key, b.revision, mutation).await.unwrap();
		equivalent(a.clone(), &b);
		assert!(
			journal
				.mutate(&a.key, a.revision - 1, DocumentMutation::Delete)
				.is_err()
		);
		assert_eq!(
			sql
				.mutate(&b.key, b.revision - 1, DocumentMutation::Delete)
				.await,
			Err(ContextError::Denied)
		);
	}
	assert!(journal.begin_index(&document(), access()).is_err());
	assert!(sql.begin_index(&document(), access()).await.is_err());
	assert!(
		sql
			.mutate(&b.key, b.revision, DocumentMutation::Revoke)
			.await
			.is_err()
	);
	let authority = sql.authority_id().to_owned();
	sql.close().await.unwrap();
	let sql = SqliteRagStore::open(dir.config()).await.unwrap();
	assert_eq!(sql.authority_id(), authority);
	equivalent(a, &sql.get_document(&b.key).await.unwrap());
	sql.close().await.unwrap();
}
#[tokio::test]
async fn context_binding_monotonic_classification_and_revocation_survive_reopen() {
	let dir = Directory::new();
	let (store, id, meta) = seeded(dir.config()).await;
	for field in [
		"tenant",
		"user",
		"agent",
		"client",
		"delegation",
		"issuer",
		"namespace",
		"config",
	] {
		let mut foreign = binding();
		let mut identity = foreign.owner.identity();
		let mut issuer = "https://issuer.example";
		match field {
			"tenant" => identity.tenant_id = Some("tenant-b".into()),
			"user" => identity.user_id = Some("bob".into()),
			"agent" => identity.agent_id = Some("agent-b".into()),
			"client" => identity.client_id = Some("other".into()),
			"delegation" => identity.delegation_id = Some("other".into()),
			"issuer" => issuer = "https://other.example",
			"namespace" => foreign.namespace = "other".into(),
			_ => foreign.fingerprint = "config-v2".into(),
		}
		foreign.owner = VerifiedOwner::from_identity(&identity, issuer).unwrap();
		assert_eq!(
			store.classification(&id, &foreign).await,
			Err(ContextError::Denied)
		);
		assert_eq!(store.revoke(&id, &foreign).await, Err(ContextError::Denied));
	}
	let other = store
		.issue_documents(
			binding(),
			60,
			DataClassification::Public,
			vec![reference(&meta)],
		)
		.await
		.unwrap();
	store
		.elevate_documents(&other, &binding(), DataClassification::Restricted, vec![])
		.await
		.unwrap();
	store
		.elevate_documents(&other, &binding(), DataClassification::Public, vec![])
		.await
		.unwrap();
	store.revoke(&id, &binding()).await.unwrap();
	store.close().await.unwrap();
	let store = SqliteRagStore::open(dir.config()).await.unwrap();
	assert_eq!(
		store.classification(&id, &binding()).await,
		Err(ContextError::Denied)
	);
	assert_eq!(
		store.classification(&other, &binding()).await,
		Ok(DataClassification::Restricted)
	);
	store.close().await.unwrap();
}
#[tokio::test]
async fn document_acl_revision_and_tenant_are_checked_in_context_transaction() {
	let dir = Directory::new();
	let (store, id, meta) = seeded(dir.config()).await;
	let denied = store
		.mutate(
			&meta.key,
			meta.revision,
			DocumentMutation::Acl {
				access: TrustedChunkAccess {
					allowed_users: vec!["bob".into()],
					..Default::default()
				},
			},
		)
		.await
		.unwrap();
	assert_eq!(
		store.classification(&id, &binding()).await,
		Err(ContextError::Denied)
	);
	assert_eq!(
		store
			.issue_documents(
				binding(),
				60,
				DataClassification::Public,
				vec![reference(&denied)]
			)
			.await,
		Err(ContextError::Denied)
	);
	let restored = store
		.mutate(
			&meta.key,
			denied.revision,
			DocumentMutation::Acl { access: access() },
		)
		.await
		.unwrap();
	assert_eq!(
		store.classification(&id, &binding()).await,
		Err(ContextError::Denied)
	); // same ACL never revives an old revision
	let mut foreign = document();
	foreign.tenant_id = "tenant-b".into();
	foreign.document_id = "foreign".into();
	let m = store.begin_index(&foreign, access()).await.unwrap();
	store.activate(&m.key, m.revision).await.unwrap();
	assert_eq!(
		store
			.issue_documents(
				binding(),
				60,
				DataClassification::Public,
				vec![reference(&m)]
			)
			.await,
		Err(ContextError::Denied)
	);
	store
		.mutate(&meta.key, restored.revision, DocumentMutation::Revoke)
		.await
		.unwrap();
	store.close().await.unwrap();
	let store = SqliteRagStore::open(dir.config()).await.unwrap();
	assert_eq!(
		store.classification(&id, &binding()).await,
		Err(ContextError::Denied)
	);
	store.close().await.unwrap();
}
#[tokio::test]
async fn context_count_is_bounded_and_expiry_is_not_renewed_by_restart() {
	let dir = Directory::new();
	let mut config = dir.config();
	config.max_contexts = 1;
	config.max_documents = 1;
	let store = SqliteRagStore::open(config.clone()).await.unwrap();
	let id = store
		.issue_documents(binding(), 1, DataClassification::Internal, vec![])
		.await
		.unwrap();
	assert_eq!(
		store
			.issue_documents(binding(), 1, DataClassification::Public, vec![])
			.await,
		Err(ContextError::Capacity)
	);
	store.begin_index(&document(), access()).await.unwrap();
	let mut extra = document();
	extra.document_id = "other".into();
	assert_eq!(
		store.begin_index(&extra, access()).await,
		Err(ContextError::Capacity)
	);
	store.close().await.unwrap();
	tokio::time::sleep(Duration::from_millis(1100)).await;
	let store = SqliteRagStore::open(config).await.unwrap();
	assert_eq!(
		store.classification(&id, &binding()).await,
		Err(ContextError::Denied)
	);
	assert!(
		store
			.issue_documents(binding(), 1, DataClassification::Public, vec![])
			.await
			.is_ok()
	);
	store.close().await.unwrap();
}
#[tokio::test(flavor = "current_thread")]
async fn busy_failure_does_not_block_tokio_and_is_sticky() {
	let dir = Directory::new();
	let (store, id, _) = seeded(dir.config()).await;
	let mut blocker = external(&dir.config().path).await;
	blocker.execute("BEGIN IMMEDIATE").await.unwrap();
	let progress = Arc::new(AtomicBool::new(false));
	let observed = progress.clone();
	let heartbeat = tokio::spawn(async move {
		tokio::time::sleep(Duration::from_millis(5)).await;
		observed.store(true, Ordering::Release);
	});
	assert_eq!(
		store.classification(&id, &binding()).await,
		Err(ContextError::Unavailable)
	);
	assert!(progress.load(Ordering::Acquire));
	heartbeat.await.unwrap();
	blocker.execute("ROLLBACK").await.unwrap();
	blocker.close().await.unwrap();
	assert_eq!(
		store.classification(&id, &binding()).await,
		Err(ContextError::Unavailable)
	);
	store.close().await.unwrap();
}
#[tokio::test]
async fn cancellation_while_sqlite_begin_is_waiting_does_not_disclose_or_poison_next_use() {
	let dir = Directory::new();
	let mut config = dir.config();
	config.busy_timeout_millis = 1000;
	let (store, id, _) = seeded(config).await;
	let store = Arc::new(store);
	let mut blocker = external(&dir.config().path).await;
	blocker.execute("BEGIN IMMEDIATE").await.unwrap();
	let call = tokio::spawn({
		let store = store.clone();
		let id = id.clone();
		async move { store.classification(&id, &binding()).await }
	});
	tokio::time::sleep(Duration::from_millis(10)).await;
	assert!(!call.is_finished());
	call.abort();
	assert!(call.await.unwrap_err().is_cancelled());
	blocker.execute("ROLLBACK").await.unwrap();
	blocker.close().await.unwrap();
	assert!(store.classification(&id, &binding()).await.is_ok());
	Arc::try_unwrap(store).ok().unwrap().close().await.unwrap();
}
#[tokio::test]
async fn competing_revision_updates_and_post_revocation_reads_are_serialized() {
	let dir = Directory::new();
	let (store, id, meta) = seeded(dir.config()).await;
	let store = Arc::new(store);
	let mut jobs = tokio::task::JoinSet::new();
	for _ in 0..8 {
		let store = store.clone();
		let key = meta.key.clone();
		jobs.spawn(async move { store.mutate(&key, 1, DocumentMutation::Revoke).await });
	}
	let mut successes = 0;
	while let Some(result) = jobs.join_next().await {
		if result.unwrap().is_ok() {
			successes += 1;
		}
	}
	assert_eq!(successes, 1);
	let mut reads = tokio::task::JoinSet::new();
	for _ in 0..16 {
		let store = store.clone();
		let id = id.clone();
		reads.spawn(async move { store.classification(&id, &binding()).await });
	}
	while let Some(result) = reads.join_next().await {
		assert_eq!(result.unwrap(), Err(ContextError::Denied));
	}
	Arc::try_unwrap(store).ok().unwrap().close().await.unwrap();
}
#[tokio::test]
async fn invalid_files_declarations_and_recovered_metadata_are_rejected() {
	let dir = Directory::new();
	SqliteRagStore::open(dir.config())
		.await
		.unwrap()
		.close()
		.await
		.unwrap();
	fs::write(&dir.config().path, b"not SQLite").unwrap();
	assert!(SqliteRagStore::open(dir.config()).await.is_err());
	assert_eq!(fs::read(&dir.config().path).unwrap(), b"not SQLite");
	for kind in [
		"clock",
		"authority",
		"payload",
		"expiry",
		"capacity",
		"namespace",
		"version",
	] {
		let dir = Directory::new();
		let (store, _, _) = seeded(dir.config()).await;
		store.close().await.unwrap();
		let mut connection = external(&dir.config().path).await;
		let query = match kind {
			"clock" => "UPDATE asp_rag_meta SET highwater=9223372036854775807",
			"authority" => "UPDATE asp_rag_meta SET authority='invalid'",
			"payload" => "UPDATE asp_rag_documents SET metadata='{}'",
			"expiry" => "UPDATE asp_rag_contexts SET expires_ms=1",
			"capacity" => "UPDATE asp_rag_meta SET max_contexts=999",
			"namespace" => "UPDATE asp_rag_meta SET namespace='other'",
			_ => "PRAGMA user_version=2",
		};
		connection.execute(query).await.unwrap();
		connection.close().await.unwrap();
		assert!(SqliteRagStore::open(dir.config()).await.is_err(), "{kind}");
	}
}
#[tokio::test]
async fn full_database_fails_closed_and_keeps_acknowledged_rows() {
	let dir = Directory::new();
	let mut config = dir.config();
	config.max_documents = 4096;
	let (store, id, original) = seeded(config.clone()).await;
	let mut accepted = 1;
	let mut failed = false;
	for n in 0..1024 {
		let mut large = document();
		large.document_id = format!("large-{n}");
		large.labels = vec!["x".repeat(256); 16];
		match store.begin_index(&large, access()).await {
			Ok(_) => accepted += 1,
			Err(ContextError::Unavailable) => {
				failed = true;
				break;
			},
			other => panic!("unexpected {other:?}"),
		}
	}
	assert!(failed);
	assert_eq!(
		store.classification(&id, &binding()).await,
		Err(ContextError::Unavailable)
	);
	store.close().await.unwrap();
	let store = SqliteRagStore::open(config).await.unwrap();
	assert!(store.classification(&id, &binding()).await.is_ok());
	assert_eq!(store.get_document(&original.key).await.unwrap(), original);
	store.close().await.unwrap();
	let mut connection = external(&dir.config().path).await;
	let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM asp_rag_documents")
		.fetch_one(&mut connection)
		.await
		.unwrap();
	assert_eq!(count, accepted);
	connection.close().await.unwrap();
}
#[tokio::test]
async fn single_owner_and_replaced_path_fail_closed() {
	let dir = Directory::new();
	let (store, id, _) = seeded(dir.config()).await;
	assert!(SqliteRagStore::open(dir.config()).await.is_err());
	fs::rename(&dir.config().path, dir.0.join("old.sqlite")).unwrap();
	assert_eq!(
		store.classification(&id, &binding()).await,
		Err(ContextError::Unavailable)
	);
	fs::rename(dir.0.join("old.sqlite"), &dir.config().path).unwrap();
	assert_eq!(
		store.classification(&id, &binding()).await,
		Err(ContextError::Unavailable)
	);
	store.close().await.unwrap();
}
#[cfg(unix)]
#[tokio::test]
async fn insecure_permissions_symlinks_and_hardlinks_are_rejected() {
	use std::os::unix::fs::{PermissionsExt, symlink};
	let dir = Directory::new();
	let (store, id, _) = seeded(dir.config()).await;
	fs::set_permissions(&dir.config().path, fs::Permissions::from_mode(0o644)).unwrap();
	assert_eq!(
		store.classification(&id, &binding()).await,
		Err(ContextError::Unavailable)
	);
	store.close().await.unwrap();
	assert!(SqliteRagStore::open(dir.config()).await.is_err());
	fs::set_permissions(&dir.config().path, fs::Permissions::from_mode(0o600)).unwrap();
	let alias = dir.0.join("alias.sqlite");
	symlink(&dir.config().path, &alias).unwrap();
	let mut config = dir.config();
	config.path = alias.clone();
	assert!(SqliteRagStore::open(config.clone()).await.is_err());
	fs::remove_file(&alias).unwrap();
	fs::hard_link(&dir.config().path, &alias).unwrap();
	assert!(SqliteRagStore::open(config).await.is_err());
}

#[tokio::test]
async fn authoritative_chunk_filter_replaces_untrusted_acl_and_rejects_stale_content() {
	let dir = Directory::new();
	let (store, _, meta) = seeded(dir.config()).await;
	let mut doc = document();
	doc.source_origin = SourceOrigin::Lifecycle {
		authority: meta.authority.clone(),
		version: meta.version,
		revision: meta.revision,
		origin: Box::new(SourceOrigin::Submitted),
	};
	let mut chunk = doc.to_chunk(
		"chunk",
		"text",
		1,
		TrustedChunkAccess {
			allow_tenant_authenticated: true,
			..Default::default()
		},
	);
	chunk.classification = DataClassification::Public;
	let subject = binding().owner.identity().into();
	let filtered = store
		.filter_chunks(&[chunk.clone()], &subject)
		.await
		.unwrap();
	assert_eq!(filtered.len(), 1);
	assert_eq!(filtered[0].classification, DataClassification::Restricted);
	assert_eq!(filtered[0].allowed_users, vec!["alice"]);
	assert!(!filtered[0].allow_tenant_authenticated);
	let mut other = binding().owner.identity();
	other.tenant_id = Some("tenant-b".into());
	assert!(
		store
			.filter_chunks(&[chunk.clone()], &other.into())
			.await
			.unwrap()
			.is_empty()
	);
	chunk.source_hash = "b".repeat(64);
	assert!(
		store
			.filter_chunks(&[chunk], &subject)
			.await
			.unwrap()
			.is_empty()
	);
	store.close().await.unwrap();
}
#[tokio::test]
async fn future_time_water_quarantines_live_store_even_after_external_repair() {
	let dir = Directory::new();
	let (store, id, _) = seeded(dir.config()).await;
	let mut connection = external(&dir.config().path).await;
	let water: i64 = sqlx::query_scalar("SELECT highwater FROM asp_rag_meta")
		.fetch_one(&mut connection)
		.await
		.unwrap();
	connection
		.execute("UPDATE asp_rag_meta SET highwater=9223372036854775807")
		.await
		.unwrap();
	assert_eq!(
		store.classification(&id, &binding()).await,
		Err(ContextError::Unavailable)
	);
	sqlx::query("UPDATE asp_rag_meta SET highwater=?")
		.bind(water)
		.execute(&mut connection)
		.await
		.unwrap();
	assert_eq!(
		store.classification(&id, &binding()).await,
		Err(ContextError::Unavailable)
	);
	connection.close().await.unwrap();
	store.close().await.unwrap();
}
#[tokio::test]
async fn repeated_reads_reclaim_wal_without_accumulating_a_read_history() {
	let dir = Directory::new();
	let (store, id, _) = seeded(dir.config()).await;
	for _ in 0..1024 {
		store.classification(&id, &binding()).await.unwrap();
	}
	let mut connection = external(&dir.config().path).await;
	let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM asp_rag_contexts")
		.fetch_one(&mut connection)
		.await
		.unwrap();
	assert_eq!(count, 1);
	let wal = dir.0.join("state.sqlite-wal");
	assert!(fs::metadata(wal).unwrap().len() <= 1_048_576);
	connection.close().await.unwrap();
	store.close().await.unwrap();
}

#[test]
fn recovery_worker() {
	let Some(path) = std::env::var_os("AISP_RAG_SQLITE_CHILD") else {
		return;
	};
	let directory = Directory(PathBuf::from(path));
	let config = directory.config();
	// The parent owns cleanup; this child is killed before normal teardown.
	let rt = tokio::runtime::Builder::new_current_thread()
		.enable_all()
		.build()
		.unwrap();
	rt.block_on(async move {
		let (store, id, meta) = seeded(config.clone()).await;
		if std::env::var("AISP_RAG_SQLITE_MODE").unwrap() == "revoked" {
			store.revoke(&id, &binding()).await.unwrap();
			store
				.mutate(&meta.key, meta.revision, DocumentMutation::Revoke)
				.await
				.unwrap();
		}
		fs::write(config.path.with_extension("ready"), id).unwrap();
		std::future::pending::<()>().await;
	});
}
#[tokio::test]
async fn acknowledged_live_and_revoked_state_recover_after_sigkill() {
	for mode in ["live", "revoked"] {
		let dir = Directory::new();
		let mut child = std::process::Command::new(std::env::current_exe().unwrap())
			.args(["--exact", "recovery_worker", "--nocapture"])
			.env("AISP_RAG_SQLITE_CHILD", &dir.0)
			.env("AISP_RAG_SQLITE_MODE", mode)
			.stdout(std::process::Stdio::null())
			.stderr(std::process::Stdio::null())
			.spawn()
			.unwrap();
		let ready = dir.config().path.with_extension("ready");
		let deadline = std::time::Instant::now() + Duration::from_secs(10);
		while !ready.exists() {
			if let Some(status) = child.try_wait().unwrap() {
				panic!("recovery worker exited {status}");
			}
			if std::time::Instant::now() >= deadline {
				let _ = child.kill();
				let _ = child.wait();
				panic!("recovery worker timeout");
			}
			tokio::time::sleep(Duration::from_millis(5)).await;
		}
		child.kill().unwrap();
		child.wait().unwrap();
		let id = fs::read_to_string(ready).unwrap();
		let store = SqliteRagStore::open(dir.config()).await.unwrap();
		assert_eq!(
			store.classification(&id, &binding()).await,
			if mode == "live" {
				Ok(DataClassification::Restricted)
			} else {
				Err(ContextError::Denied)
			}
		);
		let key = reference(
			&store
				.get_document(&security_types::DocumentKey {
					tenant_id: "tenant-a".into(),
					corpus_id: "docs".into(),
					document_id: "guide".into(),
				})
				.await
				.unwrap(),
		)
		.key;
		if mode == "revoked" {
			assert_eq!(
				store.get_document(&key).await.unwrap().state,
				DocumentState::Revoked
			);
		}
		store.close().await.unwrap();
	}
}

#[tokio::test]
async fn missing_owner_and_truncated_database_quarantine_the_live_store() {
	for owner in [true, false] {
		let dir = Directory::new();
		let (store, id, _) = seeded(dir.config()).await;
		if owner {
			fs::remove_file(dir.0.join("state.sqlite.owner")).unwrap();
		} else {
			fs::OpenOptions::new()
				.write(true)
				.open(&dir.config().path)
				.unwrap()
				.set_len(0)
				.unwrap();
		}
		assert_eq!(
			store.classification(&id, &binding()).await,
			Err(ContextError::Unavailable)
		);
		store.close().await.unwrap();
	}
}

#[tokio::test]
async fn pinned_reader_that_prevents_wal_reclamation_fails_closed() {
	let dir = Directory::new();
	let mut config = dir.config();
	config.busy_timeout_millis = 20;
	let (store, id, _) = seeded(config.clone()).await;
	let mut reader = external(&config.path).await;
	reader.execute("BEGIN").await.unwrap();
	let _: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM asp_rag_contexts")
		.fetch_one(&mut reader)
		.await
		.unwrap();
	let mut refused = false;
	for _ in 0..512 {
		// Force distinct persisted millisecond waters; a repeated identical UPDATE need not append.
		tokio::time::sleep(Duration::from_millis(2)).await;
		match store.classification(&id, &binding()).await {
			Ok(_) => {},
			Err(ContextError::Unavailable) => {
				refused = true;
				break;
			},
			other => panic!("unexpected {other:?}"),
		}
	}
	assert!(
		refused,
		"a pinned WAL reader must not permit indefinite history growth"
	);
	reader.execute("ROLLBACK").await.unwrap();
	reader.close().await.unwrap();
	assert_eq!(
		store.classification(&id, &binding()).await,
		Err(ContextError::Unavailable)
	);
	store.close().await.unwrap();
	let store = SqliteRagStore::open(config).await.unwrap();
	assert!(store.classification(&id, &binding()).await.is_ok());
	store.close().await.unwrap();
}
