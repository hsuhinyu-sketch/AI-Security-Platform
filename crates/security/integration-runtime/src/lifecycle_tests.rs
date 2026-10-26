use crate::{context_store::*, identity_binding::VerifiedOwner};
use security_audit::StateJournalConfig;
use security_pipeline::GatewayIdentity;
use security_rag::{IndexedDocument, SourceOrigin, TrustedChunkAccess, lifecycle::*};
use security_types::{DataClassification, DocumentVersion};
use std::path::PathBuf;

struct Directory(PathBuf);
impl Directory {
	fn new() -> Self {
		let path = std::env::temp_dir().join(format!("aisp-lifecycle-{}", uuid::Uuid::new_v4()));
		let mut builder = std::fs::DirBuilder::new();
		#[cfg(unix)]
		{
			use std::os::unix::fs::DirBuilderExt;
			builder.mode(0o700);
		}
		builder.create(&path).unwrap();
		Self(path)
	}
	fn journal(&self, name: &str) -> StateJournalConfig {
		StateJournalConfig {
			path: self.0.join(name),
			max_bytes: 1_048_576,
		}
	}
}
impl Drop for Directory {
	fn drop(&mut self) {
		let _ = std::fs::remove_dir_all(&self.0);
	}
}
fn identity() -> GatewayIdentity {
	GatewayIdentity {
		user_id: Some("alice".into()),
		tenant_id: Some("tenant-a".into()),
		client_id: Some("client-a".into()),
		..Default::default()
	}
}
fn binding() -> ContextBinding {
	ContextBinding {
		owner: VerifiedOwner::from_identity(&identity(), "https://issuer.example").unwrap(),
		namespace: "knowledge".into(),
		fingerprint: "config-v1".into(),
	}
}

#[test]
fn revoked_document_invalidates_context_and_stays_revoked_after_reopen() {
	let dir = Directory::new();
	let config = DocumentLifecycleConfig {
		namespace: "knowledge".into(),
		storage: dir.journal("documents.jsonl"),
		max_documents: 16,
	};
	let documents = DocumentLifecycleStore::open(config.clone()).unwrap();
	let document = IndexedDocument {
		corpus_id: "docs".into(),
		document_id: "guide".into(),
		tenant_id: "tenant-a".into(),
		source_uri: "file:///guide".into(),
		source_hash: "a".repeat(64),
		source_origin: SourceOrigin::Submitted,
		content: "private knowledge".into(),
		labels: vec![],
		classification: DataClassification::Restricted,
		classification_source: "trusted-source".into(),
	};
	let metadata = documents
		.begin_index(
			&document,
			TrustedChunkAccess {
				allowed_users: vec!["alice".into()],
				..Default::default()
			},
		)
		.unwrap();
	documents
		.activate(&metadata.key, metadata.revision)
		.unwrap();
	let reference = DocumentVersion {
		authority: metadata.authority.clone(),
		key: metadata.key.clone(),
		revision: metadata.revision,
	};
	let context_spec = dir.journal("contexts.jsonl");
	let contexts = LocalSecurityContextStore::open(context_spec.clone(), "knowledge").unwrap();
	contexts
		.register_document_validator("knowledge", documents.clone())
		.unwrap();
	let owner = binding();
	let id = contexts
		.issue_documents(
			owner.clone(),
			60,
			16,
			DataClassification::Restricted,
			vec![reference.clone()],
		)
		.unwrap();
	assert_eq!(
		contexts.classification(&id, &owner).unwrap(),
		DataClassification::Restricted
	);
	let mut foreign = owner.clone();
	let mut other = identity();
	other.user_id = Some("bob".into());
	foreign.owner = VerifiedOwner::from_identity(&other, "https://issuer.example").unwrap();
	assert!(contexts.classification(&id, &foreign).is_err());
	documents
		.mutate(&metadata.key, metadata.revision, DocumentMutation::Revoke)
		.unwrap();
	assert!(contexts.classification(&id, &owner).is_err());
	assert!(
		contexts
			.issue_documents(
				owner.clone(),
				60,
				16,
				DataClassification::Public,
				vec![reference]
			)
			.is_err()
	);
	drop(contexts);
	drop(documents);
	let documents = DocumentLifecycleStore::open(config).unwrap();
	assert_eq!(
		documents.get(&metadata.key).unwrap().state,
		DocumentState::Revoked
	);
	assert!(
		documents
			.begin_index(&document, Default::default())
			.is_err()
	);
	let contexts = LocalSecurityContextStore::open(context_spec, "knowledge").unwrap();
	contexts
		.register_document_validator("knowledge", documents.clone())
		.unwrap();
	assert!(contexts.classification(&id, &owner).is_err());
}

#[test]
fn context_revocation_and_classification_remain_monotonic_after_reopen() {
	let dir = Directory::new();
	let spec = dir.journal("contexts.jsonl");
	let store = LocalSecurityContextStore::open(spec.clone(), "knowledge").unwrap();
	let owner = binding();
	let id = store
		.issue(owner.clone(), 60, 16, DataClassification::Public)
		.unwrap();
	store
		.elevate(&id, &owner, DataClassification::Restricted)
		.unwrap();
	store
		.elevate(&id, &owner, DataClassification::Public)
		.unwrap();
	assert_eq!(
		store.classification(&id, &owner).unwrap(),
		DataClassification::Restricted
	);
	store.revoke(&id, &owner).unwrap();
	drop(store);
	let store = LocalSecurityContextStore::open(spec, "knowledge").unwrap();
	assert!(store.classification(&id, &owner).is_err());
	assert!(
		store
			.elevate(&id, &owner, DataClassification::Public)
			.is_err()
	);
}

#[cfg(feature = "a2a-sqlite")]
#[test]
fn a2a_task_ownership_and_terminal_state_survive_reopen() {
	use crate::a2a_objects::*;
	let dir = Directory::new();
	let config = A2aObjectConfig {
		max_streams: 1,
		storage: TaskStoreConfig::Sqlite {
			path: dir.0.join("tasks.db"),
			namespace: "agent".into(),
			busy_timeout_millis: 100,
		},
		..Default::default()
	};
	let store = TaskStoreHandle::from_config(&config).unwrap();
	let user = identity();
	let mut permit = store
		.begin(
			&config,
			&user,
			"https://issuer.example",
			"endpoint-a",
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
			TaskState::Working,
		)
		.unwrap();
	let mut foreign = user.clone();
	foreign.user_id = Some("bob".into());
	assert!(
		store
			.begin(
				&config,
				&foreign,
				"https://issuer.example",
				"endpoint-a",
				Some("task-a"),
				TaskOperation::Read
			)
			.is_err()
	);
	assert!(
		store
			.begin(
				&config,
				&user,
				"https://other.example",
				"endpoint-a",
				Some("task-a"),
				TaskOperation::Read
			)
			.is_err()
	);
	let stream = store.reserve_stream(&config).unwrap();
	assert!(store.reserve_stream(&config).is_err());
	drop(stream);
	drop(store.reserve_stream(&config).unwrap());
	store
		.finish(
			&config,
			&mut permit,
			"task-a",
			"context-a",
			TaskState::Completed,
		)
		.unwrap();
	assert!(
		store
			.finish(
				&config,
				&mut permit,
				"task-a",
				"context-a",
				TaskState::Working
			)
			.is_err()
	);
	drop(store);
	let store = TaskStoreHandle::from_config(&config).unwrap();
	let recovered = store
		.begin(
			&config,
			&user,
			"https://issuer.example",
			"endpoint-a",
			Some("task-a"),
			TaskOperation::Read,
		)
		.unwrap();
	assert_eq!(recovered.snapshot_state(), Some(TaskState::Completed));
	assert!(store.validate_permit(&config, &permit).is_err());
	assert!(
		store
			.begin(
				&config,
				&user,
				"https://issuer.example",
				"endpoint-a",
				Some("task-a"),
				TaskOperation::Continue
			)
			.is_err()
	);
}

#[cfg(feature = "a2a-sqlite")]
#[test]
fn a2a_event_cursors_remain_bound_to_lineage_after_reopen() {
	use crate::a2a_objects::{events::*, *};
	let dir = Directory::new();
	let config = A2aObjectConfig {
		storage: TaskStoreConfig::Sqlite {
			path: dir.0.join("tasks.db"),
			namespace: "agent".into(),
			busy_timeout_millis: 100,
		},
		..Default::default()
	};
	let tasks = TaskStoreHandle::from_config(&config).unwrap();
	let mut permit = tasks
		.begin(
			&config,
			&identity(),
			"https://issuer.example",
			"endpoint-a",
			None,
			TaskOperation::Create,
		)
		.unwrap();
	tasks
		.finish(
			&config,
			&mut permit,
			"task-a",
			"context-a",
			TaskState::Working,
		)
		.unwrap();
	let binding = EventBinding::from_permit(&permit, "a".repeat(43)).unwrap();
	let foreign = EventBinding::from_permit(&permit, "b".repeat(43)).unwrap();
	let mut settings: EventRecoveryConfig = serde_json::from_value(serde_json::json!({
		"namespace":"agent", "storage":{"path":dir.0.join("events.jsonl"),"maxBytes":1048576}
	}))
	.unwrap();
	let serialized = serde_json::to_value(&settings).unwrap();
	settings.prepare_store().unwrap();
	let events = settings.store().unwrap();
	let result = serde_json::json!({"kind":"task","id":"task-a","contextId":"context-a","status":{"state":"working"}});
	let first = events.append(binding.clone(), result.clone()).unwrap();
	let second = events.append(binding.clone(), result).unwrap();
	let batch = events.read(&binding, &first, 16).unwrap();
	assert_eq!(batch.events.len(), 1);
	assert_eq!(batch.next_cursor, second);
	assert!(events.read(&foreign, &first, 16).is_err());
	drop(events);
	drop(settings);
	let mut settings: EventRecoveryConfig = serde_json::from_value(serialized).unwrap();
	settings.prepare_store().unwrap();
	let events = settings.store().unwrap();
	assert_eq!(
		events.read(&binding, &first, 16).unwrap().next_cursor,
		second
	);
	assert!(events.read(&foreign, &first, 16).is_err());
}
