use security_rag::{DataClassification, IndexedDocument, SourceOrigin, TrustedChunkAccess};

fn document() -> IndexedDocument {
	IndexedDocument {
		tenant_id: "tenant-a".into(),
		corpus_id: "docs".into(),
		document_id: "doc".into(),
		source_uri: "https://sources.example/doc".into(),
		source_hash: "a".repeat(64),
		source_origin: SourceOrigin::Submitted,
		content: "document".into(),
		labels: vec!["private".into()],
		classification: DataClassification::Restricted,
		classification_source: "admin-rule".into(),
	}
}

#[test]
fn default_chunk_ids_are_stable_uuids_scoped_to_tenant_corpus_document_and_offset() {
	let doc = document();
	let access = TrustedChunkAccess {
		allowed_users: vec!["alice".into()],
		..Default::default()
	};
	let first = doc.to_chunk("doc:0", "fragment", 3, access.clone());
	assert!(uuid::Uuid::parse_str(&first.id).is_ok(), "{}", first.id);
	assert_eq!(first.id, doc.to_chunk("doc:0", "fragment", 3, access).id);
	assert_eq!(first.labels, doc.labels);
	assert_eq!(first.source_origin, doc.source_origin);
	assert_eq!(first.source_hash, doc.source_hash);
	assert_eq!(first.allowed_users, ["alice"]);
	let mut ids = std::collections::HashSet::from([first.id]);
	for field in ["tenant", "corpus", "document", "offset"] {
		let mut other = doc.clone();
		match field {
			"tenant" => other.tenant_id = "tenant-b".into(),
			"corpus" => other.corpus_id = "other".into(),
			"document" => other.document_id = "other".into(),
			_ => {},
		}
		let chunk = other.to_chunk(
			if field == "offset" { "doc:1" } else { "doc:0" },
			"fragment",
			3,
			Default::default(),
		);
		assert!(uuid::Uuid::parse_str(&chunk.id).is_ok());
		assert!(ids.insert(chunk.id), "collision for {field}");
	}
}

#[test]
fn lifecycle_chunk_ids_keep_the_existing_persisted_identity_and_version_boundaries() {
	let mut doc = document();
	doc.source_origin = SourceOrigin::Lifecycle {
		authority: "authority".into(),
		version: 1,
		revision: 1,
		origin: Box::new(SourceOrigin::Submitted),
	};
	let first = doc.to_chunk("doc:0", "fragment", 3, Default::default()).id;
	assert_eq!(first, "d60a92e7-feb0-21d2-ddb6-735984ea1da2");
	if let SourceOrigin::Lifecycle { revision, .. } = &mut doc.source_origin {
		*revision = 2;
	}
	assert_eq!(
		first,
		doc.to_chunk("doc:0", "fragment", 3, Default::default()).id
	);
	if let SourceOrigin::Lifecycle { version, .. } = &mut doc.source_origin {
		*version = 2;
	}
	assert_ne!(
		first,
		doc.to_chunk("doc:0", "fragment", 3, Default::default()).id
	);
}
