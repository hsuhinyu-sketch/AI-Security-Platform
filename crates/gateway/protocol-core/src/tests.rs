use super::revision::ConfigRevision;

#[tokio::test]
async fn shared_revision_invalidates_all_consumers_and_keeps_new_lease_alive() {
	let revision: gateway_contracts::ConfigRevision = ConfigRevision::default();
	let mut mcp: super::revision::ConfigLease = revision.lease();
	let llm = mcp.clone();
	assert!(mcp.is_current() && llm.is_current());
	revision.invalidate();
	tokio::time::timeout(std::time::Duration::from_secs(1), mcp.changed())
		.await
		.unwrap();
	assert!(!mcp.is_current() && !llm.is_current());
	let fresh = revision.lease();
	drop(revision);
	assert!(fresh.is_current());
}
