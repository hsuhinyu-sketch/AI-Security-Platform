use super::*;
use serde_json::json;

fn host() -> Implementation {
	Implementation::new("host", "host-version")
}
fn result(value: serde_json::Value) -> ServerResult {
	serde_json::from_value(value).unwrap()
}
fn initialize(version: &str, instructions: &str) -> ServerResult {
	result(
		json!({"protocolVersion":version,"capabilities":{"tools":{}},
		"serverInfo":{"name":"upstream","version":"1"},"instructions":instructions,"_meta":{"keep":1}}),
	)
}
fn discovery(versions: &[&str], instructions: &str) -> ServerResult {
	result(json!({"resultType":"complete","supportedVersions":versions,
		"capabilities":{"tools":{}},"serverInfo":{"name":"upstream","version":"1"},
		"instructions":instructions,"ttlMs":123,"cacheScope":"public","_meta":{"keep":1}}))
}

#[test]
fn single_initialize_preserves_the_upstream_result() {
	let original = initialize("2025-03-26", "keep these instructions");
	let merged = merge_initialize(
		[("one", original.clone())],
		ProtocolVersion::V_2025_11_25,
		false,
		false,
		host(),
	);
	assert_eq!(
		serde_json::to_value(merged).unwrap(),
		serde_json::to_value(original).unwrap()
	);
}

#[test]
fn multiplex_initialize_negotiates_version_and_keeps_instruction_order() {
	let merged = merge_initialize(
		[
			("one", initialize("2025-11-25", "first")),
			("two", initialize("2025-03-26", "second")),
			("empty", initialize("2025-06-18", "")),
		],
		ProtocolVersion::V_2025_11_25,
		true,
		true,
		host(),
	);
	assert_eq!(merged.protocol_version, ProtocolVersion::V_2025_03_26);
	assert!(
		merged
			.instructions
			.unwrap()
			.ends_with("\n\n[one]\nfirst\n\n[two]\nsecond")
	);
	assert_eq!(merged.capabilities.resources.unwrap().subscribe, Some(true));
	assert_eq!(merged.server_info.name, "host");
}

#[test]
fn empty_success_sets_keep_existing_fallback_responses() {
	for multiplexing in [false, true] {
		let merged = merge_initialize(
			Vec::<(&str, ServerResult)>::new(),
			ProtocolVersion::V_2025_03_26,
			multiplexing,
			false,
			host(),
		);
		assert_eq!(merged.protocol_version, ProtocolVersion::V_2025_03_26);
		assert!(merged.capabilities.resources.unwrap().subscribe.is_none());
		assert!(!merged.instructions.unwrap().contains('['));
		let merged = merge_discover(
			Vec::<(&str, ServerResult)>::new(),
			multiplexing,
			false,
			host(),
		);
		assert_eq!(
			merged.supported_versions,
			crate::protocol::SUPPORTED_VERSIONS
		);
		// Cache policy is supplied by the Host, not invented by aggregation.
		assert!(merged.ttl_ms.is_none());
	}
}

#[test]
fn single_discovery_only_clamps_versions_and_leaves_cache_policy_to_host() {
	let original = discovery(&["2026-07-28", "2099-01-01"], "keep");
	let merged = merge_discover([("one", original.clone())], false, false, host());
	let mut expected = serde_json::to_value(original).unwrap();
	expected["supportedVersions"] = json!(["2026-07-28"]);
	assert_eq!(serde_json::to_value(merged).unwrap(), expected);
}

#[test]
fn multiplex_discovery_intersects_all_versions_without_synthesizing_support() {
	let merged = merge_discover(
		[
			(
				"one",
				discovery(&["2026-07-28", "2025-11-25", "2099-01-01"], "first"),
			),
			("two", discovery(&["2025-11-25", "2099-01-01"], "second")),
		],
		true,
		false,
		host(),
	);
	assert_eq!(
		merged.supported_versions,
		vec![ProtocolVersion::V_2025_11_25]
	);
	assert!(
		merged
			.instructions
			.unwrap()
			.ends_with("\n\n[one]\nfirst\n\n[two]\nsecond")
	);
	let merged = merge_discover(
		[
			("one", discovery(&["2026-07-28"], "")),
			("two", discovery(&["2025-11-25"], "")),
		],
		true,
		false,
		host(),
	);
	assert!(merged.supported_versions.is_empty());
}
