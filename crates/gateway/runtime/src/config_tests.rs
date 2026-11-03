use super::*;
use crate::types::local::NormalizedLocalConfig;
use serde_json::json;

async fn normalize(config: &Config, document: &str) -> anyhow::Result<NormalizedLocalConfig> {
	NormalizedLocalConfig::from(
		config,
		&crate::resource_manager::ResourceFetcher::files_only(),
		config.gateway(),
		document,
	)
	.await
}

#[tokio::test]
async fn startup_changes_are_rejected_before_local_deserialization() {
	let config = parse_config("config: {mcp: {sessionTtl: 30s}}".into(), None).unwrap();
	for candidate in [
		json!({}),
		json!({"config":null}),
		json!({"config":{}}),
		json!({"config":{"mcp":{"sessionTtl":"60s"}}}),
		json!({"config":{"mcp":{"sessionTtl":"30s"},"securityAuditPath":"/private/candidate"}}),
	] {
		let mut candidate = candidate;
		// An unsupported startup edit must be rejected before preparing any local candidate.
		candidate["binds"] = json!([{"port":99999}]);
		let error = normalize(&config, &candidate.to_string())
			.await
			.unwrap_err()
			.to_string();
		assert!(
			error.contains("startup-only") && error.contains("restart required"),
			"{error}"
		);
		assert!(!error.contains("/private/candidate"));
	}
}

#[tokio::test]
async fn equivalent_startup_section_allows_local_changes() {
	let config = parse_config(
		"config: {mcp: {sessionTtl: 30s}, management: {mode: edge}}".into(),
		None,
	)
	.unwrap();
	let normalized = normalize(
		&config,
		r#"
# yaml-language-server: $schema=ignored
config:
  management: {mode: edge}
  mcp:
    sessionTtl: '30s'
binds:
- port: 18080
  listeners:
  - protocol: HTTP
    routes:
    - policies:
        directResponse: {status: 403}
"#,
	)
	.await
	.unwrap();
	assert_eq!(normalized.binds.len(), 1);
}

#[tokio::test]
async fn absent_null_and_empty_startup_sections_are_equivalent() {
	for original in ["{}", "config: null", "config: {}"] {
		let config = parse_config(original.into(), None).unwrap();
		for candidate in ["{}", "config: null", "config: {}"] {
			normalize(&config, candidate).await.unwrap();
		}
		assert!(
			normalize(&config, "config: {enableIpv6: true}")
				.await
				.unwrap_err()
				.to_string()
				.contains("startup-only")
		);
	}
}

#[tokio::test]
async fn startup_and_local_validation_use_the_same_environment_expansion() {
	let text = "config: {network: '${PATH}'}";
	let config = parse_config(text.into(), None).unwrap();
	assert_eq!(config.network.as_str(), std::env::var("PATH").unwrap());
	normalize(&config, text).await.unwrap();
}

#[test]
fn startup_snapshot_does_not_expose_values_in_debug_or_config_dump() {
	let document = json!({"config":{"secret":"private-value"}});
	let snapshot = StartupConfig(Arc::new(StartupConfig::section(&document).cloned()));
	assert!(!format!("{snapshot:?}").contains("private-value"));
	let config = parse_config("{}".into(), None).unwrap();
	assert!(
		serde_json::to_value(config)
			.unwrap()
			.get("startupConfig")
			.is_none()
	);
}
