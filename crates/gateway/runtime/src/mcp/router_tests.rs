use super::*;
use serde_json::json;

#[test]
fn raw_metadata_passthrough_requires_read_only_discovery_without_mcp_controls() {
	let app = App::new(Stores::with_ipv6_enabled(false), Encoder::base64());
	let mut backend = McpBackend {
		targets: vec![Arc::new(crate::types::agent::McpTarget {
			name: "local".into(),
			spec: McpTargetSpec::Mcp(crate::types::agent::StreamableHTTPTargetSpec {
				backend: SimpleBackendReference::Backend("local".into()),
				path: "/mcp".into(),
			}),
		})],
		stateful: false,
		always_use_prefix: false,
		failure_mode: Default::default(),
		session_idle_ttl: mcp::DEFAULT_SESSION_IDLE_TTL,
	};
	let request = |method, path: &str| {
		::http::Request::builder()
			.method(method)
			.uri(path)
			.body(Body::empty())
			.unwrap()
	};
	let metadata = request(Method::GET, "/.well-known/oauth-protected-resource");
	let mut policies = BackendPolicies::default();
	assert!(
		app
			.should_passthrough(&policies, &backend, &metadata)
			.is_some()
	);
	assert!(
		app
			.should_passthrough(
				&policies,
				&backend,
				&request(Method::HEAD, "/.well-known/oauth-protected-resource")
			)
			.is_some()
	);
	for (method, path) in [
		(Method::POST, "/.well-known/tool"),
		(Method::GET, "/tools/.well-known/execute"),
	] {
		assert!(
			app
				.should_passthrough(&policies, &backend, &request(method, path))
				.is_none()
		);
	}
	let config: security_integration_runtime::SecurityConfig =
		serde_json::from_value(json!({"mode":"enforce"})).unwrap();
	policies.security_audit = Some(Arc::new(config));
	assert!(
		app
			.should_passthrough(&policies, &backend, &metadata)
			.is_none()
	);
	policies.security_audit = None;
	policies.security_pipeline = Some(security_pipeline::SecurityPipelineConfig::default().into());
	assert!(
		app
			.should_passthrough(&policies, &backend, &metadata)
			.is_none()
	);
	policies.security_pipeline = None;
	policies.mcp_authorization = Some(McpAuthorizationSet::new(Vec::new().into()));
	assert!(
		app
			.should_passthrough(&policies, &backend, &metadata)
			.is_none()
	);
	policies.mcp_authorization = None;
	let mut inherited = metadata;
	inherited
		.extensions_mut()
		.insert(crate::proxy::InheritedConfigs(vec![Arc::new(
			security_integration_runtime::SecurityConfig::default(),
		)]));
	assert!(
		app
			.should_passthrough(&policies, &backend, &inherited)
			.is_none()
	);
	backend.targets.push(backend.targets[0].clone());
	assert!(
		app
			.should_passthrough(
				&policies,
				&backend,
				&request(Method::GET, "/.well-known/oauth-protected-resource")
			)
			.is_none()
	);
}
