use ai_security_platform_runtime::resource_manager::ResourceFetcher;
use ai_security_platform_runtime::types::agent::{BackendTrafficPolicy, ListenerTarget};
use ai_security_platform_runtime::types::local::NormalizedLocalConfig;
use security_integration_runtime::SecurityMode;

#[tokio::test]
async fn ai_system_expands_llm_inference_a2a_and_mcp_gateways() {
	let config = ai_security_platform_runtime::config::parse_config("{}".to_string(), None).unwrap();
	let normalized = NormalizedLocalConfig::from(
		&config,
		&ResourceFetcher::files_only(),
		ListenerTarget {
			gateway_name: "name".into(),
			gateway_namespace: "ns".into(),
			listener_name: None,
			port: None,
		},
		r#"
aiSystems:
- name: assistant
  security:
    mode: enforce
    requiredIdentity:
      user: true
      agent: true
      tenant: true
    policies:
    - id: allow-chat
      actionType: modelInvoke
      actionName: invoke
      resourceId: chat
      resourceType: model
      effect: allow
      enabled: true
  llm:
    port: 4100
    policies:
      inferenceRouting:
        endpointPicker:
          host: 127.0.0.1:8300
        destinationMode: passthrough
    models:
    - name: chat
      provider: openAI
  a2a:
    port: 4101
    backend:
      host: 127.0.0.1:8100
  mcp:
    port: 4102
    targets:
    - name: tools
      mcp:
        host: 127.0.0.1:8200
"#,
	)
	.await
	.expect("AI system composition should normalize");

	let ports = normalized
		.binds
		.iter()
		.map(|bind| bind.address.port())
		.collect::<Vec<_>>();
	assert_eq!(ports, vec![4100, 4101, 4102]);
	for listener in [
		"ai-system:assistant:llm",
		"ai-system:assistant:a2a",
		"ai-system:assistant:mcp",
	] {
		assert!(
			normalized
				.listener_routes
				.iter()
				.any(|(key, _)| key.as_str() == listener),
			"missing listener {listener}"
		);
	}
	assert!(normalized.listener_routes.iter().any(|(_, routes)| {
		routes
			.iter()
			.flat_map(|route| &route.backends)
			.any(|backend| {
				backend
					.inline_policies
					.iter()
					.any(|policy| matches!(policy, BackendTrafficPolicy::A2a(_)))
			})
	}));
	assert!(normalized.backends.iter().any(|backend| {
		backend
			.inline_policies
			.iter()
			.any(|policy| matches!(policy, BackendTrafficPolicy::InferenceRouting(_)))
	}));
	assert!(normalized.backends.iter().any(|backend| {
		backend
			.inline_policies
			.iter()
			.any(|policy| matches!(policy, BackendTrafficPolicy::SecurityAudit(_)))
	}));
	assert!(normalized.backends.iter().any(|backend| {
		backend.inline_policies.iter().any(|policy| {
			matches!(
				policy,
				BackendTrafficPolicy::SecurityAudit(config)
					if config.mode == SecurityMode::Enforce
						&& config.pipeline.policies.iter().any(|policy| policy.id == "allow-chat")
			)
		})
	}));
}
