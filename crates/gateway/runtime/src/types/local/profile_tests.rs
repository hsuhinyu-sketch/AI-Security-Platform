//! Configuration and execution rejection using the actual compiled capability set.
use super::*;
use serde_json::json;

#[cfg(not(feature = "gateway-llm"))]
#[tokio::test]
async fn disabled_llm_rejects_configuration_and_injected_execution_values() {
	let llm = json!({"models":[{"name":"local","provider":"openai"}]});
	let ai = json!({"provider":{"name":"local","provider":{"openAI":{}}}});
	for config in [
		json!({"llm":llm}),
		json!({"aiSystems":[{"name":"tools","llm":llm}]}),
		json!({"backends":[{"name":"models","ai":ai}]}),
	] {
		let error = serde_json::from_value::<LocalConfig>(config)
			.unwrap_err()
			.to_string();
		assert!(error.contains("LLM support is not compiled"), "{error}");
	}
	for result in [
		serde_json::from_value::<LocalBackendPolicies>(json!({"ai":{}})).map(|_| ()),
		serde_json::from_value::<FilterOrPolicy>(json!({"ai":{}})).map(|_| ()),
		serde_json::from_value::<LocalBackend>(json!({"ai":ai})).map(|_| ()),
	] {
		assert!(
			result
				.unwrap_err()
				.to_string()
				.contains("LLM support is not compiled")
		);
	}
	// The public input representation still rejects manually injected values. Runtime AI/
	// LLMRouter variants and their provider state are absent from this compiled profile.
	let injected = LocalBackend::AI(ai);
	let error = injected
		.as_backends(
			local_name("models".into()),
			&crate::resource_manager::ResourceFetcher::files_only(),
			Duration::from_secs(60),
		)
		.await
		.unwrap_err();
	assert!(error.to_string().contains("LLM support is not compiled"));
	assert!(
		!Backend::Opaque(
			local_name("plain".into()),
			Target::Hostname("localhost".into(), 80)
		)
		.is_llm()
	);
	let policy = crate::store::BackendPolicies {
		llm: Some(Arc::new(llm::Policy::default())),
		..Default::default()
	};
	assert!(policy.validate_compiled_protocols().is_err());
	// null keeps its historical meaning: no protocol or policy configured.
	serde_json::from_value::<LocalConfig>(
		json!({"llm":null,"aiSystems":[{"name":"tools","llm":null,"mcp":null}]}),
	)
	.unwrap();
	serde_json::from_value::<LocalBackendPolicies>(json!({"ai":null})).unwrap();
}

#[cfg(not(feature = "gateway-llm"))]
#[test]
fn mcp_sampling_and_catalog_configuration_require_compiled_llm() {
	for sessions in [
		json!({"reverse":{"samplingModels":["local"]}}),
		json!({"tasks":{"tools":["echo"],"sampling":{"authority":"127.0.0.1:4000","path":"/v1/chat/completions","model":"local"}},"reverse":{"samplingModels":["local"]}}),
	] {
		let security: security_integration_runtime::SecurityConfig =
			serde_json::from_value(json!({"mcpSessions":sessions})).unwrap();
		assert!(
			crate::capabilities::validate_security(&security, crate::capabilities::compiled_profile())
				.unwrap_err()
				.contains("sampling requires LLM")
		);
		let policy = crate::store::BackendPolicies {
			security_audit: Some(Arc::new(security.clone())),
			..Default::default()
		};
		assert!(policy.validate_compiled_protocols().is_err());
		let config = serde_json::from_value::<LocalConfig>(
			json!({"aiSystems":[{"name":"tools","security":security,"mcp":{"targets":[]}}]}),
		);
		if cfg!(feature = "gateway-mcp") {
			assert!(
				validate_gateway_capabilities(&config.unwrap())
					.unwrap_err()
					.to_string()
					.contains("sampling requires LLM")
			);
		} else {
			// A build without MCP must reject the protocol before Sampling admission.
			assert!(
				config
					.unwrap_err()
					.to_string()
					.contains("MCP support is not compiled")
			);
		}
	}
	let error = crate::config::parse_config(
		"config:\n  modelCatalog:\n  - file: /unused/catalog.json\n".into(),
		None,
	)
	.unwrap_err();
	assert!(
		error.to_string().contains("modelCatalog requires LLM"),
		"{error}"
	);
	let config: LocalConfig =
		serde_json::from_value(json!({"config":{"modelCatalog":[{"file":"/unused/catalog.json"}]}}))
			.unwrap();
	assert!(
		validate_gateway_capabilities(&config)
			.unwrap_err()
			.to_string()
			.contains("modelCatalog requires LLM")
	);
	for value in [json!(null), json!([])] {
		let config: LocalConfig =
			serde_json::from_value(json!({"config":{"modelCatalog":value}})).unwrap();
		validate_gateway_capabilities(&config).unwrap();
	}
}

#[cfg(not(feature = "gateway-mcp"))]
#[test]
fn disabled_mcp_rejects_all_configuration_entry_points() {
	for config in [
		json!({"mcp":{"targets":[]}}),
		json!({"aiSystems":[{"name":"edge","mcp":{"targets":[]}}]}),
		json!({"backends":[{"name":"tools","mcp":{"targets":[]}}]}),
	] {
		let error = serde_json::from_value::<LocalConfig>(config)
			.unwrap_err()
			.to_string();
		assert!(error.contains("MCP support is not compiled"), "{error}");
	}
	let error = serde_json::from_value::<LocalBackend>(json!({"mcp":{"targets":[]}}))
		.unwrap_err()
		.to_string();
	assert!(error.contains("MCP support is not compiled"), "{error}");
	for field in ["mcpAuthorization", "mcpGuardrails"] {
		let error = serde_json::from_value::<LocalBackendPolicies>(json!({field:{}}))
			.unwrap_err()
			.to_string();
		assert!(error.contains("MCP support is not compiled"), "{error}");
	}
	let error = serde_json::from_value::<FilterOrPolicy>(json!({"mcpAuthentication":{}}))
		.unwrap_err()
		.to_string();
	assert!(error.contains("MCP support is not compiled"), "{error}");
}

#[cfg(not(feature = "gateway-a2a"))]
#[test]
fn disabled_a2a_rejects_system_and_policy_configuration() {
	let error =
		serde_json::from_value::<LocalConfig>(json!({"aiSystems":[{"name":"edge","a2a":{}}]}))
			.unwrap_err()
			.to_string();
	assert!(error.contains("A2A support is not compiled"), "{error}");
	let error = serde_json::from_value::<LocalBackendPolicies>(json!({"a2a":{}}))
		.unwrap_err()
		.to_string();
	assert!(error.contains("A2A support is not compiled"), "{error}");
}

#[test]
fn provider_auth_and_guardrails_have_matching_compile_time_availability() {
	for (provider, provider_config, auth, auth_config, guardrail, guard_config, enabled) in [
		(
			"bedrock",
			json!({"region":"us-east-1"}),
			"aws",
			json!({}),
			"bedrockGuardrails",
			json!({"guardrailIdentifier":"guard","guardrailVersion":"1","region":"us-east-1"}),
			cfg!(feature = "providers-aws"),
		),
		(
			"azure",
			json!({"resourceName":"edge","resourceType":"openAI"}),
			"azure",
			json!({"implicit":{}}),
			"azureContentSafety",
			json!({"endpoint":"example.invalid"}),
			cfg!(feature = "providers-azure"),
		),
		(
			"vertex",
			json!({"projectId":"edge"}),
			"gcp",
			json!({}),
			"googleModelArmor",
			json!({"templateId":"guard","projectId":"edge"}),
			cfg!(feature = "providers-gcp"),
		),
	] {
		#[cfg(feature = "gateway-llm")]
		assert_eq!(
			serde_json::from_value::<LocalModelAIProvider>(json!(provider)).is_ok(),
			enabled,
			"{provider}"
		);
		// AIProvider uses the historical openAI spelling for its own variant; these cloud names agree.
		#[cfg(feature = "gateway-llm")]
		let provider_result =
			serde_json::from_value::<crate::llm::AIProvider>(json!({provider:provider_config}));
		let auth_result =
			serde_json::from_value::<crate::http::auth::BackendAuth>(json!({auth:auth_config}));
		let guard_result = serde_json::from_value::<crate::llm::policy::RequestGuardKind>(
			json!({guardrail:guard_config}),
		);
		if enabled {
			#[cfg(feature = "gateway-llm")]
			provider_result.unwrap();
			auth_result.unwrap();
			guard_result.unwrap();
		} else {
			for error in [
				#[cfg(feature = "gateway-llm")]
				provider_result.unwrap_err().to_string(),
				auth_result.unwrap_err().to_string(),
				guard_result.unwrap_err().to_string(),
			] {
				assert!(error.contains("unknown variant"), "{error}");
			}
		}
	}
}

#[tokio::test]
#[cfg(feature = "gateway-llm")]
async fn null_protocol_settings_preserve_ordinary_llm_configuration() {
	let cfg = crate::config::parse_config("{}".into(), None).unwrap();
	let target = ListenerTarget {
		gateway_name: "gateway".into(),
		gateway_namespace: "default".into(),
		listener_name: None,
		port: None,
	};
	let normalized = NormalizedLocalConfig::from(&cfg, &crate::resource_manager::ResourceFetcher::files_only(), target,
        "mcp: null\naiSystems:\n- name: edge\n  mcp: null\n  a2a: null\n  llm:\n    models:\n    - name: local\n      provider: openai\n").await.unwrap();
	assert!(
		normalized
			.backends
			.iter()
			.any(|b| matches!(b.backend, Backend::AI(..)))
	);
}

#[cfg(not(feature = "gateway-a2a"))]
#[test]
fn injected_protocol_policy_is_rejected_before_execution() {
	let policies = crate::store::BackendPolicies {
		a2a: Some(A2aPolicy {}),
		..Default::default()
	};
	assert!(
		policies
			.validate_compiled_protocols()
			.unwrap_err()
			.to_string()
			.contains("not compiled")
	);
	assert!(
		crate::store::BackendPolicies::default()
			.validate_compiled_protocols()
			.is_ok()
	);
}

#[cfg(not(feature = "gateway-mcp"))]
#[test]
fn injected_mcp_backend_is_rejected_before_mirroring_and_dispatch() {
	let backend = Backend::MCP(
		local_name("tools".into()),
		McpBackend {
			targets: vec![],
			stateful: true,
			always_use_prefix: false,
			failure_mode: FailureMode::FailClosed,
			session_idle_ttl: Duration::from_secs(60),
		},
	);
	assert!(
		backend
			.validate_compiled()
			.unwrap_err()
			.to_string()
			.contains("MCP support is not compiled")
	);
}

#[test]
fn infrastructure_hot_configuration_rejects_uncompiled_outputs() {
	for (raw, available, feature) in [
		(
			json!({"database":{"url":"sqlite::memory:"}}),
			cfg!(feature = "database"),
			"database",
		),
		(
			json!({"logging":{"database":{"url":"sqlite::memory:"}}}),
			cfg!(feature = "database"),
			"database",
		),
		(
			json!({"tracing":{"otlpEndpoint":"http://127.0.0.1:4318"}}),
			cfg!(feature = "telemetry-otlp"),
			"telemetry-otlp",
		),
	] {
		let config: LocalConfig = serde_json::from_value(json!({"config":raw})).unwrap();
		let result = validate_gateway_capabilities(&config);
		if available {
			result.unwrap();
		} else {
			assert!(result.unwrap_err().to_string().contains(feature));
		}
	}
	let config: LocalConfig = serde_json::from_value(
		json!({"config":{"database":null,"logging":{"database":null},"tracing":null}}),
	)
	.unwrap();
	validate_gateway_capabilities(&config).unwrap();
}

#[cfg(feature = "gateway-a2a")]
#[tokio::test]
async fn ai_system_protocol_routes_are_attached_to_the_actual_listener_keys() {
	let cfg = crate::config::parse_config("{}".into(), None).unwrap();
	let target = ListenerTarget {
		gateway_name: "gateway".into(),
		gateway_namespace: "default".into(),
		listener_name: None,
		port: None,
	};
	let mut system =
		json!({"name":"scene","a2a":{"port":16503,"backend":{"host":"127.0.0.1:18000"}}});
	if cfg!(feature = "gateway-llm") {
		system["llm"] = json!({"port":16501,"models":[{"name":"local","provider":"openai"}]});
	}
	if cfg!(feature = "gateway-mcp") {
		system["mcp"] = json!({"port":16502,"targets":[]});
	}
	let normalized = NormalizedLocalConfig::from(
		&cfg,
		&crate::resource_manager::ResourceFetcher::files_only(),
		target,
		&json!({"aiSystems":[system]}).to_string(),
	)
	.await
	.unwrap();
	let routes: std::collections::HashMap<_, _> = normalized
		.listener_routes
		.iter()
		.map(|(key, routes)| (key, routes))
		.collect();
	for bind in &normalized.binds {
		for listener in bind.listeners.inner.values() {
			assert!(
				routes.get(&listener.key).is_some_and(|r| !r.is_empty()),
				"listener {} has no reachable routes",
				listener.key
			);
		}
	}
}

#[cfg(all(feature = "schema", not(feature = "gateway-llm")))]
#[test]
fn disabled_llm_schema_does_not_advertise_provider_or_model_configuration() {
	let schema = serde_json::to_value(schemars::schema_for!(LocalConfig)).unwrap();
	let definitions = schema["$defs"].as_object().expect("schema definitions");
	for name in [
		"LocalLLMConfig",
		"LocalLLMModels",
		"LocalNamedAIProvider",
		"LocalAIProviders",
		"LocalModelAIProvider",
	] {
		assert!(
			!definitions.contains_key(name),
			"disabled LLM schema retained {name}"
		);
	}
}

#[cfg(feature = "gateway-llm")]
#[tokio::test]
async fn legacy_named_and_grouped_providers_keep_backend_keys_and_security_model_identity() {
	let provider = json!({"name":"model-identity", "provider":{"openAI":{"model":"upstream-model"}}});
	for input in [
		provider.clone(),
		json!({"groups":[{"providers":[provider]}]}),
	] {
		let backend: LocalBackend = serde_json::from_value(json!({"ai":input})).unwrap();
		let normalized = backend
			.as_backends(
				local_name("backend-key".into()),
				&crate::resource_manager::ResourceFetcher::files_only(),
				Duration::from_secs(60),
			)
			.await
			.unwrap();
		let backend = &normalized[0].backend;
		assert_eq!(backend.resource_name().unwrap().name, "backend-key");
		assert!(backend.is_llm());
		let Backend::AI(_, ai) = backend else {
			panic!("AI backend expected")
		};
		let (provider, _health) = ai.select_provider().unwrap();
		assert_eq!(provider.name, "model-identity");
		assert_eq!(
			provider.provider.override_model().as_deref(),
			Some("upstream-model")
		);
		let policies = crate::store::BackendPolicies {
			llm_provider: Some(provider),
			..Default::default()
		};
		assert_eq!(policies.model_name(), Some("model-identity"));
		policies.validate_compiled_protocols().unwrap();
	}
}
