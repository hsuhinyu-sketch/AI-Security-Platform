use super::*;
use serde_json::json;

fn empty() -> NormalizedLocalConfig {
	NormalizedLocalConfig {
		#[cfg(feature = "gateway-rag")]
		rag_systems: vec![],
		binds: vec![],
		listener_routes: vec![],
		listener_tcp_routes: vec![],
		policies: vec![],
		backends: vec![],
		route_groups: vec![],
		workloads: vec![],
		services: vec![],
	}
}
fn security(endpoint: &str) -> Arc<SecurityConfig> {
	Arc::new(
		serde_json::from_value(json!({
			"mode":"enforce", "remotePdp":{"endpoint":endpoint},
			"dynamicAuthorization":{"policyVersion":"v1"}
		}))
		.unwrap(),
	)
}
fn parent() -> DependencyEgressConfig {
	serde_json::from_value(json!({"destinations":{"pdp":["allowed.test:443"]}})).unwrap()
}
fn name() -> RouteName {
	RouteName {
		name: "route".into(),
		namespace: "test".into(),
		rule_name: None,
		kind: None,
	}
}
fn targeted(policy: BackendTrafficPolicy) -> TargetedPolicy {
	TargetedPolicy {
		key: "policy".into(),
		name: None,
		target: PolicyTarget::Route(name()),
		inheritance: Default::default(),
		policy: PolicyType::Backend(policy),
	}
}
fn http_route(policy: BackendTrafficPolicy) -> Route {
	Route {
		key: "route".into(),
		service_key: None,
		service_port: 0,
		name: name(),
		hostnames: vec![],
		matches: vec![],
		inline_policies: vec![],
		backends: vec![RouteBackendReference {
			weight: 1,
			target: BackendReference::Invalid.into(),
			inline_policies: vec![policy],
		}],
	}
}
fn place(config: &mut NormalizedLocalConfig, location: &str, security: Arc<SecurityConfig>) {
	let policy = BackendTrafficPolicy::SecurityAudit(security);
	match location {
		"policy" => config.policies.push(targeted(policy)),
		"backend" => config.backends.push(BackendWithPolicies {
			backend: Backend::Invalid,
			inline_policies: vec![policy],
		}),
		"http" => config
			.listener_routes
			.push(("listener".into(), vec![http_route(policy)])),
		"group" => config
			.route_groups
			.push(("group".into(), vec![http_route(policy)])),
		"tcp" => config.listener_tcp_routes.push((
			"tcp".into(),
			vec![TCPRoute {
				key: "tcp".into(),
				service_key: None,
				service_port: 0,
				name: name(),
				hostnames: vec![],
				backends: vec![TCPRouteBackendReference {
					weight: 1,
					backend: SimpleBackendReference::Invalid,
					inline_policies: vec![policy],
				}],
			}],
		)),
		_ => unreachable!(),
	}
}

#[tokio::test]
async fn every_policy_location_enforces_the_global_dependency_limit() {
	for location in ["policy", "backend", "http", "group", "tcp"] {
		let mut config = empty();
		place(
			&mut config,
			location,
			security("https://unapproved.test/pdp"),
		);
		assert!(
			config
				.prepare_security(Some(&parent()))
				.await
				.unwrap_err()
				.to_string()
				.contains("denied Pdp"),
			"{location}"
		);
		let mut config = empty();
		place(&mut config, location, security("https://allowed.test/pdp"));
		config.prepare_security(Some(&parent())).await.unwrap();
	}
}

#[test]
fn shared_declarations_are_visited_once_without_merging_distinct_runtime_owners() {
	let mut config = empty();
	let shared = security("https://allowed.test/pdp");
	for location in ["policy", "backend", "http", "group", "tcp"] {
		place(&mut config, location, shared.clone());
	}
	assert_eq!(config.security_configs().len(), 1);
	let distinct = Arc::new((*shared).clone());
	place(&mut config, "policy", distinct.clone());
	let configs = config.security_configs();
	assert_eq!(configs.len(), 2);
	assert!(configs.iter().any(|c| Arc::ptr_eq(c, &shared)));
	assert!(configs.iter().any(|c| Arc::ptr_eq(c, &distinct)));
}

#[test]
fn inheritance_keeps_parent_tls_and_destination_requirements() {
	let mut config = (*security("https://allowed.test/pdp")).clone();
	config.dependency_egress = Some(
		serde_json::from_value(
			json!({"requireTls":false,"destinations":{"pdp":["allowed.test:443","unapproved.test:443"]}}),
		)
		.unwrap(),
	);
	let mut policies = vec![BackendTrafficPolicy::SecurityAudit(Arc::new(config))];
	inherit_dependency_policy(&mut policies, &parent()).unwrap();
	let BackendTrafficPolicy::SecurityAudit(config) = &policies[0] else {
		unreachable!()
	};
	let effective = config.dependency_egress.as_ref().unwrap();
	assert!(effective.require_tls);
	use security_integration_runtime::dependency_egress::DependencyKind::Pdp;
	assert!(effective.check_url(Pdp, "https://allowed.test/pdp").is_ok());
	assert!(
		effective
			.check_url(Pdp, "https://unapproved.test/pdp")
			.is_err()
	);
	assert!(
		effective
			.check_url(Pdp, "http://allowed.test:443/pdp")
			.is_err()
	);
}

#[cfg(feature = "gateway-llm")]
#[tokio::test]
async fn fallback_providers_and_model_router_policies_cannot_escape_validation() {
	use crate::llm::{
		AIBackend, NamedAIProvider,
		model_router::{ModelRoute, ModelRoutePolicies, ModelRouter, ModelVisibility},
	};
	let denied = security("https://unapproved.test/pdp");
	let provider = |name: &str, policies| NamedAIProvider {
		name: name.into(),
		provider: serde_json::from_value(json!({"openAI":{}})).unwrap(),
		provider_backend: None,
		host_override: None,
		path_override: None,
		path_prefix: None,
		tokenize: false,
		inline_policies: policies,
	};
	let mut config = empty();
	config.backends.push(BackendWithPolicies {
		backend: Backend::AI(
			local_name("ai".into()),
			AIBackend {
				providers: crate::types::loadbalancer::EndpointSet::new(vec![
					vec![("primary".into(), provider("primary", vec![]))],
					vec![(
						"fallback".into(),
						provider(
							"fallback",
							vec![BackendTrafficPolicy::SecurityAudit(denied.clone())],
						),
					)],
				]),
			},
		),
		inline_policies: vec![],
	});
	assert!(config.prepare_security(Some(&parent())).await.is_err());
	config.backends.clear();
	let router = ModelRouter::new(
		vec![ModelRoute {
			name: "model".into(),
			visibility: ModelVisibility::Public,
			header_matches: vec![],
			backend_key: "model".into(),
			policies: ModelRoutePolicies {
				llm: Arc::new(crate::llm::Policy::default()),
				authorization: None,
			},
			backend_policies: vec![BackendTrafficPolicy::SecurityAudit(denied)],
		}],
		vec![],
		0,
	);
	config.backends.push(BackendWithPolicies {
		backend: Backend::LLMRouter(local_name("router".into()), Arc::new(router)),
		inline_policies: vec![],
	});
	assert!(config.prepare_security(Some(&parent())).await.is_err());
}

#[cfg(feature = "gateway-llm")]
#[tokio::test]
async fn security_like_keys_in_business_json_are_not_policy_declarations() {
	let mut config = empty();
	let mut policy = crate::llm::Policy::default();
	policy.overrides = Some(HashMap::from([(
		"metadata".into(),
		json!({"securityAudit":{"businessLabel":"ordinary-metadata"}}),
	)]));
	config
		.policies
		.push(targeted(BackendTrafficPolicy::AI(Arc::new(policy))));
	assert!(config.security_configs().is_empty());
	config.prepare_security(Some(&parent())).await.unwrap();
}

#[tokio::test]
async fn legacy_constraints_use_the_same_prepublication_configuration_owner() {
	let pipeline: security_pipeline::SecurityPipelineConfig = serde_json::from_value(json!({
			"policies":[{"id":"allow","effect":"allow","enabled":true}]
	}))
	.unwrap();
	let legacy: crate::types::agent::LegacySecurityPipeline = pipeline.into();
	let owner = legacy.configuration().clone();
	let mut config = empty();
	config
		.policies
		.push(targeted(BackendTrafficPolicy::SecurityPipeline(
			legacy.clone(),
		)));
	config.backends.push(BackendWithPolicies {
		backend: Backend::Invalid,
		inline_policies: vec![BackendTrafficPolicy::SecurityPipeline(legacy)],
	});
	let declarations = config.security_configs();
	assert_eq!(declarations.len(), 1);
	assert!(Arc::ptr_eq(&owner, &declarations[0]));
	config.prepare_security(None).await.unwrap();
	assert_eq!(
		owner.mode,
		security_integration_runtime::SecurityMode::Enforce
	);
}
