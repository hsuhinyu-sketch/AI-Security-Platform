use super::*;
use crate::{IntoRuntimeContext, ProxyInputs};
use std::sync::Arc;

fn legacy_inputs() -> Arc<ProxyInputs> {
	let config = Arc::new(crate::config::parse_config("{}".into(), None).unwrap());
	let stores = crate::store::Stores::default();
	let mut registry = prometheus_client::registry::Registry::default();
	let metrics = Arc::new(crate::telemetry::metrics::Metrics::new(
		&mut registry,
		config.metrics.excluded_metrics.clone(),
	));
	let client = crate::client::Client::new(
		&config.dns,
		None,
		config.backend.clone(),
		Some(metrics.clone()),
	);
	let mcp = crate::mcp::App::new(stores.clone(), config.session_encoder.clone());
	Arc::new(ProxyInputs::new(
		config,
		stores,
		client,
		metrics,
		mcp,
		#[cfg(feature = "gateway-llm")]
		None,
		None,
	))
}

#[tokio::test]
async fn shared_context_and_policy_client_do_not_retain_the_legacy_assembly() {
	let legacy = legacy_inputs();
	let weak = Arc::downgrade(&legacy);
	let shared = legacy.clone().into_runtime_context();
	let client = crate::proxy::httpproxy::PolicyClient::new(shared.clone());
	let compatible_client = crate::proxy::httpproxy::PolicyClient::new(legacy.clone());
	drop(legacy);
	assert!(weak.upgrade().is_none());
	assert!(Arc::strong_count(&shared) >= 2);
	let phase = crate::telemetry::metrics::GuardrailPhase::Request;
	let action = crate::telemetry::metrics::GuardrailAction::Reject;
	let labels = crate::telemetry::metrics::GuardrailLabels { phase, action };
	let before = shared.metrics.guardrail_checks.get_or_create(&labels).get();
	client.record_guardrail_check(phase, action);
	compatible_client.record_guardrail_check(phase, action);
	assert_eq!(
		shared.metrics.guardrail_checks.get_or_create(&labels).get(),
		before + 2
	);
}

#[tokio::test]
async fn embedding_gateway_preserves_constructor_and_separates_owners() {
	let legacy = legacy_inputs();
	let weak = Arc::downgrade(&legacy);
	let (_trigger, drain) = platform_core::drain::new();
	let gateway = crate::proxy::Gateway::new(legacy, drain);
	assert!(weak.upgrade().is_none());
	drop(gateway);
}

#[tokio::test]
#[cfg(feature = "gateway-llm")]
async fn host_drop_stops_management_while_request_readers_survive() {
	let services = ProtocolServices::new(
		crate::mcp::Service::new(
			Default::default(),
			crate::http::sessionpersistence::Encoder::base64(),
		),
		CatalogService::from_catalog(crate::llm::cost::ModelCatalog::empty()),
	);
	let handles = services.handles();
	let admin = services.catalog_admin();
	assert!(admin.list_models().is_ok());
	drop(services);
	assert!(admin.list_models().is_err());
	assert!(!handles.catalog.list_models().loaded);
}

#[tokio::test]
#[cfg(not(feature = "gateway-llm"))]
async fn mcp_only_host_handle_rejects_requests_after_owner_drop() {
	let services = ProtocolServices::new(crate::mcp::Service::new(
		Default::default(),
		crate::http::sessionpersistence::Encoder::base64(),
	));
	let handles = services.handles();
	let backend = crate::types::agent::McpBackend {
		targets: vec![],
		stateful: true,
		always_use_prefix: false,
		failure_mode: Default::default(),
		session_idle_ttl: std::time::Duration::from_secs(60),
	};
	let request = crate::http::Request::default();
	assert!(
		handles
			.mcp
			.should_passthrough(&Default::default(), &backend, &request)
			.is_ok()
	);
	drop(services);
	assert!(
		handles
			.mcp
			.should_passthrough(&Default::default(), &backend, &request)
			.is_err()
	);
}
