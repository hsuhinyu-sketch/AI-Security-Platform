//! Actual configuration admission and trusted-policy injection across build combinations.
#[cfg(not(feature = "database"))]
use crate::telemetry::log_store;
use crate::{
	store::FrontendPolices,
	telemetry::trc,
	types::{agent, frontend, local::LocalConfig},
};
use serde_json::json;
use std::sync::Arc;

#[test]
fn infrastructure_root_configuration_matches_the_compiled_outputs() {
	for (settings, available, feature) in [
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
		let mut settings = settings;
		settings["enableIpv6"] = json!(false);
		let result = crate::config::parse_config(json!({"config":settings}).to_string(), None);
		if available {
			result.unwrap();
		} else {
			assert!(result.unwrap_err().to_string().contains(feature));
		}
	}
}

#[test]
fn infrastructure_frontend_configuration_matches_the_compiled_outputs() {
	for (policy, available, feature) in [
		(
			json!({"tracing":{"host":"127.0.0.1:4317"}}),
			cfg!(feature = "telemetry-otlp"),
			"telemetry-otlp",
		),
		(
			json!({"accessLog":{"otlp":{"host":"127.0.0.1:4318"}}}),
			cfg!(feature = "telemetry-otlp"),
			"telemetry-otlp",
		),
		(
			json!({"accessLog":{"database":{}}}),
			cfg!(feature = "database"),
			"database",
		),
	] {
		let result = serde_json::from_value::<LocalConfig>(json!({"frontendPolicies":policy}));
		if available {
			result.unwrap();
		} else {
			assert!(result.unwrap_err().to_string().contains(feature));
		}
	}
}

#[test]
fn infrastructure_null_outputs_preserve_plain_logging_and_trace_context() {
	let _: LocalConfig = serde_json::from_value(json!({"frontendPolicies":{
			"tracing":null,"accessLog":{"otlp":null,"database":null,"add":{"test":"'kept'"}}
	}}))
	.unwrap();
	let trace = trc::TraceParent::new();
	let mut request = crate::http::Request::new(crate::http::Body::empty());
	trace.insert_header(&mut request);
	assert_eq!(trc::TraceParent::from_request(&request), Some(trace));
}

#[test]
fn infrastructure_typed_policies_cannot_bypass_build_capability_checks() {
	let config: agent::TracingConfig =
		serde_json::from_value(json!({"host":"127.0.0.1:4317"})).unwrap();
	let policies = FrontendPolices {
		tracing: Some(Arc::new(agent::TracingPolicy {
			config,
			fields: Default::default(),
			#[cfg(feature = "telemetry-otlp")]
			tracer: Default::default(),
		})),
		..Default::default()
	};
	assert_eq!(
		policies.validate_compiled().is_ok(),
		cfg!(feature = "telemetry-otlp")
	);
	let mut logging: frontend::LoggingPolicy = serde_json::from_value(json!({})).unwrap();
	logging.otlp = Some(serde_json::from_value(json!({"host":"127.0.0.1:4318"})).unwrap());
	logging.init_access_log_policy();
	let policies = FrontendPolices {
		access_log_otlp: logging.access_log_policy.clone(),
		access_log: Some(logging),
		..Default::default()
	};
	assert_eq!(
		policies.validate_compiled().is_ok(),
		cfg!(feature = "telemetry-otlp")
	);
	let mut logging: frontend::LoggingPolicy = serde_json::from_value(json!({})).unwrap();
	logging.database = Some(frontend::DatabaseLoggingConfig {
		add: Default::default(),
	});
	let policies = FrontendPolices {
		access_log: Some(logging),
		..Default::default()
	};
	assert_eq!(
		policies.validate_compiled().is_ok(),
		cfg!(feature = "database")
	);
}

#[cfg(not(feature = "database"))]
#[tokio::test]
async fn infrastructure_disabled_database_queries_explicitly_fail() {
	assert!(!log_store::enabled());
	let error = log_store::get(log_store::GetRequest {
		id: "missing".into(),
		include_payload: true,
	})
	.await
	.unwrap_err();
	assert!(error.to_string().contains("not compiled"));
}
