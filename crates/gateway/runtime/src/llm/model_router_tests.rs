use super::*;
use crate::http::Body;
use crate::types::agent::RouteBackendTarget;
use http_body_util::BodyExt;
use serde_json::json;

fn model(name: &str, key: &str, visibility: ModelVisibility) -> ModelRoute {
	ModelRoute {
		name: name.into(),
		visibility,
		header_matches: vec![],
		backend_key: key.into(),
		policies: ModelRoutePolicies {
			llm: Arc::new(llm::Policy::default()),
			authorization: None,
		},
		backend_policies: vec![],
	}
}
fn virtual_model(name: &str, routing: VirtualModelRouting) -> VirtualModelRoute {
	VirtualModelRoute {
		name: name.into(),
		llm_policy: Arc::new(llm::Policy::default()),
		routing,
	}
}
fn request(name: &str) -> Request {
	::http::Request::builder()
		.method("POST")
		.uri("http://local/v1/chat/completions")
		.header("content-type", "application/json")
		.body(Body::from(json!({"model":name,"messages":[]}).to_string()))
		.unwrap()
}
fn backend(result: ResolveResult) -> ResolvedBackend {
	match result {
		ResolveResult::Backend(b) => b,
		ResolveResult::DirectResponse(r) => panic!("unexpected response {}", r.status()),
	}
}
fn key(result: ResolveResult) -> String {
	match backend(result).backend.target {
		RouteBackendTarget::Backend(key) => key.to_string(),
		_ => panic!(),
	}
}
async fn response_json(result: ResolveResult) -> (::http::StatusCode, Value) {
	let ResolveResult::DirectResponse(r) = result else {
		panic!("expected direct response")
	};
	let status = r.status();
	(
		status,
		serde_json::from_slice(&r.into_body().collect().await.unwrap().to_bytes()).unwrap(),
	)
}

#[tokio::test]
async fn concrete_order_visibility_headers_and_policy_binding_remain_host_owned() {
	let mut gated = model("prod/*", "gated", ModelVisibility::Public);
	gated.header_matches =
		serde_json::from_value(json!([[{"name":"x-route","value":{"exact":"first"}}]])).unwrap();
	let policy = gated.policies.llm.clone();
	let router = ModelRouter::new(
		vec![
			model("hidden", "secret", ModelVisibility::Internal),
			gated,
			model("prod/*", "fallback", ModelVisibility::Public),
		],
		vec![],
		1,
	);
	assert_eq!(
		key(router.resolve(&mut request("prod/a")).await),
		"/fallback"
	);
	let mut r = request("prod/a");
	r.headers_mut().insert("x-route", "first".parse().unwrap());
	let resolved = backend(router.resolve(&mut r).await);
	assert!(Arc::ptr_eq(&resolved.llm_policy, &policy));
	let (status, body) = response_json(router.resolve(&mut request("hidden")).await).await;
	assert_eq!(status, ::http::StatusCode::NOT_FOUND);
	assert_eq!(body["error"]["code"], "model_not_found");
}

#[tokio::test]
async fn conditional_and_weighted_aliases_rewrite_bodies_and_preserve_original_model() {
	for routing in [
		VirtualModelRouting::Conditional(vec![
			ConditionalTarget {
				model: "missing".into(),
				when: Some(Arc::new(cel::Expression::new_strict("false").unwrap())),
			},
			ConditionalTarget {
				model: "hidden".into(),
				when: None,
			},
		]),
		VirtualModelRouting::Weighted(vec![
			WeightedTarget {
				model: "missing".into(),
				weight: 0,
			},
			WeightedTarget {
				model: "hidden".into(),
				weight: 1,
			},
		]),
	] {
		let router = ModelRouter::new(
			vec![model("hidden", "target", ModelVisibility::Internal)],
			vec![virtual_model("alias", routing)],
			1,
		);
		let mut r = request("alias");
		r.headers_mut()
			.insert(::http::header::CONTENT_LENGTH, "100".parse().unwrap());
		assert_eq!(key(router.resolve(&mut r).await), "/target");
		assert_eq!(
			r.extensions().get::<TransformationMetadata>().unwrap().0["agentgateway_user_model"],
			"alias"
		);
		assert!(r.headers().get(::http::header::CONTENT_LENGTH).is_none());
		assert!(r.extensions().get::<cel::BufferedBody>().is_none());
		let body: Value =
			serde_json::from_slice(&r.into_body().collect().await.unwrap().to_bytes()).unwrap();
		assert_eq!(body["model"], "hidden");
	}
}

#[tokio::test]
async fn virtual_errors_and_failover_keep_existing_execution_handoff() {
	for (routing, status, code) in [
		(
			VirtualModelRouting::Weighted(vec![]),
			404,
			"virtual_model_not_resolved",
		),
		(
			VirtualModelRouting::Conditional(vec![]),
			400,
			"virtual_model_no_matching_target",
		),
		(
			VirtualModelRouting::Conditional(vec![ConditionalTarget {
				model: "missing".into(),
				when: None,
			}]),
			404,
			"virtual_model_target_not_found",
		),
	] {
		let router = ModelRouter::new(vec![], vec![virtual_model("alias", routing)], 1);
		let (actual, body) = response_json(router.resolve(&mut request("alias")).await).await;
		assert_eq!(actual.as_u16(), status);
		assert_eq!(body["error"]["code"], code);
	}
	let router = ModelRouter::new(
		vec![],
		vec![virtual_model(
			"alias",
			VirtualModelRouting::Failover {
				backend_key: "failover".into(),
			},
		)],
		1,
	);
	let mut r = request("alias");
	assert_eq!(key(router.resolve(&mut r).await), "/failover");
	let body: Value =
		serde_json::from_slice(&r.into_body().collect().await.unwrap().to_bytes()).unwrap();
	assert_eq!(body["model"], "alias"); // Provider failover owns per-attempt model selection.
}

#[tokio::test]
async fn list_visibility_authorization_aliases_and_serialization_are_compatible() {
	let mut denied = model("denied", "denied", ModelVisibility::Public);
	denied.policies.authorization = Some(serde_json::from_value(json!({"rules":["false"]})).unwrap());
	let models = vec![
		model("visible", "visible", ModelVisibility::Public),
		denied,
		model("hidden", "hidden", ModelVisibility::Internal),
	];
	let virtuals = vec![
		virtual_model(
			"alias",
			VirtualModelRouting::Weighted(vec![WeightedTarget {
				model: "hidden".into(),
				weight: 1,
			}]),
		),
		virtual_model(
			"conditional",
			VirtualModelRouting::Conditional(vec![ConditionalTarget {
				model: "hidden".into(),
				when: Some(Arc::new(cel::Expression::new_strict("true").unwrap())),
			}]),
		),
		virtual_model(
			"failover",
			VirtualModelRouting::Failover {
				backend_key: "pool".into(),
			},
		),
	];
	let expected = json!({"models":models,"virtualModels":virtuals,"created":42});
	let router = ModelRouter::new(models, virtuals, 42);
	assert_eq!(serde_json::to_value(&router).unwrap(), expected);
	let mut r = ::http::Request::builder()
		.uri("http://local/v1/models")
		.body(Body::empty())
		.unwrap();
	let (status, body) = response_json(router.resolve(&mut r).await).await;
	assert_eq!(status, ::http::StatusCode::OK);
	assert_eq!(
		body["data"]
			.as_array()
			.unwrap()
			.iter()
			.map(|v| v["id"].as_str().unwrap())
			.collect::<Vec<_>>(),
		vec!["visible", "alias", "conditional", "failover"]
	);
	assert_eq!(
		body["data"][0],
		json!({"id":"visible","object":"model","created":42,"owned_by":"openai"})
	);
}

#[tokio::test]
async fn path_rewrite_preserves_query_and_bounded_body_errors_remain_explicit() {
	let router = ModelRouter::new(
		vec![model("provider/real", "target", ModelVisibility::Internal)],
		vec![virtual_model(
			"alias",
			VirtualModelRouting::Weighted(vec![WeightedTarget {
				model: "provider/real".into(),
				weight: 1,
			}]),
		)],
		1,
	);
	let mut r = ::http::Request::builder()
		.uri("http://local/model/alias/converse?trace=1")
		.body(Body::empty())
		.unwrap();
	assert_eq!(key(router.resolve(&mut r).await), "/target");
	assert_eq!(
		r.uri().path_and_query().unwrap().as_str(),
		"/model/provider%2Freal/converse?trace=1"
	);
	let mut r = request("alias");
	r.extensions_mut()
		.insert(crate::transport::BufferLimit::new(8));
	let (status, body) = response_json(router.resolve(&mut r).await).await;
	assert_eq!(status, ::http::StatusCode::PAYLOAD_TOO_LARGE);
	assert_eq!(body["error"]["code"], "request_body_too_large");
}
