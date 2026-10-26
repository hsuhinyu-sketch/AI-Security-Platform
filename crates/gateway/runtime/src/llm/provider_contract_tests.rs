use super::*;
use serde_json::{Value, json};

fn input(name: &str) -> InputFormat {
	match name {
		"Completions" => InputFormat::Completions,
		"Messages" => InputFormat::Messages,
		"Responses" => InputFormat::Responses,
		"Embeddings" => InputFormat::Embeddings,
		"Realtime" => InputFormat::Realtime,
		"CountTokens" => InputFormat::CountTokens,
		"Detect" => InputFormat::Detect,
		"Rerank" => InputFormat::Rerank,
		_ => panic!("unknown input fixture"),
	}
}
fn observe(c: &Value) -> Value {
	let family = c["family"].as_str().unwrap();
	if family == "host-route" {
		return json!(
			serde_json::from_str::<RouteType>(c["raw"].as_str().unwrap())
				.unwrap_err()
				.to_string()
		);
	}
	if family.starts_with("bedrock") || family.starts_with("vertex") {
		return observe_cloud(c);
	}

	if family == "custom" {
		let p: custom::Provider = serde_json::from_value(c["config"].clone()).unwrap();
		let formats = [
			custom::ProviderFormat::Completions,
			custom::ProviderFormat::Messages,
			custom::ProviderFormat::Responses,
			custom::ProviderFormat::Embeddings,
			custom::ProviderFormat::AnthropicTokenCount,
			custom::ProviderFormat::Realtime,
			custom::ProviderFormat::Rerank,
		];
		return json!({"native":p.native_format_for(input(c["input"].as_str().unwrap())),"formats":formats.map(|f|json!({"supports":p.supports(f),"path":p.path_for(f),"input":format!("{:?}",f.input_format()),"route":f.route_type()}))});
	}
	let route: RouteType = serde_json::from_value(c["route"].clone()).unwrap();
	match family {
		"openai" => json!(openai::path_suffix(route)),
		"anthropic" => json!(anthropic::path_suffix(route)),
		"copilot" => json!(copilot::path_suffix(route)),
		"gemini" => json!(gemini::path(route)),
		"azure" => {
			let p: azure::Provider = serde_json::from_value(c["config"].clone()).unwrap();
			let model = c["model"].as_str().unwrap();
			json!({"path":p.get_path_for_model(route,model),"host":p.get_host(),"anthropic":p.is_anthropic_model(Some(model)),"noRequest":p.is_anthropic_model(None)})
		},
		#[cfg(feature = "providers-azure")]
		"host-headers" => {
			let p: azure::Provider = serde_json::from_value(c["config"].clone()).unwrap();
			let mut req = crate::http::Request::new(crate::http::Body::empty());
			req
				.headers_mut()
				.insert("authorization", HeaderValue::from_static("Bearer existing"));
			req
				.headers_mut()
				.insert("api-key", HeaderValue::from_static("existing-api"));
			req.headers_mut().insert(
				"anthropic-version",
				HeaderValue::from_static("existing-version"),
			);
			AIProvider::Azure(p)
				.set_required_fields(&mut req, route, None)
				.unwrap();
			json!({"authorization":req.headers()["authorization"].to_str().unwrap(),"api-key":req.headers()["api-key"].to_str().unwrap(),"anthropic-version":req.headers()["anthropic-version"].to_str().unwrap()})
		},
		_ => panic!("unhandled fixture {family}"),
	}
}
#[test]
fn original_provider_a_contracts() {
	let cases: Vec<Value> = serde_json::from_str(include_str!(
		"../../../llm/tests/fixtures/provider-a-golden.json"
	))
	.unwrap();
	assert_eq!(cases.len(), 265);
	for c in cases {
		if !cfg!(feature = "providers-azure") && c["family"] == "host-headers" {
			continue;
		}
		assert_eq!(observe(&c), c["expected"], "{c}");
	}
}

fn observe_cloud(c: &Value) -> Value {
	let family = c["family"].as_str().unwrap();
	if family == "bedrock" {
		let p: bedrock::Provider = serde_json::from_value(c["config"].clone()).unwrap();
		let route = serde_json::from_value(c["route"].clone()).unwrap();
		let model = c["model"].as_str().unwrap();
		return json!({"path":p.get_path_for_route(route,c["streaming"].as_bool().unwrap(),model),"host":p.get_host(route),"anthropic":p.is_anthropic_model(Some(model)),"noRequest":p.is_anthropic_model(None)});
	}
	let p: vertex::Provider = serde_json::from_value(c["config"].clone()).unwrap();
	if family == "vertex" {
		let route = serde_json::from_value(c["route"].clone()).unwrap();
		let model = c["model"].as_str();
		return json!({"path":p.get_path_for_model(route,model,c["streaming"].as_bool().unwrap()),"host":p.get_host(route),"anthropic":p.is_anthropic_model(model),"noRequest":p.is_anthropic_model(None)});
	}
	let body = c["body"].as_str().unwrap().as_bytes().to_vec();
	let result = if family == "vertex-message" {
		p.prepare_anthropic_message_body(body)
	} else {
		p.prepare_anthropic_count_tokens_body(body)
	};
	match result {
		Ok(bytes) => json!({"bytes":bytes,"json":serde_json::from_slice::<Value>(&bytes).unwrap()}),
		Err(e) => {
			let (name, source) = match &e {
				AIError::RequestParsing(e) => ("RequestParsing", e),
				AIError::RequestMarshal(e) => ("RequestMarshal", e),
				_ => panic!("unclassified error {e:?}"),
			};
			json!({"error":e.to_string(),"variant":name,"category":format!("{:?}",source.classify()),"line":source.line(),"column":source.column()})
		},
	}
}
#[test]
fn original_provider_b_contracts() {
	let cases: Vec<Value> = serde_json::from_str(include_str!(
		"../../../llm/tests/fixtures/provider-b-golden.json"
	))
	.unwrap();
	assert_eq!(cases.len(), 471);
	for c in cases {
		if matches!(
			c["family"].as_str(),
			Some("bedrock-cache" | "bedrock-metadata")
		) {
			continue;
		}
		assert_eq!(observe_cloud(&c), c["expected"], "{c}");
	}
}

fn observe_composition(c: &Value) -> Value {
	let p: AIProvider = serde_json::from_value(c["provider"].clone()).unwrap();
	let input = input(c["input"].as_str().unwrap());
	json!({"supported":p.supported_formats(c["model"].as_str()),"native":p.native_format_for(input,c["model"].as_str()),"promptGuard":input.supports_prompt_guard()})
}
#[test]
fn original_provider_composition_contracts() {
	let cases: Vec<Value> = serde_json::from_str(include_str!(
		"../../../llm/tests/fixtures/provider-c-golden.json"
	))
	.unwrap();
	assert_eq!(cases.len(), 288);
	for c in cases {
		let provider = c["provider"]
			.as_object()
			.unwrap()
			.keys()
			.next()
			.unwrap()
			.as_str();
		if matches!(provider, "bedrock") && !cfg!(feature = "providers-aws")
			|| matches!(provider, "azure") && !cfg!(feature = "providers-azure")
			|| matches!(provider, "vertex") && !cfg!(feature = "providers-gcp")
		{
			continue;
		}
		assert_eq!(observe_composition(&c), c["expected"], "{c}");
	}
}

#[test]
fn shared_provider_types_have_one_identity() {
	use std::any::TypeId;
	assert_eq!(
		TypeId::of::<InputFormat>(),
		TypeId::of::<gateway_llm::provider::InputFormat>()
	);
	assert_eq!(
		TypeId::of::<custom::ProviderFormat>(),
		TypeId::of::<gateway_llm::provider::ProviderFormat>()
	);
	assert_eq!(
		TypeId::of::<azure::AzureResourceType>(),
		TypeId::of::<gateway_llm::provider::azure::AzureResourceType>()
	);
}

#[test]
fn host_auth_header_priority_and_connector_merge() {
	for (token, explicit, keeps_bearer) in [
		("api-key", false, false),
		("sk-ant-oat-token", false, true),
		("api-key", true, true),
	] {
		let mut req = crate::http::Request::new(crate::http::Body::empty());
		req.headers_mut().insert(
			"authorization",
			HeaderValue::from_str(&format!("Bearer {token}")).unwrap(),
		);
		req
			.headers_mut()
			.insert("x-api-key", HeaderValue::from_static("old"));
		req
			.extensions_mut()
			.insert(AppliedBackendAuthLocation { explicit });
		AIProvider::Anthropic(anthropic::Provider { model: None })
			.set_required_fields(&mut req, RouteType::Messages, None)
			.unwrap();
		assert_eq!(req.headers().contains_key("authorization"), keeps_bearer);
		assert_eq!(req.headers().contains_key("x-api-key"), !keeps_bearer);
		if !keeps_bearer {
			assert_eq!(req.headers()["x-api-key"], token);
			assert!(req.headers()["x-api-key"].is_sensitive());
		}
		assert_eq!(req.headers()["anthropic-version"], "2023-06-01");
	}
}

#[cfg(feature = "providers-azure")]
#[test]
fn host_azure_connector_merge() {
	let p: azure::Provider =
		serde_json::from_value(json!({"resourceName":"r","resourceType":"foundry"})).unwrap();
	let defaults = AIProvider::Azure(p).default_connector_policies().unwrap();
	assert!(matches!(defaults.backend_auth, Some(BackendAuth::Azure(_))));
	let explicit: BackendAuth = serde_json::from_value(
		json!({"key":{"value":"fixture-only","location":{"header":{"name":"api-key"}}}}),
	)
	.unwrap();
	let effective = defaults.merge(BackendPolicies {
		backend_auth: Some(explicit),
		..Default::default()
	});
	assert!(matches!(
		effective.backend_auth,
		Some(BackendAuth::Key { .. })
	));
}

#[tokio::test]
#[cfg(feature = "providers-aws")]
async fn host_bedrock_setup_then_real_sigv4_without_network() {
	use crate::http::auth::aws::DefaultAwsServiceName;
	for (configured_region, service, expected_region, expected_service) in [
		(None, None, "us-west-2", "bedrock"),
		(
			Some("eu-west-1"),
			Some("execute-api"),
			"eu-west-1",
			"execute-api",
		),
	] {
		let p: bedrock::Provider =
			serde_json::from_value(json!({"model":"override/claude%","region":"us-west-2"})).unwrap();
		let llm = LLMRequest {
			input_tokens: None,
			input_format: InputFormat::Completions,
			native_format: Some(custom::ProviderFormat::Completions),
			cache_convention: CacheTokenConvention::pending(),
			request_model: "request-model".into(),
			provider: "aws.bedrock".into(),
			streaming: false,
			params: Default::default(),
			prompt: None,
			provider_state: None,
		};
		let mut req = ::http::Request::builder()
			.method("POST")
			.uri("https://placeholder.invalid/old?trace=1")
			.header("content-type", "application/json")
			.body(crate::http::Body::from("{\"messages\":[]}"))
			.unwrap();
		AIProvider::Bedrock(p)
			.setup_request(
				&mut req,
				RouteType::Completions,
				Some(&llm),
				None,
				None,
				false,
			)
			.unwrap();
		assert_eq!(
			req.uri().host(),
			Some("bedrock-runtime.us-west-2.amazonaws.com")
		);
		assert_eq!(req.uri().path(), "/model/override%2Fclaude%25/converse");
		assert_eq!(req.uri().query(), Some("trace=1"));
		req
			.extensions_mut()
			.insert(DefaultAwsServiceName("bedrock".into()));
		let auth = BackendAuth::Aws(AwsAuth::ExplicitConfig {
			access_key_id: "FIXTUREACCESS".into(),
			secret_access_key: "fixture-secret-only".into(),
			region: configured_region.map(str::to_string),
			session_token: Some("fixture-session-only".into()),
			service_name: service.map(str::to_string),
		});
		crate::http::auth::apply_late_backend_auth(Some(&auth), &mut req)
			.await
			.unwrap();
		let authorization = req.headers()["authorization"].to_str().unwrap();
		assert!(authorization.starts_with("AWS4-HMAC-SHA256 Credential=FIXTUREACCESS/"));
		assert!(authorization.contains(&format!(
			"/{expected_region}/{expected_service}/aws4_request"
		)));
		assert!(authorization.contains("Signature="));
		assert_eq!(
			req.headers()["x-amz-security-token"],
			"fixture-session-only"
		);
		let body = crate::http::read_body_with_limit(std::mem::take(req.body_mut()), 1024)
			.await
			.unwrap();
		assert_eq!(body.as_ref(), b"{\"messages\":[]}");
		assert_eq!(req.headers()["content-length"], body.len().to_string());
	}
}
