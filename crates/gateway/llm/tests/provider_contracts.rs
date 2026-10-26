use gateway_llm::provider::{self, InputFormat, ProviderFormat as F};
use serde_json::{Value, json};

fn format(route: &str) -> Option<F> {
	match route {
		"completions" => Some(F::Completions),
		"messages" => Some(F::Messages),
		"responses" => Some(F::Responses),
		"embeddings" => Some(F::Embeddings),
		"realtime" => Some(F::Realtime),
		"anthropicTokenCount" => Some(F::AnthropicTokenCount),
		"rerank" => Some(F::Rerank),
		"models" | "detect" | "passthrough" => None,
		_ => panic!("unclassified fixture route"),
	}
}
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
	if family == "custom" {
		let formats: Vec<(F, Option<&str>)> = c["config"]["formats"]
			.as_array()
			.unwrap()
			.iter()
			.map(|f| {
				(
					serde_json::from_value(f["type"].clone()).unwrap(),
					f["path"].as_str(),
				)
			})
			.collect();
		let fs = [
			F::Completions,
			F::Messages,
			F::Responses,
			F::Embeddings,
			F::AnthropicTokenCount,
			F::Realtime,
			F::Rerank,
		];
		return json!({"native":provider::custom::native_format_for(formats.iter().map(|f|f.0),input(c["input"].as_str().unwrap())),"formats":fs.map(|f|json!({"supports":provider::custom::supports(formats.iter().map(|f|f.0),f),"path":provider::custom::path_for(formats.iter().copied(),f),"input":format!("{:?}",f.input_format()),"route":serde_json::to_value(f).unwrap()}))});
	}
	let route = format(c["route"].as_str().unwrap());
	match family {
		"openai" => json!(provider::openai::path_suffix(route)),
		"anthropic" => json!(provider::anthropic::path_suffix(route)),
		"copilot" => json!(if c["route"] == "models" {
			provider::copilot::MODELS_PATH
		} else {
			provider::copilot::path_suffix(route)
		}),
		"gemini" => json!(provider::gemini::path(route)),
		"azure" => {
			let cfg = &c["config"];
			let resource = serde_json::from_value(cfg["resourceType"].clone()).unwrap();
			let p = provider::azure::Endpoint {
				model: cfg["model"].as_str(),
				resource_name: cfg["resourceName"].as_str().unwrap(),
				resource_type: &resource,
				project_name: cfg["projectName"].as_str(),
				api_version: cfg["apiVersion"].as_str(),
			};
			let model = c["model"].as_str().unwrap();
			json!({"path":p.get_path_for_model(route,model),"host":p.get_host(),"anthropic":p.is_anthropic_model(Some(model)),"noRequest":p.is_anthropic_model(None)})
		},
		_ => panic!("unknown pure fixture"),
	}
}
fn check_family(family: &str) {
	let cases: Vec<Value> =
		serde_json::from_str(include_str!("fixtures/provider-a-golden.json")).unwrap();
	let cases: Vec<_> = cases.iter().filter(|c| c["family"] == family).collect();
	assert!(!cases.is_empty());
	for c in cases {
		assert_eq!(observe(c), c["expected"], "{c}");
	}
}
#[test]
fn openai_paths() {
	check_family("openai");
}
#[test]
fn anthropic_paths() {
	check_family("anthropic");
}
#[test]
fn copilot_paths() {
	check_family("copilot");
}
#[test]
fn gemini_paths() {
	check_family("gemini");
}
#[test]
fn azure_endpoints() {
	check_family("azure");
}
#[test]
fn custom_preferences_and_first_path() {
	check_family("custom");
}
#[test]
fn azure_resource_alias_and_errors() {
	use provider::azure::AzureResourceType as R;
	assert!(matches!(
		serde_json::from_str::<R>("\"aiServices\"").unwrap(),
		R::Foundry
	));
	assert_eq!(serde_json::to_string(&R::Foundry).unwrap(), "\"foundry\"");
	assert!(serde_json::from_str::<R>("\"unknown\"").is_err());
	assert!(serde_json::from_str::<F>("\"unknown\"").is_err());
}

fn observe_cloud(c: &Value) -> Value {
	let family = c["family"].as_str().unwrap();
	if family == "bedrock-cache" {
		return json!(provider::bedrock::supports_prompt_caching(
			c["model"].as_str().unwrap()
		));
	}
	if family == "bedrock-metadata" {
		return json!(provider::bedrock::extract_flat_metadata(&c["value"]));
	}
	if family == "bedrock" {
		let cfg = &c["config"];
		let p = provider::bedrock::Endpoint {
			model: cfg["model"].as_str(),
			region: cfg["region"].as_str().unwrap(),
		};
		let route = format(c["route"].as_str().unwrap());
		let model = c["model"].as_str().unwrap();
		return json!({"path":p.get_path_for_route(route,c["streaming"].as_bool().unwrap(),model),"host":p.get_host(route),"anthropic":p.is_anthropic_model(Some(model)),"noRequest":p.is_anthropic_model(None)});
	}
	let cfg = &c["config"];
	let p = provider::vertex::Endpoint {
		model: cfg["model"].as_str(),
		region: cfg["region"].as_str(),
		project_id: cfg["projectId"].as_str().unwrap(),
	};
	if family == "vertex" {
		let route = format(c["route"].as_str().unwrap());
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
				gateway_llm::WireError::RequestParsing(e) => ("RequestParsing", e),
				gateway_llm::WireError::RequestMarshal(e) => ("RequestMarshal", e),
				_ => panic!("unclassified error {e:?}"),
			};
			json!({"error":e.to_string(),"variant":name,"category":format!("{:?}",source.classify()),"line":source.line(),"column":source.column()})
		},
	}
}
fn check_cloud(family: &str) {
	let cases: Vec<Value> =
		serde_json::from_str(include_str!("fixtures/provider-b-golden.json")).unwrap();
	let mut count = 0;
	for c in cases {
		if c["family"] == family {
			count += 1;
			assert_eq!(observe_cloud(&c), c["expected"], "{c}");
		}
	}
	assert!(count > 0);
}
#[test]
fn bedrock_paths() {
	check_cloud("bedrock");
}
#[test]
fn bedrock_cache_models() {
	check_cloud("bedrock-cache");
}
#[test]
fn bedrock_metadata() {
	check_cloud("bedrock-metadata");
}
#[test]
fn vertex_paths() {
	check_cloud("vertex");
}
#[test]
fn vertex_message_body() {
	check_cloud("vertex-message");
}
#[test]
fn vertex_count_body() {
	check_cloud("vertex-count");
}

#[test]
fn provider_composition_uses_frozen_supported_format_inputs() {
	let cases: Vec<Value> =
		serde_json::from_str(include_str!("fixtures/provider-c-golden.json")).unwrap();
	assert_eq!(cases.len(), 288);
	let mut pure = 0;
	let mut host_guard = 0;
	for c in cases {
		// The Vertex Responses restriction is a Host policy, not an adapter default.
		if c["provider"].get("vertex").is_some() && c["input"] == "Responses" {
			assert!(c["expected"]["native"].is_null());
			host_guard += 1;
			continue;
		}
		let supported: Vec<F> = serde_json::from_value(c["expected"]["supported"].clone()).unwrap();
		let input = input(c["input"].as_str().unwrap());
		assert_eq!(
			serde_json::to_value(provider::custom::native_format_for(
				supported.into_iter(),
				input
			))
			.unwrap(),
			c["expected"]["native"],
			"{c}"
		);
		assert_eq!(
			json!(input.supports_prompt_guard()),
			c["expected"]["promptGuard"]
		);
		pure += 1;
	}
	assert_eq!((pure, host_guard), (282, 6));
}
