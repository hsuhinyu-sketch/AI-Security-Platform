use super::{AIError as Error, RequestType, conversion, types};
use bytes::Bytes;
use serde_json::{Value, json};

#[path = "../../../llm/tests/conversion_support/mod.rs"]
mod support;

fn error_view(error: &Error) -> Value {
	let (variant, source) = match error {
		Error::RequestMarshal(e) => ("RequestMarshal", Some(e)),
		Error::RequestParsing(e) => ("RequestParsing", Some(e)),
		Error::ResponseParsing(e) => ("ResponseParsing", Some(e)),
		Error::ResponseMarshal(e) => ("ResponseMarshal", Some(e)),
		Error::InvalidResponse(_) => ("InvalidResponse", None),
		Error::MissingField(_) => ("MissingField", None),
		_ => panic!("unclassified capture error: {error:?}"),
	};
	json!({"error":error.to_string(),"variant":variant,"category":source.map(|e|format!("{:?}",e.classify())),"line":source.map(|e|e.line()),"column":source.map(|e|e.column())})
}

#[derive(Clone, Default)]
struct Warnings(std::sync::Arc<std::sync::Mutex<Vec<String>>>);
impl tracing::Subscriber for Warnings {
	fn enabled(&self, _: &tracing::Metadata<'_>) -> bool {
		true
	}
	fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
		tracing::span::Id::from_u64(1)
	}
	fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}
	fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}
	fn enter(&self, _: &tracing::span::Id) {}
	fn exit(&self, _: &tracing::span::Id) {}
	fn event(&self, event: &tracing::Event<'_>) {
		if *event.metadata().level() != tracing::Level::WARN {
			return;
		}
		struct Visitor<'a>(&'a mut Vec<String>);
		impl tracing::field::Visit for Visitor<'_> {
			fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
				if field.name() == "message" {
					self.0.push(format!("{value:?}"));
				}
			}
		}
		event.record(&mut Visitor(&mut self.0.lock().unwrap()));
	}
}
fn openai_request(input: &str) -> Value {
	let warnings = Warnings::default();
	let result = tracing::subscriber::with_default(warnings.clone(), || {
		support::request(input, conversion::openai_compat::from_responses::translate)
	});
	json!({"result":result,"warnings":warnings.0.lock().unwrap().clone()})
}
fn chat_response(input: &str) -> Value {
	match conversion::completions::from_messages::translate_response(&Bytes::copy_from_slice(
		input.as_bytes(),
	)) {
		Ok(response) => support::wire(response.serialize().unwrap()),
		Err(error) => error_view(&error),
	}
}
fn prompts(case: &Value) -> Value {
	let mut request: types::responses::Request =
		serde_json::from_str(case["input"].as_str().unwrap()).unwrap();
	let before = request.get_messages();
	let prompts = serde_json::from_value(case["options"]["prompts"].clone()).unwrap();
	match case["options"]["mode"].as_str().unwrap() {
		"prepend" => request.prepend_prompts(prompts),
		"append" => request.append_prompts(prompts),
		"set" => request.set_messages(prompts),
		_ => unreachable!(),
	}
	json!({"before":before,"after":request.get_messages(),"wire":support::wire(serde_json::to_vec(&request).unwrap())})
}
fn tool_map(input: &str) -> Value {
	let names: Vec<String> = serde_json::from_str(input).unwrap();
	let mut map = conversion::bedrock::BedrockToolNameMap::default();
	let mapped: Vec<_> = names.iter().map(|n| map.register(n)).collect();
	let restored: Vec<_> = mapped.iter().map(|n| map.restore(n)).collect();
	json!({"mapped":mapped,"restored":restored,"empty":map.is_empty(),"unknown":map.restore("unknown")})
}
fn vertex_embedding_request(req: &types::embeddings::Request) -> Result<Vec<u8>, Error> {
	conversion::vertex::from_embeddings::translate(req)
}
fn vertex_rerank_request(req: &types::rerank::Request) -> Result<Vec<u8>, Error> {
	let provider = super::vertex::Provider {
		model: None,
		region: None,
		project_id: "local".into(),
	};
	conversion::vertex::from_rerank::translate(req, &provider)
}
fn vertex_embedding_response(input: &str) -> Value {
	match conversion::vertex::from_embeddings::translate_response(input.as_bytes(), "embed") {
		Ok(r) => support::wire(r.serialize().unwrap()),
		Err(e) => error_view(&e),
	}
}
fn vertex_rerank_response(input: &str) -> Value {
	match conversion::vertex::from_rerank::translate_response(input.as_bytes()) {
		Ok(r) => support::wire(r.serialize().unwrap()),
		Err(e) => error_view(&e),
	}
}
fn provider(options: &Value) -> super::bedrock::Provider {
	serde_json::from_value(json!({"region":options["region"].as_str().unwrap_or("us-east-1"),"model":options["provider_model"]})).unwrap()
}
fn bedrock_embedding_request(
	req: &types::embeddings::Request,
	options: &Value,
) -> Result<Vec<u8>, Error> {
	conversion::bedrock::from_embeddings::translate(req, &provider(options))
}
fn bedrock_rerank_request(req: &types::rerank::Request, options: &Value) -> Result<Vec<u8>, Error> {
	conversion::bedrock::from_rerank::translate(req, &provider(options))
}
fn bedrock_embedding_response(input: &str, options: &Value) -> Value {
	let mut headers = http::HeaderMap::new();
	if let Some(value) = options["token_header"].as_str() {
		headers.insert("x-amzn-bedrock-input-token-count", value.parse().unwrap());
	}
	match conversion::bedrock::from_embeddings::translate_response(
		input.as_bytes(),
		&headers,
		options["model"].as_str().unwrap_or("titan"),
	) {
		Ok(r) => support::wire(r.serialize().unwrap()),
		Err(e) => error_view(&e),
	}
}
fn bedrock_rerank_response(input: &str) -> Value {
	match conversion::bedrock::from_rerank::translate_response(input.as_bytes()) {
		Ok(r) => support::wire(r.serialize().unwrap()),
		Err(e) => error_view(&e),
	}
}

fn observe_all(case: &Value) -> Value {
	let input = case["input"].as_str().unwrap();
	match case["kind"].as_str().unwrap() {
		"host-responses-prompts" => prompts(case),
		"host-bedrock-tool-map" => tool_map(input),
		"vertex-embedding-request" => support::request(input, vertex_embedding_request),
		"vertex-rerank-request" => support::request(input, vertex_rerank_request),
		"vertex-embedding-response" => vertex_embedding_response(input),
		"vertex-rerank-response" => vertex_rerank_response(input),
		"bedrock-embedding-request" => {
			support::request(input, |r| bedrock_embedding_request(r, &case["options"]))
		},
		"bedrock-rerank-request" => {
			support::request(input, |r| bedrock_rerank_request(r, &case["options"]))
		},
		"bedrock-embedding-response" => bedrock_embedding_response(input, &case["options"]),
		"bedrock-rerank-response" => bedrock_rerank_response(input),
		_ => support::observe_a(case),
	}
}

#[test]
fn frozen_conversion_golden_matches_runtime_paths() {
	let fixture: Value = serde_json::from_str(include_str!(
		"../../../llm/tests/fixtures/conversion-golden.json"
	))
	.unwrap();
	for case in fixture["cases"].as_array().unwrap() {
		assert_eq!(observe_all(case), case["expected"], "{}", case["name"]);
	}
}
#[test]
fn responses_request_reexport_keeps_type_identity() {
	macro_rules! same {
		($a:ty,$b:ty) => {
			assert_eq!(std::any::TypeId::of::<$a>(), std::any::TypeId::of::<$b>());
		};
	}
	same!(
		types::responses::Request,
		gateway_llm::types::responses::Request
	);
	same!(
		types::responses::RequestInput,
		gateway_llm::types::responses::RequestInput
	);
	same!(
		types::responses::RawInputItem,
		gateway_llm::types::responses::RawInputItem
	);
}
