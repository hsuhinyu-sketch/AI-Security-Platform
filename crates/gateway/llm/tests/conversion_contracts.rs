use gateway_llm::{WireError as Error, conversion, types};
use serde_json::{Value, json};
#[path = "conversion_support/mod.rs"]
mod support;
fn error_view(error: &Error) -> Value {
	let (variant, source) = match error {
		Error::IncompleteResponse => ("IncompleteResponse", None),
		Error::ResponseMarshal(e) => ("ResponseMarshal", Some(e)),
		Error::RequestMarshal(e) => ("RequestMarshal", Some(e)),
		Error::RequestParsing(e) => ("RequestParsing", Some(e)),
		Error::MissingField(_) => ("MissingField", None),
		Error::ResponseParsing(e) => ("ResponseParsing", Some(e)),
		Error::InvalidResponse(_) => ("InvalidResponse", None),
		Error::UnsupportedConversion(_) => ("UnsupportedConversion", None),
	};
	json!({"error":error.to_string(),"variant":variant,"category":source.map(|e|format!("{:?}",e.classify())),"line":source.map(|e|e.line()),"column":source.map(|e|e.column())})
}
fn chat_response(input: &str) -> Value {
	match conversion::completions::from_messages::translate_response(input.as_bytes()) {
		Ok(r) => support::wire(serde_json::to_vec(&r).unwrap()),
		Err(e) => error_view(&e),
	}
}
fn openai_request(input: &str) -> Value {
	let mut warnings = Vec::new();
	let result = support::request::<types::responses::Request>(input, |req| {
		let value = serde_json::to_value(req).map_err(Error::RequestMarshal)?;
		let typed = serde_json::from_value::<types::responses::typed::CreateResponse>(value)
			.map_err(Error::RequestMarshal)?;
		let (request, unsupported) =
			conversion::openai_compat::from_responses::translate_internal(typed);
		if let Some(tc) = unsupported {
			warnings.push(format!(
				"Unsupported tool choice for OpenAI-compatible chat completions: {tc:?}"
			));
		}
		serde_json::to_vec(&request).map_err(Error::RequestMarshal)
	});
	json!({"result":result,"warnings":warnings})
}
fn fixture() -> Value {
	serde_json::from_str(include_str!("fixtures/conversion-golden.json")).unwrap()
}
fn check_a(kind: &str) {
	let fixture = fixture();
	let mut n = 0;
	for case in fixture["cases"]
		.as_array()
		.unwrap()
		.iter()
		.filter(|c| c["kind"] == kind)
	{
		assert_eq!(
			support::observe_a(case),
			case["expected"],
			"{}",
			case["name"]
		);
		n += 1;
	}
	assert!(n > 0, "missing golden group {kind}");
}
macro_rules! golden_a {
	($name:ident,$kind:literal) => {
		#[test]
		fn $name() {
			check_a($kind);
		}
	};
}
golden_a!(responses_raw_passthrough, "responses-wire");
golden_a!(chat_to_messages, "chat-to-messages");
golden_a!(messages_to_chat, "messages-to-chat");
golden_a!(openai_compatible, "openai-compatible");
golden_a!(chat_response_to_messages, "chat-response-to-messages");
golden_a!(data_urls, "data-url");
golden_a!(system_and_developer_text, "system-text");
golden_a!(google_error_classification, "google-error-type");

fn response<T: serde::de::DeserializeOwned, O: serde::Serialize>(
	input: &str,
	f: impl FnOnce(T) -> Result<O, Error>,
) -> Value {
	match serde_json::from_slice::<T>(input.as_bytes())
		.map_err(Error::ResponseParsing)
		.and_then(f)
	{
		Ok(value) => support::wire(serde_json::to_vec(&value).unwrap()),
		Err(error) => error_view(&error),
	}
}
fn observe_b(case: &Value) -> Value {
	let input = case["input"].as_str().unwrap();
	let options = &case["options"];
	match case["kind"].as_str().unwrap() {
		"vertex-embedding-request" => {
			support::request(input, conversion::vertex::from_embeddings::translate)
		},
		"vertex-rerank-request" => support::request(input, conversion::vertex::from_rerank::translate),
		"vertex-embedding-response" => response(input, |r| {
			conversion::vertex::from_embeddings::translate_response(r, "embed")
		}),
		"vertex-rerank-response" => {
			response(input, conversion::vertex::from_rerank::translate_response)
		},
		"bedrock-embedding-request" => support::request(input, |r| {
			conversion::bedrock::from_embeddings::translate(r, options["provider_model"].as_str())
		}),
		"bedrock-rerank-request" => support::request(input, |r| {
			conversion::bedrock::from_rerank::translate(
				r,
				options["provider_model"].as_str(),
				options["region"].as_str().unwrap_or("us-east-1"),
			)
		}),
		"bedrock-rerank-response" => response(input, |r| {
			Ok(conversion::bedrock::from_rerank::translate_response(r))
		}),
		"bedrock-embedding-response" => {
			let model = options["model"].as_str().unwrap_or("titan");
			if model.contains("cohere") {
				let tokens = options["token_header"]
					.as_str()
					.and_then(|v| v.parse::<u64>().ok())
					.unwrap_or(0);
				response(input, |r| {
					conversion::bedrock::from_embeddings::from_cohere_response(r, model, tokens)
				})
			} else {
				response(input, |r| {
					conversion::bedrock::from_embeddings::from_titan_response(r, model)
				})
			}
		},
		other => panic!("unknown pure L2b golden kind: {other}"),
	}
}
fn check_b(kind: &str) {
	let fixture = fixture();
	let mut n = 0;
	for case in fixture["cases"]
		.as_array()
		.unwrap()
		.iter()
		.filter(|c| c["kind"] == kind)
	{
		assert_eq!(observe_b(case), case["expected"], "{}", case["name"]);
		n += 1;
	}
	assert!(n > 0, "missing golden group {kind}");
}
macro_rules! golden_b {
	($name:ident,$kind:literal) => {
		#[test]
		fn $name() {
			check_b($kind);
		}
	};
}
golden_b!(vertex_embedding_requests, "vertex-embedding-request");
golden_b!(vertex_rerank_requests, "vertex-rerank-request");
golden_b!(vertex_embedding_responses, "vertex-embedding-response");
golden_b!(vertex_rerank_responses, "vertex-rerank-response");
golden_b!(bedrock_embedding_requests, "bedrock-embedding-request");
golden_b!(bedrock_rerank_requests, "bedrock-rerank-request");
golden_b!(bedrock_embedding_responses, "bedrock-embedding-response");
golden_b!(bedrock_rerank_responses, "bedrock-rerank-response");
#[test]
fn conversion_golden_groups_are_complete_and_frozen() {
	let fixture = fixture();
	let cases = fixture["cases"].as_array().unwrap();
	assert_eq!(cases.len(), 243);
	assert_eq!(
		fixture["provenance"]["capturedBeforeProductionMigration"],
		true
	);
	let mut names = std::collections::HashSet::new();
	let mut a = 0;
	let mut b = 0;
	let mut host = 0;
	for case in cases {
		assert!(names.insert(case["name"].as_str().unwrap()));
		let kind = case["kind"].as_str().unwrap();
		if kind.starts_with("host-") {
			host += 1;
			assert!(matches!(
				kind,
				"host-responses-prompts" | "host-bedrock-tool-map"
			));
		} else if kind.starts_with("bedrock-") || kind.starts_with("vertex-") {
			b += 1;
			assert_eq!(observe_b(case), case["expected"], "{}", case["name"]);
		} else {
			a += 1;
			assert_eq!(
				support::observe_a(case),
				case["expected"],
				"{}",
				case["name"]
			);
		}
	}
	assert_eq!((a, b, host), (121, 107, 15));
}
