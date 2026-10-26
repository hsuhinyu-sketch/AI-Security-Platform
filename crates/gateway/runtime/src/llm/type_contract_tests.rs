use super::{AIError, CacheTokenConvention, LLMResponse, types};

#[path = "../../../llm/tests/support/mod.rs"]
mod support;

#[test]
fn old_paths_preserve_pre_migration_wire_contracts() {
	let fixture: serde_json::Value = serde_json::from_str(include_str!(
		"../../../llm/tests/fixtures/serde-golden.json"
	))
	.unwrap();
	for case in fixture["cases"].as_array().unwrap() {
		assert_eq!(support::observe(case), case["expected"], "{}", case["name"]);
	}
}

#[test]
fn compatibility_reexports_have_one_type_identity() {
	macro_rules! same {
		($old:ty, $new:ty) => {
			assert_eq!(
				std::any::TypeId::of::<$old>(),
				std::any::TypeId::of::<$new>()
			);
		};
	}
	same!(LLMResponse, gateway_llm::LLMResponse);
	same!(CacheTokenConvention, gateway_llm::CacheTokenConvention);
	same!(
		types::completions::Request,
		gateway_llm::types::completions::Request
	);
	same!(
		types::completions::typed::Request,
		gateway_llm::types::completions::typed::Request
	);
	same!(
		types::messages::Request,
		gateway_llm::types::messages::Request
	);
	same!(
		types::messages::typed::MessagesResponse,
		gateway_llm::types::messages::typed::MessagesResponse
	);
	same!(
		types::responses::Response,
		gateway_llm::types::responses::Response
	);
	same!(
		types::responses::typed::Response,
		gateway_llm::types::responses::typed::Response
	);
	same!(
		types::embeddings::Request,
		gateway_llm::types::embeddings::Request
	);
	same!(
		types::embeddings::typed::Request,
		gateway_llm::types::embeddings::typed::Request
	);
	same!(
		types::count_tokens::Response,
		gateway_llm::types::count_tokens::Response
	);
	same!(types::rerank::Request, gateway_llm::types::rerank::Request);
	same!(
		types::bedrock::Message,
		gateway_llm::types::bedrock::Message
	);
	same!(
		types::vertex::PredictRequest,
		gateway_llm::types::vertex::PredictRequest
	);
	let _: LLMResponse = gateway_llm::LLMResponse::default();
	let _: Option<platform_core::strng::Strng> = gateway_llm::LLMResponse::default().provider_model;
}

#[test]
fn pure_bridge_error_maps_to_original_host_variant() {
	let fixture: serde_json::Value = serde_json::from_str(include_str!(
		"../../../llm/tests/fixtures/serde-golden.json"
	))
	.unwrap();
	let mut checked = 0;
	for case in fixture["cases"].as_array().unwrap().iter().filter(|case| {
		case["kind"].as_str().unwrap().ends_with("-bridge") && case["expected"].get("error").is_some()
	}) {
		let input = case["input"].as_str().unwrap();
		let error = if case["kind"] == "embeddings-bridge" {
			let request: types::embeddings::Request = serde_json::from_str(input).unwrap();
			let result: Result<types::embeddings::typed::Request, gateway_llm::WireError> =
				(&request).try_into();
			result.unwrap_err()
		} else {
			let request: types::completions::Request = serde_json::from_str(input).unwrap();
			let result: Result<types::completions::typed::Request, gateway_llm::WireError> =
				(&request).try_into();
			result.unwrap_err()
		};
		let host: AIError = error.into();
		assert_eq!(
			host.to_string(),
			case["expected"]["error"].as_str().unwrap()
		);
		assert!(matches!(host, AIError::RequestMarshal(_)));
		checked += 1;
	}
	assert_eq!(checked, 3);
}

#[test]
fn host_response_adapters_preserve_usage_cache_and_completion_fields() {
	use super::ResponseType;
	let fixture: serde_json::Value = serde_json::from_str(include_str!(
		"../../../llm/tests/fixtures/serde-golden.json"
	))
	.unwrap();
	let input = |name: &str| {
		fixture["cases"]
			.as_array()
			.unwrap()
			.iter()
			.find(|case| case["name"] == name)
			.unwrap()["input"]
			.as_str()
			.unwrap()
	};
	let chat: types::completions::Response =
		serde_json::from_str(input("chat-response-normal")).unwrap();
	let usage = chat.to_llm_response(true);
	assert_eq!(
		(usage.input_tokens, usage.output_tokens, usage.total_tokens),
		(Some(10), Some(3), Some(13))
	);
	assert_eq!(
		(
			usage.cached_input_tokens,
			usage.reasoning_tokens,
			usage.input_audio_tokens
		),
		(Some(4), Some(2), Some(1))
	);
	assert_eq!(usage.completion, Some(vec!["ok".into()]));
	assert!(chat.to_llm_response(false).completion.is_none());
	let messages: types::messages::Response =
		serde_json::from_str(input("messages-response-normal")).unwrap();
	let usage = messages.to_llm_response(true);
	assert_eq!(
		(usage.input_tokens, usage.output_tokens, usage.total_tokens),
		(Some(5), Some(2), Some(7))
	);
	assert_eq!(
		(usage.cached_input_tokens, usage.cache_creation_input_tokens),
		(Some(7), Some(6))
	);
	assert_eq!(usage.completion, Some(vec!["ok".into()]));
	assert_eq!(usage.input_audio_tokens, None);
}

#[test]
fn count_response_host_parser_preserves_alias_bytes_and_error_class() {
	use types::count_tokens::{Response, ResponseExt};
	for raw in [r#"{"input_tokens":7}"#, r#"{"inputTokens":7}"#] {
		let bytes = bytes::Bytes::copy_from_slice(raw.as_bytes());
		let (original, tokens) = Response::translate_response(bytes.clone()).unwrap();
		assert_eq!(original, bytes);
		assert_eq!(tokens, 7);
	}
	assert!(matches!(
		Response::translate_response(bytes::Bytes::from_static(b"{}")),
		Err(AIError::ResponseParsing(_))
	));
}
