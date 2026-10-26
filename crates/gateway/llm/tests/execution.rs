use gateway_llm::provider::{
	InputFormat as I, ProviderFormat as F, RouteType as R,
	adapter::{Adapter, Custom},
	azure, bedrock,
	custom::ProviderFormatConfig,
	endpoint::RequestDetails,
	request::{EncodedRequest, RequestEncoder},
	vertex,
};
use gateway_llm::{CacheTokenConvention, WireError};
use std::sync::Mutex;

#[derive(Default)]
struct Encoder {
	calls: Mutex<Vec<&'static str>>,
	fail: bool,
}
impl Encoder {
	fn record(&self, name: &'static str) -> Result<Vec<u8>, WireError> {
		self.calls.lock().unwrap().push(name);
		if self.fail {
			Err(WireError::InvalidResponse("conversion rejected".into()))
		} else {
			Ok(br#"{"model":"claude","messages":[]}"#.to_vec())
		}
	}
}
impl RequestEncoder for Encoder {
	type Error = WireError;
	fn openai(&self) -> Result<Vec<u8>, WireError> {
		self.record("openai")
	}
	fn anthropic(&self) -> Result<Vec<u8>, WireError> {
		self.record("anthropic")
	}
	fn openai_chat(&self) -> Result<Vec<u8>, WireError> {
		self.record("chat")
	}
	fn vertex(&self) -> Result<Vec<u8>, WireError> {
		self.record("vertex")
	}
	fn bedrock(&self) -> Result<EncodedRequest, WireError> {
		Ok(EncodedRequest {
			body: self.record("bedrock")?,
			tool_name_map: Default::default(),
		})
	}
	fn bedrock_count_tokens(&self) -> Result<Vec<u8>, WireError> {
		self.record("bedrock-count")
	}
}

#[test]
fn unsupported_request_never_converts_and_conversion_failure_is_not_retried() {
	let formats = [ProviderFormatConfig {
		format: F::Embeddings,
		path: None,
	}];
	let provider = Adapter::Custom(Custom {
		model: None,
		formats: &formats,
	});
	let encoder = Encoder::default();
	assert!(
		provider
			.encode(I::Completions, Some(F::Embeddings), "model", &encoder)
			.is_err()
	);
	assert!(encoder.calls.lock().unwrap().is_empty());
	let encoder = Encoder {
		fail: true,
		..Default::default()
	};
	assert!(
		Adapter::OpenAI(None)
			.encode(I::Completions, Some(F::Completions), "model", &encoder)
			.is_err()
	);
	assert_eq!(*encoder.calls.lock().unwrap(), ["openai"]);
}

#[test]
fn provider_conversion_and_vertex_versioning_follow_the_existing_wire_contract() {
	let formats = [ProviderFormatConfig {
		format: F::Completions,
		path: None,
	}];
	for (provider, input, native, expected) in [
		(
			Adapter::OpenAI(None),
			I::Completions,
			Some(F::Completions),
			"openai",
		),
		(
			Adapter::Anthropic(None),
			I::Completions,
			Some(F::Messages),
			"anthropic",
		),
		(
			Adapter::Gemini(None),
			I::Responses,
			Some(F::Completions),
			"chat",
		),
		(
			Adapter::Custom(Custom {
				model: None,
				formats: &formats,
			}),
			I::Responses,
			Some(F::Completions),
			"chat",
		),
		(
			Adapter::Bedrock(bedrock::Endpoint {
				model: None,
				region: "us-east-1",
			}),
			I::CountTokens,
			Some(F::AnthropicTokenCount),
			"bedrock-count",
		),
	] {
		let encoder = Encoder::default();
		provider.encode(input, native, "model", &encoder).unwrap();
		assert_eq!(*encoder.calls.lock().unwrap(), [expected]);
	}
	let encoder = Encoder::default();
	let provider = Adapter::Vertex(vertex::Endpoint {
		model: Some("claude-sonnet"),
		region: None,
		project_id: "project",
	});
	let body = provider
		.encode(I::Messages, Some(F::Messages), "claude-sonnet", &encoder)
		.unwrap()
		.body;
	let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
	assert_eq!(value["anthropic_version"], "vertex-2023-10-16");
	assert!(value.get("model").is_none());
	assert_eq!(*encoder.calls.lock().unwrap(), ["anthropic"]);
}

#[test]
fn endpoint_projection_preserves_provider_base_paths_overrides_and_queries() {
	let uri = "https://incoming.example/v1/chat/completions?trace=keep"
		.parse()
		.unwrap();
	let details = Some(RequestDetails {
		model: "model",
		native_format: Some(F::Completions),
		streaming: false,
	});
	for (provider, expected) in [
		(Adapter::OpenAI(None), "/v1/chat/completions?trace=keep"),
		(Adapter::Copilot(None), "/chat/completions?trace=keep"),
		(
			Adapter::Gemini(None),
			"/v1beta/openai/chat/completions?trace=keep",
		),
	] {
		assert_eq!(
			provider
				.request_path(&uri, R::Completions, details, None, false)
				.unwrap()
				.unwrap()
				.as_str(),
			expected
		);
		assert!(
			provider
				.request_path(&uri, R::Completions, details, None, true)
				.unwrap()
				.is_none()
		);
	}
	assert_eq!(
		Adapter::OpenAI(None)
			.request_path(&uri, R::Detect, None, Some("/proxy/"), false)
			.unwrap()
			.unwrap()
			.as_str(),
		"/proxy/chat/completions?trace=keep"
	);
	let formats = [ProviderFormatConfig {
		format: F::Completions,
		path: Some("/custom?version=1".into()),
	}];
	let provider = Adapter::Custom(Custom {
		model: None,
		formats: &formats,
	});
	assert_eq!(
		provider
			.request_path(&uri, R::Completions, details, Some("/ignored"), true)
			.unwrap()
			.unwrap()
			.as_str(),
		"/custom?version=1&trace=keep"
	);
	assert_eq!(
		Adapter::Copilot(None)
			.request_path(&uri, R::Models, None, None, false)
			.unwrap()
			.unwrap()
			.as_str(),
		"/models?trace=keep"
	);
}

#[test]
fn cloud_descriptions_preserve_native_preferences_and_cache_accounting() {
	let foundry = azure::AzureResourceType::Foundry;
	let provider = Adapter::Azure(azure::Endpoint {
		model: None,
		resource_name: "resource",
		resource_type: &foundry,
		project_name: Some("project"),
		api_version: None,
	});
	assert_eq!(
		provider.native_format_for(I::Messages, Some("claude-sonnet")),
		Some(F::Messages)
	);
	assert_eq!(
		provider.native_format_for(I::Messages, Some("gpt-4o")),
		Some(F::Completions)
	);
	// Preserve the existing Azure accounting convention; this migration does not
	// silently change billing semantics even on its Anthropic-native endpoint.
	assert_eq!(
		provider.cache_convention(Some(F::Messages), "claude-sonnet"),
		CacheTokenConvention::InputIncludesCache
	);
	let vertex = Adapter::Vertex(vertex::Endpoint {
		model: None,
		region: None,
		project_id: "project",
	});
	assert_eq!(vertex.native_format_for(I::Responses, Some("model")), None);
	let bedrock = Adapter::Bedrock(bedrock::Endpoint {
		model: None,
		region: "us-east-1",
	});
	assert_eq!(
		bedrock.native_format_for(I::CountTokens, Some("anthropic.claude")),
		Some(F::AnthropicTokenCount)
	);
	assert_eq!(
		bedrock.native_format_for(I::CountTokens, Some("amazon.titan")),
		None
	);
}

#[test]
fn model_paths_round_trip_escaped_ids_and_leave_unrelated_routes_unchanged() {
	use gateway_llm::routing::path::{extract_model_from_path, rewrite_path_model};
	for path in [
		"/model/old/converse-stream",
		"/model/old/invoke",
		"/v1/publishers/anthropic/models/old:rawPredict",
	] {
		let rewritten = rewrite_path_model(path, "team/model%encoded").unwrap();
		assert_eq!(
			extract_model_from_path(&rewritten).as_deref(),
			Some("team/model%encoded")
		);
	}
	assert!(rewrite_path_model("/v1/chat/completions", "new").is_none());
	assert!(extract_model_from_path("/model/name/not-invoke").is_none());
}

#[test]
fn buffered_streaming_and_error_choices_preserve_custom_and_cloud_asymmetries() {
	use gateway_llm::provider::response::{
		ErrorEncoding as E, ResponseDetails, ResponseEncoding as B, StreamEncoding as S,
	};
	let formats = [ProviderFormatConfig {
		format: F::Completions,
		path: None,
	}];
	let custom = Adapter::Custom(Custom {
		model: None,
		formats: &formats,
	});
	let req = ResponseDetails {
		input_format: I::Responses,
		native_format: Some(F::Completions),
		request_model: "model",
	};
	assert_eq!(custom.response_encoding(req).unwrap(), B::OpenAIToResponses);
	assert_eq!(custom.stream_encoding(req).unwrap(), S::OpenAIToResponses);
	assert_eq!(custom.error_encoding(req).unwrap(), E::Passthrough);
	let vertex = Adapter::Vertex(vertex::Endpoint {
		model: None,
		region: Some("us-central1"),
		project_id: "project",
	});
	assert!(vertex.response_encoding(req).is_err()); // Existing buffered API rejects this shape.
	assert_eq!(vertex.stream_encoding(req).unwrap(), S::Responses);
	let bedrock = Adapter::Bedrock(bedrock::Endpoint {
		model: None,
		region: "us-east-1",
	});
	assert_eq!(
		bedrock
			.stream_encoding(ResponseDetails {
				input_format: I::Detect,
				..req
			})
			.unwrap(),
		S::DetectBedrock
	);
	assert_eq!(bedrock.error_encoding(req).unwrap(), E::Bedrock);
}
