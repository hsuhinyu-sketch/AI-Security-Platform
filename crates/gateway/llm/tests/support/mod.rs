//! Shared observer: exercised against Runtime before migration and the independent crate afterwards.
use serde::{Serialize, de::DeserializeOwned};
use serde_json::{Value, json};

use super::{CacheTokenConvention, LLMResponse, types};

fn failure(error: serde_json::Error) -> Value {
	json!({"error": error.to_string(), "category": format!("{:?}", error.classify()),
        "line": error.line(), "column": error.column()})
}

fn serialized<T: Serialize>(value: T) -> Value {
	let wire = serde_json::to_string(&value).unwrap();
	assert_eq!(wire, serde_json::to_string(&value).unwrap());
	json!({"json":serde_json::to_value(value).unwrap(), "wire":wire})
}

fn round_trip<T: Serialize + DeserializeOwned>(input: &str) -> Value {
	match serde_json::from_str::<T>(input) {
		Ok(value) => serialized(value),
		Err(error) => failure(error),
	}
}

fn deserialize<T: DeserializeOwned + std::fmt::Debug>(input: &str) -> Value {
	match serde_json::from_str::<T>(input) {
		Ok(value) => json!({"debug":format!("{value:?}")}),
		Err(error) => failure(error),
	}
}

pub fn observe(case: &Value) -> Value {
	let input = case["input"].as_str().unwrap();
	match case["kind"].as_str().unwrap() {
		"chat-request" => round_trip::<types::completions::Request>(input),
		"chat-response" => round_trip::<types::completions::Response>(input),
		"chat-typed-request" => round_trip::<types::completions::typed::Request>(input),
		"chat-error" => round_trip::<types::completions::typed::ChatCompletionErrorResponse>(input),
		"responses-response" => round_trip::<types::responses::Response>(input),
		"responses-vendor" => round_trip::<types::responses::RequestVendorExtensions>(input),
		"messages-request" => round_trip::<types::messages::Request>(input),
		"messages-response" => round_trip::<types::messages::Response>(input),
		"messages-typed-request" => round_trip::<types::messages::typed::Request>(input),
		"embeddings-request" => round_trip::<types::embeddings::Request>(input),
		"embeddings-response" => round_trip::<types::embeddings::Response>(input),
		"embeddings-typed-request" => round_trip::<types::embeddings::typed::Request>(input),
		"count-request" => round_trip::<types::count_tokens::Request>(input),
		"count-response" => round_trip::<types::count_tokens::Response>(input),
		"rerank-request" => round_trip::<types::rerank::Request>(input),
		"rerank-response" => round_trip::<types::rerank::Response>(input),
		"rerank-lenient" => match types::rerank::parse_response_lenient(input.as_bytes()) {
			Ok(value) => serialized(value),
			Err(error) => failure(error),
		},
		"bedrock-message" => round_trip::<types::bedrock::Message>(input),
		"bedrock-error" => deserialize::<types::bedrock::ConverseErrorResponse>(input),
		"bedrock-embedding" => round_trip::<types::bedrock::AmazonTitanV2EmbeddingResponse>(input),
		"bedrock-converse-response" => deserialize::<types::bedrock::ConverseResponse>(input),
		"vertex-predict-response" => deserialize::<types::vertex::PredictResponse>(input),
		"vertex-rank-response" => deserialize::<types::vertex::RankResponse>(input),
		"chat-bridge" => {
			let request: types::completions::Request = serde_json::from_str(input).unwrap();
			let result: Result<types::completions::typed::Request, _> = (&request).try_into();
			match result {
				Ok(value) => serialized(value),
				Err(error) => json!({"error":error.to_string(), "boundary":"request-marshal"}),
			}
		},
		"embeddings-bridge" => {
			let request: types::embeddings::Request = serde_json::from_str(input).unwrap();
			let result: Result<types::embeddings::typed::Request, _> = (&request).try_into();
			match result {
				Ok(value) => serialized(value),
				Err(error) => json!({"error":error.to_string(), "boundary":"request-marshal"}),
			}
		},
		"vertex-predict-request" => serialized(types::vertex::PredictRequest {
			instances: vec![types::vertex::Instance {
				content: "hello".into(),
				task_type: Some("RETRIEVAL_QUERY".into()),
				title: None,
			}],
			parameters: Some(types::vertex::Parameters {
				auto_truncate: Some(false),
				output_dimensionality: Some(4),
			}),
		}),
		"vertex-rank-request" => serialized(types::vertex::RankRequest {
			model: "ranker".into(),
			query: "q".into(),
			records: vec![types::vertex::RankRecord {
				id: "1".into(),
				content: "a".into(),
			}],
			top_n: Some(1),
			ignore_record_details_in_response: true,
		}),
		"normalized-response" => serialized(LLMResponse {
			input_tokens: Some(12),
			input_audio_tokens: Some(2),
			output_tokens: Some(3),
			total_tokens: Some(15),
			reasoning_tokens: Some(1),
			cache_creation_input_tokens: Some(4),
			cached_input_tokens: Some(5),
			service_tier: Some("standard".into()),
			provider_model: Some("model".into()),
			completion: Some(vec!["ok".into()]),
			first_token: Some(std::time::Instant::now()),
			..Default::default()
		}),
		"cache-convention" => json!({"default":format!("{:?}",CacheTokenConvention::default()),
            "pending":format!("{:?}",CacheTokenConvention::pending()),
            "variants":[format!("{:?}",CacheTokenConvention::InputIncludesCache),format!("{:?}",CacheTokenConvention::InputExcludesCache)]}),
		"bedrock-inference" => serialized(types::bedrock::InferenceConfiguration {
			max_tokens: 128,
			temperature: Some(0.5),
			top_p: None,
			top_k: None,
			stop_sequences: vec![],
		}),
		"bedrock-titan-request" => serialized(types::bedrock::AmazonTitanV2EmbeddingRequest {
			input_text: "hello".into(),
			dimensions: Some(4),
			normalize: Some(true),
			embedding_types: None,
		}),
		unknown => panic!("unknown fixture kind: {unknown}"),
	}
}
