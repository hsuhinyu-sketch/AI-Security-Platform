pub mod request;
pub mod response;
pub mod from_rerank {
	use crate::{WireError, types};
	/// Build a full Bedrock model ARN if the caller supplied a bare model id.
	fn model_arn(model: &str, region: &str) -> String {
		if model.starts_with("arn:") {
			model.to_string()
		} else {
			format!("arn:aws:bedrock:{region}::foundation-model/{model}")
		}
	}
	/// `max_tokens_per_doc` plus any unknown passthrough fields, for `additionalModelRequestFields`.
	fn additional_model_request_fields(req: &types::rerank::Request) -> Option<serde_json::Value> {
		let mut fields = match req.rest.as_object() {
			Some(map) if !map.is_empty() => map.clone(),
			_ => serde_json::Map::new(),
		};
		if let Some(max) = req.max_tokens_per_doc {
			fields.insert("max_tokens_per_doc".to_string(), max.into());
		}
		(!fields.is_empty()).then(|| serde_json::Value::Object(fields))
	}
	pub fn translate(
		req: &types::rerank::Request,
		provider_model: Option<&str>,
		region: &str,
	) -> Result<Vec<u8>, WireError> {
		if req.documents.is_empty() {
			return Err(WireError::MissingField("rerank documents".into()));
		}
		let model = provider_model.or(req.model.as_deref()).unwrap_or_default();
		let sources = req
			.documents
			.iter()
			.map(|d| types::bedrock::RerankSource {
				r#type: types::bedrock::RerankSourceType::Inline,
				inline_document_source: types::bedrock::RerankInlineDoc {
					r#type: types::bedrock::RerankContentType::Text,
					text_document: types::bedrock::RerankText { text: d.as_text() },
				},
			})
			.collect();
		let bedrock_req = types::bedrock::RerankRequest {
			queries: vec![types::bedrock::RerankQuery {
				r#type: types::bedrock::RerankContentType::Text,
				text_query: types::bedrock::RerankText {
					text: req.query.clone(),
				},
			}],
			sources,
			reranking_configuration: types::bedrock::RerankConfiguration {
				r#type: types::bedrock::RerankConfigType::BedrockRerankingModel,
				bedrock_reranking_configuration: types::bedrock::RerankInner {
					model_configuration: types::bedrock::RerankModelConfig {
						model_arn: model_arn(model, region),
						additional_model_request_fields: additional_model_request_fields(req),
					},
					number_of_results: req.top_n.unwrap_or(req.documents.len() as u32),
				},
			},
		};
		serde_json::to_vec(&bedrock_req).map_err(WireError::RequestMarshal)
	}
	pub fn translate_response(resp: types::bedrock::RerankResponse) -> types::rerank::Response {
		let results = resp
			.results
			.into_iter()
			.map(|r| types::rerank::RerankResult {
				index: r.index,
				relevance_score: r.relevance_score,
				document: None,
			})
			.collect();
		let out = types::rerank::Response {
			id: None,
			results,
			meta: None,
			rest: serde_json::Value::Null,
		};
		out
	}
}

pub mod from_embeddings {
	use crate::{WireError, types};
	pub fn translate(
		req: &types::embeddings::Request,
		provider_model: Option<&str>,
	) -> Result<Vec<u8>, WireError> {
		let typed = crate::types::convert::<_, types::embeddings::typed::Request>(req)
			.map_err(WireError::RequestMarshal)?;

		let model = provider_model.unwrap_or(&typed.model);

		// Bedrock has two embedding model families with incompatible APIs:
		// Cohere accepts batched text arrays; Titan accepts a single string.
		if model.contains("cohere") {
			let input = typed.input.as_strings();

			let bedrock_req = types::bedrock::CohereEmbeddingRequest {
				texts: input,
				input_type: req
					.rest
					.get("input_type")
					.and_then(|v| v.as_str())
					.unwrap_or("search_query")
					.to_string(),
				truncate: req
					.rest
					.get("truncate")
					.and_then(|v| v.as_str())
					.map(|s| s.to_string()),
			};
			serde_json::to_vec(&bedrock_req).map_err(WireError::RequestMarshal)
		} else {
			// Titan only accepts a single string; array input is rejected.
			let input = match &typed.input {
				types::embeddings::typed::EmbeddingInput::String(s) => s.to_string(),
				types::embeddings::typed::EmbeddingInput::Array(_) => {
					return Err(WireError::RequestParsing(serde::de::Error::custom(
						"Titan requires a single string input",
					)));
				},
			};
			let bedrock_req = types::bedrock::AmazonTitanV2EmbeddingRequest {
				input_text: input,
				dimensions: typed.dimensions,
				normalize: req.rest.get("normalize").and_then(|v| v.as_bool()),
				// Map OpenAI encoding_format → Titan embedding_types (Base64→Binary, Float→Float)
				embedding_types: typed.encoding_format.as_ref().map(|f| match f {
					types::embeddings::typed::EncodingFormat::Base64 => {
						vec![types::bedrock::BedrockEmbeddingType::Binary]
					},
					types::embeddings::typed::EncodingFormat::Float => {
						vec![types::bedrock::BedrockEmbeddingType::Float]
					},
				}),
			};
			serde_json::to_vec(&bedrock_req).map_err(WireError::RequestMarshal)
		}
	}
	pub fn from_cohere_response(
		resp: types::bedrock::CohereEmbeddingResponse,
		model: &str,
		prompt_tokens: u64,
	) -> Result<types::embeddings::Response, WireError> {
		let typed_resp = types::embeddings::typed::Response {
			object: "list".to_string(),
			data: resp
				.embeddings
				.into_iter()
				.enumerate()
				.map(|(i, e)| types::embeddings::typed::Embedding {
					object: "embedding".to_string(),
					embedding: e,
					index: i as u32,
				})
				.collect(),
			model: model.to_string(),
			usage: types::embeddings::typed::Usage {
				prompt_tokens: prompt_tokens as u32,
				total_tokens: prompt_tokens as u32,
			},
		};
		// Convert the normalized internal typed response back to the passthrough-preserving OpenAI format
		let openai_resp = crate::types::convert::<_, types::embeddings::Response>(&typed_resp)
			.map_err(WireError::ResponseParsing)?;
		Ok(openai_resp)
	}

	pub fn from_titan_response(
		mut resp: types::bedrock::AmazonTitanV2EmbeddingResponse,
		model: &str,
	) -> Result<types::embeddings::Response, WireError> {
		let typed_resp = types::embeddings::typed::Response {
			object: "list".to_string(),
			data: vec![types::embeddings::typed::Embedding {
				object: "embedding".to_string(),
				// Zero-clone optimization: Move the large vector out of the response body
				// to avoid expensive re-allocations during translation.
				embedding: if !resp.embedding.is_empty() {
					std::mem::take(&mut resp.embedding)
				} else {
					// When embedding_types is set, Titan returns results in embeddingsByType
					// instead of the top-level embedding field.
					resp
						.embeddings_by_type
						.remove("float")
						.and_then(|v| serde_json::from_value::<Vec<f32>>(v).ok())
						.unwrap_or_default()
				},
				index: 0,
			}],
			model: model.to_string(),
			usage: types::embeddings::typed::Usage {
				prompt_tokens: resp.input_text_token_count as u32,
				total_tokens: resp.input_text_token_count as u32,
			},
		};
		// Convert the normalized internal typed response back to the passthrough-preserving OpenAI format
		let openai_resp = crate::types::convert::<_, types::embeddings::Response>(&typed_resp)
			.map_err(WireError::ResponseParsing)?;
		Ok(openai_resp)
	}
}

/// Aggregate already-decoded Converse content into the existing Messages response fields.
/// The envelope and its generated ID remain with the caller.
pub fn anthropic_content_and_usage(
	message: &crate::types::bedrock::Message,
	token_usage: Option<crate::types::bedrock::TokenUsage>,
	tool_name_map: Option<&crate::provider::bedrock::BedrockToolNameMap>,
) -> (
	Vec<crate::types::messages::typed::ContentBlock>,
	crate::types::messages::typed::Usage,
) {
	use crate::provider::bedrock::{BedrockToolNameMap, restore_tool_name};
	use crate::types::{bedrock, messages::typed as messagest};
	fn translate_content_block_to_anthropic(
		block: &bedrock::ContentBlock,
		tool_name_map: Option<&BedrockToolNameMap>,
	) -> Option<messagest::ContentBlock> {
		match block {
			bedrock::ContentBlock::Text(text) => {
				Some(messagest::ContentBlock::Text(messagest::ContentTextBlock {
					text: text.clone(),
					citations: None,
					cache_control: None,
				}))
			},
			bedrock::ContentBlock::ReasoningContent(reasoning) => {
				// Extract text and signature from either format
				let (thinking_text, signature) = match reasoning {
					bedrock::ReasoningContentBlock::Structured { reasoning_text } => (
						reasoning_text.text.clone(),
						reasoning_text.signature.clone().unwrap_or_default(),
					),
					bedrock::ReasoningContentBlock::Simple { text } => (text.clone(), String::new()),
				};
				Some(messagest::ContentBlock::Thinking {
					thinking: thinking_text,
					signature,
				})
			},
			bedrock::ContentBlock::ToolUse(tool_use) => Some(messagest::ContentBlock::ToolUse {
				id: tool_use.tool_use_id.clone(),
				name: restore_tool_name(tool_name_map, &tool_use.name),
				input: tool_use.input.clone(),
				cache_control: None,
			}),
			bedrock::ContentBlock::Image(img) => Some(messagest::ContentBlock::Image(
				messagest::ContentImageBlock {
					source: serde_json::json!({
						"type": "base64",
						"media_type": format!("image/{}", img.format),
						"data": img.source.bytes
					}),
					cache_control: None,
				},
			)),
			bedrock::ContentBlock::ToolResult(_) => None, // Skip tool results in responses
			bedrock::ContentBlock::CachePoint(_) => None, // Skip cache points - they're metadata only
		}
	}
	let content: Vec<messagest::ContentBlock> = message
		.content
		.iter()
		.filter_map(|block| translate_content_block_to_anthropic(block, tool_name_map))
		.collect();

	let usage = token_usage
		.map(|u| messagest::Usage {
			input_tokens: u.input_tokens,
			output_tokens: u.output_tokens,
			cache_creation_input_tokens: u.cache_write_input_tokens,
			cache_read_input_tokens: u.cache_read_input_tokens,
			service_tier: None,
		})
		.unwrap_or(messagest::Usage {
			input_tokens: 0,
			output_tokens: 0,
			cache_creation_input_tokens: None,
			cache_read_input_tokens: None,
			service_tier: None,
		});

	(content, usage)
}
