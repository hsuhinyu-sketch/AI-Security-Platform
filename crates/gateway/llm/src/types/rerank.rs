use serde::{Deserialize, Serialize};

/// Canonical rerank request, modeled on the Cohere `/v2/rerank` API.
/// Unknown fields are preserved via `rest` for passthrough to compatible providers.
#[derive(Debug, Deserialize, Clone, Serialize)]
pub struct Request {
	#[serde(skip_serializing_if = "Option::is_none")]
	pub model: Option<String>,
	pub query: String,
	pub documents: Vec<Document>,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub top_n: Option<u32>,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub return_documents: Option<bool>,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub max_tokens_per_doc: Option<u32>,
	#[serde(flatten, default)]
	pub rest: serde_json::Value,
}

/// A document is either a plain string or a structured object (e.g. `{ "text": ... }`).
/// String semantics are guaranteed across all providers; object/structured-field
/// semantics are best-effort and provider-dependent.
#[derive(Debug, Deserialize, Clone, Serialize)]
#[serde(untagged)]
pub enum Document {
	Text(String),
	Object(serde_json::Map<String, serde_json::Value>),
}

impl Document {
	/// Extract the text content. For objects, reads the `text` field (Cohere convention).
	/// Used by the Bedrock/Vertex rerank translation.
	pub fn as_text(&self) -> String {
		match self {
			Document::Text(s) => s.clone(),
			Document::Object(m) => m
				.get("text")
				.and_then(|v| v.as_str())
				.map(|s| s.to_string())
				.unwrap_or_default(),
		}
	}
}

#[derive(Debug, Deserialize, Clone, Serialize)]
pub struct Response {
	#[serde(skip_serializing_if = "Option::is_none")]
	pub id: Option<String>,
	pub results: Vec<RerankResult>,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub meta: Option<Meta>,
	#[serde(flatten, default)]
	pub rest: serde_json::Value,
}

#[derive(Debug, Deserialize, Clone, Serialize)]
pub struct RerankResult {
	pub index: u32,
	pub relevance_score: f64,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub document: Option<Document>,
}

#[derive(Debug, Deserialize, Clone, Serialize, Default)]
pub struct Meta {
	#[serde(skip_serializing_if = "Option::is_none")]
	pub billed_units: Option<BilledUnits>,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub tokens: Option<Tokens>,
	#[serde(flatten, default)]
	pub rest: serde_json::Value,
}

/// Cohere reports token counts as floats.
#[derive(Debug, Deserialize, Clone, Serialize, Default)]
pub struct Tokens {
	#[serde(skip_serializing_if = "Option::is_none")]
	pub input_tokens: Option<f64>,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub output_tokens: Option<f64>,
}

#[derive(Debug, Deserialize, Clone, Serialize, Default)]
pub struct BilledUnits {
	#[serde(skip_serializing_if = "Option::is_none")]
	pub search_units: Option<u32>,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub total_tokens: Option<u32>,
}

/// Parse a rerank response, accepting either Cohere's `results` or Voyage's `data` key.
pub fn parse_response_lenient(bytes: &[u8]) -> Result<Response, serde_json::Error> {
	// Fast path: the canonical Cohere shape (`results` present) parses in a single pass. This is the
	// common case, so avoid the intermediate `Value` round-trip unless the strict parse fails.
	if let Ok(resp) = serde_json::from_slice::<Response>(bytes) {
		return Ok(resp);
	}
	// Fallback: Voyage returns `data` instead of `results`; rewrite the key and retry.
	let mut v: serde_json::Value = serde_json::from_slice(bytes)?;
	if let Some(obj) = v.as_object_mut()
		&& !obj.contains_key("results")
		&& let Some(data) = obj.remove("data")
	{
		obj.insert("results".to_string(), data);
	}
	serde_json::from_value(v)
}
