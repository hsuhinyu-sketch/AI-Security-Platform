use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Clone, Serialize)]
pub struct Response {
	pub object: String,
	pub model: String,
	pub usage: Usage,
	#[serde(flatten, default)]
	pub rest: serde_json::Value,
}

#[derive(Debug, Deserialize, Clone, Serialize)]
pub struct Usage {
	pub prompt_tokens: u32,
	pub total_tokens: u32,
	#[serde(flatten, default)]
	pub rest: serde_json::Value,
}

#[derive(Debug, Deserialize, Clone, Serialize)]
pub struct Request {
	pub model: Option<String>,
	pub input: serde_json::Value,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub user: Option<String>,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub encoding_format: Option<typed::EncodingFormat>,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub dimensions: Option<u32>,

	// Everything else - passthrough
	#[serde(flatten, default)]
	pub rest: serde_json::Value,
}

impl TryInto<typed::Request> for &Request {
	type Error = crate::WireError;

	fn try_into(self) -> Result<typed::Request, Self::Error> {
		super::convert::<_, typed::Request>(self).map_err(crate::WireError::RequestMarshal)
	}
}

/// 'typed' provides a strictly-typed internal representation of the OpenAI embeddings API.
/// This is used as a normalization bridge for non-OpenAI providers (e.g. Bedrock, Vertex).
/// These providers are converted into these typed structs first to ensure validity,
/// and then converted back to the top-level passthrough-preserving structs for the client.
pub mod typed {
	use serde::{Deserialize, Serialize};

	#[derive(Debug, Serialize, Default, Clone, Copy, PartialEq, Deserialize)]
	#[serde(rename_all = "lowercase")]
	pub enum EncodingFormat {
		#[default]
		Float,
		Base64,
	}

	#[derive(Debug, Deserialize, Clone, Serialize)]
	pub struct Request {
		pub model: String,
		pub input: EmbeddingInput,
		#[serde(skip_serializing_if = "Option::is_none")]
		pub user: Option<String>,
		#[serde(skip_serializing_if = "Option::is_none")]
		pub encoding_format: Option<EncodingFormat>,
		#[serde(skip_serializing_if = "Option::is_none")]
		pub dimensions: Option<u32>,
	}

	#[derive(Debug, Deserialize, Clone, Serialize)]
	#[serde(untagged)]
	pub enum EmbeddingInput {
		String(String),
		Array(Vec<String>),
	}

	impl EmbeddingInput {
		pub fn as_strings(&self) -> Vec<String> {
			match self {
				EmbeddingInput::String(s) => vec![s.clone()],
				EmbeddingInput::Array(arr) => arr.clone(),
			}
		}

		pub fn first(&self) -> Option<&str> {
			match self {
				EmbeddingInput::String(s) => Some(s),
				EmbeddingInput::Array(arr) => arr.first().map(|s| s.as_str()),
			}
		}
	}

	#[derive(Debug, Deserialize, Clone, Serialize)]
	pub struct Response {
		pub object: String,
		pub model: String,
		pub data: Vec<Embedding>,
		pub usage: Usage,
	}

	#[derive(Debug, Deserialize, Clone, Serialize)]
	pub struct Embedding {
		pub index: u32,
		pub object: String,
		pub embedding: Vec<f32>,
	}

	#[derive(Debug, Deserialize, Clone, Serialize)]
	pub struct Usage {
		pub prompt_tokens: u32,
		pub total_tokens: u32,
	}
}
