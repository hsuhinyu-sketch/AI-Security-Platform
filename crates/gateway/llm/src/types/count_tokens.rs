use serde::{Deserialize, Serialize};

use super::messages;

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct Request {
	pub messages: Vec<messages::RequestMessage>,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub model: Option<String>,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub system: Option<messages::TextBlock>,
	#[serde(flatten)]
	pub rest: serde_json::Map<String, serde_json::Value>,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct Response {
	#[serde(alias = "inputTokens")]
	pub input_tokens: u64,
}
