//! Provider error envelopes. Parsing diagnostics and HTTP execution remain Host-owned.
use crate::{
	WireError,
	types::{bedrock, completions::typed as chat, messages::typed as messages},
};
use bytes::Bytes;
fn marshal(value: &impl serde::Serialize) -> Result<Bytes, WireError> {
	serde_json::to_vec(value)
		.map(Bytes::from)
		.map_err(WireError::ResponseMarshal)
}
fn anthropic_type(status: http::StatusCode) -> &'static str {
	match status {
		http::StatusCode::BAD_REQUEST => "invalid_request_error",
		http::StatusCode::UNAUTHORIZED | http::StatusCode::FORBIDDEN => "authentication_error",
		http::StatusCode::NOT_FOUND => "not_found_error",
		http::StatusCode::TOO_MANY_REQUESTS => "rate_limit_error",
		_ => "api_error",
	}
}
fn google(bytes: &[u8]) -> Result<chat::GoogleErrorResponse, WireError> {
	serde_json::from_slice(bytes).or_else(|_| {
		serde_json::from_slice::<Vec<chat::GoogleErrorResponse>>(bytes)
			.map_err(WireError::ResponseParsing)?
			.into_iter()
			.next()
			.ok_or_else(|| WireError::InvalidResponse("error response missing error details".into()))
	})
}
fn openai(message: String, code: Option<String>, kind: &str) -> Result<Bytes, WireError> {
	marshal(&chat::ChatCompletionErrorResponse {
		event_id: None,
		error: chat::ChatCompletionError {
			r#type: Some(kind.to_string()),
			message,
			param: None,
			code,
			event_id: None,
		},
	})
}
fn anthropic(message: String, kind: &str, envelope_kind: &str) -> Result<Bytes, WireError> {
	marshal(&messages::MessagesErrorResponse {
		r#type: envelope_kind.to_string(),
		error: messages::MessagesError {
			r#type: kind.to_string(),
			message,
		},
	})
}
pub fn google_to_openai(bytes: &Bytes) -> Result<Bytes, WireError> {
	let response = google(bytes)?;
	openai(
		response.error.message.clone(),
		response.error.status.clone(),
		super::completions::google_error_type(&response.error),
	)
}
pub fn google_to_anthropic(bytes: &Bytes) -> Result<Bytes, WireError> {
	let response = google(bytes)?;
	anthropic(
		response.error.message.clone(),
		super::completions::google_error_type(&response.error),
		"error",
	)
}
pub fn normalize_anthropic(bytes: &Bytes, status: http::StatusCode) -> Result<Bytes, WireError> {
	if serde_json::from_slice::<messages::MessagesErrorResponse>(bytes).is_ok() {
		return Ok(bytes.clone());
	}
	anthropic(
		String::from_utf8_lossy(bytes).into_owned(),
		anthropic_type(status),
		"error",
	)
}
pub fn anthropic_to_openai(bytes: &Bytes) -> Result<Bytes, WireError> {
	let message = serde_json::from_slice::<messages::MessagesErrorResponse>(bytes)
		.map(|r| r.error.message)
		.unwrap_or_else(|_| String::from_utf8_lossy(bytes).into_owned());
	openai(message, None, "invalid_request_error")
}
pub fn openai_to_anthropic(bytes: &Bytes, status: http::StatusCode) -> Result<Bytes, WireError> {
	let response: chat::ChatCompletionErrorResponse =
		serde_json::from_slice(bytes).map_err(WireError::ResponseParsing)?;
	anthropic(
		response.error.message.clone(),
		response
			.error
			.r#type
			.as_deref()
			.unwrap_or(anthropic_type(status)),
		"error",
	)
}
fn bedrock_message(bytes: &[u8]) -> String {
	serde_json::from_slice::<bedrock::ConverseErrorResponse>(bytes)
		.map(|r| r.message)
		.unwrap_or_else(|_| String::from_utf8_lossy(bytes).into_owned())
}
pub fn bedrock_to_openai(bytes: &Bytes) -> Result<Bytes, WireError> {
	openai(bedrock_message(bytes), None, "invalid_request_error")
}
pub fn bedrock_to_anthropic(bytes: &Bytes) -> Result<Bytes, WireError> {
	anthropic(bedrock_message(bytes), "invalid_request_error", "")
}
