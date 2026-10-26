//! Streamable HTTP data rules. The caller owns I/O, decompression limits and leases.
use http::{
	HeaderMap, HeaderValue, Method, Request, StatusCode, Uri,
	header::{ACCEPT, CONTENT_TYPE},
};
use rmcp::model::{ClientJsonRpcMessage, ServerJsonRpcMessage};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResponseKind {
	Accepted,
	Json,
	Sse,
}

#[derive(Debug, PartialEq, Eq)]
pub enum ResponseError {
	Status(StatusCode),
	ContentType(Option<HeaderValue>),
	GetContentType(Option<HeaderValue>),
}

impl std::fmt::Display for ResponseError {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		match self {
			Self::Status(status) => write!(f, "unexpected HTTP status: {status}"),
			Self::ContentType(actual) => write!(f, "unexpected content type: {actual:?}"),
			Self::GetContentType(actual) => {
				write!(f, "unexpected content type for GET streams: {actual:?}")
			},
		}
	}
}
impl std::error::Error for ResponseError {}

/// Context/session headers belong to the caller. Emit message-derived routing
/// headers after applying that context, using protocol::emit_standard_headers.
pub fn encode_post(
	uri: Uri,
	message: &ClientJsonRpcMessage,
) -> Result<Request<Vec<u8>>, serde_json::Error> {
	let mut request = Request::new(serde_json::to_vec(message)?);
	*request.method_mut() = Method::POST;
	*request.uri_mut() = uri;
	request
		.headers_mut()
		.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
	request.headers_mut().insert(
		ACCEPT,
		HeaderValue::from_static("text/event-stream, application/json"),
	);
	Ok(request)
}

pub fn classify_post_response(
	status: StatusCode,
	headers: &HeaderMap,
) -> Result<ResponseKind, ResponseError> {
	// Preserve the existing 202/204 compatibility before inspecting Content-Type.
	if status == StatusCode::ACCEPTED || status == StatusCode::NO_CONTENT {
		return Ok(ResponseKind::Accepted);
	}
	if !status.is_success() {
		return Err(ResponseError::Status(status));
	}
	let content_type = headers.get(CONTENT_TYPE);
	match content_type {
		Some(value) if value.as_bytes().starts_with(b"text/event-stream") => Ok(ResponseKind::Sse),
		Some(value) if value.as_bytes().starts_with(b"application/json") => Ok(ResponseKind::Json),
		_ => Err(ResponseError::ContentType(content_type.cloned())),
	}
}

pub fn validate_get_response(status: StatusCode, headers: &HeaderMap) -> Result<(), ResponseError> {
	if !status.is_success() {
		return Err(ResponseError::Status(status));
	}
	let content_type = headers.get(CONTENT_TYPE);
	match content_type {
		Some(value) if value.as_bytes().starts_with(b"text/event-stream") => Ok(()),
		_ => Err(ResponseError::GetContentType(content_type.cloned())),
	}
}

pub fn session_id(headers: &HeaderMap) -> Option<String> {
	headers
		.get("mcp-session-id")
		.and_then(|value| value.to_str().ok())
		.map(str::to_string)
}

/// Bytes must already have passed the caller's decompression and size limits.
pub fn decode_json(bytes: &[u8]) -> Result<Option<ServerJsonRpcMessage>, serde_json::Error> {
	let value: Option<serde_json::Value> = serde_json::from_slice(bytes)?;
	value.map(crate::wire::decode_server).transpose()
}

/// Decode one already-framed SSE event. Missing/empty data is ignored; malformed
/// nonempty data remains an error. HTTP JSON null handling does not apply to SSE.
pub fn decode_sse_data(
	data: Option<&str>,
) -> Result<Option<ServerJsonRpcMessage>, serde_json::Error> {
	data
		.filter(|data| !data.is_empty())
		.map(|data| serde_json::from_str(data).and_then(crate::wire::decode_server))
		.transpose()
}

#[cfg(test)]
mod tests;
