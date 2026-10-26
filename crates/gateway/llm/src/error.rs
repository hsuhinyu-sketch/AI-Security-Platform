//! Pure LLM conversion failures. HTTP status mapping and response parse logging remain in the Host.

#[derive(thiserror::Error, Debug)]
pub enum WireError {
	#[error("failed to marshal response: {0}")]
	ResponseMarshal(serde_json::Error),
	#[error("response was missing fields")]
	IncompleteResponse,
	#[error("unsupported conversion: {0}")]
	UnsupportedConversion(arcstr::ArcStr),
	#[error("failed to marshal request: {0}")]
	RequestMarshal(serde_json::Error),
	#[error("failed to parse response: {0}")]
	ResponseParsing(serde_json::Error),
	#[error("invalid response: {0}")]
	InvalidResponse(arcstr::ArcStr),
	#[error("missing field: {0}")]
	MissingField(arcstr::ArcStr),
	#[error("failed to parse request: {0}")]
	RequestParsing(serde_json::Error),
}
