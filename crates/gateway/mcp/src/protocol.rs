//! MCP version and HTTP metadata rules, without a listener, transport client or policy engine.
use http::HeaderMap;
use rmcp::model::{
	ClientJsonRpcMessage, ClientNotification, ClientRequest, ConstString, GetMeta, ProtocolVersion,
	RequestId,
};

pub const HEADER_MCP_METHOD: &str = "mcp-method";
pub const HEADER_MCP_NAME: &str = "mcp-name";
pub const HEADER_MCP_PARAM_PREFIX: &str = "mcp-param-";
pub const HEADER_MCP_PROTOCOL_VERSION: &str = "mcp-protocol-version";

/// Versions understood by this gateway's wire layer. SDK upgrades cannot silently add eras.
/// Optional methods/extensions still require Host admission and explicit capability support.
pub const SUPPORTED_VERSIONS: &[ProtocolVersion] = &[
	ProtocolVersion::V_2024_11_05,
	ProtocolVersion::V_2025_03_26,
	ProtocolVersion::V_2025_06_18,
	ProtocolVersion::V_2025_11_25,
	ProtocolVersion::V_2026_07_28,
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
	InvalidProtocolVersion,
	UnsupportedVersion(Option<RequestId>, String),
	UnsupportedVersionForInitialize(Option<RequestId>, String),
	VersionMismatch(Option<RequestId>),
	HeaderBodyMismatch(Option<RequestId>, &'static str),
	InvalidRoutingHeader(Option<RequestId>, &'static str),
}
impl std::fmt::Display for Error {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		match self {
			Self::InvalidProtocolVersion => {
				f.write_str("invalid MCP protocol version header or metadata")
			},
			Self::UnsupportedVersion(_, v) => write!(f, "unsupported MCP protocol version: {v}"),
			Self::UnsupportedVersionForInitialize(_, v) => {
				write!(f, "unsupported MCP protocol version for initialize: {v}")
			},
			Self::VersionMismatch(_) => f.write_str("MCP protocol version header/body mismatch"),
			Self::HeaderBodyMismatch(_, h) => write!(f, "{h} header/body mismatch"),
			Self::InvalidRoutingHeader(_, h) => write!(f, "invalid MCP routing header: {h}"),
		}
	}
}
impl std::error::Error for Error {}

#[derive(Debug, Clone)]
pub struct RequestProtocol {
	version: Option<ProtocolVersion>,
}
impl RequestProtocol {
	pub fn is_modern(&self) -> bool {
		self.version.as_ref() == Some(&ProtocolVersion::V_2026_07_28)
	}
	pub fn uses_sessions(&self) -> bool {
		!self.is_modern()
	}
}

/// SEP-2243 sentinel encoding, available without enabling SDK HTTP client/server features.
pub fn encode_header_value(value: &str) -> String {
	use base64::{Engine, prelude::BASE64_STANDARD};
	if value.starts_with([' ', '\t'])
		|| value.ends_with([' ', '\t'])
		|| value.chars().any(|c| !(0x20..=0x7e).contains(&(c as u32)))
		|| (value.starts_with("=?base64?") && value.ends_with("?="))
	{
		format!("=?base64?{}?=", BASE64_STANDARD.encode(value))
	} else {
		value.into()
	}
}
pub fn decode_header_value(value: &str) -> Option<String> {
	use base64::{Engine, prelude::BASE64_STANDARD};
	match value
		.strip_prefix("=?base64?")
		.and_then(|s| s.strip_suffix("?="))
	{
		Some(encoded) => String::from_utf8(BASE64_STANDARD.decode(encoded).ok()?).ok(),
		None => Some(value.into()),
	}
}

pub fn emit_standard_headers(headers: &mut HeaderMap, message: &ClientJsonRpcMessage) {
	match message_method(message) {
		Some(method) => {
			if let Ok(value) = ::http::HeaderValue::from_str(&encode_header_value(method)) {
				headers.insert(HEADER_MCP_METHOD, value);
			}
		},
		None => {
			headers.remove(HEADER_MCP_METHOD);
		},
	}
	match message_name(message) {
		Some(name) => {
			if let Ok(value) = ::http::HeaderValue::from_str(&encode_header_value(name)) {
				headers.insert(HEADER_MCP_NAME, value);
			}
		},
		None => {
			headers.remove(HEADER_MCP_NAME);
		},
	}
}

pub fn validate_standard_headers(
	headers: &HeaderMap,
	message: &ClientJsonRpcMessage,
	protocol: &RequestProtocol,
) -> Result<(), Error> {
	let request_id = request_id(message);
	let modern = protocol.is_modern();

	validate_standard_header(
		headers,
		HEADER_MCP_METHOD,
		message_method(message),
		modern && message_method(message).is_some(),
		request_id.clone(),
	)?;
	validate_standard_header(
		headers,
		HEADER_MCP_NAME,
		message_name(message),
		modern && message_name(message).is_some(),
		request_id.clone(),
	)?;

	for (name, value) in headers {
		if name
			.as_str()
			.get(..HEADER_MCP_PARAM_PREFIX.len())
			.is_some_and(|prefix| prefix.eq_ignore_ascii_case(HEADER_MCP_PARAM_PREFIX))
		{
			if headers.get_all(name).iter().count() != 1 {
				return Err(Error::InvalidRoutingHeader(
					request_id.clone(),
					HEADER_MCP_PARAM_PREFIX,
				));
			}
			let value = value
				.to_str()
				.map_err(|_| Error::InvalidRoutingHeader(request_id.clone(), HEADER_MCP_PARAM_PREFIX))?;
			if decode_header_value(value).is_none() {
				return Err(Error::InvalidRoutingHeader(
					request_id.clone(),
					HEADER_MCP_PARAM_PREFIX,
				));
			}
		}
	}

	Ok(())
}

fn validate_standard_header(
	headers: &HeaderMap,
	header_name: &'static str,
	body_value: Option<&str>,
	required: bool,
	request_id: Option<RequestId>,
) -> Result<(), Error> {
	let Some(raw) = headers.get(header_name) else {
		if required {
			return Err(Error::InvalidRoutingHeader(request_id, header_name));
		}
		return Ok(());
	};
	if headers.get_all(header_name).iter().count() != 1 {
		return Err(Error::InvalidRoutingHeader(request_id, header_name));
	}
	let raw = raw
		.to_str()
		.map_err(|_| Error::InvalidRoutingHeader(request_id.clone(), header_name))?;
	let decoded = decode_header_value(raw)
		.ok_or_else(|| Error::InvalidRoutingHeader(request_id.clone(), header_name))?;
	if let Some(body_value) = body_value
		&& decoded != body_value
	{
		return Err(Error::HeaderBodyMismatch(request_id, header_name));
	}
	Ok(())
}

pub fn request_id(message: &ClientJsonRpcMessage) -> Option<RequestId> {
	match message {
		ClientJsonRpcMessage::Request(req) => Some(req.id.clone()),
		_ => None,
	}
}

fn message_method(message: &ClientJsonRpcMessage) -> Option<&str> {
	match message {
		ClientJsonRpcMessage::Request(req) => Some(req.request.method()),
		ClientJsonRpcMessage::Notification(notification) => Some(match &notification.notification {
			ClientNotification::CancelledNotification(n) => n.method.as_str(),
			ClientNotification::ProgressNotification(n) => n.method.as_str(),
			ClientNotification::InitializedNotification(n) => n.method.as_str(),
			ClientNotification::RootsListChangedNotification(n) => n.method.as_str(),
			ClientNotification::TaskStatusNotification(n) => n.method.as_str(),
			ClientNotification::CustomNotification(n) => n.method.as_str(),
		}),
		_ => None,
	}
}

fn message_name(message: &ClientJsonRpcMessage) -> Option<&str> {
	let ClientJsonRpcMessage::Request(req) = message else {
		return None;
	};
	match &req.request {
		ClientRequest::CallToolRequest(r) => Some(&r.params.name),
		ClientRequest::GetPromptRequest(r) => Some(&r.params.name),
		ClientRequest::ReadResourceRequest(r) => Some(&r.params.uri),
		ClientRequest::SubscribeRequest(r) => Some(&r.params.uri),
		ClientRequest::UnsubscribeRequest(r) => Some(&r.params.uri),
		_ => None,
	}
}

pub fn protocol_version_header(
	headers: &::http::HeaderMap,
	request_id: Option<RequestId>,
) -> Result<Option<ProtocolVersion>, Error> {
	let Some(value) = headers.get(HEADER_MCP_PROTOCOL_VERSION) else {
		return Ok(None);
	};
	if headers.get_all(HEADER_MCP_PROTOCOL_VERSION).iter().count() != 1 {
		return Err(Error::InvalidProtocolVersion);
	}
	let value = value.to_str().map_err(|_| Error::InvalidProtocolVersion)?;
	let version = SUPPORTED_VERSIONS
		.iter()
		.find(|version| version.as_str() == value)
		.cloned()
		.ok_or_else(|| Error::UnsupportedVersion(request_id, value.to_string()))?;
	Ok(Some(version))
}

pub fn request_protocol(
	headers: &::http::HeaderMap,
	message: &ClientJsonRpcMessage,
	request_id: Option<RequestId>,
) -> Result<RequestProtocol, Error> {
	let header_version = protocol_version_header(headers, request_id.clone())?;
	let body_version = message_protocol_version(message, request_id.clone())?;
	let initialize = is_initialize_request(message);

	if let (Some(header), Some(body)) = (&header_version, &body_version)
		&& header != body
	{
		return Err(Error::VersionMismatch(request_id));
	}

	let declared_version = header_version.as_ref().or(body_version.as_ref());
	let declares_modern_version = declared_version == Some(&ProtocolVersion::V_2026_07_28);
	let missing_modern_version_source = header_version.is_none() || body_version.is_none();
	if declares_modern_version && missing_modern_version_source {
		return Err(Error::InvalidProtocolVersion);
	}

	let version = body_version.or(header_version);
	if initialize
		&& let Some(v) = version.as_ref()
		&& v == &ProtocolVersion::V_2026_07_28
	{
		// `initialize` selects legacy session semantics. Modern versions use
		// `server/discover` plus per-request `_meta`, so accepting 2026+ here would
		// create a session that claims a protocol era that no longer defines it.
		return Err(Error::UnsupportedVersionForInitialize(
			request_id,
			v.to_string(),
		));
	}

	Ok(RequestProtocol { version })
}

fn is_initialize_request(message: &ClientJsonRpcMessage) -> bool {
	matches!(
		message,
		ClientJsonRpcMessage::Request(req)
			if matches!(req.request, ClientRequest::InitializeRequest(_))
	)
}

fn message_protocol_version(
	message: &ClientJsonRpcMessage,
	id: Option<RequestId>,
) -> Result<Option<ProtocolVersion>, Error> {
	let (meta, initialization) = match message {
		ClientJsonRpcMessage::Request(req) => (
			req.request.get_meta(),
			match &req.request {
				ClientRequest::InitializeRequest(init) => Some(&init.params.protocol_version),
				_ => None,
			},
		),
		ClientJsonRpcMessage::Notification(n) => (n.notification.get_meta(), None),
		_ => return Ok(None),
	};
	let metadata = meta
		.get("io.modelcontextprotocol/protocolVersion")
		.map(|v| {
			let version = v.as_str().ok_or(Error::InvalidProtocolVersion)?;
			SUPPORTED_VERSIONS
				.iter()
				.find(|v| v.as_str() == version)
				.cloned()
				.ok_or_else(|| Error::UnsupportedVersion(id.clone(), version.into()))
		})
		.transpose()?;
	if let Some(version) = initialization {
		if !SUPPORTED_VERSIONS.contains(version) {
			return Err(Error::UnsupportedVersionForInitialize(
				id,
				version.to_string(),
			));
		}
		if metadata.as_ref().is_some_and(|v| v != version) {
			return Err(Error::VersionMismatch(id));
		}
		return Ok(Some(version.clone()));
	}
	Ok(metadata)
}

/// Legacy GET/DELETE session endpoints cannot be selected by a modern version.
pub fn check_session_protocol(headers: &HeaderMap) -> Result<(), Error> {
	if let Some(version) = protocol_version_header(headers, None)?
		&& version == ProtocolVersion::V_2026_07_28
	{
		return Err(Error::UnsupportedVersion(None, version.to_string()));
	}
	Ok(())
}

#[cfg(test)]
mod tests;
