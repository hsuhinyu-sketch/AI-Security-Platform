use super::*;
use serde_json::{Value, json};

fn request(method: &str, params: Value) -> ClientJsonRpcMessage {
	serde_json::from_value(json!({"jsonrpc":"2.0","id":3,"method":method,"params":params})).unwrap()
}
fn modern() -> ClientJsonRpcMessage {
	request(
		"tools/call",
		json!({"name":"echo","arguments":{},"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28"}}),
	)
}
fn headers() -> HeaderMap {
	let mut headers = HeaderMap::new();
	headers.insert(HEADER_MCP_PROTOCOL_VERSION, "2026-07-28".parse().unwrap());
	emit_standard_headers(&mut headers, &modern());
	headers
}
#[test]
fn modern_requires_matching_version_sources_and_routing_headers() {
	let req = modern();
	let protocol = request_protocol(&headers(), &req, request_id(&req)).unwrap();
	assert!(protocol.is_modern());
	assert!(!protocol.uses_sessions());
	assert!(validate_standard_headers(&headers(), &req, &protocol).is_ok());
	for name in [HEADER_MCP_METHOD, HEADER_MCP_NAME] {
		let mut h = headers();
		h.remove(name);
		assert!(validate_standard_headers(&h, &req, &protocol).is_err());
	}
	let mut h = headers();
	h.remove(HEADER_MCP_PROTOCOL_VERSION);
	assert_eq!(
		request_protocol(&h, &req, request_id(&req)).unwrap_err(),
		Error::InvalidProtocolVersion
	);
	let req = request("tools/call", json!({"name":"echo","arguments":{}}));
	assert_eq!(
		request_protocol(&headers(), &req, request_id(&req)).unwrap_err(),
		Error::InvalidProtocolVersion
	);
}
#[test]
fn malformed_metadata_and_unknown_versions_do_not_select_legacy_semantics() {
	for version in [json!(null), json!(9), json!({}), json!("2099-01-01")] {
		let req = request(
			"tools/call",
			json!({"name":"echo","_meta":{"io.modelcontextprotocol/protocolVersion":version}}),
		);
		assert!(request_protocol(&HeaderMap::new(), &req, request_id(&req)).is_err());
	}
	let req = modern();
	let mut h = headers();
	h.insert(HEADER_MCP_PROTOCOL_VERSION, "2025-11-25".parse().unwrap());
	assert!(matches!(
		request_protocol(&h, &req, request_id(&req)),
		Err(Error::VersionMismatch(_))
	));
}
#[test]
fn initialization_only_accepts_explicit_legacy_versions() {
	for version in SUPPORTED_VERSIONS {
		let req = request(
			"initialize",
			json!({"protocolVersion":version,"capabilities":{},"clientInfo":{"name":"wire","version":"1"}}),
		);
		let mut h = HeaderMap::new();
		h.insert(
			HEADER_MCP_PROTOCOL_VERSION,
			version.as_str().parse().unwrap(),
		);
		let result = request_protocol(&h, &req, request_id(&req));
		if version == &ProtocolVersion::V_2026_07_28 {
			assert!(matches!(
				result,
				Err(Error::UnsupportedVersionForInitialize(_, _))
			));
		} else {
			assert!(result.unwrap().uses_sessions());
			assert!(
				request_protocol(&HeaderMap::new(), &req, request_id(&req))
					.unwrap()
					.uses_sessions()
			);
		}
	}
	let req = request(
		"initialize",
		json!({"protocolVersion":"2099-01-01","capabilities":{},"clientInfo":{"name":"wire","version":"1"}}),
	);
	assert!(matches!(
		request_protocol(&HeaderMap::new(), &req, request_id(&req)),
		Err(Error::UnsupportedVersionForInitialize(..))
	));
}
#[test]
fn duplicate_headers_are_rejected_even_when_values_agree() {
	let req = modern();
	let protocol = request_protocol(&headers(), &req, request_id(&req)).unwrap();
	for name in [
		HEADER_MCP_METHOD,
		HEADER_MCP_NAME,
		HEADER_MCP_PROTOCOL_VERSION,
		"mcp-param-region",
	] {
		let mut h = headers();
		let value = h
			.get(name)
			.cloned()
			.unwrap_or_else(|| "same".parse().unwrap());
		if !h.contains_key(name) {
			h.insert(name, value.clone());
		}
		h.append(name, value);
		if name == HEADER_MCP_PROTOCOL_VERSION {
			assert!(protocol_version_header(&h, request_id(&req)).is_err());
		} else {
			assert!(
				validate_standard_headers(&h, &req, &protocol).is_err(),
				"{name}"
			);
		}
	}
}
#[test]
fn header_encoding_round_trips_names_and_rejects_invalid_sentinels() {
	for name in [
		"echo",
		"",
		" 空间/工具 ",
		"\ttab",
		"=?base64?YQ==?=",
		"line\r\nbreak",
	] {
		assert_eq!(
			decode_header_value(&encode_header_value(name)).as_deref(),
			Some(name)
		);
		let req = request(
			"tools/call",
			json!({"name":name,"arguments":{},"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28"}}),
		);
		let mut h = headers();
		emit_standard_headers(&mut h, &req);
		let protocol = request_protocol(&h, &req, request_id(&req)).unwrap();
		assert!(validate_standard_headers(&h, &req, &protocol).is_ok());
	}
	for value in ["=?base64?%%%?=", "=?base64?/w==?="] {
		assert!(decode_header_value(value).is_none());
	}
}
#[test]
fn named_methods_validate_the_actual_name_or_uri() {
	for (method, params) in [
		("tools/call", json!({"name":"echo"})),
		("prompts/get", json!({"name":"support"})),
		("resources/read", json!({"uri":"file:///workspace/guide"})),
	] {
		let mut params = params;
		params["_meta"] = json!({"io.modelcontextprotocol/protocolVersion":"2026-07-28"});
		let req = request(method, params);
		let mut h = headers();
		emit_standard_headers(&mut h, &req);
		let protocol = request_protocol(&h, &req, request_id(&req)).unwrap();
		assert!(validate_standard_headers(&h, &req, &protocol).is_ok());
		h.insert(HEADER_MCP_NAME, "different".parse().unwrap());
		assert!(matches!(
			validate_standard_headers(&h, &req, &protocol),
			Err(Error::HeaderBodyMismatch(..))
		));
	}
}

#[test]
fn session_endpoint_version_check_and_initialization_metadata_cannot_conflict() {
	assert!(check_session_protocol(&headers()).is_err());
	assert!(check_session_protocol(&HeaderMap::new()).is_ok());
	let mut h = HeaderMap::new();
	h.insert(HEADER_MCP_PROTOCOL_VERSION, "2025-11-25".parse().unwrap());
	assert!(check_session_protocol(&h).is_ok());
	let req = request(
		"initialize",
		json!({"protocolVersion":"2025-11-25", "capabilities":{},
		"clientInfo":{"name":"wire","version":"1"}, "_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28"}}),
	);
	assert!(matches!(
		request_protocol(&h, &req, request_id(&req)),
		Err(Error::VersionMismatch(_))
	));
}
