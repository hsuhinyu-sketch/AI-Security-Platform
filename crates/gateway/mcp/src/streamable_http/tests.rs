use super::*;
use serde_json::json;

fn headers(content_type: Option<&str>) -> HeaderMap {
	let mut headers = HeaderMap::new();
	if let Some(value) = content_type {
		headers.insert(CONTENT_TYPE, value.parse().unwrap());
	}
	headers
}

#[test]
fn post_encoding_preserves_typed_payload_and_leaves_trusted_context_to_caller() {
	let message: ClientJsonRpcMessage =
		serde_json::from_value(json!({"jsonrpc":"2.0","id":3,"method":"tools/call",
		"params":{"name":"echo","arguments":{"text":"雪"},"_meta":{"trace":"keep"}}}))
		.unwrap();
	let uri: Uri = "http://upstream/mcp?route=a".parse().unwrap();
	let request = encode_post(uri.clone(), &message).unwrap();
	assert_eq!(request.method(), Method::POST);
	assert_eq!(request.uri(), &uri);
	assert_eq!(request.headers()[CONTENT_TYPE], "application/json");
	assert_eq!(
		request.headers()[ACCEPT],
		"text/event-stream, application/json"
	);
	assert_eq!(request.headers().len(), 2);
	assert_eq!(
		serde_json::from_slice::<serde_json::Value>(request.body()).unwrap(),
		serde_json::to_value(message).unwrap()
	);
}

#[test]
fn post_status_precedence_and_content_type_compatibility_are_preserved() {
	for content in [None, Some("text/plain"), Some("application/json")] {
		for status in [StatusCode::ACCEPTED, StatusCode::NO_CONTENT] {
			assert_eq!(
				classify_post_response(status, &headers(content)),
				Ok(ResponseKind::Accepted)
			);
		}
		for status in [
			StatusCode::TEMPORARY_REDIRECT,
			StatusCode::FORBIDDEN,
			StatusCode::INTERNAL_SERVER_ERROR,
		] {
			assert_eq!(
				classify_post_response(status, &headers(content)),
				Err(ResponseError::Status(status))
			);
		}
	}
	for content in [
		"application/json",
		"application/json; charset=utf-8",
		"application/json-compatible",
	] {
		assert_eq!(
			classify_post_response(StatusCode::OK, &headers(Some(content))),
			Ok(ResponseKind::Json)
		);
	}
	for content in ["text/event-stream", "text/event-stream; charset=utf-8"] {
		assert_eq!(
			classify_post_response(StatusCode::OK, &headers(Some(content))),
			Ok(ResponseKind::Sse)
		);
	}
	for content in [None, Some("text/plain"), Some("APPLICATION/JSON")] {
		assert!(matches!(
			classify_post_response(StatusCode::OK, &headers(content)),
			Err(ResponseError::ContentType(_))
		));
	}
}

#[test]
fn get_requires_an_sse_content_type_even_for_accepted_status() {
	for status in [StatusCode::OK, StatusCode::ACCEPTED, StatusCode::NO_CONTENT] {
		assert_eq!(
			validate_get_response(status, &headers(Some("text/event-stream"))),
			Ok(())
		);
		assert!(matches!(
			validate_get_response(status, &headers(Some("application/json"))),
			Err(ResponseError::GetContentType(_))
		));
	}
	assert_eq!(
		validate_get_response(StatusCode::FORBIDDEN, &headers(Some("text/event-stream"))),
		Err(ResponseError::Status(StatusCode::FORBIDDEN))
	);
}

#[test]
fn json_null_and_empty_sse_events_have_distinct_existing_semantics() {
	assert!(decode_json(b"null").unwrap().is_none());
	for invalid in [b"".as_slice(), b"{", b"[]"] {
		assert!(decode_json(invalid).is_err());
	}
	for event in [None, Some("")] {
		assert!(decode_sse_data(event).unwrap().is_none());
	}
	for invalid in ["null", " ", "{", "[]"] {
		assert!(decode_sse_data(Some(invalid)).is_err());
	}
	let message = json!({"jsonrpc":"2.0","id":"reverse","method":"sampling/createMessage",
		"params":{"messages":[],"maxTokens":4,"includeContext":"allServers","vendor":"keep"}});
	let bytes = serde_json::to_vec(&message).unwrap();
	for decoded in [
		decode_json(&bytes).unwrap().unwrap(),
		decode_sse_data(Some(std::str::from_utf8(&bytes).unwrap()))
			.unwrap()
			.unwrap(),
	] {
		assert_eq!(serde_json::to_value(decoded).unwrap(), message);
	}
}

#[test]
fn session_header_projection_preserves_existing_invalid_utf8_handling() {
	let mut headers = HeaderMap::new();
	assert_eq!(session_id(&headers), None);
	headers.insert("mcp-session-id", "opaque".parse().unwrap());
	assert_eq!(session_id(&headers).as_deref(), Some("opaque"));
	headers.insert("mcp-session-id", HeaderValue::from_bytes(&[0xff]).unwrap());
	assert_eq!(session_id(&headers), None);
}
