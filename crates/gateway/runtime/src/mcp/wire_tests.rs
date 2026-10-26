use crate::proxy::ProxyError;
use http_body_util::BodyExt;

#[test]
fn independent_header_codec_matches_the_pinned_sdk() {
	use gateway_mcp::protocol as core;
	use rmcp::transport::common::mcp_headers as sdk;
	let mut cases = vec![
		String::new(),
		"echo".into(),
		" leading".into(),
		"trailing\t".into(),
		"工具".into(),
		"line\r\nbreak".into(),
		"=?base64?YQ==?=".into(),
	];
	for character in '\0'..='\u{ff}' {
		cases.push(format!("prefix{character}suffix"));
	}
	for value in cases {
		let encoded = core::encode_header_value(&value);
		assert_eq!(encoded, sdk::encode_header_value(&value));
		assert_eq!(
			core::decode_header_value(&encoded),
			sdk::decode_header_value(&encoded)
		);
	}
	for invalid in ["=?base64?%%%?=", "=?base64?/w==?="] {
		assert_eq!(
			core::decode_header_value(invalid),
			sdk::decode_header_value(invalid)
		);
	}
}

#[tokio::test]
async fn host_preserves_wire_error_ids_status_and_version_information() {
	use gateway_mcp::protocol::Error;
	use rmcp::model::RequestId;
	for initialization in [false, true] {
		let id = Some(RequestId::Number(17));
		let error = if initialization {
			Error::UnsupportedVersionForInitialize(id, "2099-01-01".into())
		} else {
			Error::UnsupportedVersion(id, "2099-01-01".into())
		};
		let response = ProxyError::from(error).into_response_with_grpc(false);
		assert_eq!(response.status(), http::StatusCode::BAD_REQUEST);
		let bytes = response.into_body().collect().await.unwrap().to_bytes();
		let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
		assert_eq!(value["id"], 17);
		assert_eq!(value["error"]["code"], -32022);
		assert_eq!(value["error"]["data"]["requested"], "2099-01-01");
		let versions = value["error"]["data"]["supported"].as_array().unwrap();
		assert!(versions.iter().any(|v| v == "2025-11-25"));
		assert_eq!(versions.iter().any(|v| v == "2026-07-28"), !initialization);
	}
}
