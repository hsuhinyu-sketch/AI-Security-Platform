#![cfg(feature = "presidio")]
use security_pii::*;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

async fn sidecar(
	status: u16,
	body: &str,
	delay_ms: u64,
) -> (String, tokio::task::JoinHandle<serde_json::Value>) {
	let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
	let addr = listener.local_addr().unwrap();
	let body = body.to_owned();
	let handle = tokio::spawn(async move {
		let (mut stream, _) = listener.accept().await.unwrap();
		let mut bytes = Vec::new();
		let mut buffer = [0; 4096];
		let (start, length) = loop {
			let n = stream.read(&mut buffer).await.unwrap();
			assert!(n > 0);
			bytes.extend_from_slice(&buffer[..n]);
			if let Some(i) = bytes.windows(4).position(|b| b == b"\r\n\r\n") {
				let headers = String::from_utf8_lossy(&bytes[..i]);
				let length = headers
					.lines()
					.find_map(|line| {
						line
							.to_ascii_lowercase()
							.strip_prefix("content-length: ")
							.and_then(|n| n.parse::<usize>().ok())
					})
					.unwrap();
				break (i + 4, length);
			}
		};
		while bytes.len() < start + length {
			let n = stream.read(&mut buffer).await.unwrap();
			assert!(n > 0);
			bytes.extend_from_slice(&buffer[..n]);
		}
		let request = serde_json::from_slice(&bytes[start..start + length]).unwrap();
		tokio::time::sleep(Duration::from_millis(delay_ms)).await;
		let wire = format!(
			"HTTP/1.1 {status} result\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
			body.len()
		);
		let _ = stream.write_all(wire.as_bytes()).await;
		request
	});
	(format!("http://{addr}"), handle)
}
fn config(endpoint: String) -> PiiConfig {
	serde_json::from_value(serde_json::json!({"backend":"presidio","presidioEndpoint":endpoint,"policy":{"entities":{"EMAIL_ADDRESS":{"action":"replace","value":"[EMAIL]"}}}})).unwrap()
}
#[tokio::test]
async fn official_wire_unicode_offsets_and_request_entities() {
	let (endpoint, server) = sidecar(
		200,
		r#"[{"entity_type":"EMAIL_ADDRESS","start":2,"end":19,"score":0.9,"analysis_explanation":null}]"#,
		0,
	)
	.await;
	let out = config(endpoint)
		.build()
		.unwrap()
		.unwrap()
		.inspect("甲😀alice@example.com!")
		.await
		.unwrap();
	assert_eq!(out.text, "甲😀[EMAIL]!");
	let request = server.await.unwrap();
	assert_eq!(request["entities"], serde_json::json!(["EMAIL_ADDRESS"]));
	assert_eq!(request["return_decision_process"], false);
	assert_eq!(request["language"], "en");
}
#[tokio::test]
async fn transport_error_timeout_http_error_oversize_and_invalid_ranges_fail_closed() {
	for (status, body) in [
		(503, "sensitive error text"),
		(200, "not json"),
		(
			200,
			r#"[{"entity_type":"EMAIL_ADDRESS","start":0,"end":999,"score":0.9}]"#,
		),
		(
			200,
			r#"[{"entity_type":"UNKNOWN","start":0,"end":1,"score":0.9}]"#,
		),
	] {
		let (endpoint, server) = sidecar(status, body, 0).await;
		assert!(
			config(endpoint)
				.build()
				.unwrap()
				.unwrap()
				.inspect("alice@example.com")
				.await
				.is_err()
		);
		server.await.unwrap();
	}
	let (endpoint, server) = sidecar(200, &"x".repeat(4096), 0).await;
	let mut cfg = config(endpoint);
	cfg.max_response_bytes = 32;
	assert!(cfg.build().unwrap().unwrap().inspect("text").await.is_err());
	server.await.unwrap();
	let (endpoint, server) = sidecar(200, "[]", 200).await;
	let mut cfg = config(endpoint);
	cfg.timeout_ms = 10;
	assert!(matches!(
		cfg.build().unwrap().unwrap().inspect("text").await,
		Err(PiiError::Timeout)
	));
	server.abort();
	let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
	let endpoint = format!("http://{}", listener.local_addr().unwrap());
	drop(listener);
	assert!(matches!(
		config(endpoint)
			.build()
			.unwrap()
			.unwrap()
			.inspect("text")
			.await,
		Err(PiiError::Unavailable)
	));
}
#[test]
fn endpoint_is_fixed_loopback_only_without_redirect_or_credential_overrides() {
	for endpoint in [
		"http://example.com",
		"http://localhost:5002",
		"http://127.0.0.1:5002/other",
		"http://u:p@127.0.0.1",
		"http://127.0.0.1/?token=secret",
	] {
		assert!(config(endpoint.into()).build().is_err());
	}
	assert!(config("http://127.0.0.1:5002".into()).build().is_ok());
}
