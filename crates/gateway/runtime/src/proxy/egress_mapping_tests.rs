use super::*;
use serde_json::json;
use std::time::Duration;

async fn denied_by_egress(method: ::http::Method, mirror: bool) {
	let upstream = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
	let address = upstream.local_addr().unwrap();
	let inputs = execution_tests::inputs(&[address]);
	let mut route = json!({"backends":[{"host":address.to_string()}]});
	if mirror {
		route["policies"] =
			json!({"requestMirror":{"backend":{"host":address.to_string()},"percentage":1.0}});
	}
	let raw = json!({
		"frontendPolicies":{"connect":{"mode":"route"}},
		"binds":[{"port":0,"listeners":[{"routes":[route]}]}]
	});
	let mut normalized = Box::pin(crate::types::local::NormalizedLocalConfig::compute(
		&inputs.cfg,
		&crate::resource_manager::ResourceFetcher::files_only(),
		inputs.cfg.gateway(),
		&raw.to_string(),
	))
	.await
	.unwrap();
	let security = Arc::new(
		serde_json::from_value::<security_integration_runtime::SecurityConfig>(json!({
			"mode":"enforce","dataEgress":{"classification":"restricted"}
		}))
		.unwrap(),
	);
	// Exercise the existing trusted embedding path, without adding a YAML field
	// or a production-only endpoint for attaching a security declaration.
	for (_, routes) in &mut normalized.listener_routes {
		for route in routes {
			for backend in &mut route.backends {
				backend
					.inline_policies
					.push(BackendTrafficPolicy::SecurityAudit(security.clone()));
			}
		}
	}
	let bind_name = normalized.binds[0].key.clone();
	inputs.stores.binds.sync_local(
		normalized.binds,
		normalized.listener_routes,
		normalized.listener_tcp_routes,
		normalized.policies,
		normalized.backends,
		normalized.route_groups,
		Default::default(),
	);
	let local_addr = inputs.stores.binds.read().bind(&bind_name).unwrap().address;
	let proxy = HTTPProxy {
		bind_name,
		inputs,
		selected_listener: None,
		target_address: local_addr,
	};
	let mut connection = Extension::new();
	connection.insert(TCPConnectionInfo {
		peer_addr: "127.0.0.1:54321".parse().unwrap(),
		local_addr,
		start: Instant::now(),
		raw_peer_addr: None,
	});
	let uri = if method == ::http::Method::CONNECT {
		address.to_string()
	} else {
		"http://localhost/test".into()
	};
	let mut req = ::http::Request::builder()
		.method(method.clone())
		.uri(uri)
		.body(http::Body::empty())
		.unwrap();
	if method == ::http::Method::CONNECT {
		let upgrade = hyper::upgrade::on(&mut req);
		req.extensions_mut().insert(upgrade);
	}
	let response = tokio::time::timeout(
		Duration::from_secs(5),
		Box::pin(proxy.proxy(Arc::new(connection), req)),
	)
	.await
	.unwrap();
	assert_eq!(response.status(), StatusCode::FORBIDDEN);
	let body = http::read_resp_body(response).await.unwrap();
	assert_eq!(body.as_ref(), b"authorization failed");
	assert!(
		tokio::time::timeout(Duration::from_millis(50), upstream.accept())
			.await
			.is_err(),
		"refusal must happen before dialing either primary or mirror upstream"
	);
}

#[tokio::test]
async fn unsupported_egress_adapter_returns_generic_forbidden_before_dial() {
	denied_by_egress(::http::Method::POST, false).await;
}

#[tokio::test]
async fn security_blocked_connect_returns_generic_forbidden_before_dial() {
	denied_by_egress(::http::Method::CONNECT, false).await;
}

#[tokio::test]
async fn security_blocked_mirror_returns_generic_forbidden_before_dial() {
	denied_by_egress(::http::Method::POST, true).await;
}

#[tokio::test]
async fn debug_logging_omits_credentials_without_changing_forwarded_request() {
	use tokio::io::{AsyncReadExt, AsyncWriteExt};
	use tracing::Level;
	// Other tests install tracing subscribers concurrently. Isolate this capture
	// so its callsite filtering is not affected by their process-wide registry.
	if std::env::var_os("AISP_LOG_CAPTURE_CHILD").is_none() {
		let output = std::process::Command::new(std::env::current_exe().unwrap())
			.args([
				"--exact",
				"proxy::httpproxy::egress_mapping_tests::debug_logging_omits_credentials_without_changing_forwarded_request",
				"--nocapture",
			])
			.env("AISP_LOG_CAPTURE_CHILD", "1")
			.output()
			.unwrap();
		assert!(
			output.status.success(),
			"{}\n{}",
			String::from_utf8_lossy(&output.stdout),
			String::from_utf8_lossy(&output.stderr)
		);
		return;
	}
	#[derive(Clone)]
	struct Capture(Arc<std::sync::Mutex<Vec<u8>>>);
	impl std::io::Write for Capture {
		fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
			self.0.lock().unwrap().extend_from_slice(bytes);
			Ok(bytes.len())
		}
		fn flush(&mut self) -> std::io::Result<()> {
			Ok(())
		}
	}
	let output = Capture(Arc::new(std::sync::Mutex::new(Vec::new())));
	let writer = output.clone();
	let subscriber = tracing_subscriber::fmt()
		.with_max_level(Level::TRACE)
		.with_ansi(false)
		.without_time()
		.with_writer(move || writer.clone())
		.finish();
	let _subscriber = tracing::subscriber::set_default(subscriber);
	let upstream = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
	let address = upstream.local_addr().unwrap();
	let server = tokio::spawn(async move {
		let (mut stream, _) = upstream.accept().await.unwrap();
		let mut request = Vec::new();
		while !request.windows(4).any(|w| w == b"\r\n\r\n") {
			let mut bytes = [0; 2048];
			let n = stream.read(&mut bytes).await.unwrap();
			assert!(n > 0);
			request.extend_from_slice(&bytes[..n]);
		}
		stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nSet-Cookie: session=response-secret\r\nConnection: close\r\n\r\nok").await.unwrap();
		String::from_utf8(request).unwrap()
	});
	let inputs = execution_tests::inputs(&[address]);
	let raw = json!({"binds":[{"port":0,"listeners":[{"routes":[{"backends":[{"host":address.to_string()}]}]}]}]});
	let normalized = Box::pin(crate::types::local::NormalizedLocalConfig::compute(
		&inputs.cfg,
		&crate::resource_manager::ResourceFetcher::files_only(),
		inputs.cfg.gateway(),
		&raw.to_string(),
	))
	.await
	.unwrap();
	let bind_name = normalized.binds[0].key.clone();
	inputs.stores.binds.sync_local(
		normalized.binds,
		normalized.listener_routes,
		normalized.listener_tcp_routes,
		normalized.policies,
		normalized.backends,
		normalized.route_groups,
		Default::default(),
	);
	let local_addr = inputs.stores.binds.read().bind(&bind_name).unwrap().address;
	let proxy = HTTPProxy {
		bind_name,
		inputs,
		selected_listener: None,
		target_address: local_addr,
	};
	let mut connection = Extension::new();
	connection.insert(TCPConnectionInfo {
		peer_addr: "127.0.0.1:54321".parse().unwrap(),
		local_addr,
		start: Instant::now(),
		raw_peer_addr: None,
	});
	let req = ::http::Request::builder()
		.uri("http://localhost/test?api_key=query-secret")
		.header("authorization", "Bearer auth-secret")
		.header("cookie", "session=cookie-secret")
		.header("x-api-key", "header-secret")
		.body(http::Body::empty())
		.unwrap();
	let response = Box::pin(proxy.proxy(Arc::new(connection), req)).await;
	assert_eq!(response.status(), StatusCode::OK);
	assert_eq!(response.headers()["set-cookie"], "session=response-secret");
	assert_eq!(http::read_resp_body(response).await.unwrap(), "ok");
	let forwarded = server.await.unwrap();
	for secret in [
		"query-secret",
		"auth-secret",
		"cookie-secret",
		"header-secret",
	] {
		assert!(forwarded.contains(secret), "missing forwarded {secret}");
	}
	let logs = String::from_utf8(output.0.lock().unwrap().clone()).unwrap();
	assert!(logs.contains("selected route"));
	for secret in [
		"query-secret",
		"auth-secret",
		"cookie-secret",
		"header-secret",
		"response-secret",
	] {
		assert!(
			!logs.contains(secret),
			"credential leaked into log: {secret}"
		);
	}
}

#[test]
fn tunnel_debug_redacts_proxy_credentials() {
	let tunnel = crate::client::TunnelConfig {
		target: crate::types::agent::Target::from(("localhost", 8080)),
		transport: Box::new(crate::client::Transport::default()),
		token: Some("Basic proxy-secret".parse().unwrap()),
	};
	let formatted = format!("{tunnel:?}");
	assert!(formatted.contains("[REDACTED]"));
	assert!(!formatted.contains("proxy-secret"));
}
