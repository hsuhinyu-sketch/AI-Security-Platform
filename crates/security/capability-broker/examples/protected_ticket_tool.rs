//! Local side-effect backend, not a UI/demo event generator. The listener is
//! loopback-only; a nonlocal deployment must terminate authenticated TLS first.
use axum::{
	extract::{Request, State},
	http::StatusCode,
	middleware::{self, Next},
	response::{IntoResponse, Response},
};
use security_audit::StateJournalConfig;
use security_capability_broker::{
	RemoteCapabilityConsumerConfig,
	ticket_backend::{DurableTicketTool, VerifiedToolGateway},
};
use std::{path::PathBuf, sync::Arc};
use subtle::ConstantTimeEq;

async fn gateway_transport(
	State(secret): State<Arc<String>>,
	mut request: Request,
	next: Next,
) -> Response {
	let header = request
		.headers()
		.get_all("authorization")
		.iter()
		.take(2)
		.collect::<Vec<_>>();
	let supplied = (header.len() == 1)
		.then(|| header[0].to_str().ok())
		.flatten()
		.and_then(|v| v.strip_prefix("Bearer "));
	let authenticated =
		supplied.is_some_and(|supplied| bool::from(supplied.as_bytes().ct_eq(secret.as_bytes())));
	if !authenticated {
		return StatusCode::FORBIDDEN.into_response();
	}
	request.headers_mut().remove("authorization");
	request
		.extensions_mut()
		.insert(VerifiedToolGateway("gateway-local".into()));
	next.run(request).await
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
	let directory = PathBuf::from(std::env::var("AISP_TICKET_DIRECTORY")?);
	let secret = std::env::var("AISP_TOOL_GATEWAY_TOKEN")?;
	if secret.len() != 64 || !secret.bytes().all(|b| b.is_ascii_hexdigit()) {
		return Err(
			std::io::Error::other(
				"AISP_TOOL_GATEWAY_TOKEN must be 32 random bytes encoded as 64 hex digits",
			)
			.into(),
		);
	}
	// Construct/drop the blocking HTTPS client outside the async runtime.
	let consumer: RemoteCapabilityConsumerConfig = serde_json::from_value(serde_json::json!({
		"consumeEndpoint":std::env::var("AISP_BROKER_CONSUME_ENDPOINT")?,
		"identityPemFile":std::env::var("AISP_TOOL_IDENTITY_PEM")?,
		"rootCaPemFile":std::env::var("AISP_BROKER_CA_PEM")?,
		"timeoutMillis":1000
	}))?;
	let backend = DurableTicketTool::open(
		&directory.join("operations.jsonl"),
		&StateJournalConfig {
			path: directory.join("tickets.jsonl"),
			max_bytes: 16 * 1024 * 1024,
		},
		1024,
		"gateway-local".into(),
		Arc::new(
			consumer
				.consumer()
				.map_err(|_| std::io::Error::other("unable to initialize broker consumer"))?,
		),
	)
	.map_err(std::io::Error::other)?;
	let router = backend
		.clone()
		.router()
		.route_layer(middleware::from_fn_with_state(
			Arc::new(secret),
			gateway_transport,
		));
	let port = std::env::var("AISP_TICKET_PORT")
		.unwrap_or_else(|_| "8089".into())
		.parse::<u16>()?;
	let runtime = tokio::runtime::Builder::new_multi_thread()
		.worker_threads(2)
		.max_blocking_threads(16)
		.enable_all()
		.build()?;
	let result = runtime.block_on(async move {
		let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, port)).await?;
		axum::serve(listener, router)
			.with_graceful_shutdown(async {
				let _ = tokio::signal::ctrl_c().await;
			})
			.await
	});
	drop(runtime);
	drop(backend);
	result?;
	Ok(())
}
