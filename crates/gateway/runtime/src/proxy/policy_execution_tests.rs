use super::*;
use gateway_protocol_core::execution::BoundHttpExecution;
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::sync::Notify;

pub(crate) struct Server {
	pub address: SocketAddr,
	pub calls: Arc<AtomicUsize>,
	pub started: Arc<Notify>,
	task: tokio::task::JoinHandle<()>,
}
impl Drop for Server {
	fn drop(&mut self) {
		self.task.abort();
	}
}
impl Server {
	pub async fn new(body: &'static str) -> Self {
		let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
		let address = listener.local_addr().unwrap();
		let calls = Arc::new(AtomicUsize::new(0));
		let started = Arc::new(Notify::new());
		let task = tokio::spawn({
			let calls = calls.clone();
			let started = started.clone();
			async move {
				let mut connections = tokio::task::JoinSet::new();
				loop {
					tokio::select! {
						accepted = listener.accept() => {
							let (socket, _) = accepted.unwrap();
							let calls = calls.clone(); let started = started.clone();
							connections.spawn(async move {
								let service = hyper::service::service_fn(move |req: ::http::Request<hyper::body::Incoming>| {
									calls.fetch_add(1, Ordering::SeqCst);
									started.notify_one();
									async move {
										if req.uri().path() == "/hold" { std::future::pending::<()>().await; }
										Ok::<_, std::convert::Infallible>(::http::Response::builder().header("content-type", "application/json").body(http_body_util::Full::new(Bytes::from_static(body.as_bytes()))).unwrap())
									}
								});
								let _ = hyper::server::conn::http1::Builder::new().serve_connection(TokioIo::new(socket), service).await;
							});
						},
						Some(_) = connections.join_next() => {},
					}
				}
			}
		});
		Self {
			address,
			calls,
			started,
			task,
		}
	}
	pub fn target(&self) -> SimpleBackendReference {
		SimpleBackendReference::InlineBackend(Target::Address(self.address))
	}
}

pub(crate) fn inputs(allowed: &[SocketAddr]) -> Arc<RuntimeContext> {
	let mut config = crate::config::parse_config("{}".into(), None).unwrap();
	config.dependency_egress = Some(serde_json::from_value(serde_json::json!({
		"requireTls":false,"destinations":{"guardrail":allowed.iter().map(ToString::to_string).collect::<Vec<_>>(),
		"oidc":allowed.iter().map(ToString::to_string).collect::<Vec<_>>()}
	})).unwrap());
	let mut registry = prometheus_client::registry::Registry::default();
	let metrics = Arc::new(crate::telemetry::metrics::Metrics::new(
		&mut registry,
		config.metrics.excluded_metrics.clone(),
	));
	let upstream = client::Client::new(
		&config.dns,
		None,
		config.backend.clone(),
		Some(metrics.clone()),
	);
	Arc::new(RuntimeContext {
		cfg: Arc::new(config),
		stores: Default::default(),
		upstream,
		metrics,
		admin: None,
		ca: None,
		guardrails: None,
		vehicle_state: Default::default(),
		circuit_breakers: None,
	})
}
fn request(path: &str) -> Request {
	::http::Request::builder()
		.uri(path)
		.body(http::Body::empty())
		.unwrap()
}

#[tokio::test]
async fn bound_port_and_previous_host_path_agree_on_allowed_and_foreign_targets() {
	let allowed = Server::new("{}").await;
	let foreign = Server::new("{}").await;
	let inputs = inputs(&[allowed.address]);
	let outbound = Some(OutboundCallLabels {
		kind: OutboundCallKind::Policy,
		subtype: OutboundCallSubtype::Guardrail,
	});
	let previous = RuntimePolicyExecutor {
		inputs: inputs.clone(),
		outbound,
	};
	let client = PolicyClient::new(inputs)
		.with_outbound(OutboundCallKind::Policy, OutboundCallSubtype::Guardrail);
	for server in [&allowed, &foreign] {
		let old = previous
			.call_reference(request("/"), &server.target())
			.await;
		let new = client
			.bind_reference(&server.target(), &[])
			.execute(request("http://untrusted.invalid/wire-authority"))
			.await;
		if server.address == allowed.address {
			assert_eq!(old.unwrap().status(), StatusCode::OK);
			assert_eq!(new.unwrap().status(), StatusCode::OK);
		} else {
			assert!(matches!(old, Err(ProxyError::AuthorizationFailed)));
			assert!(matches!(new, Err(ProxyError::AuthorizationFailed)));
		}
	}
	assert_eq!(allowed.calls.load(Ordering::SeqCst), 2);
	assert_eq!(foreign.calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
#[cfg(feature = "gateway-llm")]
async fn webhook_consumer_uses_bound_port_for_success_and_egress_denial() {
	let server = Server::new(r#"{"action":{"reason":"ok"}}"#).await;
	for allowed in [true, false] {
		let allowed_targets = if allowed {
			vec![server.address]
		} else {
			vec![]
		};
		let execution = PolicyClient::new(inputs(&allowed_targets))
			.with_outbound(OutboundCallKind::Policy, OutboundCallSubtype::Guardrail)
			.bind_reference(&server.target(), &[]);
		let result =
			crate::llm::policy::webhook::send_request(&execution, &HeaderMap::new(), vec![]).await;
		assert_eq!(result.is_ok(), allowed);
	}
	assert_eq!(server.calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn dropping_bound_execution_does_not_replay_an_uncertain_request() {
	let server = Server::new("{}").await;
	let execution = PolicyClient::new(inputs(&[server.address]))
		.with_outbound(OutboundCallKind::Policy, OutboundCallSubtype::Guardrail)
		.bind_reference(&server.target(), &[]);
	let mut call = execution.execute(request("/hold"));
	tokio::select! {
		_ = server.started.notified() => {},
		result = &mut call => panic!("upstream should remain pending: {result:?}"),
		_ = tokio::time::sleep(std::time::Duration::from_secs(5)) => panic!("dispatch did not reach upstream"),
	}
	drop(call);
	let response = execution
		.execute(request("/after-cancellation"))
		.await
		.unwrap();
	assert_eq!(response.status(), StatusCode::OK);
	assert_eq!(server.calls.load(Ordering::SeqCst), 2);
}

#[test]
fn network_selection_cannot_represent_protocol_or_admin_execution() {
	use super::super::policy_client::NetworkBackend;
	let name = ResourceName::new("internal".into(), "".into());
	assert!(NetworkBackend::try_from(Backend::Internal(name, InternalBackend::Forward)).is_err());
	fn send_sync<T: Send + Sync>() {}
	send_sync::<PolicyClient>();
	send_sync::<super::super::policy_client::BoundDependency>();
}
