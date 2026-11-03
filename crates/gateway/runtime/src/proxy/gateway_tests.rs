use super::*;
use crate::runtime::services::ProtocolServices;
use crate::types::agent::{Bind, BindMode};
use std::net::{Shutdown, TcpListener};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn context() -> Arc<RuntimeContext> {
	let mut cfg = crate::config::parse_config("{}".into(), None).unwrap();
	cfg.termination_min_deadline = Duration::ZERO;
	cfg.termination_max_deadline = Duration::from_millis(100);
	let mut registry = prometheus_client::registry::Registry::default();
	let metrics = Arc::new(crate::telemetry::metrics::Metrics::new(
		&mut registry,
		cfg.metrics.excluded_metrics.clone(),
	));
	let upstream = client::Client::new(&cfg.dns, None, cfg.backend.clone(), Some(metrics.clone()));
	Arc::new(RuntimeContext {
		cfg: Arc::new(cfg),
		stores: Default::default(),
		metrics,
		upstream,
		admin: None,
		ca: None,
		guardrails: None,
		vehicle_state: Default::default(),
		circuit_breakers: None,
	})
}

fn services(pi: &RuntimeContext) -> ProtocolServices {
	ProtocolServices::new(
		#[cfg(feature = "gateway-mcp")]
		crate::mcp::Service::new(pi.stores.clone(), pi.cfg.session_encoder.clone()),
		#[cfg(feature = "gateway-llm")]
		crate::llm::cost::CatalogService::from_catalog(crate::llm::cost::ModelCatalog::empty()),
	)
}

fn bind(address: SocketAddr) -> Arc<Bind> {
	Arc::new(Bind {
		key: strng::new("lifecycle-test"),
		address,
		protocol: BindProtocol::http,
		tunnel_protocol: TunnelProtocol::Direct,
		mode: BindMode::Standard,
		listeners: Default::default(),
	})
}

fn socket(address: SocketAddr, reuse: bool) -> TcpListener {
	let socket = socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::STREAM, None).unwrap();
	#[cfg(unix)]
	socket.set_reuse_port(reuse).unwrap();
	socket.set_reuse_address(true).unwrap();
	socket.bind(&address.into()).unwrap();
	socket.listen(32).unwrap();
	socket.set_nonblocking(true).unwrap();
	socket.into()
}

async fn wait_ready(ready: &Ready, expected: bool) {
	let mut rx = ready.subscribe();
	tokio::time::timeout(
		Duration::from_secs(5),
		rx.wait_for(|value| *value == expected),
	)
	.await
	.unwrap()
	.unwrap();
	assert_eq!(ready.pending().is_empty(), expected);
}

async fn stop(tasks: ListenerTasks) {
	tasks.cancel.cancel();
	tokio::time::timeout(Duration::from_secs(5), tasks.join())
		.await
		.unwrap();
}

#[tokio::test]
async fn single_listener_removal_releases_port() {
	let pi = context();
	let services = services(&pi);
	let (_trigger, drain) = drain::new();
	let listener = socket("127.0.0.1:0".parse().unwrap(), false);
	let addr = listener.local_addr().unwrap();
	let ready = Ready::new();
	let tasks = ListenerTasks::start(
		pi,
		services.handles(),
		drain,
		bind(addr),
		BindListeners::Single(listener),
		ready.clone(),
	);
	wait_ready(&ready, true).await;
	stop(tasks).await;
	let _rebound = socket(addr, false);
	assert!(ready.pending().is_empty());
}

#[tokio::test]
async fn per_core_removal_joins_all_threads_and_releases_port() {
	let pi = context();
	let services = services(&pi);
	let (_trigger, drain) = drain::new();
	let cores = core_affinity::get_core_ids().unwrap();
	assert!(!cores.is_empty());
	let mut listeners = HashMap::new();
	let first = socket("127.0.0.1:0".parse().unwrap(), true);
	let addr = first.local_addr().unwrap();
	listeners.insert(cores[0], first);
	for core in cores.into_iter().skip(1).take(1) {
		listeners.insert(core, socket(addr, true));
	}
	let ready = Ready::new();
	let tasks = ListenerTasks::start(
		pi,
		services.handles(),
		drain,
		bind(addr),
		BindListeners::PerCore(listeners),
		ready.clone(),
	);
	wait_ready(&ready, true).await;
	stop(tasks).await;
	// Exclusive bind proves that every SO_REUSEPORT socket was closed.
	let _rebound = socket(addr, false);
	assert!(ready.pending().is_empty());
}

#[tokio::test]
async fn affinity_failure_blocks_readiness_until_bind_removal() {
	let available = core_affinity::get_core_ids().unwrap();
	let unavailable = (0..1024)
		.find(|id| !available.iter().any(|core| core.id == *id))
		.unwrap();
	let pi = context();
	let services = services(&pi);
	let (_trigger, drain) = drain::new();
	let listener = socket("127.0.0.1:0".parse().unwrap(), true);
	let addr = listener.local_addr().unwrap();
	let ready = Ready::new();
	let tasks = ListenerTasks::start(
		pi,
		services.handles(),
		drain,
		bind(addr),
		BindListeners::PerCore(HashMap::from([(
			core_affinity::CoreId { id: unavailable },
			listener,
		)])),
		ready.clone(),
	);
	// Wait for the failed thread to close its socket; readiness must stay blocked.
	let rebound = tokio::time::timeout(Duration::from_secs(5), async {
		loop {
			if let Ok(listener) = TcpListener::bind(addr) {
				break listener;
			}
			tokio::time::sleep(Duration::from_millis(5)).await;
		}
	})
	.await
	.unwrap();
	assert!(!ready.pending().is_empty());
	stop(tasks).await;
	assert!(ready.pending().is_empty());
	drop(rebound);
}

#[tokio::test]
async fn empty_per_core_set_is_not_ready() {
	let pi = context();
	let services = services(&pi);
	let (_trigger, drain) = drain::new();
	let ready = Ready::new();
	let tasks = ListenerTasks::start(
		pi,
		services.handles(),
		drain,
		bind("127.0.0.1:1".parse().unwrap()),
		BindListeners::PerCore(HashMap::new()),
		ready.clone(),
	);
	assert!(!ready.pending().is_empty());
	stop(tasks).await;
	assert!(ready.pending().is_empty());
}

#[cfg(target_os = "linux")]
async fn fatal_accept(per_core: bool) {
	let pi = context();
	let services = services(&pi);
	let (_trigger, drain) = drain::new();
	let listener = socket("127.0.0.1:0".parse().unwrap(), per_core);
	let control = listener.try_clone().unwrap();
	let addr = listener.local_addr().unwrap();
	let listeners = if per_core {
		BindListeners::PerCore(HashMap::from([(
			core_affinity::get_core_ids().unwrap()[0],
			listener,
		)]))
	} else {
		BindListeners::Single(listener)
	};
	let ready = Ready::new();
	let tasks = ListenerTasks::start(
		pi,
		services.handles(),
		drain,
		bind(addr),
		listeners,
		ready.clone(),
	);
	wait_ready(&ready, true).await;
	// Linux returns EINVAL from accept after shutting down a listening socket.
	// Exercise the real accept error without closing a borrowed file descriptor.
	socket2::SockRef::from(&control)
		.shutdown(Shutdown::Both)
		.unwrap();
	wait_ready(&ready, false).await;
	drop(control);
	assert!(
		ready
			.pending()
			.iter()
			.any(|name| name.contains("lifecycle-test"))
	);
	stop(tasks).await;
	assert!(ready.pending().is_empty());
	let _rebound = socket(addr, false);
}

#[tokio::test]
#[cfg(target_os = "linux")]
async fn fatal_accept_blocks_single_listener_readiness() {
	fatal_accept(false).await;
}

#[tokio::test]
#[cfg(target_os = "linux")]
async fn fatal_accept_blocks_per_core_listener_readiness() {
	fatal_accept(true).await;
}

#[tokio::test]
async fn host_registers_initial_listeners_before_readiness_and_removes_them() {
	let pi = context();
	let services = services(&pi);
	let binding = bind("127.0.0.1:0".parse().unwrap());
	pi.stores.binds.write().insert_bind((*binding).clone());
	let ready = Ready::new();
	let startup = ready.register_task("agentgateway");
	let (trigger, drain) = drain::new();
	let gateway = Gateway::with_services(pi.clone(), services, drain);
	let host = tokio::spawn(gateway.run_with_readiness(ready.clone(), startup));
	wait_ready(&ready, true).await;
	let addr = pi.stores.binds.read().bind(&binding.key).unwrap().address;
	pi.stores.binds.write().remove_bind(binding.key.clone());
	tokio::time::timeout(Duration::from_secs(5), async {
		loop {
			if let Ok(listener) = TcpListener::bind(addr) {
				break listener;
			}
			tokio::time::sleep(Duration::from_millis(5)).await;
		}
	})
	.await
	.unwrap();
	tokio::time::timeout(
		Duration::from_secs(5),
		trigger.start_drain_and_wait(drain::DrainMode::Graceful),
	)
	.await
	.unwrap();
	host.await.unwrap();
}

#[tokio::test]
async fn per_core_graceful_shutdown_finishes_with_open_connection() {
	let pi = context();
	let services = services(&pi);
	let (trigger, drain) = drain::new();
	let listener = socket("127.0.0.1:0".parse().unwrap(), true);
	let addr = listener.local_addr().unwrap();
	let ready = Ready::new();
	let tasks = ListenerTasks::start(
		pi,
		services.handles(),
		drain,
		bind(addr),
		BindListeners::PerCore(HashMap::from([(
			core_affinity::get_core_ids().unwrap()[0],
			listener,
		)])),
		ready.clone(),
	);
	wait_ready(&ready, true).await;
	let mut connection = tokio::net::TcpStream::connect(addr).await.unwrap();
	connection
		.write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
		.await
		.unwrap();
	let mut response = [0; 4096];
	let count = tokio::time::timeout(Duration::from_secs(5), connection.read(&mut response))
		.await
		.unwrap()
		.unwrap();
	assert!(
		response[..count].starts_with(b"HTTP/1.1"),
		"listener must accept and handle the connection before shutdown"
	);
	tokio::time::timeout(Duration::from_secs(5), async {
		tokio::join!(
			trigger.start_drain_and_wait(drain::DrainMode::Graceful),
			tasks.join()
		);
	})
	.await
	.unwrap();
	let _rebound = socket(addr, false);
}

#[tokio::test]
async fn socket_creation_failure_blocks_host_startup_until_removed() {
	let pi = context();
	let services = services(&pi);
	let occupied = socket("127.0.0.1:0".parse().unwrap(), false);
	let binding = bind(occupied.local_addr().unwrap());
	pi.stores.binds.write().insert_bind((*binding).clone());
	let ready = Ready::new();
	let startup = ready.register_task("agentgateway");
	let (trigger, drain) = drain::new();
	let gateway = Gateway::with_services(pi.clone(), services, drain);
	let host = tokio::spawn(gateway.run_with_readiness(ready.clone(), startup));
	tokio::time::timeout(Duration::from_secs(5), async {
		while !ready.pending().contains("bind lifecycle-test") {
			tokio::task::yield_now().await;
		}
	})
	.await
	.unwrap();
	assert!(!*ready.subscribe().borrow());
	pi.stores.binds.write().remove_bind(binding.key.clone());
	wait_ready(&ready, true).await;
	tokio::time::timeout(
		Duration::from_secs(5),
		trigger.start_drain_and_wait(drain::DrainMode::Graceful),
	)
	.await
	.unwrap();
	host.await.unwrap();
}
