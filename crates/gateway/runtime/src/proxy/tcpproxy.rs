#[cfg(feature = "providers-aws")]
use crate::types::agent::Target;
use std::net::SocketAddr;
use std::sync::Arc;

use futures::pin_mut;
use rand::prelude::IndexedRandom;

use crate::cel::SourceContext;
use crate::proxy::httpproxy::BackendCall;
use crate::proxy::{ProxyError, WaypointService, httpproxy};
use crate::store::{BackendPolicies, FrontendPolices, RoutePath};
use crate::telemetry::log;
use crate::telemetry::log::{DropOnLog, RequestLog};
use crate::telemetry::metrics::TCPLabels;
use crate::transport::stream::{Socket, TCPConnectionInfo, TLSConnectionInfo, WaypointTLSInfo};
use crate::types::agent::{
	BackendTrafficPolicy, BindKey, Listener, ListenerProtocol, SimpleBackend, SimpleBackendReference,
	SimpleBackendWithPolicies, TCPRoute, TCPRouteBackend, TCPRouteBackendReference,
	TransportProtocol,
};
use crate::types::discovery::gatewayaddress::Destination;
use crate::types::discovery::{NetworkAddress, WaypointIdentity};
use crate::types::{agent, frontend};
use crate::{RuntimeContext, Stores, *};

#[derive(Clone)]
pub struct TCPProxy {
	pub(super) bind_name: BindKey,
	pub(super) inputs: Arc<RuntimeContext>,
	pub(super) selected_listener: Arc<Listener>,
	#[allow(unused)]
	pub(super) target_address: SocketAddr,
}

impl TCPProxy {
	pub async fn proxy(&self, connection: Socket) {
		let start = platform_core::Timestamp::now();

		let tcp = connection
			.ext::<TCPConnectionInfo>()
			.expect("tcp connection must be set");
		let tls = connection.ext::<TLSConnectionInfo>();
		let unverified_workload = crate::cel::WorkloadContext::from_stores(
			&self.inputs.stores,
			&self.inputs.cfg.network,
			tcp.peer_addr.ip(),
		);
		let src = SourceContext::from_tcp_connection(
			tcp,
			tls.and_then(|t| t.src_identity.clone()),
			unverified_workload,
		);
		let mut log: DropOnLog = RequestLog::new_with_catalog(
			log::CelLogging::new(
				self.inputs.cfg.logging.clone(),
				self.inputs.cfg.metrics.clone(),
			),
			self.inputs.metrics.clone(),
			#[cfg(feature = "gateway-llm")]
			None,
			start,
			tcp.clone(),
		)
		.into();
		// Set source context for TCP logging
		log.with(|l| l.source_context = Some(src));
		let ret = self.proxy_internal(connection, log.as_mut().unwrap()).await;
		if let Err(e) = ret {
			log.with(|l| l.error = Some(e.to_string()));
		}
	}

	async fn proxy_internal(
		&self,
		connection: Socket,
		log: &mut RequestLog,
	) -> Result<(), ProxyError> {
		let frontend_policies = {
			let binds = self.inputs.stores.read_binds();
			let bind_port = binds.bind(&self.bind_name).map(|bind| bind.address.port());
			binds.listener_frontend_policies(
				&self.selected_listener.name,
				bind_port,
				connection
					.ext::<WaypointService>()
					.map(WaypointService::as_policy_ref),
			)
		};

		// Apply frontend policies for access logging (skip tracing for TCP)
		frontend_policies.register_cel_expressions(log.cel.ctx());
		if let Some(lp) = &frontend_policies.access_log {
			httpproxy::apply_logging_policy_to_log(log, lp);
		}

		// Only sniff TLS if: From waypoint AND service port's appProtocol is TLS
		let should_sniff = connection
			.ext::<WaypointTLSInfo>()
			.map(|info| info.should_sniff_tls)
			.unwrap_or(false);

		let connection = if should_sniff {
			Self::sniff_tls_sni(connection, &frontend_policies)
				.await
				.map_err(ProxyError::Processing)?
		} else {
			connection
		};
		if let Some(authz) = frontend_policies.network_authorization.as_ref() {
			authz.apply(
				log
					.source_context
					.as_ref()
					.expect("expected source context"),
			)?;
		}
		log.tls_info = connection.ext::<TLSConnectionInfo>().cloned();
		log.backend_protocol = Some(cel::BackendProtocol::tcp);
		let tcp_labels = TCPLabels {
			bind: Some(&self.bind_name).into(),
			gateway: Some(&self.selected_listener.name.as_gateway_name()).into(),
			listener: self.selected_listener.name.listener_name.clone().into(),
			protocol: if log.tls_info.is_some() {
				TransportProtocol::tls
			} else {
				TransportProtocol::tcp
			},
		};
		self
			.inputs
			.metrics
			.downstream_connection
			.get_or_create(&tcp_labels)
			.inc();
		let sni = log
			.tls_info
			.as_ref()
			.and_then(|tls| tls.server_name.as_deref())
			.map(|s| s.to_string());

		let selected_listener = self.selected_listener.clone();
		let inputs = self.inputs.clone();
		let bind_name = self.bind_name.clone();
		debug!(bind=%bind_name, "route for bind");
		log.bind_name = Some(bind_name.clone());
		log.listener_name = Some(selected_listener.name.clone());
		debug!(bind=%bind_name, listener=%selected_listener.key, "selected listener");

		let selected_route = select_best_route(
			sni.as_deref(),
			selected_listener.clone(),
			&self.inputs.stores,
			&self.inputs.cfg.network,
			self.target_address,
			self.inputs.cfg.self_addr.as_ref(),
		)
		.ok_or(ProxyError::RouteNotFound)?;
		log.route_name = Some(selected_route.name.clone());

		let route_path = RoutePath {
			routes: vec![&selected_route.name],
			service: selected_route.service_key.as_ref(),
			listener: &selected_listener.name,
			route_inlines: vec![&[]],
		};

		debug!(bind=%bind_name, listener=%selected_listener.key, route=%selected_route.key, "selected route");
		let selected_backend =
			select_tcp_backend(selected_route.as_ref()).ok_or(ProxyError::NoValidBackends)?;
		let selected_backend = resolve_backend(selected_backend, self.inputs.as_ref())?;
		let backend_policies = get_backend_policies(
			&self.inputs,
			&selected_backend.backend,
			&selected_backend.inline_policies,
			Some(route_path),
		);

		let hbone_source = connection
			.ext::<WaypointService>()
			.map(|_| crate::client::HboneSourceRole::Waypoint)
			.or(Some(crate::client::HboneSourceRole::Gateway));
		let backend_call = Self::build_backend_call(
			&mut Some(log),
			sni,
			&inputs,
			&selected_backend.backend.backend,
			backend_policies,
			hbone_source,
		)?;

		let bi = selected_backend.backend.backend.backend_info();
		log.endpoint = Some(backend_call.target.clone());
		log.backend_info = Some(bi);

		let transport = crate::proxy::httpproxy::build_transport(
			&inputs,
			&backend_call,
			hbone_source,
			backend_call.backend_policies.backend_tls.clone(),
			backend_call.backend_policies.tunnel.as_ref(),
			// TODO: for TCP we should actually probably do something here: telling it to not use ALPN at all?
			None,
		)
		.await?;

		// export rx/tx bytes on drop
		let mut connection = connection;
		connection.set_transport_metrics(self.inputs.metrics.clone(), tcp_labels);

		inputs
			.upstream
			.call_tcp(client::TCPCall {
				source: connection,
				target: backend_call.target,
				transport,
			})
			.await?;
		Ok(())
	}

	pub fn build_backend_call(
		log: &mut Option<&mut RequestLog>,
		sni: Option<String>,
		inputs: &RuntimeContext,
		selected_backend: &SimpleBackend,
		backend_policies: BackendPolicies,
		hbone_source: Option<crate::client::HboneSourceRole>,
	) -> Result<BackendCall, ProxyError> {
		let backend_call = match &selected_backend {
			SimpleBackend::Service(svc, port) => httpproxy::build_service_call(
				inputs,
				backend_policies.into(),
				log,
				httpproxy::ServiceCallOverride::default(),
				svc,
				port,
				sni.as_deref(),
				hbone_source,
			)?,
			SimpleBackend::Opaque(_, target) => BackendCall::new(target.clone(), backend_policies),
			#[cfg(feature = "providers-aws")]
			SimpleBackend::Aws(_, config) => {
				let default_policies = BackendPolicies {
					backend_tls: Some(http::backendtls::SYSTEM_TRUST.clone()),
					backend_auth: Some(http::auth::BackendAuth::Aws(
						http::auth::AwsAuth::Implicit {
							service_name: None,
							assume_role: None,
							source_credentials_cache: Default::default(),
							assume_role_cache: Default::default(),
						},
					)),
					..Default::default()
				};
				BackendCall::new(
					Target::Hostname(config.get_host().into(), 443),
					default_policies.merge(backend_policies),
				)
			},
			#[cfg(not(feature = "providers-aws"))]
			SimpleBackend::Aws(..) => return Err(ProxyError::AuthorizationFailed),
			SimpleBackend::Invalid => return Err(ProxyError::BackendDoesNotExist),
		};
		Ok(backend_call)
	}

	async fn sniff_tls_sni(raw_stream: Socket, policies: &FrontendPolices) -> anyhow::Result<Socket> {
		let def = frontend::TLS::default();
		let tls_pol = policies.tls.as_ref();
		let to = tls_pol.unwrap_or(&def).handshake_timeout;
		let handshake = async move {
			let (mut ext, counter, inner) = raw_stream.into_parts();
			let inner = Socket::new_rewind(inner);
			let acceptor =
				tokio_rustls::LazyConfigAcceptor::new(rustls::server::Acceptor::default(), inner);
			pin_mut!(acceptor);
			let mut start = acceptor.as_mut().await?;
			let ch = start.client_hello();
			let sni = ch.server_name().unwrap_or_default().to_string();
			start.io.rewind();
			let existing = ext.remove().unwrap_or_default();
			ext.insert(TLSConnectionInfo {
				server_name: Some(sni),
				..existing
			});
			Ok(Socket::from_rewind(ext, counter, start.io))
		};
		tokio::time::timeout(to, handshake).await?
	}
}

fn select_best_route(
	host: Option<&str>,
	listener: Arc<Listener>,
	stores: &Stores,
	network: &Strng,
	dst: SocketAddr,
	self_addr: Option<&WaypointIdentity>,
) -> Option<Arc<TCPRoute>> {
	// TCP matching is much simpler than HTTP.
	// We pick the best matching hostname, else fallback to precedence:
	//
	//  * The oldest Route based on creation timestamp.
	//  * The Route appearing first in alphabetical order by "{namespace}/{name}".

	// Assume matches are ordered already (not true today)

	// Try explicit TCP routes first
	let listener_tcp_routes = {
		let binds = stores.read_binds();
		binds.get_listener_tcp_routes(&listener.key)
	};
	if let Some(listener_tcp_routes) = listener_tcp_routes {
		for hnm in agent::HostnameMatch::all_matches_or_none(host) {
			if let Some(r) = listener_tcp_routes.get_hostname(&hnm) {
				return Some(Arc::new(r.clone()));
			}
		}
	}

	// For HBONE waypoints, check service-keyed routes then fall back to default
	if matches!(listener.protocol, ListenerProtocol::HBONE) {
		let svc = resolve_waypoint_service(stores, network, dst, self_addr)?;

		// When routes are attached to a Service via parentRef, they take priority
		// over listener-attached routes. If service routes exist but none match,
		// the request is rejected (per GAMMA spec).
		let svc_nh = svc.namespaced_hostname();
		let svc_tcp_routes = {
			let binds = stores.read_binds();
			binds.get_service_tcp_routes(&svc_nh)
		};
		if let Some(svc_tcp_routes) = svc_tcp_routes {
			for hnm in agent::HostnameMatch::all_matches(&svc.hostname) {
				// Match port-agnostic routes (service_port == 0) and those scoped to
				// this port; being port-scoped is not itself a precedence tiebreaker.
				if let Some(r) = svc_tcp_routes
					.get_hostname_routes(&hnm)
					.find(|r| r.service_port == 0 || r.service_port == dst.port())
				{
					return Some(Arc::new(r.clone()));
				}
			}
			// GAMMA: service routes exist but none matched -> reject
			return None;
		}

		// No service-keyed routes: generate default passthrough
		return Some(Arc::new(TCPRoute {
			key: strng::literal!("_waypoint-default-tcp"),
			service_key: None,
			service_port: 0,
			name: crate::types::agent::RouteName {
				name: strng::literal!("_waypoint-default-tcp"),
				namespace: svc.namespace.clone(),
				rule_name: None,
				kind: None,
			},
			hostnames: vec![],
			backends: vec![TCPRouteBackendReference {
				weight: 1,
				backend: SimpleBackendReference::Service {
					name: svc.namespaced_hostname(),
					port: dst.port(),
				},
				inline_policies: Vec::new(),
			}],
		}));
	}
	None
}

/// Resolve the waypoint service from a VIP and verify this proxy owns it.
fn resolve_waypoint_service(
	stores: &Stores,
	network: &Strng,
	dst: SocketAddr,
	self_addr: Option<&WaypointIdentity>,
) -> Option<Arc<crate::types::discovery::Service>> {
	let self_id = self_addr.or_else(|| {
		warn!("waypoint requires self address for TCP routing");
		None
	})?;

	let svc = stores
		.read_discovery()
		.services
		.get_by_vip(&NetworkAddress {
			network: network.clone(),
			address: dst.ip(),
		})?;

	let wp = svc.waypoint.as_ref()?;
	let is_ours = match &wp.destination {
		Destination::Address(addr) => {
			let stores_ref = stores.clone();
			self_id.matches_address(addr, |a| {
				let discovery = stores_ref.read_discovery();
				discovery
					.services
					.get_by_vip(a)
					.map(|s| (s.name.clone(), s.namespace.clone()))
			})
		},
		Destination::Hostname(n) => self_id.matches_hostname(n),
	};
	if !is_ours {
		warn!(
			"service {} is meant for waypoint {:?}, but we are {}.{}",
			svc.hostname, wp.destination, self_id.gateway, self_id.namespace
		);
		return None;
	}

	Some(svc)
}

fn select_tcp_backend(route: &TCPRoute) -> Option<TCPRouteBackendReference> {
	route
		.backends
		.choose_weighted(&mut rand::rng(), |b| b.weight)
		.ok()
		.cloned()
}

fn resolve_backend(
	b: TCPRouteBackendReference,
	pi: &RuntimeContext,
) -> Result<TCPRouteBackend, ProxyError> {
	let backend = super::resolve_simple_backend(&b.backend, pi)?;
	Ok(TCPRouteBackend {
		weight: b.weight,
		backend,
		inline_policies: b.inline_policies,
	})
}

pub fn get_backend_policies(
	inputs: &RuntimeContext,
	backend: &SimpleBackendWithPolicies,
	inline_policies: &[BackendTrafficPolicy],
	route_path: Option<RoutePath>,
) -> BackendPolicies {
	inputs.stores.read_binds().backend_policies(
		backend.backend.target(),
		&[&backend.inline_policies, inline_policies],
		route_path,
	)
}
