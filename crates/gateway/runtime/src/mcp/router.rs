use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::response::Response;
use platform_core::prelude::{AssertSize, Strng};

use crate::http::authorization::RuleSets;
use crate::http::sessionpersistence::Encoder;
use crate::http::*;
use crate::mcp::handler::RelayInputs;
use crate::mcp::session::SessionManager;
use crate::mcp::sse::LegacySSEService;
use crate::mcp::streamablehttp::{StreamableHttpServerConfig, StreamableHttpService};
use crate::mcp::{FailureMode, MCPInfo, McpAuthorizationSet, auth};
use crate::proxy::ProxyError;
use crate::proxy::httpproxy::{MustSnapshot, PolicyClient};
use crate::store::{BackendPolicies, Stores};
use crate::telemetry::log::RequestLog;
use crate::types::agent::{
	BackendTargetRef, McpBackend, McpTargetSpec, ResourceName, SimpleBackend, SimpleBackendReference,
};
use crate::{cel, mcp};

#[derive(Debug, Clone)]
pub struct App {
	state: Stores,
	session: Arc<SessionManager>,
	pub(super) closed: tokio_util::sync::CancellationToken,
}

impl App {
	pub fn new(state: Stores, encoder: Encoder) -> Self {
		let session = crate::mcp::session::SessionManager::new(encoder);
		Self {
			state,
			session,
			closed: Default::default(),
		}
	}

	pub(super) fn shutdown(&self) {
		self.closed.cancel();
		self.session.shutdown();
	}

	pub fn should_passthrough(
		&self,
		backend_policies: &BackendPolicies,
		backend: &McpBackend,
		req: &Request,
	) -> Option<SimpleBackendReference> {
		if backend.targets.len() != 1 {
			return None;
		}

		if backend_policies.mcp_authentication.is_some() {
			return None;
		}
		if !req.uri().path().contains("/.well-known/") {
			return None;
		}
		match backend.targets.first().map(|t| &t.spec) {
			Some(McpTargetSpec::Mcp(s)) => Some(s.backend.clone()),
			Some(McpTargetSpec::Sse(s)) => Some(s.backend.clone()),
			_ => None,
		}
	}

	#[allow(clippy::too_many_arguments)]
	pub async fn serve(
		&self,
		pi: impl crate::IntoRuntimeContext,
		backend_group_name: ResourceName,
		backend: McpBackend,
		backend_policies: BackendPolicies,
		mut req: MustSnapshot<'_>,
		mut log: &mut RequestLog,
	) -> Result<Response, ProxyError> {
		let pi = pi.into_runtime_context();
		if self.closed.is_cancelled() {
			return Err(ProxyError::MCP(mcp::Error::UnknownSession));
		}

		let backends = {
			let binds = self.state.read_binds();
			let nt = backend
				.targets
				.iter()
				.map(|t| {
					let be = t
						.spec
						.backend()
						.map(|b| crate::proxy::resolve_simple_backend_with_policies(b, &pi))
						.transpose()?;
					let inline_pols = be.as_ref().map(|pol| pol.inline_policies.as_slice());
					let sub_backend_target = BackendTargetRef::Backend {
						name: backend_group_name.name.as_ref(),
						namespace: backend_group_name.namespace.as_ref(),
						section: Some(t.name.as_ref()),
					};
					let backend_policies = backend_policies
						.clone()
						.merge(binds.sub_backend_policies(sub_backend_target, inline_pols));
					tracing::trace!("merged policies {:?}", backend_policies);
					Ok::<_, ProxyError>(Arc::new(McpTarget {
						name: t.name.clone(),
						spec: t.spec.clone(),
						backend: be.map(|b| b.backend),
						backend_policies,
						always_use_prefix: backend.always_use_prefix,
					}))
				})
				.collect::<Result<Vec<_>, _>>()?;

			McpBackendGroup {
				targets: nt,
				stateful: backend.stateful,
				failure_mode: backend.failure_mode,
				session_idle_ttl: backend.session_idle_ttl,
			}
		};
		let sessions = self.session.clone();
		sessions.ensure_idle_running();
		let client = PolicyClient::new(pi.clone());
		let authorization_policies = backend_policies
			.mcp_authorization
			.unwrap_or_else(|| McpAuthorizationSet::new(RuleSets::from(Vec::new())));
		let authn = backend_policies.mcp_authentication;
		let mcp_guardrails = backend_policies.mcp_guardrails.clone();
		let security_pipeline = backend_policies.security_pipeline.clone();
		let security_audit = backend_policies.security_audit.clone();

		// Store an empty value, we will populate each field async
		let logy = log.mcp_status.clone();
		logy.store(Some(MCPInfo::default()));
		req.extensions_mut().insert(logy);
		let tracer = log.span_writer();
		req.extensions_mut().insert(tracer);

		authorization_policies.register(log.cel.ctx());
		log.cel.ctx().maybe_buffer_request_body(&mut req).await;

		// `response` is not valid here, since we run authz first
		// MCP context is added later. The context is inserted after
		// authentication so it can include verified claims

		// Take a request snapshot before authentication can mutate or partially consume the
		// request. If authentication lets the request continue, the normal snapshot below
		// replaces this with the post-authentication request state.
		Self::snapshot_request_without_clearing_extensions(&mut req, log);
		if let Some(auth) = authn.as_ref()
			&& let Some(resp) = auth::enforce_authentication(&mut req, auth, &client).await?
		{
			return Ok(resp);
		}

		// MCP requires CEL execution after the snapshot so we do not clear extensions
		if req
			.headers()
			.contains_key(crate::execution_budget::mcp_task_cleanup::HEADER)
			&& !security_audit
				.as_ref()
				.is_some_and(|c| c.execution_budget.is_some())
		{
			return Err(ProxyError::AuthorizationFailed);
		}
		if let Some(config) = &security_audit {
			if config.execution_budget.is_some() {
				if config.mcp_sessions.is_none()
					|| backends
						.targets
						.iter()
						.any(|t| !matches!(t.spec, McpTargetSpec::Mcp(_)))
				{
					return Err(ProxyError::AuthorizationFailed);
				}
				if crate::execution_budget::is_control_path(req.uri().path()) {
					let req = req.take_and_snapshot_without_clearing_extensions(Some(&mut log))?;
					return Box::pin(crate::execution_budget::control(config, req)).await;
				}
				if req
					.headers()
					.contains_key(crate::execution_budget::mcp_task_cleanup::HEADER)
				{
					Box::pin(crate::execution_budget::mcp_task_cleanup::prepare(
						config, &mut req,
					))
					.await?;
				}
				crate::execution_budget::prepare(config, &mut req)?;
			}
		}
		if security_audit.as_ref().is_some_and(|c| {
			(c.cross_component.is_some() || c.execution_budget.is_some()) && c.mcp_sessions.is_none()
		}) {
			let identity = crate::security::identity_from_extensions(req.extensions());
			let action = security_pipeline::mcp_session_for_identity(
				crate::security::request_id(req.extensions_mut()),
				identity,
				"use",
				"mcp-gateway",
			);
			return Err(super::session_security::deny(
				&action,
				"cross-component-requires-session-protection",
			));
		}
		if security_audit
			.as_ref()
			.is_some_and(|c| c.mcp_sessions.is_some())
		{
			let targets = backends
				.targets
				.iter()
				.map(|t| (&t.name, format!("{:?}", t.spec), format!("{:?}", t.backend)))
				.collect::<Vec<_>>();
			let scope = serde_json::to_string(&(
				&backend_group_name,
				&log.bind_name,
				&log.listener_name,
				&log.route_name,
				req.uri().authority().map(|a| a.as_str()),
				req.uri().path_and_query().map(|p| p.as_str()),
				targets,
			))
			.expect("scope serializes");
			req
				.extensions_mut()
				.insert(super::session_security::SessionScope(
					super::session_security::digest(&scope),
				));
		}
		let req = req.take_and_snapshot_without_clearing_extensions(Some(&mut log))?;
		let execution = req
			.extensions()
			.get::<crate::execution_budget::ExecutionScope>()
			.cloned()
			.map(Box::new);
		let task_cleanup = req
			.extensions()
			.get::<crate::execution_budget::mcp_task_cleanup::Scope>()
			.cloned()
			.map(Box::new);
		if log.request_processing_duration.is_none() {
			// This is a bit inaccurate but the best we can do for the MCP path without very invasive changes.
			log.request_processing_duration = Some(log.request_processing_start.elapsed());
		}
		let upstream_start = Instant::now();
		let serve = async {
			if req.uri().path() == "/sse" {
				// Legacy handling
				// Assume this is streamable HTTP otherwise
				let sse = LegacySSEService::new(sessions);
				Box::pin(
					sse
						.handle(
							req,
							RelayInputs {
								backend: backends.clone(),
								policies: authorization_policies.clone(),
								mcp_guardrails: mcp_guardrails.clone(),
								security_pipeline: security_pipeline.clone(),
								security_audit: security_audit.clone(),
								client: client.clone(),
							},
						)
						.assert_size::<{ 20 * 1024 }>(),
				)
				.await
			} else {
				let streamable = StreamableHttpService::new(
					sessions,
					StreamableHttpServerConfig {
						stateful_mode: backend.stateful,
					},
				);
				Box::pin(
					streamable
						.handle(
							req,
							RelayInputs {
								backend: backends.clone(),
								policies: authorization_policies.clone(),
								mcp_guardrails: mcp_guardrails.clone(),
								security_pipeline: security_pipeline.clone(),
								security_audit: security_audit.clone(),
								client: client.clone(),
							},
						)
						.assert_size::<{ 4 * 1024 }>(),
				)
				.await
			}
		};
		let mut response = if let Some(scope) = &task_cleanup {
			Box::pin(scope.run(serve)).await?
		} else if let Some(scope) = &execution {
			Box::pin(scope.run(serve)).await?
		} else {
			serve.await
		};
		let upstream_end = Instant::now();
		// This aggregates the total time; no per-backend timings for fanout.
		log.upstream_duration = Some(upstream_end - upstream_start);
		if response.is_ok() {
			log.response_processing_start = Some(upstream_end);
		}
		if let Ok(response) = response.as_mut() {
			response
				.extensions_mut()
				.insert(cel::ProxyContext::from_std_durations(
					log.request_processing_duration,
					log.upstream_duration,
					log.response_processing_duration,
				));
		}
		response.map(|response| {
			if let Some(scope) = &task_cleanup {
				scope.protect(response)
			} else {
				match &execution {
					Some(scope) => crate::execution_budget::protect_output(response, scope),
					None => response,
				}
			}
		})
	}

	fn snapshot_request_without_clearing_extensions(
		req: &mut MustSnapshot<'_>,
		log: &mut RequestLog,
	) {
		log.request_snapshot = log
			.cel
			.cel_context
			.maybe_snapshot_request(req, false)
			.map(Arc::new);
	}
}

#[derive(Debug, Clone)]
pub struct McpBackendGroup {
	pub targets: Vec<Arc<McpTarget>>,
	pub stateful: bool,
	pub failure_mode: FailureMode,
	pub session_idle_ttl: Duration,
}

impl Default for McpBackendGroup {
	fn default() -> Self {
		Self {
			targets: vec![],
			stateful: true,
			failure_mode: crate::mcp::FailureMode::default(),
			session_idle_ttl: mcp::DEFAULT_SESSION_IDLE_TTL,
		}
	}
}

#[derive(Debug)]
pub struct McpTarget {
	pub name: Strng,
	pub spec: crate::types::agent::McpTargetSpec,
	pub backend_policies: BackendPolicies,
	pub backend: Option<SimpleBackend>,
	pub always_use_prefix: bool,
}
