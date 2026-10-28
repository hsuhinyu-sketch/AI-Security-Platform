use gateway_mcp::execution::FanoutPlan;
use gateway_mcp::merge::MessageStream;
use gateway_mcp::routing::{rewrite_resource_update_message, set_subscription_ack_id};
use gateway_mcp::wire::normalize_outbound_for_protocol;
use std::collections::HashMap;
use std::sync::Arc;

use anyhow::anyhow;
use futures_core::Stream;
use futures_util::StreamExt;
use http::StatusCode;
use http::request::Parts;
use platform_core::prelude::AssertSize;
use platform_core::version::BuildInfo;
use rmcp::ErrorData;
use rmcp::model::{
	CacheScope, ClientNotification, ClientRequest, Implementation, JsonRpcNotification,
	JsonRpcRequest, ProtocolVersion, RequestId, ServerJsonRpcMessage, ServerResult,
};
use tracing::{debug, warn};

use crate::guardrails::{ResponseContext, ToolCallContext};
use crate::http::Response;
use crate::http::sessionpersistence::MCPSession;
use crate::mcp;
use crate::mcp::mergestream::{MergeFn, MergePlan, Messages};
use crate::mcp::rbac::{CelExecWrapper, McpAuthorizationSet};
use crate::mcp::router::McpBackendGroup;
use crate::mcp::streamablehttp::{RequestProtocol, ServerSseMessage};
use crate::mcp::upstream::{IncomingRequestContext, UpstreamError};
use crate::mcp::{ClientError, FailureMode, MCPInfo, mergestream, rbac, upstream};
use crate::proxy::httpproxy::PolicyClient;
use crate::telemetry::log::{AsyncLog, SpanWriteOnDrop, SpanWriter};

#[path = "request.rs"]
mod request;

#[derive(Debug, Clone)]
pub struct Relay {
	upstreams: Arc<upstream::UpstreamGroup>,
	pub policies: McpAuthorizationSet,
	pub(crate) mcp_guardrails: Option<Arc<crate::mcp::guardrails::McpGuardrails>>,
	pub(crate) security_pipeline: Option<crate::types::agent::LegacySecurityPipeline>,
	pub(crate) security_audit: Option<Arc<security_integration_runtime::SecurityConfig>>,
	pub(crate) policy_client: PolicyClient,
}

pub struct RelayInputs {
	pub backend: McpBackendGroup,
	pub policies: McpAuthorizationSet,
	pub mcp_guardrails: Option<Arc<crate::mcp::guardrails::McpGuardrails>>,
	pub security_pipeline: Option<crate::types::agent::LegacySecurityPipeline>,
	pub security_audit: Option<Arc<security_integration_runtime::SecurityConfig>>,
	pub client: PolicyClient,
}

impl RelayInputs {
	pub fn build_new_connections(self) -> Result<Relay, mcp::Error> {
		let r = Relay::new(self.backend, self.policies, self.client)?;
		Ok(Relay {
			mcp_guardrails: self.mcp_guardrails,
			security_pipeline: self.security_pipeline,
			security_audit: self.security_audit,
			..r
		})
	}
}

impl Relay {
	pub fn with_inputs(&self, inputs: RelayInputs) -> Self {
		Self {
			upstreams: self.upstreams.clone(),
			policies: inputs.policies,
			mcp_guardrails: inputs.mcp_guardrails,
			security_pipeline: inputs.security_pipeline,
			security_audit: inputs.security_audit,
			policy_client: inputs.client,
		}
	}

	fn permits_transport(&self, server: &str) -> bool {
		self
			.security_audit
			.as_ref()
			.and_then(|config| config.data_egress.as_ref())
			.is_none_or(|egress| egress.permits_mcp_transport(server))
	}

	fn prepare_notification(
		&self,
		method: &str,
		server: &str,
		ctx: &mut IncomingRequestContext,
	) -> Result<(), UpstreamError> {
		crate::mcp::security::mark_egress(None, server, method, ctx);
		if method == "notifications/initialized" {
			return Ok(());
		}
		let action = ctx
			.extensions_mut()
			.get::<crate::mcp::security::McpEgressContext>()
			.expect("gateway just installed MCP context")
			.action
			.clone();
		self.security().unsupported(&action).map_err(|_| {
			UpstreamError::InvalidRequest("security policy denied unsupported MCP notification".into())
		})?;
		Ok(())
	}

	pub fn new(
		backend: McpBackendGroup,
		policies: McpAuthorizationSet,
		client: PolicyClient,
	) -> Result<Self, mcp::Error> {
		Ok(Self {
			upstreams: Arc::new(upstream::UpstreamGroup::new(client.clone(), backend)?),
			policies,
			mcp_guardrails: None,
			security_pipeline: None,
			security_audit: None,
			policy_client: client,
		})
	}

	fn rewrite_outbound_server_messages(&self, target: &str, stream: Messages) -> Messages {
		let target = target.to_string();
		let default_target_name = self.upstreams.default_target_name.clone();
		stream.map_server_messages(move |message| {
			rewrite_resource_update_message(default_target_name.as_deref(), &target, message)
		})
	}

	pub(crate) fn default_target_name(&self) -> Option<&str> {
		self.upstreams.default_target_name.as_deref()
	}

	pub fn get_sessions(&self) -> Option<Vec<MCPSession>> {
		let mut sessions = Vec::with_capacity(self.upstreams.size());
		for (_, us) in self.upstreams.iter_named() {
			sessions.push(us.get_session_state()?);
		}
		Some(sessions)
	}

	pub fn set_sessions(&self, sessions: Vec<MCPSession>) -> anyhow::Result<()> {
		if sessions.iter().all(|session| session.target_name.is_none()) {
			if sessions.len() != self.upstreams.size() {
				anyhow::bail!(
					"session count {} did not match initialized upstreams {}",
					sessions.len(),
					self.upstreams.size()
				);
			}
			for ((_, us), session) in self.upstreams.iter_named().zip(sessions) {
				us.set_session_id(session.session.as_deref(), session.backend);
			}
			return Ok(());
		}

		if sessions.iter().any(|session| session.target_name.is_none()) {
			anyhow::bail!("mixed keyed and unkeyed MCP session state is unsupported");
		}

		// Target-keyed resume is intentionally strict: if the initialized target set changed,
		// failing the resume is safer than binding persisted session state to the wrong target.
		let mut by_target = HashMap::with_capacity(sessions.len());
		for session in sessions {
			let target_name = session
				.target_name
				.clone()
				.expect("checked all sessions are target-keyed above");
			if by_target.insert(target_name.clone(), session).is_some() {
				anyhow::bail!("duplicate persisted session for target {target_name}");
			}
		}

		if by_target.len() != self.upstreams.size() {
			anyhow::bail!(
				"persisted target count {} did not match initialized upstreams {}",
				by_target.len(),
				self.upstreams.size()
			);
		}

		for (target_name, us) in self.upstreams.iter_named() {
			let session = by_target
				.remove(target_name.as_str())
				.ok_or_else(|| anyhow::anyhow!("missing persisted session for target {target_name}"))?;
			us.set_session_id(session.session.as_deref(), session.backend);
		}
		Ok(())
	}
	pub fn is_multiplexing(&self) -> bool {
		self.upstreams.is_multiplexing
	}

	async fn enforce_vehicle_tool_guardrails(
		&self,
		r: &JsonRpcRequest<ClientRequest>,
	) -> Result<(), UpstreamError> {
		let Some(guardrails) = self.policy_client.guardrails() else {
			return Ok(());
		};
		let ClientRequest::CallToolRequest(ctr) = &r.request else {
			return Ok(());
		};
		let arguments = serde_json::Value::Object(ctr.params.arguments.clone().unwrap_or_default());
		let ctx = ToolCallContext {
			name: ctr.params.name.to_string(),
			arguments,
		};
		let decision = guardrails
			.check_tool_call(&ctx, self.policy_client.vehicle_state())
			.await;
		if decision.is_allowed() {
			return Ok(());
		}

		let _ = decision.to_safety_event("mcp-tool", ctr.params.name.to_string());
		Err(UpstreamError::InvalidRequest(match &decision {
			crate::guardrails::GuardrailDecision::Reject { reason, .. }
			| crate::guardrails::GuardrailDecision::RequireApproval { reason }
			| crate::guardrails::GuardrailDecision::FailSafe { reason }
			| crate::guardrails::GuardrailDecision::Mask { reason, .. }
			| crate::guardrails::GuardrailDecision::Defer { reason } => reason.clone(),
			crate::guardrails::GuardrailDecision::Allow => {
				unreachable!("allow decisions are not rejected")
			},
		}))
	}

	fn security(&self) -> super::security::McpSecurity<'_> {
		super::security::McpSecurity::new(
			self.security_audit.as_deref(),
			self.security_pipeline.as_ref(),
		)
	}

	fn apply_vehicle_response_guardrails<S>(&self, stream: S) -> Messages
	where
		S: Stream<Item = Result<ServerJsonRpcMessage, ClientError>> + Send + 'static,
	{
		let Some(guardrails) = self.policy_client.guardrails().cloned() else {
			return Messages::from_stream(stream);
		};
		let vehicle_state = self.policy_client.vehicle_state().clone();
		Messages::from_stream(stream.then(move |msg| {
			let guardrails = guardrails.clone();
			let vehicle_state = vehicle_state.clone();
			async move {
				let msg = msg?;
				let content = serde_json::to_string(&msg).unwrap_or_default();
				let ctx = ResponseContext {
					content,
					model: "mcp".to_string(),
				};
				let decision = guardrails.check_response(&ctx, &vehicle_state).await;
				if decision.is_allowed() {
					return Ok(msg);
				}
				let _ = decision.to_safety_event("mcp-response", "mcp");
				let reason = match &decision {
					crate::guardrails::GuardrailDecision::Reject { reason, .. }
					| crate::guardrails::GuardrailDecision::RequireApproval { reason }
					| crate::guardrails::GuardrailDecision::FailSafe { reason }
					| crate::guardrails::GuardrailDecision::Mask { reason, .. }
					| crate::guardrails::GuardrailDecision::Defer { reason } => reason.clone(),
					crate::guardrails::GuardrailDecision::Allow => {
						unreachable!("allow decisions are not rejected")
					},
				};
				Err(ClientError::new(anyhow!(reason)))
			}
		}))
	}

	fn build_guardrails_ctx(
		&self,
		r: &JsonRpcRequest<ClientRequest>,
		ctx: &IncomingRequestContext,
		backends: Vec<String>,
	) -> Option<GuardrailsCtx> {
		let ext = self.mcp_guardrails.as_ref()?;
		let method = r.request.method().to_string();
		if !ext.runs_response(&method) {
			// we only need an GuardrailsCtx for response-phase guardrails hooks
			return None;
		}
		Some(GuardrailsCtx {
			ext: ext.clone(),
			method,
			backends,
			client: self.policy_client.clone(),
			req_ctx: Arc::new(ctx.clone()),
		})
	}

	pub(crate) async fn run_guardrails_call_request<P: serde::de::DeserializeOwned>(
		&self,
		ext_ctx: &mut crate::mcp::guardrails::CallRequestCtx<'_>,
		ctx: &mut IncomingRequestContext,
	) -> Result<Option<P>, UpstreamError> {
		use crate::mcp::guardrails::Outcome;
		let Some(ext) = self.mcp_guardrails.as_ref() else {
			return Ok(None);
		};
		let method = ext_ctx.method;
		match crate::mcp::guardrails::run_call_request::<P>(ext, ext_ctx, ctx, &self.policy_client)
			.await
		{
			Outcome::Pass => Ok(None),
			Outcome::Mutated(p) => {
				tracing::debug!(method, "mcpGuardrails: request mutated");
				Ok(Some(p))
			},
			Outcome::Reject(rej) => {
				tracing::debug!(
					method,
					code = rej.code.0,
					message = %rej.message,
					"mcpGuardrails: request rejected",
				);
				Err(UpstreamError::McpGuardrails(rej))
			},
		}
	}

	pub(crate) async fn maybe_run_guardrails_call_request<P>(
		&self,
		backend: &str,
		method: &str,
		params: &mut P,
		ctx: &mut IncomingRequestContext,
	) -> Result<(), UpstreamError>
	where
		P: serde::Serialize + serde::de::DeserializeOwned,
	{
		let Some(ext) = self.mcp_guardrails.as_ref() else {
			return Ok(());
		};
		// Skip the (potentially expensive) params serialization when this method
		// has no request-phase hook configured.
		if !ext.runs_request(method) {
			return Ok(());
		}
		let params_b = serde_json::to_vec(&*params)
			.map_err(|e| UpstreamError::InvalidRequest(format!("serialize {method} params: {e}")))?;
		let backends = [backend.to_string()];
		if let Some(p) = self
			.run_guardrails_call_request::<P>(
				&mut crate::mcp::guardrails::CallRequestCtx {
					backends: &backends,
					method,
					params: Some(params_b.into()),
				},
				ctx,
			)
			.await?
		{
			*params = p;
		}
		Ok(())
	}

	fn merge_plan<F>(plan: F) -> MergePlan
	where
		F: FnOnce(&CelExecWrapper) -> Box<MergeFn> + Send + Sync + 'static,
	{
		Box::new(plan) as MergePlan
	}

	pub fn merge_tools(
		&self,
		request_id: String,
		identity: security_pipeline::GatewayIdentity,
	) -> MergePlan {
		let policies = self.policies.clone();
		let security = self.security_audit.clone();
		let default_target_name = self.upstreams.default_target_name.clone();
		Self::merge_plan(move |cel: &CelExecWrapper| -> Box<MergeFn> {
			let cel = cel.clone();
			Box::new(move |streams| {
				Ok(gateway_mcp::merge::merge_tools(
					streams,
					default_target_name.as_deref(),
					|server_name, tool| {
						// The same order as before: RBAC, then the S2 visibility check,
						// then the multiplexed projection performed by the component.
						policies.validate(
							&rbac::ResourceType::Tool(rbac::ResourceId::new(
								server_name.to_string(),
								tool.name.to_string(),
							)),
							&cel,
						) && security.as_ref().is_none_or(|security| {
							crate::security::evaluate(
								security,
								&security_pipeline::tool_invoke_for_identity(
									format!("{request_id}:{}", tool.name),
									identity.clone(),
									tool.name.to_string(),
								),
							)
							.is_ok()
						})
					},
				))
			})
		})
	}

	pub fn merge_initialize(&self, pv: ProtocolVersion, multiplexing: bool) -> MergePlan {
		let resource_subscribe = self.upstreams.stateful();
		Self::merge_plan(move |_: &CelExecWrapper| -> Box<MergeFn> {
			Box::new(move |results| {
				Ok(
					gateway_mcp::discovery::merge_initialize(
						results,
						pv,
						multiplexing,
						resource_subscribe,
						gateway_implementation(),
					)
					.into(),
				)
			})
		})
	}

	pub fn merge_discover(&self, multiplexing: bool) -> MergePlan {
		let resource_subscribe = self.upstreams.stateful();
		Self::merge_plan(move |_: &CelExecWrapper| -> Box<MergeFn> {
			Box::new(move |results| {
				Ok(
					gateway_mcp::discovery::merge_discover(
						results,
						multiplexing,
						resource_subscribe,
						gateway_implementation(),
					)
					.into(),
				)
			})
		})
	}

	pub fn merge_prompts(
		&self,
		request_id: String,
		identity: security_pipeline::GatewayIdentity,
	) -> MergePlan {
		let policies = self.policies.clone();
		let security = self.security_audit.clone();
		let legacy = self.security_pipeline.clone();
		let default_target_name = self.upstreams.default_target_name.clone();
		Self::merge_plan(move |cel: &CelExecWrapper| -> Box<MergeFn> {
			let cel = cel.clone();
			Box::new(move |streams| {
				Ok(gateway_mcp::merge::merge_prompts(
					streams,
					default_target_name.as_deref(),
					|server_name, prompt| {
						policies.validate(
							&rbac::ResourceType::Prompt(rbac::ResourceId::new(
								server_name.to_string(),
								prompt.name.to_string(),
							)),
							&cel,
						) && super::security::McpSecurity::new(security.as_deref(), legacy.as_ref())
							.visible_object(
								&request_id,
								&identity,
								server_name,
								security_types::ResourceType::McpPrompt,
								&prompt.name,
								"prompts/get",
							)
					},
				))
			})
		})
	}

	pub fn merge_resources(
		&self,
		request_id: String,
		identity: security_pipeline::GatewayIdentity,
	) -> MergePlan {
		let policies = self.policies.clone();
		let security = self.security_audit.clone();
		let legacy = self.security_pipeline.clone();
		let default_target_name = self.upstreams.default_target_name.clone();
		Self::merge_plan(move |cel: &CelExecWrapper| -> Box<MergeFn> {
			let cel = cel.clone();
			Box::new(move |streams| {
				Ok(gateway_mcp::merge::merge_resources(
					streams,
					default_target_name.as_deref(),
					|server_name, resource| {
						policies.validate(
							&rbac::ResourceType::Resource(rbac::ResourceId::new(
								server_name.to_string(),
								resource.uri.to_string(),
							)),
							&cel,
						) && super::security::McpSecurity::new(security.as_deref(), legacy.as_ref())
							.visible_object(
								&request_id,
								&identity,
								server_name,
								security_types::ResourceType::McpResource,
								&resource.uri,
								"resources/read",
							)
					},
				))
			})
		})
	}

	pub fn merge_resource_templates(
		&self,
		request_id: String,
		identity: security_pipeline::GatewayIdentity,
	) -> MergePlan {
		let policies = self.policies.clone();
		let security = self.security_audit.clone();
		let legacy = self.security_pipeline.clone();
		let default_target_name = self.upstreams.default_target_name.clone();
		Self::merge_plan(move |cel: &CelExecWrapper| -> Box<MergeFn> {
			let cel = cel.clone();
			Box::new(move |streams| {
				Ok(gateway_mcp::merge::merge_resource_templates(
					streams,
					default_target_name.as_deref(),
					|server_name, template| {
						policies.validate(
							&rbac::ResourceType::Resource(rbac::ResourceId::new(
								server_name.to_string(),
								template.uri_template.to_string(),
							)),
							&cel,
						) && super::security::McpSecurity::new(security.as_deref(), legacy.as_ref())
							.visible_object(
								&request_id,
								&identity,
								server_name,
								security_types::ResourceType::McpResource,
								&template.uri_template,
								"resources/read",
							)
					},
				))
			})
		})
	}

	pub fn merge_empty(&self) -> MergePlan {
		Self::merge_plan(|_: &CelExecWrapper| -> Box<MergeFn> {
			Box::new(|_| Ok(rmcp::model::ServerResult::empty(())))
		})
	}

	pub fn merge_subscriptions_listen(&self, subscription_id: RequestId) -> MergePlan {
		Self::merge_plan(move |_: &CelExecWrapper| -> Box<MergeFn> {
			Box::new(move |_| Ok(gateway_mcp::merge::subscription_ack(subscription_id)))
		})
	}
	pub(crate) async fn prepare_single(
		&self,
		r: JsonRpcRequest<ClientRequest>,
		mut ctx: IncomingRequestContext,
		service_name: &str,
	) -> Result<Messages, UpstreamError> {
		// The opt-in security contract must not change a transparent gateway's
		// request handling when no platform security has been installed.
		if self.security_audit.is_some() {
			super::session_security::tasks::prepare(
				&r,
				&mut ctx,
				service_name,
				self.mcp_guardrails.is_some(),
			)?;
		}
		self
			.security()
			.authorize_request(&r, &mut ctx, service_name)?;
		// Stateless single-target bootstrap must obey the same server filter as fanout,
		// including transports that never enter the HTTP egress hook (e.g. stdio).
		if !self.permits_transport(service_name) {
			return Err(UpstreamError::InvalidRequest(
				"security policy denied MCP transport".into(),
			));
		}
		self.enforce_vehicle_tool_guardrails(&r).await?;
		crate::mcp::security::mark_egress(Some(&r), service_name, "", &mut ctx);
		crate::execution_budget::bind_mcp_invocation(&r, &mut ctx, service_name)?;
		let task_admission = super::session_security::tasks::bind_budget(&ctx)?;
		let id = r.id.clone();
		let Ok(us) = self.upstreams.get(service_name) else {
			return Err(UpstreamError::InvalidRequest(format!(
				"unknown service {service_name}"
			)));
		};
		let guardrails = self.build_guardrails_ctx(&r, &ctx, vec![service_name.to_string()]);
		let protected_request = r.clone();
		super::session_security::prepare_subscription(&r, &mut ctx, service_name)?;
		let stream = self.rewrite_outbound_server_messages(
			service_name,
			Box::pin(us.generic_stream(r, &ctx).assert_size::<{ 3 * 1024 }>()).await?,
		);
		let stream = super::session_security::tasks::hold_admission(stream, task_admission);
		let stream = self.apply_vehicle_response_guardrails(stream);
		let stream = super::session_security::protect_messages_with_sampling(
			stream,
			&ctx,
			Some(&protected_request),
			service_name,
			#[cfg(feature = "gateway-llm")]
			Some(super::session_security::reverse::sampling::Transport {
				upstreams: self.upstreams.clone(),
				context: ctx.clone(),
			}),
		);
		let stream = crate::execution_budget::record_mcp_result(stream, &ctx, id.clone());

		match guardrails {
			Some(guardrails) => Ok(Messages::from_stream(wrap_with_guardrails(
				stream, guardrails,
			))),
			None => Ok(stream),
		}
	}

	pub async fn send_single(
		&self,
		r: JsonRpcRequest<ClientRequest>,
		ctx: IncomingRequestContext,
		service_name: &str,
		mcp_log: Option<AsyncLog<MCPInfo>>,
	) -> Result<Response, UpstreamError> {
		let id = r.id.clone();
		let downstream_modern = ctx_downstream_modern(&ctx);
		let stream = self.prepare_single(r, ctx, service_name).await?;
		messages_to_response(id, stream, mcp_log, downstream_modern)
	}
	pub async fn send_fanout_deletion(
		&self,
		ctx: IncomingRequestContext,
	) -> Result<Response, UpstreamError> {
		let futs: Vec<_> = self
			.upstreams
			.iter_named()
			.filter(|(name, _)| self.permits_transport(name.as_str()))
			.map(|(name, con)| {
				let mut ctx = ctx.clone();
				crate::mcp::security::mark_egress(None, name.as_str(), "transport/delete", &mut ctx);
				async move { (name, con.delete(&ctx).await) }
			})
			.collect();

		if futs.is_empty() && self.upstreams.size() > 0 {
			return Err(UpstreamError::InvalidRequest(
				"no authorized MCP transport upstreams".into(),
			));
		}
		let fut_results = futures::future::join_all(futs).await;

		for (name, result) in fut_results {
			match result {
				Ok(_) => {},
				Err(e) => {
					if self.upstreams.failure_mode == FailureMode::FailOpen {
						warn!(
							"upstream '{}' failed during deletion, skipping: {}",
							name, e
						);
					} else {
						return Err(e);
					}
				},
			}
		}
		Ok(accepted_response())
	}
	pub async fn send_fanout_get(
		&self,
		ctx: IncomingRequestContext,
	) -> Result<Response, UpstreamError> {
		let mut streams = Vec::new();
		let mut unsupported_get_streams = 0;

		let futs: Vec<_> = self
			.upstreams
			.iter_named()
			.filter(|(name, _)| self.permits_transport(name.as_str()))
			.map(|(name, con)| {
				let mut ctx = ctx.clone();
				crate::mcp::security::mark_egress(None, name.as_str(), "transport/get", &mut ctx);
				async move { (name, con.get_event_stream(&ctx).await) }
			})
			.collect();

		if futs.is_empty() && self.upstreams.size() > 0 {
			return Err(UpstreamError::InvalidRequest(
				"no authorized MCP transport upstreams".into(),
			));
		}
		let selected_count = futs.len();
		let fut_results = futures::future::join_all(futs).await;

		for (name, result) in fut_results {
			match result {
				Ok(s) => {
					let s = super::session_security::protect_messages(s, &ctx, None, name.as_str());
					let s = self.rewrite_outbound_server_messages(name.as_str(), s);
					streams.push((name.to_string(), s));
				},
				Err(e) => {
					let is_405 = if let UpstreamError::Http(ClientError::Status(ref r)) = e
						&& r.status() == StatusCode::METHOD_NOT_ALLOWED
					{
						true
					} else {
						false
					};
					if is_405 && self.upstreams.is_multiplexing {
						debug!("upstream '{}' does not support GET stream, skipping", name);
						unsupported_get_streams += 1;
						continue;
					}
					if self.upstreams.failure_mode == FailureMode::FailOpen {
						if !is_405 {
							// per spec, a 405 is a valid response to say a GET stream is not supported so avoid log spam.
							warn!("upstream '{}' failed for GET stream, skipping: {}", name, e);
						} else {
							debug!("upstream '{}' failed for GET stream, skipping: {}", name, e);
						}
					} else {
						return Err(e);
					}
				},
			}
		}

		if streams.is_empty() {
			if unsupported_get_streams > 0 && unsupported_get_streams == selected_count {
				return Err(crate::proxy::ProxyError::MCP(mcp::Error::GetStreamNotSupported).into());
			}
			// FailClosed: unreachable — InitializeRequest would have failed with NoBackends.
			// FailOpen: keep the SSE connection open so legacy SSE clients do not immediately
			// reconnect in a tight loop after all upstream GET streams disappear.
			return messages_to_response(
				RequestId::Number(0),
				Messages::pending(),
				None,
				ctx_downstream_modern(&ctx),
			);
		}

		let failure_mode = if ctx
			.as_request()
			.extensions()
			.get::<super::session_security::SessionAccess>()
			.is_some()
		{
			FailureMode::FailClosed
		} else {
			self.upstreams.failure_mode
		};
		let ms = mergestream::MergeStream::new_without_merge(streams, failure_mode.into());
		let ms = self.apply_vehicle_response_guardrails(ms);
		messages_to_response(RequestId::Number(0), ms, None, ctx_downstream_modern(&ctx))
	}

	pub(crate) async fn prepare_fanout(
		&self,
		r: JsonRpcRequest<ClientRequest>,
		mut ctx: IncomingRequestContext,
		merge: MergePlan,
		target_names: Option<Vec<String>>,
	) -> Result<(FanoutPlan<ClientError>, FanoutFinish), UpstreamError> {
		let object_list = crate::mcp::security::is_discovery_list(&r.request);
		let cross_component = self
			.security_audit
			.as_ref()
			.is_some_and(|c| c.cross_component.is_some());
		if !object_list && !cross_component {
			self
				.security()
				.authorize_request(&r, &mut ctx, "mcp-gateway")?;
		}
		self.enforce_vehicle_tool_guardrails(&r).await?;
		let id = r.id.clone();
		let subscription_id = if matches!(&r.request, ClientRequest::SubscriptionsListenRequest(_)) {
			Some(id.clone())
		} else {
			None
		};
		let mut streams = Vec::new();
		let method = r.request.method().to_string();
		let method = method.as_str();
		let mut selected_upstreams = self
			.upstreams
			.iter_named()
			.filter(|(name, _)| {
				self.permits_transport(name.as_str())
					&& target_names
						.as_ref()
						.is_none_or(|targets| targets.iter().any(|target| target == name.as_str()))
			})
			.collect::<Vec<_>>();
		if selected_upstreams.is_empty() {
			return Err(UpstreamError::InvalidRequest(
				"no upstreams available".to_string(),
			));
		}
		if object_list || cross_component {
			let mut last_denial = None;
			selected_upstreams.retain(|(name, _)| {
				match self
					.security()
					.authorize_request(&r, &mut ctx, name.as_str())
				{
					Ok(()) => true,
					Err(error) => {
						last_denial = Some(error);
						false
					},
				}
			});
			if selected_upstreams.is_empty() {
				return Err(last_denial.expect("nonempty selection rejected before dispatch"));
			}
		}

		// service_names for the single fanout-wide mcpGuardrails hook: every backend this call
		// fans out to (just the one name when there is a single backend).
		let service_names = self.mcp_guardrails.as_ref().map(|_| {
			selected_upstreams
				.iter()
				.map(|(n, _)| n.to_string())
				.collect::<Vec<_>>()
		});

		// Request-phase hook runs once for the whole client call. params is None for
		// fanout (no body to rewrite); header/metadata side effects apply to the single
		// shared ctx forwarded to every upstream. A reject fails the whole call.
		if let Some(ext) = self.mcp_guardrails.as_ref() {
			// params is None, so mutations are discarded unparsed and the params
			// type is never used.
			let outcome = Box::pin(
				crate::mcp::guardrails::run_call_request::<serde_json::Value>(
					ext,
					&mut crate::mcp::guardrails::CallRequestCtx {
						backends: service_names.as_deref().unwrap_or_default(),
						method,
						params: None,
					},
					&mut ctx,
					&self.policy_client,
				)
				.assert_size::<{ 4 * 1024 }>(),
			)
			.await;
			if let crate::mcp::guardrails::Outcome::Reject(rej) = outcome {
				return Err(UpstreamError::McpGuardrails(rej));
			}
		}

		let futs: Vec<_> = selected_upstreams
			.into_iter()
			.map(|(name, con)| {
				let r = r.clone();
				let mut ctx = ctx.clone();
				crate::mcp::security::mark_egress(Some(&r), name.as_str(), "", &mut ctx);
				async move { (name, con.generic_stream(r, &ctx).await) }
			})
			.collect();

		let fut_results = futures::future::join_all(futs).await;

		let cel = CelExecWrapper::new(ctx.as_request().map(|_| ()));
		for (name, result) in fut_results {
			match result {
				Ok(s) => {
					let s = super::session_security::protect_messages(s, &ctx, Some(&r), name.as_str());
					let mut s = self.rewrite_outbound_server_messages(name.as_str(), s);
					if let Some(subscription_id) = subscription_id.clone() {
						s = s.map_server_messages(move |message| {
							set_subscription_ack_id(message, &subscription_id)
						});
					}
					streams.push((name.to_string(), s));
				},
				Err(e) => {
					if self.upstreams.failure_mode == FailureMode::FailOpen {
						warn!("upstream '{}' failed during fanout, skipping: {}", name, e);
					} else {
						return Err(e);
					}
				},
			}
		}

		if streams.is_empty() {
			// Unlike GET fanout, ordinary request fanout does not have a transport-level
			// "stay connected" fallback, and most MCP methods do not have a safe generic
			// synthetic success response. By the time we get here, every initialized
			// upstream has failed this request, so we surface that as an error even in
			// FailOpen rather than inventing a method-specific response.
			return Err(UpstreamError::InvalidRequest(
				"no upstreams available".to_string(),
			));
		}

		let failure_mode = if ctx
			.as_request()
			.extensions()
			.get::<super::session_security::SessionAccess>()
			.is_some()
		{
			FailureMode::FailClosed
		} else {
			self.upstreams.failure_mode
		};
		let merge = merge(&cel);
		let protected_ctx = ctx.clone();
		let protected = protected_ctx
			.as_request()
			.extensions()
			.get::<super::session_security::SessionAccess>()
			.is_some();
		let guardrails = service_names.and_then(|sn| self.build_guardrails_ctx(&r, &ctx, sn));
		Ok((
			FanoutPlan {
				streams,
				merge,
				failure_mode: failure_mode.into(),
			},
			FanoutFinish {
				protected,
				ctx: protected_ctx,
				guardrails,
			},
		))
	}

	pub async fn send_notification(
		&self,
		r: JsonRpcNotification<ClientNotification>,
		ctx: IncomingRequestContext,
	) -> Result<Response, UpstreamError> {
		let method = crate::mcp::security::notification_method(&r.notification);
		let mut selected = Vec::new();
		for (name, con) in self
			.upstreams
			.iter_named()
			.filter(|(name, _)| self.permits_transport(name.as_str()))
		{
			let mut ctx = ctx.clone();
			self.prepare_notification(method, name.as_str(), &mut ctx)?;
			selected.push((name, con, ctx));
		}
		if selected.is_empty() && self.upstreams.size() > 0 {
			return Err(UpstreamError::InvalidRequest(
				"no authorized MCP transport upstreams".into(),
			));
		}
		// All authorization finishes before any upstream notification is sent.
		let futs: Vec<_> = selected
			.into_iter()
			.map(|(name, con, ctx)| {
				let notification = r.notification.clone();
				async move { (name, con.generic_notification(notification, &ctx).await) }
			})
			.collect();

		let fut_results = futures::future::join_all(futs).await;

		for (name, result) in fut_results {
			match result {
				Ok(_) => {},
				Err(e) => {
					if self.upstreams.failure_mode == FailureMode::FailOpen {
						warn!(
							"upstream '{}' failed during notification, skipping: {}",
							name, e
						);
					} else {
						return Err(e);
					}
				},
			}
		}

		Ok(accepted_response())
	}

	pub async fn send_notification_single(
		&self,
		r: ClientNotification,
		mut ctx: IncomingRequestContext,
		service_name: &str,
	) -> Result<Response, UpstreamError> {
		if !self.permits_transport(service_name) {
			return Err(UpstreamError::InvalidRequest(
				"security policy denied MCP transport".into(),
			));
		}
		self.prepare_notification(
			crate::mcp::security::notification_method(&r),
			service_name,
			&mut ctx,
		)?;
		let Ok(us) = self.upstreams.get(service_name) else {
			return Err(UpstreamError::InvalidRequest(format!(
				"unknown service {service_name}"
			)));
		};
		us.generic_notification(r, &ctx).await?;
		Ok(accepted_response())
	}
}

fn gateway_implementation() -> Implementation {
	Implementation::new("agentgateway", BuildInfo::new().version.to_string())
}

pub fn setup_request_log(
	http: Parts,
	span_name: &str,
) -> (SpanWriteOnDrop, AsyncLog<MCPInfo>, CelExecWrapper) {
	let log = http
		.extensions
		.get::<AsyncLog<MCPInfo>>()
		.cloned()
		.unwrap_or_default();

	let tracer = http
		.extensions
		.get::<SpanWriter>()
		.cloned()
		.unwrap_or_default();
	let cel = CelExecWrapper::new(::http::Request::from_parts(http, ()));
	let _span = tracer.start(span_name.to_string());
	(_span, log, cel)
}

pub(crate) struct FanoutFinish {
	protected: bool,
	ctx: IncomingRequestContext,
	guardrails: Option<GuardrailsCtx>,
}

impl FanoutFinish {
	pub(crate) fn finish<E>(self, stream: MessageStream<E>) -> MessageStream<E>
	where
		E: Send + 'static,
	{
		let stream = if self.protected {
			let ctx = self.ctx;
			stream.map_server_messages(move |mut rpc| {
				if let ServerJsonRpcMessage::Response(response) = &mut rpc {
					match &mut response.result {
						ServerResult::InitializeResult(init) => {
							super::session_security::restrict_for_context(&mut init.capabilities, &ctx)
						},
						ServerResult::DiscoverResult(discovery) => {
							super::session_security::restrict_for_context(&mut discovery.capabilities, &ctx)
						},
						_ => {},
					}
				}
				rpc
			})
		} else {
			stream
		};
		match self.guardrails {
			Some(guardrails) => MessageStream::from_stream(wrap_with_guardrails(stream, guardrails)),
			None => stream,
		}
	}
}

pub(crate) struct GuardrailsCtx {
	pub ext: Arc<crate::mcp::guardrails::McpGuardrails>,
	pub method: String,
	pub backends: Vec<String>,
	pub client: PolicyClient,
	pub req_ctx: Arc<IncomingRequestContext>,
}

pub(super) fn messages_to_response<E>(
	id: RequestId,
	stream: impl Stream<Item = Result<ServerJsonRpcMessage, E>> + Send + 'static,
	mcp_log: Option<AsyncLog<MCPInfo>>,
	downstream_modern: bool,
) -> Result<Response, UpstreamError>
where
	E: std::fmt::Display + Send + 'static,
{
	Ok(mcp::session::sse_stream_response(
		into_sse_stream(id, stream, mcp_log, downstream_modern),
		None,
	))
}

pub(super) fn ctx_downstream_modern(ctx: &IncomingRequestContext) -> bool {
	ctx
		.as_request()
		.extensions()
		.get::<RequestProtocol>()
		.is_some_and(RequestProtocol::is_modern)
}

fn wrap_with_guardrails<E>(
	stream: impl Stream<Item = Result<ServerJsonRpcMessage, E>> + Send + 'static,
	guardrails: GuardrailsCtx,
) -> impl Stream<Item = Result<ServerJsonRpcMessage, E>> + Send + 'static
where
	E: Send + 'static,
{
	use futures_util::StreamExt;
	let guardrails = Arc::new(guardrails);
	stream.then(move |rpc| {
		let ctx = guardrails.clone();
		async move {
			match rpc {
				Ok(mut rpc) => {
					if let Some(scrubbed) = apply_guardrails_response_intercept(&ctx, &rpc).await {
						rpc = scrubbed;
					}
					Ok(rpc)
				},
				Err(e) => Err(e),
			}
		}
	})
}

fn into_sse_stream<E>(
	request_id: RequestId,
	stream: impl Stream<Item = Result<ServerJsonRpcMessage, E>> + Send + 'static,
	mcp_log: Option<AsyncLog<MCPInfo>>,
	downstream_modern: bool,
) -> impl Stream<Item = ServerSseMessage> + Send + 'static
where
	E: std::fmt::Display + Send + 'static,
{
	use futures_util::StreamExt;
	let mut captured_terminal = false;
	stream.map(move |rpc| {
		let r = match rpc {
			Ok(rpc) => {
				let rpc = with_gateway_cache_policy(rpc);
				let rpc = normalize_outbound_for_protocol(rpc, downstream_modern);
				if !captured_terminal && let Some(log) = mcp_log.as_ref() {
					captured_terminal = capture_terminal_mcp_payload(log, &request_id, &rpc);
				}
				rpc
			},
			Err(e) => ServerJsonRpcMessage::error(
				ErrorData::internal_error(e.to_string(), None),
				Some(request_id.clone()),
			),
		};
		// TODO: is it ok to have no event_id here?
		ServerSseMessage {
			event_id: None,
			message: Arc::new(r),
		}
	})
}

fn with_gateway_cache_policy(mut msg: ServerJsonRpcMessage) -> ServerJsonRpcMessage {
	let ServerJsonRpcMessage::Response(resp) = &mut msg else {
		return msg;
	};

	// Cache hints must describe the gateway-visible result, not the upstream's result.
	// For now, keep all cacheable MCP responses immediately stale/private because
	// routing config, backend membership, and authz filtering can change without a
	// client invalidation path. A future opt-in can allow positive TTLs when no
	// per-user/authz-dependent filtering applies.
	match &mut resp.result {
		ServerResult::DiscoverResult(r) => {
			r.ttl_ms = Some(0);
			r.cache_scope = Some(CacheScope::Private);
		},
		ServerResult::ListToolsResult(r) => {
			r.ttl_ms = Some(0);
			r.cache_scope = Some(CacheScope::Private);
		},
		ServerResult::ListPromptsResult(r) => {
			r.ttl_ms = Some(0);
			r.cache_scope = Some(CacheScope::Private);
		},
		ServerResult::ListResourcesResult(r) => {
			r.ttl_ms = Some(0);
			r.cache_scope = Some(CacheScope::Private);
		},
		ServerResult::ListResourceTemplatesResult(r) => {
			r.ttl_ms = Some(0);
			r.cache_scope = Some(CacheScope::Private);
		},
		ServerResult::ReadResourceResult(r) => {
			r.ttl_ms = Some(0);
			r.cache_scope = Some(CacheScope::Private);
		},
		_ => {},
	}

	msg
}

async fn apply_guardrails_response_intercept(
	ctx: &GuardrailsCtx,
	msg: &ServerJsonRpcMessage,
) -> Option<ServerJsonRpcMessage> {
	use crate::mcp::guardrails::Outcome;
	// The stream is request-scoped, so the only Response on it is the terminal.
	let ServerJsonRpcMessage::Response(resp) = msg else {
		return None;
	};
	let json: bytes::Bytes = match serde_json::to_vec(&resp.result) {
		Ok(v) => v.into(),
		Err(e) => {
			// Fail the response rather than skip a hook the operator configured,
			// matching the request side's handling of serialize failures.
			tracing::warn!(error = %e, "mcpGuardrails: failed to serialize result for inspection");
			return Some(ServerJsonRpcMessage::error(
				ErrorData::internal_error(format!("mcpGuardrails: serialize result: {e}"), None),
				Some(resp.id.clone()),
			));
		},
	};
	match crate::mcp::guardrails::run_response(
		&ctx.ext,
		&ctx.method,
		&ctx.backends,
		json,
		&ctx.req_ctx,
		&ctx.client,
	)
	.await
	{
		Outcome::Pass => None,
		Outcome::Mutated(new_result) => {
			Some(ServerJsonRpcMessage::response(new_result, resp.id.clone()))
		},
		Outcome::Reject(rej) => Some(ServerJsonRpcMessage::error(rej, Some(resp.id.clone()))),
	}
}

fn capture_terminal_mcp_payload(
	log: &AsyncLog<MCPInfo>,
	request_id: &RequestId,
	message: &ServerJsonRpcMessage,
) -> bool {
	match message {
		ServerJsonRpcMessage::Response(response) if response.id == *request_id => {
			if let ServerResult::CallToolResult(result) = &response.result {
				log.non_atomic_mutate(|mcp| mcp.capture_call_result(result));
			}
			true
		},
		ServerJsonRpcMessage::Error(error) if error.id.as_ref() == Some(request_id) => {
			log.non_atomic_mutate(|mcp| mcp.capture_call_error(&error.error));
			true
		},
		_ => false,
	}
}

fn accepted_response() -> Response {
	::http::Response::builder()
		.status(StatusCode::ACCEPTED)
		.body(crate::http::Body::empty())
		.expect("valid response")
}
