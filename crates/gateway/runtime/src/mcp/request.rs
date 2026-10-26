//! Host-side object execution. Protocol routing owns no upstream connections or grants.
use super::{Relay, accepted_response};
use crate::http::Response;
use crate::mcp::guardrails::methods;
use crate::mcp::mergestream::Messages;
use crate::mcp::rbac::{self, CelExecWrapper};
use crate::mcp::upstream::{IncomingRequestContext, UpstreamError};
use crate::mcp::{MCPInfo, security, session_security};
use crate::telemetry::log::{AsyncLog, SpanWriteOnDrop};
use gateway_mcp::routing::ObjectKind;
use rmcp::model::{ClientJsonRpcMessage, ClientNotification, ClientRequest, JsonRpcRequest};

impl Relay {
	pub(in crate::mcp) fn validate_subscription_request(
		&self,
		request: &JsonRpcRequest<ClientRequest>,
		target: Option<&str>,
		span: &mut SpanWriteOnDrop,
		log: &AsyncLog<MCPInfo>,
		cel: &CelExecWrapper,
	) -> Result<(), UpstreamError> {
		let ClientRequest::SubscriptionsListenRequest(listen) = &request.request else {
			return Err(UpstreamError::InvalidMethod(
				request.request.method().to_string(),
			));
		};
		let resources = listen
			.params
			.notifications
			.resource_subscriptions
			.as_deref()
			.unwrap_or_default();
		let Some(target) = target else {
			if !resources.is_empty() {
				return Err(UpstreamError::InvalidRequest(
					"subscription target missing".into(),
				));
			}
			return Ok(());
		};
		if self.default_target_name().is_none() && self.upstreams.get_name(target).is_none() {
			return Err(UpstreamError::InvalidRequest(format!(
				"unknown service {target}"
			)));
		}
		for uri in resources {
			span.rename_span(format!("{} {target}", request.request.method()));
			log.non_atomic_mutate(|entry| entry.set_resource(target.to_owned(), uri.clone()));
			if !self.policies.validate(
				&crate::mcp::rbac::ResourceType::Resource(crate::mcp::rbac::ResourceId::new(
					target.to_owned(),
					uri.clone(),
				)),
				cel,
			) {
				return Err(UpstreamError::Authorization {
					resource_type: "resource".into(),
					resource_name: uri.clone(),
				});
			}
		}
		Ok(())
	}

	pub(in crate::mcp) async fn prepare_routed_object_request(
		&self,
		route: gateway_mcp::routing::ObjectRoute,
		mut request: JsonRpcRequest<ClientRequest>,
		mut ctx: IncomingRequestContext,
		span: &mut SpanWriteOnDrop,
		log: &AsyncLog<MCPInfo>,
		cel: &CelExecWrapper,
	) -> Result<Messages, UpstreamError> {
		let method = request.request.method().to_string();
		// Preserve URI target validation against active connections. A lexical route
		// is neither an existing upstream nor permission to execute against it.
		if route.kind == ObjectKind::Resource
			&& self.upstreams.default_target_name.is_none()
			&& self.upstreams.get_name(&route.target).is_none()
		{
			return Err(UpstreamError::InvalidRequest(format!(
				"unknown service {}",
				route.target
			)));
		}
		span.rename_span(format!("{method} {}", route.target));
		log.non_atomic_mutate(|entry| match route.kind {
			ObjectKind::Tool => {
				entry.set_tool(route.target.clone(), route.object.clone());
				if let ClientRequest::CallToolRequest(call) = &request.request {
					entry.capture_call_arguments(call.params.arguments.clone());
				}
			},
			ObjectKind::Prompt => entry.set_prompt(route.target.clone(), route.object.clone()),
			ObjectKind::Resource => entry.set_resource(route.target.clone(), route.object.clone()),
		});
		let resource_id = rbac::ResourceId::new(route.target.clone(), route.object.clone());
		let (resource, resource_type) = match route.kind {
			ObjectKind::Tool => (rbac::ResourceType::Tool(resource_id), "tool"),
			ObjectKind::Prompt => (rbac::ResourceType::Prompt(resource_id), "prompt"),
			ObjectKind::Resource => (rbac::ResourceType::Resource(resource_id), "resource"),
		};
		// Keep the existing method-specific hooks and their ordering: namespace
		// projection, request hook, RBAC using its original object, final execution.
		let refresh_cel = match &mut request.request {
			ClientRequest::CallToolRequest(call) => {
				Box::pin(self.maybe_run_guardrails_call_request(
					&route.target,
					methods::TOOLS_CALL,
					&mut call.params,
					&mut ctx,
				))
				.await?;
				true
			},
			ClientRequest::GetPromptRequest(call) => {
				Box::pin(self.maybe_run_guardrails_call_request(
					&route.target,
					methods::PROMPTS_GET,
					&mut call.params,
					&mut ctx,
				))
				.await?;
				true
			},
			ClientRequest::ReadResourceRequest(call) => {
				Box::pin(self.maybe_run_guardrails_call_request(
					&route.target,
					methods::RESOURCES_READ,
					&mut call.params,
					&mut ctx,
				))
				.await?;
				true
			},
			_ => false,
		};
		let updated_cel;
		let cel = if refresh_cel {
			updated_cel = CelExecWrapper::new(ctx.as_request().map(|_| ()));
			&updated_cel
		} else {
			cel
		};
		if !self.policies.validate(&resource, cel) {
			return Err(UpstreamError::Authorization {
				resource_type: resource_type.to_string(),
				resource_name: if !refresh_cel && route.kind == ObjectKind::Resource {
					route.object
				} else {
					route.requested
				},
			});
		}
		self.prepare_single(request, ctx, &route.target).await
	}

	pub(in crate::mcp) async fn send_reverse_response(
		&self,
		message: ClientJsonRpcMessage,
		mut ctx: IncomingRequestContext,
	) -> Result<Response, UpstreamError> {
		let http = ctx.as_request();
		let access = http
			.extensions()
			.get::<session_security::SessionAccess>()
			.ok_or_else(|| {
				UpstreamError::InvalidRequest("reverse response requires protected session".into())
			})?;
		let (server, message, action, response_ticket) =
			session_security::reverse::response(access, message)?;
		if let Some(ticket) = &response_ticket {
			ctx.extensions_mut().insert(ticket.clone());
		}
		ctx.extensions_mut().insert(security::McpEgressContext {
			server: server.clone(),
			action,
			supported: true,
		});
		let send = Box::pin(self.upstreams.get(&server)?.generic_response(message, &ctx));
		if let Some(ticket) = &response_ticket {
			ticket.run(send).await?;
		} else {
			send.await?;
		}
		Ok(accepted_response())
	}

	pub(in crate::mcp) async fn send_reverse_cancel(
		&self,
		mut notification: ClientNotification,
		mut ctx: IncomingRequestContext,
	) -> Result<Response, UpstreamError> {
		let http = ctx.as_request();
		let access = http
			.extensions()
			.get::<session_security::SessionAccess>()
			.ok_or_else(|| {
				UpstreamError::InvalidRequest("reverse cancellation requires protected session".into())
			})?;
		let server = session_security::reverse::cancel(access, &notification)?;
		let action = security_pipeline::mcp_operation_for_identity(
			uuid::Uuid::new_v4().to_string(),
			crate::security::identity_from_extensions(http.extensions()),
			"notifications/cancelled/request",
			security_types::ResourceType::McpServer,
			&server,
		);
		ctx.extensions_mut().insert(security::McpEgressContext {
			server: server.clone(),
			action,
			supported: true,
		});
		// Arbitrary caller reasons are not disclosed to the upstream.
		if let ClientNotification::CancelledNotification(cancel) = &mut notification {
			cancel.params.reason = None;
		}
		self
			.upstreams
			.get(&server)?
			.generic_notification(notification, &ctx)
			.await?;
		Ok(accepted_response())
	}
}
