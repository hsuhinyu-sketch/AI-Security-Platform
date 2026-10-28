use crate::types::agent::LegacySecurityPipeline;
use base64::Engine;
use rmcp::model::{ClientRequest, JsonRpcRequest};
use security_capability_broker::CAPABILITY_CONTEXT_HEADER;
use security_integration_runtime::SecurityConfig;
use security_pipeline::{GatewayError, GatewayIdentity};
use security_types::ResourceType;

#[cfg(test)]
#[path = "security_tests.rs"]
mod tests;

/// A borrowed view of the two declarations, evaluated independently with their original modes.
/// Rules are never concatenated: an Allow in one declaration cannot override the other's Deny.
#[derive(Clone, Copy)]
pub(super) struct McpSecurity<'a> {
	common: Option<&'a SecurityConfig>,
	legacy: Option<&'a LegacySecurityPipeline>,
}

impl<'a> McpSecurity<'a> {
	pub(super) fn new(
		common: Option<&'a SecurityConfig>,
		legacy: Option<&'a LegacySecurityPipeline>,
	) -> Self {
		Self { common, legacy }
	}

	fn configurations(&self) -> impl Iterator<Item = &'a SecurityConfig> {
		self
			.common
			.into_iter()
			.chain(self.legacy.map(|config| config.configuration().as_ref()))
	}

	pub(super) fn authorize(
		&self,
		action: &security_types::ActionRequest,
		arguments: Option<&serde_json::Value>,
	) -> Result<(), GatewayError> {
		for config in self.configurations() {
			security_integration_runtime::evaluate_with_audit(
				config,
				action,
				arguments,
				&crate::security_events::UiSecurityAuditSink,
			)?;
		}
		Ok(())
	}

	fn authorize_tool(
		&self,
		action: &security_types::ActionRequest,
		arguments: &serde_json::Value,
	) -> Result<Option<security_integration_runtime::CapabilityGrant>, GatewayError> {
		// Preserve common authorization/approval before the legacy constraint. Publish the
		// capability into the request only after both declarations have accepted the call.
		let grant = self
			.common
			.map(|config| {
				security_integration_runtime::authorize_tool_with_capability_with_audit(
					config,
					action,
					arguments,
					&crate::security_events::UiSecurityAuditSink,
				)
			})
			.transpose()?
			.flatten();
		if let Some(legacy) = self.legacy {
			security_integration_runtime::evaluate_with_audit(
				legacy.configuration(),
				action,
				Some(arguments),
				&crate::security_events::UiSecurityAuditSink,
			)?;
		}
		Ok(grant)
	}

	pub(super) fn unsupported(
		&self,
		action: &security_types::ActionRequest,
	) -> Result<(), UpstreamError> {
		for config in self.configurations() {
			unsupported(config, action)?;
		}
		Ok(())
	}

	pub(super) fn requires_tool_approval(&self, action: &security_types::ActionRequest) -> bool {
		self
			.configurations()
			.any(|config| config.pipeline.requires_tool_approval(action))
	}

	pub(super) fn visible_object(
		&self,
		request_id: &str,
		identity: &GatewayIdentity,
		server: &str,
		kind: ResourceType,
		object: &str,
		method: &str,
	) -> bool {
		let action = security_pipeline::mcp_operation_for_identity(
			request_id,
			identity.clone(),
			method,
			kind,
			security_pipeline::mcp_object_id(server, object),
		);
		self.authorize(&action, None).is_ok()
	}

	pub(super) fn authorize_request(
		&self,
		request: &JsonRpcRequest<ClientRequest>,
		context: &mut IncomingRequestContext,
		server: &str,
	) -> Result<(), UpstreamError> {
		if self.common.is_none() && self.legacy.is_none() {
			return Ok(());
		}
		let op = normalize(
			request,
			context.security_request_id(),
			identity_from_context(context),
			server,
		);
		if op.kind == OperationKind::Unsupported || requires_protected_subscription(request, context) {
			return self.unsupported(&op.action);
		}
		if let Some(config) = self.common {
			let http = context.as_request();
			if let Some(flow) = crate::security_flow::prepare(config, http.headers(), http.extensions())
				.map_err(|e| UpstreamError::InvalidRequest(e.to_string()))?
			{
				context.extensions_mut().insert(McpEgressContext {
					server: server.into(),
					action: op.action.clone(),
					supported: true,
				});
				let destination = if op.kind == OperationKind::Tool {
					format!("{server}/{}", op.action.resource.id)
				} else {
					server.to_owned()
				};
				flow
					.check(&op.action, &destination)
					.map_err(|e| UpstreamError::InvalidRequest(e.to_string()))?;
				context.extensions_mut().insert(flow);
			}
		}
		if op.kind == OperationKind::Control {
			return Ok(());
		}
		if let Some(egress) = self.common.and_then(|config| config.data_egress.as_ref()) {
			let destination = if op.kind == OperationKind::Tool {
				format!("{server}/{}", op.action.resource.id)
			} else {
				server.to_owned()
			};
			security_integration_runtime::check_data_egress(
				egress,
				&op.action,
				&destination,
				&crate::security_events::UiSecurityAuditSink,
			)
			.map_err(UpstreamError::Security)?;
		}
		if let Some(arguments) = &op.arguments {
			let grant = self
				.authorize_tool(&op.action, arguments)
				.map_err(UpstreamError::Security)?;
			if let Some(grant) = grant {
				let capability = ::http::HeaderValue::from_str(&grant.token)
					.map_err(|_| UpstreamError::InvalidRequest("invalid broker token".into()))?;
				let encoded = serde_json::to_vec(&op.action)
					.map(|v| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(v))
					.map_err(|_| {
						UpstreamError::InvalidRequest("unable to encode capability context".into())
					})?;
				let context_header = ::http::HeaderValue::from_str(&encoded).map_err(|_| {
					UpstreamError::InvalidRequest(format!("invalid {CAPABILITY_CONTEXT_HEADER}"))
				})?;
				context.extensions_mut().insert(IssuedCapability {
					capability,
					context: context_header,
				});
			}
			Ok(())
		} else {
			self
				.authorize(&op.action, None)
				.map_err(UpstreamError::Security)
		}
	}
}

pub(crate) use gateway_mcp::{OperationKind, is_discovery_list, normalize, notification_method};

use crate::mcp::upstream::{IncomingRequestContext, IssuedCapability, UpstreamError};

pub(crate) use super::McpEgressContext;

pub(crate) fn mark_egress(
	request: Option<&JsonRpcRequest<ClientRequest>>,
	server: &str,
	transport_method: &str,
	context: &mut IncomingRequestContext,
) {
	let identity = identity_from_context(context);
	let (action, supported) = if let Some(request) = request {
		let op = normalize(request, context.security_request_id(), identity, server);
		(op.action, op.kind != OperationKind::Unsupported)
	} else {
		(
			security_pipeline::mcp_operation_for_identity(
				context.security_request_id(),
				identity,
				transport_method,
				ResourceType::McpServer,
				server,
			),
			matches!(
				transport_method,
				"transport/get" | "transport/delete" | "notifications/initialized"
			),
		)
	};
	context.extensions_mut().insert(McpEgressContext {
		server: server.into(),
		action,
		supported,
	});
}

fn requires_protected_subscription(
	request: &JsonRpcRequest<ClientRequest>,
	context: &IncomingRequestContext,
) -> bool {
	matches!(
		request.request,
		ClientRequest::SubscribeRequest(_) | ClientRequest::UnsubscribeRequest(_)
	) && context
		.as_request()
		.extensions()
		.get::<super::session_security::SessionAccess>()
		.is_none()
}

fn unsupported(
	config: &security_integration_runtime::SecurityConfig,
	action: &security_types::ActionRequest,
) -> Result<(), UpstreamError> {
	security_integration_runtime::unsupported_operation_with_audit(
		config,
		action,
		"mcp",
		&crate::security_events::UiSecurityAuditSink,
	)
	.map_err(UpstreamError::Security)
}

pub(crate) fn identity_from_context(context: &IncomingRequestContext) -> GatewayIdentity {
	crate::security::identity_from_extensions(context.as_request().extensions())
}
