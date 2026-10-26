use base64::Engine;
use rmcp::model::{ClientRequest, JsonRpcRequest};
use security_capability_broker::CAPABILITY_CONTEXT_HEADER;
use security_pipeline::{GatewayIdentity, SecurityPipelineConfig};
use security_types::ResourceType;

#[cfg(test)]
#[path = "security_tests.rs"]
mod tests;

pub(crate) fn visible_object(
	config: Option<&security_integration_runtime::SecurityConfig>,
	legacy: Option<&SecurityPipelineConfig>,
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
	config.is_none_or(|config| crate::security::evaluate(config, &action).is_ok())
		&& legacy.is_none_or(|config| {
			config
				.build(crate::security_events::UiSecurityAuditSink)
				.authorize(&action, None)
				.is_ok()
		})
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

pub fn enforce_request(
	config: &SecurityPipelineConfig,
	request: &JsonRpcRequest<ClientRequest>,
	context: &IncomingRequestContext,
	server: &str,
) -> Result<(), UpstreamError> {
	let op = normalize(
		request,
		context.security_request_id(),
		identity_from_context(context),
		server,
	);
	if op.kind == OperationKind::Unsupported || requires_protected_subscription(request, context) {
		return unsupported(
			&security_integration_runtime::SecurityConfig {
				mode: security_integration_runtime::SecurityMode::Enforce,
				..Default::default()
			},
			&op.action,
		);
	}
	if op.kind == OperationKind::Control {
		return Ok(());
	}
	config
		.build(crate::security_events::UiSecurityAuditSink)
		.authorize(&op.action, op.arguments.as_ref())
		.map(|_| ())
		.map_err(UpstreamError::Security)
}

pub fn audit_request(
	config: &security_integration_runtime::SecurityConfig,
	request: &JsonRpcRequest<ClientRequest>,
	context: &mut IncomingRequestContext,
	server: &str,
) -> Result<(), UpstreamError> {
	let op = normalize(
		request,
		context.security_request_id(),
		identity_from_context(context),
		server,
	);
	if op.kind == OperationKind::Unsupported || requires_protected_subscription(request, context) {
		return unsupported(config, &op.action);
	}
	let http = context.as_request();
	if let Some(flow) = crate::security_flow::prepare(config, http.headers(), http.extensions())
		.map_err(|e| UpstreamError::InvalidRequest(e.to_string()))?
	{
		mark_egress(Some(request), server, "", context);
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
	if op.kind == OperationKind::Control {
		return Ok(());
	}
	if let Some(egress) = &config.data_egress {
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
		let grant = security_integration_runtime::authorize_tool_with_capability_with_audit(
			config,
			&op.action,
			arguments,
			&crate::security_events::UiSecurityAuditSink,
		)
		.map_err(UpstreamError::Security)?;
		if let Some(grant) = grant {
			let capability = ::http::HeaderValue::from_str(&grant.token)
				.map_err(|_| UpstreamError::InvalidRequest("invalid broker token".into()))?;
			let encoded = serde_json::to_vec(&op.action)
				.map(|v| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(v))
				.map_err(|_| UpstreamError::InvalidRequest("unable to encode capability context".into()))?;
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
		security_integration_runtime::evaluate_with_audit(
			config,
			&op.action,
			None,
			&crate::security_events::UiSecurityAuditSink,
		)
		.map_err(UpstreamError::Security)
	}
}

pub(crate) fn identity_from_context(context: &IncomingRequestContext) -> GatewayIdentity {
	crate::security::identity_from_extensions(context.as_request().extensions())
}
