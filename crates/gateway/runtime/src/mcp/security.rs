use base64::Engine;
use rmcp::model::{ClientRequest, ConstString, JsonRpcRequest};
use security_capability_broker::CAPABILITY_CONTEXT_HEADER;
use security_pipeline::{
	GatewayError, GatewayIdentity, SecurityPipelineConfig, tool_invoke_for_identity, tool_list,
};
use security_types::ResourceType;

pub(crate) fn notification_method(notification: &rmcp::model::ClientNotification) -> &str {
	use rmcp::model::ClientNotification::*;
	match notification {
		CancelledNotification(r) => r.method.as_str(),
		ProgressNotification(r) => r.method.as_str(),
		InitializedNotification(r) => r.method.as_str(),
		RootsListChangedNotification(r) => r.method.as_str(),
		TaskStatusNotification(r) => r.method.as_str(),
		CustomNotification(r) => r.method.as_str(),
	}
}

/// Lists fan out; permissions and egress must be checked for each selected server.
pub(crate) fn is_object_list(request: &ClientRequest) -> bool {
	matches!(
		request.method().to_string().as_str(),
		"resources/list" | "resources/templates/list" | "prompts/list"
	)
}

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

pub(crate) fn object_action(
	request: &JsonRpcRequest<ClientRequest>,
	identity: GatewayIdentity,
	server: &str,
) -> Option<security_types::ActionRequest> {
	let (kind, id) = match &request.request {
		ClientRequest::GetTaskRequest(_)
		| ClientRequest::GetTaskPayloadRequest(_)
		| ClientRequest::CancelTaskRequest(_) => (ResourceType::McpServer, server.to_owned()),
		ClientRequest::ReadResourceRequest(call) => (
			ResourceType::McpResource,
			security_pipeline::mcp_object_id(server, &call.params.uri),
		),
		ClientRequest::SubscribeRequest(call) => (
			ResourceType::McpResource,
			security_pipeline::mcp_object_id(server, &call.params.uri),
		),
		ClientRequest::UnsubscribeRequest(call) => (
			ResourceType::McpResource,
			security_pipeline::mcp_object_id(server, &call.params.uri),
		),
		ClientRequest::GetPromptRequest(call) => (
			ResourceType::McpPrompt,
			security_pipeline::mcp_object_id(server, &call.params.name),
		),
		_ if is_object_list(&request.request) => (ResourceType::McpServer, server.into()),
		_ => return None,
	};
	let action = security_pipeline::mcp_operation_for_identity(
		request.id.to_string(),
		identity,
		request.request.method().to_string(),
		kind,
		id,
	);
	Some(action)
}

use crate::mcp::upstream::{IncomingRequestContext, IssuedCapability, UpstreamError};

/// Internal-only proof of the protocol operation selected by the gateway, never a client header.
#[derive(Clone)]
pub(crate) struct McpEgressContext {
	pub server: String,
	pub action: security_types::ActionRequest,
	pub supported: bool,
}

pub(crate) fn mark_egress(
	request: Option<&JsonRpcRequest<ClientRequest>>,
	server: &str,
	transport_method: &str,
	context: &mut IncomingRequestContext,
) {
	let identity = identity_from_context(context);
	let mut supported = true;
	let action = match request {
		Some(request) => {
			if let Some(action) = object_action(request, identity.clone(), server) {
				action
			} else if let ClientRequest::CallToolRequest(call) = &request.request {
				tool_invoke_for_identity(
					request.id.to_string(),
					identity,
					call.params.name.to_string(),
				)
			} else {
				supported = matches!(
					request.request,
					ClientRequest::InitializeRequest(_)
						| ClientRequest::PingRequest(_)
						| ClientRequest::ListToolsRequest(_)
				);
				security_pipeline::mcp_operation_for_identity(
					request.id.to_string(),
					identity,
					request.request.method().to_string(),
					ResourceType::McpServer,
					server,
				)
			}
		},
		None => {
			supported = matches!(
				transport_method,
				"transport/get" | "transport/delete" | "notifications/initialized"
			);
			security_pipeline::mcp_operation_for_identity(
				uuid::Uuid::new_v4().to_string(),
				identity,
				transport_method,
				ResourceType::McpServer,
				server,
			)
		},
	};
	context.extensions_mut().insert(McpEgressContext {
		server: server.into(),
		action,
		supported,
	});
}

/// Enforce the configured security pipeline for a supported MCP business operation.
/// Identity is derived only from previously validated JWT claims carried in the request context.
pub fn enforce_request(
	config: &SecurityPipelineConfig,
	request: &JsonRpcRequest<ClientRequest>,
	context: &IncomingRequestContext,
	server: &str,
) -> Result<(), UpstreamError> {
	if matches!(
		request.request,
		ClientRequest::SubscribeRequest(_) | ClientRequest::UnsubscribeRequest(_)
	) && context
		.as_request()
		.extensions()
		.get::<super::session_security::SessionAccess>()
		.is_none()
	{
		let action =
			object_action(request, identity_from_context(context), server).expect("subscription action");
		let enforce = security_integration_runtime::SecurityConfig {
			mode: security_integration_runtime::SecurityMode::Enforce,
			..Default::default()
		};
		return security_integration_runtime::unsupported_operation_with_audit(
			&enforce,
			&action,
			"mcp",
			&crate::security_events::UiSecurityAuditSink,
		)
		.map_err(|e| UpstreamError::InvalidRequest(error_message(e)));
	}
	if let Some(action) = object_action(request, identity_from_context(context), server) {
		return config
			.build(crate::security_events::UiSecurityAuditSink)
			.authorize(&action, None)
			.map(|_| ())
			.map_err(|error| UpstreamError::InvalidRequest(error_message(error)));
	}
	let ClientRequest::CallToolRequest(call) = &request.request else {
		if matches!(
			request.request,
			ClientRequest::InitializeRequest(_)
				| ClientRequest::PingRequest(_)
				| ClientRequest::ListToolsRequest(_)
		) {
			return Ok(());
		}
		let action = security_pipeline::mcp_operation_for_identity(
			request.id.to_string(),
			identity_from_context(context),
			request.request.method().to_string(),
			ResourceType::McpServer,
			server,
		);
		let enforce = security_integration_runtime::SecurityConfig {
			mode: security_integration_runtime::SecurityMode::Enforce,
			..Default::default()
		};
		return security_integration_runtime::unsupported_operation_with_audit(
			&enforce,
			&action,
			"mcp",
			&crate::security_events::UiSecurityAuditSink,
		)
		.map_err(|error| UpstreamError::InvalidRequest(error_message(error)));
	};
	let identity = identity_from_context(context);
	let action = tool_invoke_for_identity(
		request.id.to_string(),
		identity,
		call.params.name.to_string(),
	);
	let arguments = serde_json::Value::Object(call.params.arguments.clone().unwrap_or_default());
	config
		.build(crate::security_events::UiSecurityAuditSink)
		.authorize(&action, Some(&arguments))
		.map(|_| ())
		.map_err(|error| UpstreamError::InvalidRequest(error_message(error)))
}

/// Applies common security controls to MCP Tool, Resource and Prompt operations.
pub fn audit_request(
	config: &security_integration_runtime::SecurityConfig,
	request: &JsonRpcRequest<ClientRequest>,
	context: &mut IncomingRequestContext,
	mcp_server_id: &str,
) -> Result<(), UpstreamError> {
	let identity = identity_from_context(context);
	if matches!(
		request.request,
		ClientRequest::SubscribeRequest(_) | ClientRequest::UnsubscribeRequest(_)
	) && context
		.as_request()
		.extensions()
		.get::<super::session_security::SessionAccess>()
		.is_none()
	{
		let action = object_action(request, identity, mcp_server_id).expect("subscription action");
		return security_integration_runtime::unsupported_operation_with_audit(
			config,
			&action,
			"mcp",
			&crate::security_events::UiSecurityAuditSink,
		)
		.map_err(|e| UpstreamError::InvalidRequest(error_message(e)));
	}
	let http = context.as_request();
	if let Some(flow) = crate::security_flow::prepare(config, http.headers(), http.extensions())
		.map_err(|e| UpstreamError::InvalidRequest(e.to_string()))?
	{
		mark_egress(Some(request), mcp_server_id, "", context);
		let operation = context
			.extensions_mut()
			.get::<McpEgressContext>()
			.expect("just installed")
			.clone();
		let destination =
			if operation.action.action.action_type == security_types::ActionType::ToolInvoke {
				format!("{mcp_server_id}/{}", operation.action.resource.id)
			} else {
				mcp_server_id.to_string()
			};
		if !operation.supported {
			return Err(UpstreamError::InvalidRequest(
				"unsupported cross-component MCP operation".into(),
			));
		}
		flow
			.check(&operation.action, &destination)
			.map_err(|e| UpstreamError::InvalidRequest(e.to_string()))?;
		context.extensions_mut().insert(flow);
	}
	if let Some(action) = object_action(request, identity.clone(), mcp_server_id) {
		if let Some(egress) = &config.data_egress {
			security_integration_runtime::check_data_egress(
				egress,
				&action,
				mcp_server_id,
				&crate::security_events::UiSecurityAuditSink,
			)
			.map_err(|error| UpstreamError::InvalidRequest(error_message(error)))?;
		}
		return security_integration_runtime::evaluate_with_audit(
			config,
			&action,
			None,
			&crate::security_events::UiSecurityAuditSink,
		)
		.map_err(|error| UpstreamError::InvalidRequest(error_message(error)));
	}
	let (action, arguments) = match &request.request {
		ClientRequest::CallToolRequest(call) => (
			tool_invoke_for_identity(
				request.id.to_string(),
				identity,
				call.params.name.to_string(),
			),
			Some(serde_json::Value::Object(
				call.params.arguments.clone().unwrap_or_default(),
			)),
		),
		ClientRequest::ListToolsRequest(_) => (
			tool_list(request.id.to_string(), identity, mcp_server_id),
			None,
		),
		ClientRequest::InitializeRequest(_) | ClientRequest::PingRequest(_) => return Ok(()),
		_ => {
			let action = security_pipeline::mcp_operation_for_identity(
				request.id.to_string(),
				identity,
				request.request.method().to_string(),
				ResourceType::McpServer,
				mcp_server_id,
			);
			return security_integration_runtime::unsupported_operation_with_audit(
				config,
				&action,
				"mcp",
				&crate::security_events::UiSecurityAuditSink,
			)
			.map_err(|error| UpstreamError::InvalidRequest(error_message(error)));
		},
	};
	match arguments {
		Some(arguments) => {
			if let Some(egress) = &config.data_egress {
				let destination = format!("{mcp_server_id}/{}", action.resource.id);
				security_integration_runtime::check_data_egress(
					egress,
					&action,
					&destination,
					&crate::security_events::UiSecurityAuditSink,
				)
				.map_err(|error| UpstreamError::InvalidRequest(error_message(error)))?;
			}
			let capability = security_integration_runtime::authorize_tool_with_capability_with_audit(
				config,
				&action,
				&arguments,
				&crate::security_events::UiSecurityAuditSink,
			)
			.map_err(|error| UpstreamError::InvalidRequest(error_message(error)))?;
			if let Some(capability) = capability {
				let capability = ::http::HeaderValue::from_str(&capability.token).map_err(|_| {
					UpstreamError::InvalidRequest("capability broker returned an invalid token".into())
				})?;
				let context_header = serde_json::to_vec(&action)
					.map(|bytes| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes))
					.map_err(|_| {
						UpstreamError::InvalidRequest("unable to encode capability action context".into())
					})?;
				let context_header = ::http::HeaderValue::from_str(&context_header).map_err(|_| {
					UpstreamError::InvalidRequest(format!(
						"unable to construct {CAPABILITY_CONTEXT_HEADER} header"
					))
				})?;
				context.extensions_mut().insert(IssuedCapability {
					capability,
					context: context_header,
				});
			}
			Ok(())
		},
		None => security_integration_runtime::evaluate_with_audit(
			config,
			&action,
			None,
			&crate::security_events::UiSecurityAuditSink,
		)
		.map_err(|error| UpstreamError::InvalidRequest(error_message(error))),
	}
}

pub(crate) fn identity_from_context(context: &IncomingRequestContext) -> GatewayIdentity {
	let request = context.as_request();
	let Some(claims) = request.extensions().get::<crate::http::jwt::Claims>() else {
		return GatewayIdentity::default();
	};
	GatewayIdentity {
		user_id: string_claim(&claims.inner, &["sub", "user_id", "userId"]),
		agent_id: string_claim(&claims.inner, &["agent_id", "agentId"]),
		tenant_id: string_claim(&claims.inner, &["tenant_id", "tenantId"]),
		delegation_id: string_claim(&claims.inner, &["delegation_id", "delegationId"]),
		session_id: string_claim(&claims.inner, &["sid", "session_id", "sessionId"]),
		client_id: string_claim(&claims.inner, &["azp", "client_id", "clientId"]),
	}
}

fn string_claim(
	claims: &serde_json::Map<String, serde_json::Value>,
	names: &[&str],
) -> Option<String> {
	names.iter().find_map(|name| {
		claims
			.get(*name)
			.and_then(serde_json::Value::as_str)
			.map(ToOwned::to_owned)
	})
}

fn error_message(error: GatewayError) -> String {
	match error {
		GatewayError::Denied(decision) => format!(
			"security policy denied request{}",
			decision
				.policy_id
				.as_deref()
				.map(|id| format!(" by '{id}'"))
				.unwrap_or_default()
		),
		GatewayError::DeniedByControl { denial, .. } => {
			format!(
				"security control '{}' denied request: {}",
				denial.control_id, denial.reason
			)
		},
		GatewayError::Capability(error) => format!("capability validation failed: {error:?}"),
		GatewayError::CapabilityUnavailable => "capability broker is not configured".to_string(),
	}
}
