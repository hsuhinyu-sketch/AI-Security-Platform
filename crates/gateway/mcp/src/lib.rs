//! MCP operation semantics, independent of gateway transport and policy execution.
pub mod capabilities;
pub mod discovery;
pub mod execution;
pub mod merge;
#[cfg(feature = "openapi")]
pub mod openapi;
pub mod protocol;
pub mod reverse;
pub mod routing;
pub mod sampling;
pub mod streamable_http;
pub mod transport;
pub mod wire;
use rmcp::model::{ClientRequest, ConstString, JsonRpcRequest};
use security_pipeline::{GatewayIdentity, tool_invoke_for_identity, tool_list};
use security_types::ResourceType;

pub fn notification_method(notification: &rmcp::model::ClientNotification) -> &str {
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

/// Discovery and lists fan out; check permissions and egress for each selected server.
pub fn is_discovery_list(request: &ClientRequest) -> bool {
	matches!(
		request.method().to_string().as_str(),
		"server/discover"
			| "tools/list"
			| "resources/list"
			| "resources/templates/list"
			| "prompts/list"
	)
}

/// One normalized description shared by authorization, egress and stream rechecks.
/// The wire RPC ID is deliberately not part of the security identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OperationKind {
	Control,
	Tool,
	List,
	Object,
	Unsupported,
}

pub struct NormalizedOperation {
	pub action: security_types::ActionRequest,
	pub arguments: Option<serde_json::Value>,
	pub kind: OperationKind,
}

pub fn normalize(
	request: &JsonRpcRequest<ClientRequest>,
	request_id: &str,
	identity: GatewayIdentity,
	server: &str,
) -> NormalizedOperation {
	let method = request.request.method().to_string();
	let (kind, resource, id) = match &request.request {
		ClientRequest::CallToolRequest(call) => {
			return NormalizedOperation {
				action: tool_invoke_for_identity(request_id, identity, call.params.name.to_string()),
				arguments: Some(serde_json::Value::Object(
					call.params.arguments.clone().unwrap_or_default(),
				)),
				kind: OperationKind::Tool,
			};
		},
		ClientRequest::ListToolsRequest(_) => {
			return NormalizedOperation {
				action: tool_list(request_id, identity, server),
				arguments: None,
				kind: OperationKind::List,
			};
		},
		ClientRequest::InitializeRequest(_) | ClientRequest::PingRequest(_) => (
			OperationKind::Control,
			ResourceType::McpServer,
			server.to_owned(),
		),
		ClientRequest::GetTaskRequest(_)
		| ClientRequest::GetTaskPayloadRequest(_)
		| ClientRequest::CancelTaskRequest(_) => (
			OperationKind::Object,
			ResourceType::McpServer,
			server.to_owned(),
		),
		ClientRequest::DiscoverRequest(_) => (
			OperationKind::Object,
			ResourceType::McpServer,
			server.to_owned(),
		),
		ClientRequest::ReadResourceRequest(call) => (
			OperationKind::Object,
			ResourceType::McpResource,
			security_pipeline::mcp_object_id(server, &call.params.uri),
		),
		ClientRequest::SubscribeRequest(call) => (
			OperationKind::Object,
			ResourceType::McpResource,
			security_pipeline::mcp_object_id(server, &call.params.uri),
		),
		ClientRequest::UnsubscribeRequest(call) => (
			OperationKind::Object,
			ResourceType::McpResource,
			security_pipeline::mcp_object_id(server, &call.params.uri),
		),
		ClientRequest::GetPromptRequest(call) => (
			OperationKind::Object,
			ResourceType::McpPrompt,
			security_pipeline::mcp_object_id(server, &call.params.name),
		),
		_ if is_discovery_list(&request.request) => (
			OperationKind::Object,
			ResourceType::McpServer,
			server.to_owned(),
		),
		_ => (
			OperationKind::Unsupported,
			ResourceType::McpServer,
			server.to_owned(),
		),
	};
	NormalizedOperation {
		action: security_pipeline::mcp_operation_for_identity(
			request_id, identity, method, resource, id,
		),
		arguments: None,
		kind,
	}
}

#[cfg(test)]
mod tests;
