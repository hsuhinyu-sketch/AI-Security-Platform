use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Subject {
	pub user_id: Option<String>,
	pub agent_id: Option<String>,
	/// Tenant boundary carried end-to-end with an AI action request.
	pub tenant_id: Option<String>,
	/// Identifier of the verified grant that lets `agent_id` act for `user_id`.
	/// It is a correlation value, not a downstream credential.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub delegation_id: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum ActionType {
	ModelInvoke,
	InferenceRoute,
	AgentInvoke,
	ToolList,
	ToolInvoke,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Action {
	pub action_type: ActionType,
	pub name: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum ResourceType {
	Model,
	InferenceEndpoint,
	Agent,
	McpServer,
	Tool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Resource {
	pub id: String,
	pub resource_type: ResourceType,
}

/// Verified request attributes used to narrow a static permission at authorization time.
/// These fields are normalized by the gateway; callers must not supply them as arbitrary
/// Tool arguments or headers.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct AuthorizationContext {
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub session_id: Option<String>,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub client_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ActionRequest {
	pub request_id: String,
	pub subject: Subject,
	pub action: Action,
	pub resource: Resource,
	#[serde(default)]
	pub authorization_context: AuthorizationContext,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum DecisionEffect {
	Allow,
	Deny,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Decision {
	pub request_id: String,
	pub effect: DecisionEffect,
	pub policy_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SecurityEvent {
	pub event_id: String,
	pub request_id: String,
	pub subject: Subject,
	pub action: Action,
	pub resource: Resource,
	pub authorization_context: AuthorizationContext,
	pub decision: DecisionEffect,
	pub policy_id: Option<String>,
	pub timestamp: DateTime<Utc>,
}
