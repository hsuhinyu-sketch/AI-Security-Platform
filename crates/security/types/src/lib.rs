use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Ordered sensitivity used by data-flow controls. Legacy/missing metadata defaults to the
/// most restrictive class, so an old or incomplete index entry cannot silently downgrade data.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "camelCase")]
pub enum DataClassification {
	Public,
	Internal,
	#[default]
	Restricted,
}

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
	/// Accept a document into a knowledge corpus before chunking and indexing.
	KnowledgeIngest,
	/// Search a knowledge corpus and select document chunks for an AI context.
	KnowledgeRetrieve,
	/// Assemble already-authorized knowledge chunks into an LLM context.
	ContextAssemble,
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
	KnowledgeBase,
	Document,
	DocumentChunk,
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
	/// Version of the dynamic policy bundle that produced this decision, when applicable.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub policy_version: Option<String>,
	/// The latest instant at which an allow decision may be reused.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub expires_at: Option<DateTime<Utc>>,
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
	pub policy_version: Option<String>,
	pub decision_expires_at: Option<DateTime<Utc>>,
	pub timestamp: DateTime<Utc>,
}
