use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
pub mod a2a;
mod documents;
mod protocol;
pub use documents::{DocumentKey, DocumentVersion, DocumentVersionValidator};
pub use protocol::{CheckStage, RequestContext, SecurityFailureKind};

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
	DependencyInvoke,
	/// Creation/use of an execution budget; does not grant business operations.
	ExecutionOperation,
	ModelInvoke,
	InferenceRoute,
	AgentInvoke,
	/// Task lifecycle permission, in addition to AgentInvoke and ownership checks.
	AgentTaskOperation,
	/// Visibility of an artifact embedded in an authorized Task response.
	AgentArtifactRead,
	/// Fetch external artifact bytes; reading a Task or inline artifact does not grant this.
	AgentArtifactDownload,
	/// Read gateway-observed events; never grants a Task operation or upstream resubscription.
	AgentEventRecover,
	/// Manage or receive Task-scoped Gateway-terminated push channels.
	AgentPushOperation,
	ToolList,
	ToolInvoke,
	/// MCP resource/prompt operations; the exact protocol method is Action.name.
	McpOperation,
	/// MCP transport session lifecycle; does not grant Tool/Resource/Prompt permissions.
	McpSessionOperation,
	/// Async Tool Task lifecycle, in addition to the originating Tool permission.
	McpTaskOperation,
	/// Accept a document into a knowledge corpus before chunking and indexing.
	KnowledgeIngest,
	/// Search a knowledge corpus and select document chunks for an AI context.
	KnowledgeRetrieve,
	/// Assemble already-authorized knowledge chunks into an LLM context.
	ContextAssemble,
	/// Lifecycle control of identity-bound RAG security contexts, not content assembly.
	ContextOperation,
	KnowledgeDocumentOperation,
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
	DependencyEndpoint,
	Execution,
	Model,
	InferenceEndpoint,
	Agent,
	AgentTask,
	AgentArtifact,
	McpServer,
	McpSession,
	McpTask,
	Tool,
	McpResource,
	McpPrompt,
	KnowledgeBase,
	Document,
	DocumentChunk,
	SecurityContext,
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
