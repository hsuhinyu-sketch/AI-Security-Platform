use std::collections::HashMap;
use std::sync::Mutex;

use audit_core::{AuditSink, event_from_decision};
use chrono::{DateTime, Duration, Utc};
use security_contracts::{
	Action, ActionRequest, ActionType, AuthorizationContext, Decision, DecisionEffect, Resource,
	ResourceType, Subject,
};
use security_engine::decide;
use security_policy::Policy;
use sha2::{Digest, Sha256};
use uuid::Uuid;

pub mod pipeline;

pub use pipeline::{
	AgentDelegation, AgentDelegationConfig, ApprovalProvider, Authorizer, CachedDynamicPdp,
	ControlDenial, DecisionCache, DelegationRevocationCheck, DelegationRevocationError,
	DelegationRevocationProvider, DelegationRevocationRegistry, DelegationScope,
	DynamicAuthorizationConfig, DynamicPdp, DynamicPdpError, DynamicPdpFailureMode, DynamicPolicy,
	GatewayError, LocalDynamicPdp, PolicyAuthorizer, RemoteDynamicPdp, RemotePdpRequest,
	RemotePdpResponse, RemotePdpTransport, RequiredIdentity, RequiredToolApproval,
	RequiredToolApprovalConfig, RequiredToolArguments, RequiredToolArgumentsConfig, SecurityControl,
	SecurityPipeline, SecurityPipelineConfig, StaticAndDynamicAuthorizer, StaticApproval,
	ToolApproval,
};

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GatewayIdentity {
	pub user_id: Option<String>,
	pub agent_id: Option<String>,
	pub tenant_id: Option<String>,
	/// Correlates this request to a delegation grant carried by verified authentication.
	pub delegation_id: Option<String>,
	/// Session identifier carried by verified authentication, when available.
	pub session_id: Option<String>,
	/// OAuth client/application identifier carried by verified authentication, when available.
	pub client_id: Option<String>,
}

impl GatewayIdentity {
	fn authorization_context(&self) -> AuthorizationContext {
		AuthorizationContext {
			session_id: self.session_id.clone(),
			client_id: self.client_id.clone(),
		}
	}
}

impl From<GatewayIdentity> for Subject {
	fn from(value: GatewayIdentity) -> Self {
		Self {
			user_id: value.user_id,
			agent_id: value.agent_id,
			tenant_id: value.tenant_id,
			delegation_id: value.delegation_id,
		}
	}
}

pub fn model_invoke(
	request_id: impl Into<String>,
	user_id: Option<String>,
	agent_id: Option<String>,
	model_id: impl Into<String>,
) -> ActionRequest {
	model_invoke_for_identity(
		request_id,
		GatewayIdentity {
			user_id,
			agent_id,
			tenant_id: None,
			delegation_id: None,
			session_id: None,
			client_id: None,
		},
		model_id,
	)
}

pub fn model_invoke_for_identity(
	request_id: impl Into<String>,
	identity: GatewayIdentity,
	model_id: impl Into<String>,
) -> ActionRequest {
	let authorization_context = identity.authorization_context();
	ActionRequest {
		request_id: request_id.into(),
		subject: identity.into(),
		action: Action {
			action_type: ActionType::ModelInvoke,
			name: "invoke".into(),
		},
		resource: Resource {
			id: model_id.into(),
			resource_type: ResourceType::Model,
		},
		authorization_context,
	}
}

pub fn agent_invoke_for_identity(
	request_id: impl Into<String>,
	identity: GatewayIdentity,
	agent_id: impl Into<String>,
) -> ActionRequest {
	agent_action_for_identity(request_id, identity, agent_id, "invoke")
}

/// Normalizes an A2A JSON-RPC method into an authorization action.
pub fn agent_action_for_identity(
	request_id: impl Into<String>,
	identity: GatewayIdentity,
	agent_id: impl Into<String>,
	method: impl Into<String>,
) -> ActionRequest {
	let authorization_context = identity.authorization_context();
	ActionRequest {
		request_id: request_id.into(),
		subject: identity.into(),
		action: Action {
			action_type: ActionType::AgentInvoke,
			name: method.into(),
		},
		resource: Resource {
			id: agent_id.into(),
			resource_type: ResourceType::Agent,
		},
		authorization_context,
	}
}

pub fn inference_route_for_identity(
	request_id: impl Into<String>,
	identity: GatewayIdentity,
	endpoint_picker: impl Into<String>,
) -> ActionRequest {
	let authorization_context = identity.authorization_context();
	ActionRequest {
		request_id: request_id.into(),
		subject: identity.into(),
		action: Action {
			action_type: ActionType::InferenceRoute,
			name: "select-destination".into(),
		},
		resource: Resource {
			id: endpoint_picker.into(),
			resource_type: ResourceType::InferenceEndpoint,
		},
		authorization_context,
	}
}

pub fn tool_invoke(
	request_id: impl Into<String>,
	user_id: Option<String>,
	agent_id: Option<String>,
	tool_name: impl Into<String>,
) -> ActionRequest {
	tool_invoke_for_identity(
		request_id,
		GatewayIdentity {
			user_id,
			agent_id,
			tenant_id: None,
			delegation_id: None,
			session_id: None,
			client_id: None,
		},
		tool_name,
	)
}

pub fn tool_invoke_for_identity(
	request_id: impl Into<String>,
	identity: GatewayIdentity,
	tool_name: impl Into<String>,
) -> ActionRequest {
	let tool_name = tool_name.into();
	let authorization_context = identity.authorization_context();
	ActionRequest {
		request_id: request_id.into(),
		subject: identity.into(),
		action: Action {
			action_type: ActionType::ToolInvoke,
			name: tool_name.clone(),
		},
		resource: Resource {
			id: tool_name,
			resource_type: ResourceType::Tool,
		},
		authorization_context,
	}
}

pub fn tool_list(
	request_id: impl Into<String>,
	identity: GatewayIdentity,
	mcp_server_id: impl Into<String>,
) -> ActionRequest {
	let authorization_context = identity.authorization_context();
	ActionRequest {
		request_id: request_id.into(),
		subject: identity.into(),
		action: Action {
			action_type: ActionType::ToolList,
			name: "list".into(),
		},
		resource: Resource {
			id: mcp_server_id.into(),
			resource_type: ResourceType::McpServer,
		},
		authorization_context,
	}
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Capability {
	pub token: String,
	pub request_id: String,
	pub subject: Subject,
	pub action: Action,
	pub resource: Resource,
	pub arguments_hash: String,
	pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CapabilityError {
	NotFound,
	Expired,
	RequestMismatch,
	ArgumentsMismatch,
}

/// Issues opaque, short-lived, one-time capabilities after authorization.
/// The Agent receives no downstream credential: a Tool-side enforcer must consume the
/// capability before executing the action.
#[derive(Default)]
pub struct CapabilityBroker {
	capabilities: Mutex<HashMap<String, Capability>>,
}

impl CapabilityBroker {
	pub fn issue(
		&self,
		request: &ActionRequest,
		arguments: &serde_json::Value,
		ttl: Duration,
	) -> Capability {
		let capability = Capability {
			token: Uuid::new_v4().to_string(),
			request_id: request.request_id.clone(),
			subject: request.subject.clone(),
			action: request.action.clone(),
			resource: request.resource.clone(),
			arguments_hash: arguments_hash(arguments),
			expires_at: Utc::now() + ttl,
		};
		self
			.capabilities
			.lock()
			.expect("capability broker lock poisoned")
			.insert(capability.token.clone(), capability.clone());
		capability
	}

	pub fn consume(
		&self,
		token: &str,
		request: &ActionRequest,
		arguments: &serde_json::Value,
	) -> Result<Capability, CapabilityError> {
		// Remove before validation so a capability is single-use even after a failed replay.
		let capability = self
			.capabilities
			.lock()
			.expect("capability broker lock poisoned")
			.remove(token)
			.ok_or(CapabilityError::NotFound)?;
		if Utc::now() >= capability.expires_at {
			return Err(CapabilityError::Expired);
		}
		if capability.request_id != request.request_id
			|| capability.subject != request.subject
			|| capability.action != request.action
			|| capability.resource != request.resource
		{
			return Err(CapabilityError::RequestMismatch);
		}
		if capability.arguments_hash != arguments_hash(arguments) {
			return Err(CapabilityError::ArgumentsMismatch);
		}
		Ok(capability)
	}
}

fn arguments_hash(arguments: &serde_json::Value) -> String {
	let bytes = serde_json::to_vec(arguments).expect("JSON values serialize");
	Sha256::digest(bytes)
		.iter()
		.map(|byte| format!("{byte:02x}"))
		.collect()
}

/// Security enforcement facade used by an LLM/MCP request path.
/// It produces an audit event for every decision and only issues a capability after ALLOW.
pub struct SecurityGateway<S> {
	policies: Vec<Policy>,
	audit: S,
	capabilities: CapabilityBroker,
}

impl<S: AuditSink> SecurityGateway<S> {
	pub fn new(policies: Vec<Policy>, audit: S) -> Self {
		Self {
			policies,
			audit,
			capabilities: CapabilityBroker::default(),
		}
	}

	pub fn authorize(&self, request: &ActionRequest) -> Decision {
		let decision = decide(&self.policies, request);
		self.audit.record(event_from_decision(
			Uuid::new_v4().to_string(),
			request,
			&decision,
		));
		decision
	}

	pub fn authorize_tool(
		&self,
		request: &ActionRequest,
		arguments: &serde_json::Value,
		ttl: Duration,
	) -> Result<Capability, GatewayError> {
		let decision = self.authorize(request);
		if decision.effect == DecisionEffect::Deny {
			return Err(GatewayError::Denied(decision));
		}
		Ok(self.capabilities.issue(request, arguments, ttl))
	}

	pub fn consume_tool_capability(
		&self,
		token: &str,
		request: &ActionRequest,
		arguments: &serde_json::Value,
	) -> Result<Capability, GatewayError> {
		self
			.capabilities
			.consume(token, request, arguments)
			.map_err(GatewayError::Capability)
	}
}

#[cfg(test)]
mod tests {
	use audit_core::InMemoryAuditSink;
	use security_contracts::DecisionEffect;

	use super::*;

	fn allow_delete_policy() -> Policy {
		Policy {
			id: "allow-alice-delete".into(),
			priority: 10,
			tenant_id: Some("tenant-a".into()),
			user_id: Some("alice".into()),
			agent_id: Some("maintenance-agent".into()),
			action_type: Some(ActionType::ToolInvoke),
			action_name: Some("db.delete".into()),
			resource_id: Some("prod-db".into()),
			resource_type: Some(ResourceType::Tool),
			effect: DecisionEffect::Allow,
			enabled: true,
		}
	}

	fn delete_request() -> ActionRequest {
		ActionRequest {
			request_id: "request-1".into(),
			subject: GatewayIdentity {
				user_id: Some("alice".into()),
				agent_id: Some("maintenance-agent".into()),
				tenant_id: Some("tenant-a".into()),
				delegation_id: None,
				session_id: None,
				client_id: None,
			}
			.into(),
			action: Action {
				action_type: ActionType::ToolInvoke,
				name: "db.delete".into(),
			},
			resource: Resource {
				id: "prod-db".into(),
				resource_type: ResourceType::Tool,
			},
			authorization_context: Default::default(),
		}
	}

	#[test]
	fn capability_is_bound_to_the_authorized_tool_call_and_audited() {
		let audit = InMemoryAuditSink::default();
		let gateway = SecurityGateway::new(vec![allow_delete_policy()], &audit);
		let request = delete_request();
		let arguments = serde_json::json!({ "recordId": "42" });

		let capability = gateway
			.authorize_tool(&request, &arguments, Duration::seconds(30))
			.unwrap();
		assert!(
			gateway
				.consume_tool_capability(&capability.token, &request, &arguments)
				.is_ok()
		);
		assert_eq!(
			gateway.consume_tool_capability(&capability.token, &request, &arguments),
			Err(GatewayError::Capability(CapabilityError::NotFound))
		);

		let events = audit.events();
		assert_eq!(events.len(), 1);
		assert_eq!(events[0].decision, DecisionEffect::Allow);
		assert_eq!(events[0].subject.tenant_id.as_deref(), Some("tenant-a"));
	}

	#[test]
	fn changed_arguments_cannot_consume_a_capability() {
		let audit = InMemoryAuditSink::default();
		let gateway = SecurityGateway::new(vec![allow_delete_policy()], audit);
		let request = delete_request();
		let capability = gateway
			.authorize_tool(
				&request,
				&serde_json::json!({ "recordId": "42" }),
				Duration::seconds(30),
			)
			.unwrap();

		assert_eq!(
			gateway.consume_tool_capability(
				&capability.token,
				&request,
				&serde_json::json!({ "recordId": "43" })
			),
			Err(GatewayError::Capability(CapabilityError::ArgumentsMismatch))
		);
	}

	#[test]
	fn unmatched_tool_request_is_denied_and_audited() {
		let audit = InMemoryAuditSink::default();
		let gateway = SecurityGateway::new(vec![allow_delete_policy()], &audit);
		let mut request = delete_request();
		request.subject.tenant_id = Some("tenant-b".into());

		assert!(matches!(
			gateway.authorize_tool(&request, &serde_json::json!({}), Duration::seconds(30)),
			Err(GatewayError::Denied(_))
		));
		assert_eq!(audit.events()[0].decision, DecisionEffect::Deny);
	}
}
