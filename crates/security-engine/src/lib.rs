use security_contracts::{ActionRequest, Decision, DecisionEffect};
use security_policy::{Policy, evaluate};

pub fn decide(policies: &[Policy], request: &ActionRequest) -> Decision {
	match evaluate(policies, request) {
		Some(policy) => Decision {
			request_id: request.request_id.clone(),
			effect: policy.effect,
			policy_id: Some(policy.id.clone()),
			policy_version: None,
			expires_at: None,
		},
		None => Decision {
			request_id: request.request_id.clone(),
			// Protected resources are fail-closed unless a policy explicitly allows them.
			effect: DecisionEffect::Deny,
			policy_id: None,
			policy_version: None,
			expires_at: None,
		},
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use security_contracts::{Action, ActionType, Resource, ResourceType, Subject};

	#[test]
	fn deny_matching_tool_call() {
		let request = ActionRequest {
			request_id: "req-1".into(),
			subject: Subject {
				user_id: Some("alice".into()),
				agent_id: None,
				tenant_id: Some("tenant-a".into()),
				delegation_id: None,
			},
			action: Action {
				action_type: ActionType::ToolInvoke,
				name: "db.delete".into(),
			},
			resource: Resource {
				id: "prod-db".into(),
				resource_type: ResourceType::Tool,
			},
			authorization_context: Default::default(),
		};
		let policies = vec![Policy {
			id: "deny-prod-delete".into(),
			priority: 0,
			tenant_id: Some("tenant-a".into()),
			user_id: Some("alice".into()),
			agent_id: None,
			action_type: Some(ActionType::ToolInvoke),
			action_name: Some("db.delete".into()),
			resource_id: Some("prod-db".into()),
			resource_type: Some(ResourceType::Tool),
			effect: DecisionEffect::Deny,
			enabled: true,
		}];
		assert_eq!(decide(&policies, &request).effect, DecisionEffect::Deny);
	}

	#[test]
	fn deny_wins_over_a_matching_allow() {
		let request = ActionRequest {
			request_id: "req-2".into(),
			subject: Subject {
				user_id: Some("alice".into()),
				agent_id: None,
				tenant_id: None,
				delegation_id: None,
			},
			action: Action {
				action_type: ActionType::ToolInvoke,
				name: "db.delete".into(),
			},
			resource: Resource {
				id: "prod-db".into(),
				resource_type: ResourceType::Tool,
			},
			authorization_context: Default::default(),
		};
		let policies = vec![
			Policy {
				id: "allow-tools".into(),
				priority: 100,
				tenant_id: None,
				user_id: Some("alice".into()),
				agent_id: None,
				action_type: Some(ActionType::ToolInvoke),
				action_name: None,
				resource_id: None,
				resource_type: Some(ResourceType::Tool),
				effect: DecisionEffect::Allow,
				enabled: true,
			},
			Policy {
				id: "deny-delete".into(),
				priority: 1,
				tenant_id: None,
				user_id: Some("alice".into()),
				agent_id: None,
				action_type: Some(ActionType::ToolInvoke),
				action_name: Some("db.delete".into()),
				resource_id: None,
				resource_type: Some(ResourceType::Tool),
				effect: DecisionEffect::Deny,
				enabled: true,
			},
		];

		let decision = decide(&policies, &request);
		assert_eq!(decision.effect, DecisionEffect::Deny);
		assert_eq!(decision.policy_id.as_deref(), Some("deny-delete"));
	}

	#[test]
	fn unmatched_requests_are_denied() {
		let request = ActionRequest {
			request_id: "req-3".into(),
			subject: Subject {
				user_id: None,
				agent_id: None,
				tenant_id: None,
				delegation_id: None,
			},
			action: Action {
				action_type: ActionType::ModelInvoke,
				name: "invoke".into(),
			},
			resource: Resource {
				id: "model-a".into(),
				resource_type: ResourceType::Model,
			},
			authorization_context: Default::default(),
		};

		assert_eq!(decide(&[], &request).effect, DecisionEffect::Deny);
	}
}
