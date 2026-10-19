use security_policy::{Policy, evaluate};
use security_types::{ActionRequest, Decision, DecisionEffect};

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
