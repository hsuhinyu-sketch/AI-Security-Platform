use security_types::{ActionRequest, ActionType, DecisionEffect, ResourceType};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Policy {
	pub id: String,
	#[serde(default)]
	pub priority: i32,
	pub tenant_id: Option<String>,
	pub user_id: Option<String>,
	pub agent_id: Option<String>,
	pub action_type: Option<ActionType>,
	pub action_name: Option<String>,
	pub resource_id: Option<String>,
	pub resource_type: Option<ResourceType>,
	pub effect: DecisionEffect,
	pub enabled: bool,
}

impl Policy {
	pub fn matches(&self, request: &ActionRequest) -> bool {
		if !self.enabled {
			return false;
		}
		if self
			.tenant_id
			.as_deref()
			.is_some_and(|v| request.subject.tenant_id.as_deref() != Some(v))
		{
			return false;
		}
		if self
			.user_id
			.as_deref()
			.is_some_and(|v| request.subject.user_id.as_deref() != Some(v))
		{
			return false;
		}
		if self
			.agent_id
			.as_deref()
			.is_some_and(|v| request.subject.agent_id.as_deref() != Some(v))
		{
			return false;
		}
		if self
			.action_type
			.is_some_and(|v| request.action.action_type != v)
		{
			return false;
		}
		if self
			.action_name
			.as_deref()
			.is_some_and(|v| request.action.name != v)
		{
			return false;
		}
		if self
			.resource_id
			.as_deref()
			.is_some_and(|v| request.resource.id != v)
		{
			return false;
		}
		if self
			.resource_type
			.is_some_and(|v| request.resource.resource_type != v)
		{
			return false;
		}
		true
	}
}

pub fn evaluate<'a>(policies: &'a [Policy], request: &ActionRequest) -> Option<&'a Policy> {
	// A matching deny always wins. Within the same effect, the highest priority wins;
	// declaration order is retained as the deterministic tie-breaker.
	let highest_priority = |effect| {
		policies
			.iter()
			.filter(|policy| policy.effect == effect && policy.matches(request))
			.fold(None::<&Policy>, |selected, policy| match selected {
				Some(current) if current.priority >= policy.priority => Some(current),
				_ => Some(policy),
			})
	};

	highest_priority(DecisionEffect::Deny).or_else(|| highest_priority(DecisionEffect::Allow))
}
