use async_trait::async_trait;
use regex::Regex;

use super::api::{
	GuardrailDecision, RequestContext, ResponseContext, SafetyAction, SafetyCategory, SafetyLevel,
	ToolCallContext, VehicleGuardrails,
};
use super::policy::{GuardrailsConfig, ToolRule};
use super::vehicle::VehicleState;

pub struct HybridGuardrails {
	config: GuardrailsConfig,
	request_rules: Vec<CompiledRequestRule>,
	response_rules: Vec<CompiledResponseRule>,
}

struct CompiledRequestRule {
	name: String,
	pattern: Regex,
}

struct CompiledResponseRule {
	name: String,
	pattern: Regex,
}

impl HybridGuardrails {
	pub fn new(config: GuardrailsConfig) -> anyhow::Result<Self> {
		let mut request_rules = Vec::new();
		for rule in &config.request_rules {
			request_rules.push(CompiledRequestRule {
				name: rule.name.clone(),
				pattern: Regex::new(&rule.pattern)?,
			});
		}
		let mut response_rules = Vec::new();
		for rule in &config.response_rules {
			response_rules.push(CompiledResponseRule {
				name: rule.name.clone(),
				pattern: Regex::new(&rule.pattern)?,
			});
		}
		Ok(Self {
			config,
			request_rules,
			response_rules,
		})
	}

	fn tool_rule(&self, tool_name: &str) -> Option<&ToolRule> {
		self
			.config
			.tool_rules
			.iter()
			.find(|rule| rule.name == tool_name)
	}
}

#[async_trait]
impl VehicleGuardrails for HybridGuardrails {
	async fn check_request(
		&self,
		ctx: &RequestContext,
		_vehicle: &VehicleState,
	) -> GuardrailDecision {
		for rule in &self.request_rules {
			if rule.pattern.is_match(&ctx.prompt) {
				return GuardrailDecision::Reject {
					reason: format!("request matched guardrail rule '{}'", rule.name),
					action: SafetyAction::Block,
				};
			}
		}
		GuardrailDecision::Allow
	}

	async fn check_tool_call(
		&self,
		ctx: &ToolCallContext,
		vehicle: &VehicleState,
	) -> GuardrailDecision {
		let Some(rule) = self.tool_rule(&ctx.name) else {
			// Unknown tools are denied by default in vehicle mode.
			return GuardrailDecision::Reject {
				reason: format!("tool '{}' is not declared in guardrail policy", ctx.name),
				action: SafetyAction::Block,
			};
		};

		if !rule.allowed {
			return GuardrailDecision::Reject {
				reason: format!("tool '{}' is denied by guardrail policy", ctx.name),
				action: SafetyAction::Block,
			};
		}

		if let Some(max_speed_kmh) = rule.max_speed_kmh
			&& vehicle.speed_kmh > max_speed_kmh
		{
			let level = if matches!(vehicle.safety_mode, super::vehicle::SafetyMode::Emergency) {
				SafetyLevel::L4
			} else {
				rule.level
			};
			let decision = if level == SafetyLevel::L4 {
				GuardrailDecision::FailSafe {
					reason: format!(
						"tool '{}' is not allowed above {} km/h; current speed {} km/h",
						ctx.name, max_speed_kmh, vehicle.speed_kmh
					),
				}
			} else {
				GuardrailDecision::RequireApproval {
					reason: format!(
						"tool '{}' requires approval above {} km/h; current speed {} km/h",
						ctx.name, max_speed_kmh, vehicle.speed_kmh
					),
				}
			};
			return decision;
		}

		GuardrailDecision::Allow
	}

	async fn check_response(
		&self,
		ctx: &ResponseContext,
		_vehicle: &VehicleState,
	) -> GuardrailDecision {
		for rule in &self.response_rules {
			if rule.pattern.is_match(&ctx.content) {
				return GuardrailDecision::Reject {
					reason: format!("response matched guardrail rule '{}'", rule.name),
					action: SafetyAction::Block,
				};
			}
		}
		GuardrailDecision::Allow
	}
}

// Silence unused category warning in this module; categories are used by SafetyEvent constructors.
#[allow(dead_code)]
fn _safety_categories() -> (SafetyCategory, SafetyAction) {
	(SafetyCategory::ToolCall, SafetyAction::Block)
}
