use std::sync::Arc;

use bytes::Bytes;

use crate::guardrails::{ResponseContext, VehicleGuardrails, VehicleState};
use crate::llm::policy::{FailureMode, StreamingEvaluator, StreamingGuardrailOutcome};

/// Adapter that runs vehicle response guardrails inside the existing streaming
/// SSE guardrail window pipeline.
pub struct VehicleStreamingResponseEvaluator {
	guardrails: Arc<dyn VehicleGuardrails>,
	model: String,
	vehicle_state: VehicleState,
}

impl VehicleStreamingResponseEvaluator {
	pub fn new(
		guardrails: Arc<dyn VehicleGuardrails>,
		model: impl Into<String>,
		vehicle_state: VehicleState,
	) -> Self {
		Self {
			guardrails,
			model: model.into(),
			vehicle_state,
		}
	}
}

#[async_trait::async_trait]
impl StreamingEvaluator for VehicleStreamingResponseEvaluator {
	fn failure_mode(&self) -> FailureMode {
		// Vehicle guardrails should fail closed by default.
		FailureMode::FailClosed
	}

	async fn evaluate(&mut self, window: &str) -> anyhow::Result<Option<StreamingGuardrailOutcome>> {
		let ctx = ResponseContext {
			content: window.to_string(),
			model: self.model.clone(),
		};
		let decision = self
			.guardrails
			.check_response(&ctx, &self.vehicle_state)
			.await;
		if decision.is_allowed() {
			return Ok(None);
		}

		let reason = match &decision {
			crate::guardrails::GuardrailDecision::Reject { reason, .. }
			| crate::guardrails::GuardrailDecision::RequireApproval { reason }
			| crate::guardrails::GuardrailDecision::FailSafe { reason }
			| crate::guardrails::GuardrailDecision::Mask { reason, .. }
			| crate::guardrails::GuardrailDecision::Defer { reason } => reason.clone(),
			crate::guardrails::GuardrailDecision::Allow => {
				unreachable!("allow decisions are not blocked")
			},
		};
		Ok(Some(StreamingGuardrailOutcome::Blocked(
			Bytes::copy_from_slice(reason.as_bytes()),
		)))
	}
}
