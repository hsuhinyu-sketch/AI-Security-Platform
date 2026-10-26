use super::*;

#[cfg(feature = "schema")]
#[test]
fn host_cost_schema_keeps_existing_names_and_numeric_fields() {
	use schemars::JsonSchema;
	assert_eq!(Breakdown::schema_name(), "CostBreakdown");
	let schema = serde_json::to_value(schemars::schema_for!(Breakdown)).unwrap();
	for name in [
		"total",
		"input",
		"output",
		"cacheRead",
		"cacheWrite",
		"reasoning",
		"inputAudio",
		"outputAudio",
	] {
		assert_eq!(schema["properties"][name]["type"], "number", "{name}");
	}
	assert_eq!(schema["additionalProperties"], false);
}

#[test]
fn shared_cost_values_preserve_json_and_lazy_cel() {
	use ::cel::types::dynamic::DynamicType;
	let wire = serde_json::json!({"total":28.0,"input":1.0,"output":2.0,
		"cacheRead":3.0,"cacheWrite":4.0,"reasoning":5.0,"inputAudio":6.0,"outputAudio":7.0});
	let cost: Breakdown = serde_json::from_value(wire.clone()).unwrap();
	assert_eq!(serde_json::to_value(&cost).unwrap(), wire);
	for (name, expected) in wire.as_object().unwrap() {
		assert_eq!(
			cost.field(name),
			Some(::cel::Value::from(expected.as_f64().unwrap()))
		);
	}
	assert!(cost.field("cache_read").is_none());
	assert!(cost.field("unknown").is_none());
}

#[test]
fn observation_values_keep_provider_identity_response_usage_and_lazy_prompt() {
	use crate::llm::{CacheTokenConvention, InputFormat, LLMInfo, LLMRequest, LLMResponse};
	use std::sync::Arc;
	let prompt = Arc::new(vec![crate::llm::SimpleChatCompletionMessage {
		role: "user".into(),
		content: "private prompt".into(),
	}]);
	let info = LLMInfo::new(
		LLMRequest {
			input_tokens: Some(2),
			input_format: InputFormat::Messages,
			native_format: None,
			cache_convention: CacheTokenConvention::InputIncludesCache,
			request_model: "requested-model".into(),
			provider: "configured-provider".into(),
			streaming: true,
			params: Default::default(),
			prompt: Some(prompt.clone()),
			provider_state: None,
		},
		LLMResponse {
			input_tokens: Some(17),
			output_tokens: Some(3),
			provider_model: Some("served-model".into()),
			..Default::default()
		},
	);
	let context = crate::cel::LLMContext::from(info);
	assert_eq!(context.input_tokens, Some(17));
	assert_eq!(context.output_tokens, Some(3));
	assert!(Arc::ptr_eq(context.prompt.as_ref().unwrap(), &prompt));
	assert!(context.cost.is_none() && context.cost_rates.is_none() && context.cost_status.is_none());
	let executor = crate::cel::Executor::new_llm_rate_limit_streaming(None, &context);
	let expression = crate::cel::Expression::new_strict(
		"llm.provider == 'configured-provider' && llm.requestModel == 'requested-model' && llm.responseModel == 'served-model' && !has(llm.cost)"
	).unwrap();
	assert!(executor.eval_bool(&expression));
}
