use super::*;
use serde_json::json;

fn schema() -> Value {
	json!({"type":"object","properties":{
		"answer":{"type":"string","minLength":1,"maxLength":4,"enum":["yes","no"]},
		"count":{"type":"integer","minimum":1,"maximum":3}},"required":["answer"],"additionalProperties":false})
}

#[test]
fn form_contract_restricts_fields_schema_size_and_response_values() {
	let params = json!({"message":"continue?","requestedSchema":schema()});
	assert!(valid_form_request(
		&params,
		&["answer".into(), "count".into()]
	));
	assert!(!valid_form_request(&params, &["answer".into()]));
	for patch in [
		json!({"mode":"url"}),
		json!({"unknown":true}),
		json!({"message":"a".repeat(8193)}),
	] {
		let mut changed = params.clone();
		changed
			.as_object_mut()
			.unwrap()
			.extend(patch.as_object().unwrap().clone());
		assert!(!valid_form_request(
			&changed,
			&["answer".into(), "count".into()]
		));
	}
	for content in [json!({"answer":"yes"}), json!({"answer":"no","count":2})] {
		assert!(valid_form_response(
			&json!({"action":"accept","content":content}),
			&schema()
		));
	}
	for content in [
		json!({}),
		json!({"answer":"maybe"}),
		json!({"answer":"yes","count":1.5}),
		json!({"answer":"yes","count":4}),
		json!({"answer":"yes","secret":"leak"}),
	] {
		assert!(!valid_form_response(
			&json!({"action":"accept","content":content}),
			&schema()
		));
	}
	assert!(valid_form_response(&json!({"action":"cancel"}), &schema()));
	assert!(!valid_form_response(
		&json!({"action":"decline","content":{}}),
		&schema()
	));
}

#[test]
fn schema_rejects_nested_data_unbounded_fields_and_invalid_constraints() {
	for changed in [
		json!({"type":"object","properties":{"nested":{"type":"object"}}}),
		json!({"type":"object","properties":{},"required":["missing"]}),
		json!({"type":"object","properties":{"x":{"type":"string","maxLength":8193}}}),
		json!({"type":"object","properties":{},"additionalProperties":true}),
	] {
		assert!(!valid_schema(&changed));
	}
	let mut changed = schema();
	for i in 0..17 {
		changed["properties"][format!("field{i}")] = json!({"type":"string"});
	}
	assert!(!valid_schema(&changed));
}

#[test]
fn roots_validate_before_filtering_and_strip_untrusted_task_display_names() {
	let original = json!({"roots":[{"uri":"file:///approved","name":"untrusted display"},
		{"uri":"file:///secret","name":"secret"}],"_meta":{"trace":"keep"}});
	let mut result = original.clone();
	assert!(filter_roots_response(
		&mut result,
		&["file:///approved".into()],
		true
	));
	assert_eq!(result["roots"], json!([{"uri":"file:///approved"}]));
	let mut result = original;
	result["roots"][1]["extra"] = json!("denied");
	let before = result.clone();
	assert!(!filter_roots_response(
		&mut result,
		&["file:///approved".into()],
		false
	));
	assert_eq!(result, before);
	assert!(valid_roots_request(&json!({"_meta":{"trace":"keep"}})));
	assert!(!valid_roots_request(&json!({"uri":"file:///secret"})));
}

#[test]
fn sampling_response_only_allows_bounded_text_from_host_selected_models() {
	let original = json!({"role":"assistant","model":"local","content":{"type":"text","text":"answer"},"stopReason":"endTurn"});
	assert!(valid_sampling_response(&original, &["local".into()]));
	assert!(!valid_sampling_response(&original, &["other".into()]));
	for patch in [
		json!({"role":"user"}),
		json!({"extra":"leak"}),
		json!({"stopReason":"unknown"}),
		json!({"content":{"type":"text","text":"a".repeat(8193)}}),
		json!({"content":{"type":"image","data":"not-permitted"}}),
	] {
		let mut changed = original.clone();
		changed
			.as_object_mut()
			.unwrap()
			.extend(patch.as_object().unwrap().clone());
		assert!(!valid_sampling_response(&changed, &["local".into()]));
	}
}
