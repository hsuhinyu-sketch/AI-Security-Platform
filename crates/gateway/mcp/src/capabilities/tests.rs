use super::*;
use serde_json::json;

#[test]
fn protected_projection_preserves_only_admitted_base_capabilities() {
	for (stateful, subscribe) in [
		(false, None),
		(false, Some(false)),
		(false, Some(true)),
		(true, None),
		(true, Some(false)),
		(true, Some(true)),
	] {
		let mut capabilities: ServerCapabilities = serde_json::from_value(json!({
			"resources":{"subscribe":subscribe,"listChanged":true},
			"tools":{"listChanged":true},"prompts":{"listChanged":true},
			"tasks":{"requests":{"tools":{"call":{}}}},
			"logging":{},"completions":{},"experimental":{"vendor":{}},"extensions":{"vendor":{}}
		}))
		.unwrap();
		restrict_session_capabilities(&mut capabilities, stateful);
		let resources = if let Some(value) = subscribe.filter(|_| stateful) {
			json!({"subscribe":value})
		} else {
			json!({})
		};
		assert_eq!(
			serde_json::to_value(&capabilities).unwrap(),
			json!({"resources":resources,"tools":{},"prompts":{}})
		);
		let once = capabilities.clone();
		restrict_session_capabilities(&mut capabilities, stateful);
		assert_eq!(
			serde_json::to_value(capabilities).unwrap(),
			serde_json::to_value(once).unwrap()
		);
	}
	let mut empty = ServerCapabilities::default();
	restrict_session_capabilities(&mut empty, true);
	assert_eq!(serde_json::to_value(empty).unwrap(), json!({}));
}
