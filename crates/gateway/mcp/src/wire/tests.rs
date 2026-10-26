use super::*;
use serde_json::json;
#[test]
fn reverse_decoding_preserves_security_relevant_params_without_sdk_field_loss() {
	for method in ["roots/list", "sampling/createMessage"] {
		let value = json!({"jsonrpc":"2.0","id":"upstream","method":method,"params":{"unexpected":"must-be-validated","_meta":{"binding":"task"}}});
		let decoded = decode_server(value.clone()).unwrap();
		assert_eq!(serde_json::to_value(decoded).unwrap(), value);
	}
}
#[test]
fn reverse_decoder_rejects_invalid_id_role_and_params() {
	let base = json!({"jsonrpc":"2.0","id":1,"method":"sampling/createMessage","params":{}});
	for (field, value) in [
		("id", json!(null)),
		("id", json!(true)),
		("jsonrpc", json!("1.0")),
		("result", json!({})),
		("error", json!({})),
		("params", json!([])),
		("params", json!(null)),
	] {
		let mut changed = base.clone();
		changed[field] = value;
		assert!(decode_server(changed).is_err(), "{field}");
	}
}
#[test]
fn legacy_result_projection_drops_modern_cache_and_result_fields() {
	let value = json!({"jsonrpc":"2.0","id":1,"result":{"resultType":"complete","tools":[],"ttlMs":60,"cacheScope":"public"}});
	let message: ServerJsonRpcMessage = serde_json::from_value(value.clone()).unwrap();
	assert_eq!(
		serde_json::to_value(normalize_outbound_for_protocol(message.clone(), true)).unwrap(),
		value
	);
	let projected = serde_json::to_value(normalize_outbound_for_protocol(message, false)).unwrap();
	assert_eq!(
		projected,
		json!({"jsonrpc":"2.0","id":1,"result":{"tools":[]}})
	);
}
