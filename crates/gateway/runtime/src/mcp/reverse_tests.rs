use super::*;

#[test]
fn sampling_negotiation_matches_compiled_model_execution() {
	let (access, parent) = setup();
	let config =
		serde_json::from_value(json!({"samplingModels":["local"],"roots":["file:///workspace"]}))
			.unwrap();
	let mut capabilities = serde_json::from_value(json!({"sampling":{},"roots":{}})).unwrap();
	negotiate(access.binding.as_ref().unwrap(), &config, &mut capabilities).unwrap();
	let value = serde_json::to_value(capabilities).unwrap();
	assert_eq!(
		value.get("sampling").is_some(),
		cfg!(feature = "gateway-llm")
	);
	assert!(value.get("roots").is_some());
	if !cfg!(feature = "gateway-llm") {
		let mut message = serde_json::from_value(json!({"jsonrpc":"2.0","id":9,"method":"sampling/createMessage","params":{"messages":[{"role":"user","content":{"type":"text","text":"hello"}}],"maxTokens":8}})).unwrap();
		assert!(request(&access, Some(&parent), &mut message).is_err());
	}
}

fn setup() -> (SessionAccess, ParentLease) {
	let mut access = super::super::tests::access();
	access.limits.reverse =
		Some(serde_json::from_value(json!({"roots":["file:///workspace"]})).unwrap());
	let mut caps = serde_json::from_value(json!({"roots":{}})).unwrap();
	negotiate(
		access.binding.as_ref().unwrap(),
		access.limits.reverse.as_ref().unwrap(),
		&mut caps,
	)
	.unwrap();
	let rpc: JsonRpcRequest<ClientRequest> = serde_json::from_value(
		json!({"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"echo","arguments":{}}}),
	)
	.unwrap();
	let op = crate::mcp::security::normalize(&rpc, "internal", access.identity.clone(), "tools");
	let parent = parent(
		&access,
		"tools",
		Some(&rpc),
		Some(Arc::new((op.action, op.arguments))),
	)
	.unwrap()
	.unwrap();
	(access, parent)
}
fn question(access: &SessionAccess, parent: &ParentLease) -> String {
	let mut message =
		serde_json::from_value(json!({"jsonrpc":"2.0","id":21,"method":"roots/list","params":{}}))
			.unwrap();
	request(access, Some(parent), &mut message).unwrap();
	serde_json::to_value(message).unwrap()["id"]
		.as_str()
		.unwrap()
		.to_owned()
}
fn answer(id: &str) -> ClientJsonRpcMessage {
	serde_json::from_value(json!({"jsonrpc":"2.0","id":id,"result":{"roots":[{"uri":"file:///workspace"},{"uri":"file:///private"}]}})).unwrap()
}

#[test]
fn reverse_response_is_single_use_and_bound_to_live_parent() {
	let (access, parent) = setup();
	let id = question(&access, &parent);
	let (server, forwarded, _, _) = response(&access, answer(&id)).unwrap();
	assert_eq!(server, "tools");
	let forwarded = serde_json::to_value(forwarded).unwrap();
	assert_eq!(forwarded["id"], 21);
	assert_eq!(forwarded["result"]["roots"].as_array().unwrap().len(), 1);
	assert!(response(&access, answer(&id)).is_err());
	let id = question(&access, &parent);
	drop(parent);
	assert!(response(&access, answer(&id)).is_err());
	assert!(
		access
			.binding
			.as_ref()
			.unwrap()
			.reverse
			.lock()
			.unwrap()
			.pending
			.is_empty()
	);
}

#[test]
fn reverse_response_from_other_session_or_after_deadline_is_denied() {
	let (access, parent) = setup();
	let id = question(&access, &parent);
	let (foreign, _parent) = setup();
	assert!(response(&foreign, answer(&id)).is_err());
	access
		.binding
		.as_ref()
		.unwrap()
		.reverse
		.lock()
		.unwrap()
		.pending
		.get_mut(&id)
		.unwrap()
		.expires = Instant::now() - Duration::from_secs(1);
	assert!(response(&access, answer(&id)).is_err());
}
