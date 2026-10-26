use super::*;
use serde_json::json;
fn call(method: &str, params: serde_json::Value) -> JsonRpcRequest<ClientRequest> {
	serde_json::from_value(json!({"jsonrpc":"2.0","id":7,"method":method,"params":params})).unwrap()
}
#[test]
fn object_and_list_resources_use_the_actual_server() {
	for (method, params, kind) in [
		(
			"resources/read",
			json!({"uri":"file:///guide"}),
			OperationKind::Object,
		),
		(
			"prompts/get",
			json!({"name":"support"}),
			OperationKind::Object,
		),
		("tools/list", json!({}), OperationKind::List),
	] {
		let rpc = call(method, params);
		let a = normalize(&rpc, "internal", Default::default(), "server-a");
		let b = normalize(&rpc, "internal", Default::default(), "server-b");
		assert_eq!(a.kind, kind);
		assert_ne!(a.action.resource.id, b.action.resource.id);
	}
}

#[test]
fn discovery_requires_the_selected_server_policy() {
	let rpc = call("server/discover", json!({}));
	assert!(is_discovery_list(&rpc.request));
	let operation = normalize(&rpc, "internal", Default::default(), "server-a");
	assert_eq!(operation.kind, OperationKind::Object);
	assert_eq!(
		operation.action.resource.resource_type,
		ResourceType::McpServer
	);
	assert_eq!(operation.action.resource.id, "server-a");
	assert_eq!(
		operation.action.action.action_type,
		security_types::ActionType::McpOperation
	);
}
