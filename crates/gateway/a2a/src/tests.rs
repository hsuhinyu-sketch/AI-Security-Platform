use super::*;
use serde_json::json;

#[test]
fn request_envelope_retains_strict_validation() {
	let valid = json!({"jsonrpc":"2.0","id":1,"method":"message/send","params":{}});
	assert_eq!(
		serde_json::from_value::<RequestEnvelope>(valid)
			.unwrap()
			.validated_method()
			.unwrap(),
		"message/send"
	);
	for invalid in [
		json!({"jsonrpc":"2.0","id":null,"method":"message/send","params":{}}),
		json!({"jsonrpc":"2.0","id":1,"method":"message/send","params":{},"error":null}),
		json!({"jsonrpc":"2.0","id":1,"method":"message/send","params":[]}),
	] {
		assert!(
			serde_json::from_value::<RequestEnvelope>(invalid)
				.unwrap()
				.validated_method()
				.is_err()
		);
	}
	assert!(!supported_method("custom/execute"));
	assert!(supported_method(EVENT_READ_METHOD));
}

#[test]
fn protected_card_clips_unsupported_capabilities_and_rewrites_origin() {
	let mut card = json!({"protocolVersion":"0.3.0", "url":"https://upstream.example/agent",
		"capabilities":{"pushNotifications":true,"extensions":[{}],"stateTransitionHistory":true},
		"supportsAuthenticatedExtendedCard":true});
	rewrite_card(
		&mut card,
		"https://gateway.example/agent/.well-known/agent-card.json"
			.parse()
			.unwrap(),
		true,
		false,
	)
	.unwrap();
	assert_eq!(card["url"], "https://gateway.example/agent");
	assert_eq!(card["capabilities"]["pushNotifications"], false);
	assert_eq!(card["capabilities"]["stateTransitionHistory"], false);
	assert!(card["capabilities"].get("extensions").is_none());
	assert_eq!(card["supportsAuthenticatedExtendedCard"], false);
	let mut unsupported = json!({"protocolVersion":"1.0", "supportedInterfaces":[]});
	assert!(
		rewrite_card(
			&mut unsupported,
			"https://gateway.example/.well-known/agent-card.json"
				.parse()
				.unwrap(),
			true,
			true
		)
		.is_err()
	);
}

#[test]
fn discovery_interfaces_keep_paths_and_queries_when_rewritten() {
	let mut card =
		json!({"supportedInterfaces":[{"url":"https://upstream.example/rpc?binding=json"}]});
	rewrite_card(
		&mut card,
		"https://gateway.example/.well-known/agent-card.json"
			.parse()
			.unwrap(),
		false,
		false,
	)
	.unwrap();
	assert_eq!(
		card["supportedInterfaces"][0]["url"],
		"https://gateway.example/rpc?binding=json"
	);
}
