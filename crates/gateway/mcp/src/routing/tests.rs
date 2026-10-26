use super::*;
use serde_json::{Value, json};

#[test]
fn subscription_batch_maps_one_target_and_preserves_order_and_duplicates() {
	let resources = vec![
		"docs+file:///a".into(),
		"docs+https://host/b?x=1#part".into(),
		"docs+file:///a".into(),
	];
	let before = resources.clone();
	assert_eq!(
		route_subscription_resources(None, &resources).unwrap(),
		(
			Some("docs".into()),
			vec![
				"file:///a".into(),
				"https://host/b?x=1#part".into(),
				"file:///a".into()
			]
		)
	);
	assert_eq!(resources, before);
	let resources = vec!["file:///a".into(), "scheme+extra://b".into()];
	assert_eq!(
		route_subscription_resources(Some("docs"), &resources).unwrap(),
		(Some("docs".into()), resources)
	);
	for default in [None, Some("docs")] {
		assert_eq!(
			route_subscription_resources(default, &[]).unwrap(),
			(None, vec![])
		);
	}
}

#[test]
fn invalid_subscription_batches_do_not_modify_the_input_or_select_another_target() {
	for (resources, error) in [
		(
			vec!["docs+file:///a".into(), "other+file:///b".into()],
			Error::MixedSubscriptionTargets,
		),
		(
			vec!["docs+file:///a".into(), "file:///b".into()],
			Error::InvalidResourceUri,
		),
	] {
		let before = resources.clone();
		assert_eq!(route_subscription_resources(None, &resources), Err(error));
		assert_eq!(resources, before);
	}
	// Existence and authorization remain Host responsibilities.
	assert_eq!(
		route_subscription_resources(None, &["unknown+file:///a".into()])
			.unwrap()
			.0
			.as_deref(),
		Some("unknown")
	);
}

#[test]
fn default_target_keeps_original_names_and_uris() {
	for name in ["echo", "echo_with_suffix", "", "中文"] {
		assert_eq!(resource_name(Some("local"), "local", name), name);
		assert_eq!(
			parse_resource_name(Some("local"), name).unwrap(),
			("local", name)
		);
	}
	for uri in ["file:///docs/a?x=1#part", "scheme+extra://path", "relative"] {
		assert_eq!(resource_uri(Some("local"), "local", uri), uri);
		assert_eq!(
			parse_resource_uri(Some("local"), uri).unwrap(),
			("local", uri)
		);
	}
}

#[test]
fn multiplexed_names_and_uris_round_trip_without_losing_suffixes() {
	for target in ["first", "other-server"] {
		for name in ["echo_with_suffix", "", "中文"] {
			let projected = resource_name(None, target, name);
			assert_eq!(
				parse_resource_name(None, &projected).unwrap(),
				(target, name)
			);
		}
		for uri in [
			"file:///docs/a?x=1#part",
			"https://host/path",
			"scheme+extra://path",
		] {
			let projected = resource_uri(None, target, uri);
			assert_eq!(parse_resource_uri(None, &projected).unwrap(), (target, uri));
		}
	}
	assert_eq!(
		parse_resource_name(None, "echo"),
		Err(Error::InvalidResourceName)
	);
	assert_eq!(
		parse_resource_uri(None, "file:///a"),
		Err(Error::InvalidResourceUri)
	);
	assert_eq!(resource_uri(None, "local", "relative"), "relative");
	// Target existence remains a Host decision; parsing cannot silently select another server.
	assert_eq!(
		parse_resource_uri(None, "unknown+file:///a").unwrap(),
		("unknown", "file:///a")
	);
}

#[test]
fn resource_updates_project_only_the_uri_and_preserve_metadata() {
	let original = json!({"jsonrpc":"2.0","method":"notifications/resources/updated",
		"params":{"uri":"file:///docs/a","_meta":{"marker":42}}});
	let mut expected = original.clone();
	expected["params"]["uri"] = json!("docs+file:///docs/a");
	let message = serde_json::from_value(original.clone()).unwrap();
	assert_eq!(
		serde_json::to_value(rewrite_resource_update_message(None, "docs", message)).unwrap(),
		expected
	);
	let message = serde_json::from_value(original.clone()).unwrap();
	assert_eq!(
		serde_json::to_value(rewrite_resource_update_message(
			Some("docs"),
			"docs",
			message
		))
		.unwrap(),
		original
	);
}

#[test]
fn subscription_ack_replaces_only_the_correlation_id() {
	let original = json!({"jsonrpc":"2.0","method":"notifications/subscriptions/acknowledged",
		"params":{"notifications":{},"_meta":{"marker":42,"io.modelcontextprotocol/subscriptionId":"upstream"}}});
	for id in [RequestId::Number(8), RequestId::String("client".into())] {
		let message = serde_json::from_value(original.clone()).unwrap();
		let result: Value = serde_json::to_value(set_subscription_ack_id(message, &id)).unwrap();
		let mut expected = original.clone();
		expected["params"]["_meta"]["io.modelcontextprotocol/subscriptionId"] =
			serde_json::to_value(id).unwrap();
		assert_eq!(result, expected);
	}
	let original = json!({"jsonrpc":"2.0","method":"notifications/resources/updated","params":{"uri":"file:///a"}});
	let message = serde_json::from_value(original.clone()).unwrap();
	assert_eq!(
		serde_json::to_value(set_subscription_ack_id(message, &RequestId::Number(8))).unwrap(),
		original
	);
}

#[test]
fn object_requests_route_in_place_without_changing_arguments_or_metadata() {
	for (method, field, object, kind, extra) in [
		(
			"tools/call",
			"name",
			"echo_with_suffix",
			ObjectKind::Tool,
			json!({"arguments":{"x":1}}),
		),
		(
			"prompts/get",
			"name",
			"guide_prompt",
			ObjectKind::Prompt,
			json!({"arguments":{"topic":"ai"}}),
		),
		(
			"resources/read",
			"uri",
			"file:///guide?x=1#part",
			ObjectKind::Resource,
			json!({}),
		),
		(
			"resources/subscribe",
			"uri",
			"file:///guide",
			ObjectKind::Resource,
			json!({}),
		),
		(
			"resources/unsubscribe",
			"uri",
			"file:///guide",
			ObjectKind::Resource,
			json!({}),
		),
	] {
		for default in [None, Some("local")] {
			let requested = if kind == ObjectKind::Resource {
				resource_uri(default, "local", object)
			} else {
				resource_name(default, "local", object)
			};
			let mut params = extra.clone();
			params[field] = json!(requested);
			params["_meta"] = json!({"trace":"keep","progressToken":7});
			let mut request: ClientRequest =
				serde_json::from_value(json!({"method":method,"params":params})).unwrap();
			let mut expected = serde_json::to_value(&request).unwrap();
			expected["params"][field] = json!(object);
			assert_eq!(
				route_request(default, &mut request).unwrap().unwrap(),
				ObjectRoute {
					kind,
					target: "local".into(),
					requested,
					object: object.into(),
				}
			);
			assert_eq!(serde_json::to_value(request).unwrap(), expected);
		}
	}
}

#[test]
fn completions_route_the_reference_without_modifying_argument_context() {
	for (reference, object, kind) in [
		(
			json!({"type":"ref/prompt","name":"local_guide_prompt"}),
			"guide_prompt",
			ObjectKind::Prompt,
		),
		(
			json!({"type":"ref/resource","uri":"local+file:///guide/{page}"}),
			"file:///guide/{page}",
			ObjectKind::Resource,
		),
	] {
		let mut request: ClientRequest = serde_json::from_value(json!({"method":"completion/complete","params":{
			"ref":reference,"argument":{"name":"page","value":"a"},"context":{"arguments":{"topic":"ai"}},"_meta":{"trace":"keep"}
		}})).unwrap();
		let mut expected = serde_json::to_value(&request).unwrap();
		let key = if kind == ObjectKind::Resource {
			"uri"
		} else {
			"name"
		};
		expected["params"]["ref"][key] = json!(object);
		let route = route_request(None, &mut request).unwrap().unwrap();
		assert_eq!(route.kind, kind);
		assert_eq!(route.target, "local");
		assert_eq!(route.object, object);
		assert_eq!(serde_json::to_value(request).unwrap(), expected);
	}
}

#[test]
fn lifecycle_methods_and_failed_routes_do_not_get_rewritten() {
	for value in [
		json!({"method":"ping"}),
		json!({"method":"tools/list","params":{}}),
		json!({"method":"server/discover","params":{}}),
		json!({"method":"tasks/get","params":{"taskId":"opaque"}}),
		json!({"method":"subscriptions/listen","params":{"notifications":{"resourceSubscriptions":["local+file:///guide"]}}}),
		json!({"method":"custom/method","params":{"name":"local_echo"}}),
	] {
		let mut request: ClientRequest = serde_json::from_value(value).unwrap();
		let before = serde_json::to_value(&request).unwrap();
		assert_eq!(route_request(None, &mut request).unwrap(), None);
		assert_eq!(serde_json::to_value(request).unwrap(), before);
	}
	for value in [
		json!({"method":"tools/call","params":{"name":"unprefixed","arguments":{}}}),
		json!({"method":"resources/read","params":{"uri":"file:///guide"}}),
	] {
		let mut request: ClientRequest = serde_json::from_value(value).unwrap();
		let before = serde_json::to_value(&request).unwrap();
		assert!(route_request(None, &mut request).is_err());
		assert_eq!(serde_json::to_value(request).unwrap(), before);
	}
}

#[test]
fn legacy_handshake_scopes_tool_and_prompt_without_widening_other_messages() {
	for method in ["tools/call", "prompts/get"] {
		let request: ClientRequest =
			serde_json::from_value(json!({"method":method,"params":{"name":"docs_echo"}})).unwrap();
		assert_eq!(
			legacy_initialization_target(None, Some(&request))
				.unwrap()
				.as_deref(),
			Some("docs")
		);
		assert_eq!(
			legacy_initialization_target(Some("fixed"), Some(&request))
				.unwrap()
				.as_deref(),
			Some("fixed")
		);
		let request: ClientRequest =
			serde_json::from_value(json!({"method":method,"params":{"name":"unscoped"}})).unwrap();
		assert_eq!(
			legacy_initialization_target(None, Some(&request)),
			Err(Error::InvalidResourceName)
		);
	}
	let request: ClientRequest = serde_json::from_value(
		json!({"method":"resources/read","params":{"uri":"docs+file:///guide"}}),
	)
	.unwrap();
	assert_eq!(
		legacy_initialization_target(None, Some(&request)).unwrap(),
		None
	);
	assert_eq!(legacy_initialization_target(None, None).unwrap(), None);
}
