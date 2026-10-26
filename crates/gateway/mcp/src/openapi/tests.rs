use super::*;

fn adapter() -> Adapter {
	let schema: OpenAPI = serde_json::from_value(json!({
		"openapi":"3.0.3", "info":{"title":"local","version":"1"},
		"servers":[{"url":"https://ignored.example/api"}],
		"paths":{"/items/{id}":{"post":{"operationId":"save","parameters":[
			{"name":"id","in":"path","required":true,"schema":{"type":"string"}},
			{"name":"tag","in":"query","schema":{"type":"string"}},
			{"name":"authorization","in":"header","schema":{"type":"string"}},
			{"name":"x-client","in":"header","schema":{"type":"string"}},
			{"name":"host","in":"header","schema":{"type":"string"}}
		],"requestBody":{"content":{"application/json":{"schema":{"type":"object"}}}},"responses":{"200":{"description":"ok"}}}}}
	})).unwrap();
	Adapter::new(
		parse_openapi_schema(&schema).unwrap(),
		get_server_prefix(&schema).unwrap(),
	)
}

#[test]
fn schema_dispatch_and_parameter_encoding_do_not_require_host_runtime() {
	let adapter = adapter();
	assert_eq!(adapter.tools()[0].name, "save");
	let request = serde_json::from_value(json!({"jsonrpc":"2.0","id":"client-1","method":"tools/call","params":{"name":"save","arguments":{
		"path":{"id":"a/b"},"query":{"tag":"a&b"},"body":{"value":7},
		"header":{"authorization":"untrusted","x-client":"allowed","host":"evil.example","x-unknown":"not-in-schema"}
	}}})).unwrap();
	let Dispatch::Call { id, name, call } = adapter.dispatch(request, "bound.example:8080").unwrap()
	else {
		panic!("expected call")
	};
	assert_eq!(id, RequestId::String("client-1".into()));
	assert_eq!(name, "save");
	assert_eq!(
		call.request.uri(),
		"http://bound.example:8080/api/items/a%2Fb?tag=a%26b"
	);
	assert_eq!(call.request.method(), Method::POST);
	assert_eq!(
		serde_json::from_slice::<Value>(call.request.body()).unwrap(),
		json!({"value":7})
	);
	assert!(!call.headers.contains_key(HOST));
	assert!(!call.headers.contains_key("x-unknown"));
	let mut headers = call.request.into_parts().0.headers;
	headers.insert(
		"authorization",
		HeaderValue::from_static("trusted-host-credential"),
	);
	apply_headers(&mut headers, call.headers);
	assert_eq!(headers["authorization"], "trusted-host-credential");
	assert_eq!(headers["x-client"], "allowed");
}

#[test]
fn local_discovery_and_invalid_tool_never_produce_an_http_call() {
	let adapter = adapter();
	let request =
		serde_json::from_value(json!({"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}))
			.unwrap();
	let Dispatch::Local(Some(message)) = adapter.dispatch(request, "bound.example").unwrap() else {
		panic!("expected local list")
	};
	let value = serde_json::to_value(message).unwrap();
	assert_eq!(value["result"]["tools"][0]["name"], "save");
	let request = serde_json::from_value(
		json!({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"unknown"}}),
	)
	.unwrap();
	assert!(matches!(
		adapter.dispatch(request, "bound.example"),
		Err(DispatchError::Conversion(_))
	));
}

#[test]
fn response_conversion_preserves_error_and_structured_content_semantics() {
	assert_eq!(
		decode_tool_response("save", http::StatusCode::BAD_REQUEST, br#"{"error":"bad"}"#).unwrap(),
		json!({"error":"bad"})
	);
	assert_eq!(
		decode_tool_response("save", http::StatusCode::OK, b"[1,2]").unwrap(),
		json!({"data":[1,2]})
	);
	assert!(
		decode_tool_response("save", http::StatusCode::INTERNAL_SERVER_ERROR, b"failed").is_err()
	);
	let message = tool_response(RequestId::Number(7), json!({"value":1})).unwrap();
	let value = serde_json::to_value(message).unwrap();
	assert_eq!(value["id"], 7);
	assert_eq!(value["result"]["structuredContent"], json!({"value":1}));
	assert_eq!(
		serde_json::from_str::<Value>(value["result"]["content"][0]["text"].as_str().unwrap()).unwrap(),
		json!({"value":1})
	);
}
