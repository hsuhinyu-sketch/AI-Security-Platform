use super::*;
use crate::merge::{MergeError, MergeFailureMode, MessageStream};
use crate::routing::ObjectKind;
use futures_util::StreamExt;
use rmcp::model::{ClientRequest, JsonRpcRequest, RequestId, ServerJsonRpcMessage, ServerResult};
use std::sync::{
	Arc,
	atomic::{AtomicBool, Ordering},
};

#[derive(Debug, PartialEq, Eq)]
enum TestError {
	Host,
	Merge,
}
impl From<MergeError> for TestError {
	fn from(_: MergeError) -> Self {
		Self::Merge
	}
}

#[derive(Clone, Copy)]
struct Context;

#[derive(Default)]
struct FakeHost {
	calls: Vec<&'static str>,
	target: Option<String>,
	object: Option<String>,
	kind: Option<ObjectKind>,
	forwarded: Option<serde_json::Value>,
	lists: Vec<FanoutMethod>,
	fail: bool,
	finished: Option<Arc<AtomicBool>>,
}

fn response(id: RequestId) -> ServerJsonRpcMessage {
	ServerJsonRpcMessage::response(ServerResult::empty(()), id)
}

fn plan(stream: MessageStream<TestError>) -> FanoutPlan<TestError> {
	FanoutPlan {
		streams: vec![("server".into(), stream)],
		merge: Box::new(|_| Ok(ServerResult::empty(()))),
		failure_mode: MergeFailureMode::FailClosed,
	}
}

impl HostExecution for FakeHost {
	type Context = Context;
	type Error = TestError;

	fn fanout<'a>(
		&'a mut self,
		_: Context,
		method: FanoutMethod,
		request: JsonRpcRequest<ClientRequest>,
		target: Option<String>,
	) -> gateway_protocol_core::execution::ExecutionFuture<'a, FanoutPlan<Self::Error>, Self::Error>
	{
		self.calls.push(if method == FanoutMethod::Initialize {
			"initialize"
		} else {
			"list"
		});
		self.lists.push(method);
		self.target = target;
		self.forwarded = Some(serde_json::to_value(&request.request).unwrap());
		Box::pin(async move {
			if self.fail {
				return Err(TestError::Host);
			}
			Ok(plan(MessageStream::from(response(request.id))))
		})
	}

	fn task<'a>(
		&'a mut self,
		_: Context,
		request: JsonRpcRequest<ClientRequest>,
	) -> gateway_protocol_core::execution::ExecutionFuture<'a, SinglePlan<Self::Error>, Self::Error>
	{
		self.calls.push("task");
		self.forwarded = Some(serde_json::to_value(&request.request).unwrap());
		Box::pin(async move {
			if self.fail {
				return Err(TestError::Host);
			}
			Ok(SinglePlan {
				stream: MessageStream::from(response(request.id)),
			})
		})
	}

	fn finish_fanout(&mut self, stream: MessageStream<Self::Error>) -> MessageStream<Self::Error> {
		if let Some(flag) = &self.finished {
			flag.store(true, Ordering::Release);
		}
		stream
	}

	fn call<'a>(
		&'a mut self,
		_: Context,
		route: ObjectRoute,
		request: JsonRpcRequest<ClientRequest>,
	) -> gateway_protocol_core::execution::ExecutionFuture<'a, SinglePlan<Self::Error>, Self::Error>
	{
		self.calls.push("call");
		self.target = Some(route.target);
		self.object = Some(route.object);
		self.kind = Some(route.kind);
		self.forwarded = Some(serde_json::to_value(&request.request).unwrap());
		Box::pin(async move {
			if self.fail {
				return Err(TestError::Host);
			}
			Ok(SinglePlan {
				stream: MessageStream::from(response(request.id)),
			})
		})
	}
}

fn request(value: serde_json::Value) -> JsonRpcRequest<ClientRequest> {
	serde_json::from_value(value).unwrap()
}

#[tokio::test]
async fn dispatches_initialize_list_and_tool_call_to_complete_host_operations() {
	let mut host = FakeHost::default();
	let context = Context;
	let initialized = request(serde_json::json!({
		"jsonrpc": "2.0", "id": 1, "method": "initialize",
		"params": {
			"protocolVersion": "2025-11-25",
			"capabilities": {},
			"clientInfo": {"name": "test", "version": "1"}
		}
	}));
	let outcome = dispatch(
		initialized,
		RouteContext {
			default_target: None,
		},
		&mut host,
		context,
	)
	.await
	.unwrap();
	assert!(matches!(outcome, DispatchOutcome::Messages(_)));

	let list = request(serde_json::json!({
		"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}
	}));
	let outcome = dispatch(
		list,
		RouteContext {
			default_target: None,
		},
		&mut host,
		context,
	)
	.await
	.unwrap();
	assert!(matches!(outcome, DispatchOutcome::Messages(_)));

	let call = request(serde_json::json!({
		"jsonrpc": "2.0", "id": 3, "method": "tools/call",
		"params": {"name": "docs_echo", "arguments": {}}
	}));
	let outcome = dispatch(
		call,
		RouteContext {
			default_target: None,
		},
		&mut host,
		context,
	)
	.await
	.unwrap();
	assert!(matches!(outcome, DispatchOutcome::Messages(_)));
	assert_eq!(host.calls, ["initialize", "list", "call"]);
	assert_eq!(host.target.as_deref(), Some("docs"));
	assert_eq!(host.object.as_deref(), Some("echo"));
}

#[tokio::test]
async fn runs_the_host_finish_hook_after_merge() {
	let finished = Arc::new(AtomicBool::new(false));
	let mut host = FakeHost {
		finished: Some(finished.clone()),
		..Default::default()
	};
	let context = Context;
	let list = request(serde_json::json!({
		"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}
	}));
	let outcome = dispatch(
		list,
		RouteContext {
			default_target: None,
		},
		&mut host,
		context,
	)
	.await
	.unwrap();
	assert!(matches!(outcome, DispatchOutcome::Messages(_)));
	assert!(finished.load(Ordering::Acquire));
}

#[tokio::test]
async fn unsupported_methods_do_not_call_the_host_or_mutate_routing() {
	let mut host = FakeHost::default();
	let context = Context;
	let ping = request(serde_json::json!({
		"jsonrpc": "2.0", "id": 4, "method": "tasks/list", "params": {}
	}));
	let outcome = dispatch(
		ping,
		RouteContext {
			default_target: None,
		},
		&mut host,
		context,
	)
	.await
	.unwrap();
	assert!(matches!(outcome, DispatchOutcome::Unsupported));
	assert!(host.calls.is_empty());
}

#[tokio::test]
async fn routing_errors_do_not_reach_the_host() {
	let mut host = FakeHost::default();
	let context = Context;
	let call = request(serde_json::json!({
		"jsonrpc": "2.0", "id": 3, "method": "tools/call",
		"params": {"name": "echo", "arguments": {}}
	}));
	let error = dispatch(
		call,
		RouteContext {
			default_target: None,
		},
		&mut host,
		context,
	)
	.await
	.unwrap_err();
	assert!(matches!(error, DispatchError::Route(_)));
	assert!(host.calls.is_empty());
}

#[tokio::test]
async fn host_errors_are_not_converted_into_success() {
	let mut host = FakeHost {
		fail: true,
		..Default::default()
	};
	let context = Context;
	let list = request(serde_json::json!({
		"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}
	}));
	let error = dispatch(
		list,
		RouteContext {
			default_target: None,
		},
		&mut host,
		context,
	)
	.await
	.unwrap_err();
	assert!(matches!(error, DispatchError::Host(TestError::Host)));
}

#[tokio::test]
async fn merged_terminal_message_keeps_the_client_request_id() {
	let mut host = FakeHost::default();
	let context = Context;
	let list = request(serde_json::json!({
		"jsonrpc": "2.0", "id": "client-7", "method": "tools/list", "params": {}
	}));
	let outcome = dispatch(
		list,
		RouteContext {
			default_target: None,
		},
		&mut host,
		context,
	)
	.await
	.unwrap();
	let DispatchOutcome::Messages(mut stream) = outcome else {
		panic!("expected messages");
	};
	let message = stream.next().await.unwrap().unwrap();
	assert!(matches!(
		message,
		ServerJsonRpcMessage::Response(response) if response.id == RequestId::String("client-7".into())
	));
}

#[tokio::test]
async fn all_lists_preserve_method_and_rpc_id_and_run_response_protection() {
	for (method, expected) in [
		("tools/list", FanoutMethod::Tools),
		("prompts/list", FanoutMethod::Prompts),
		("resources/list", FanoutMethod::Resources),
		("resources/templates/list", FanoutMethod::ResourceTemplates),
	] {
		let finished = Arc::new(AtomicBool::new(false));
		let mut host = FakeHost {
			finished: Some(finished.clone()),
			..Default::default()
		};
		let outcome = dispatch(
			request(serde_json::json!({"jsonrpc":"2.0","id":"list-7","method":method,"params":{}})),
			RouteContext {
				default_target: None,
			},
			&mut host,
			Context,
		)
		.await
		.unwrap();
		let DispatchOutcome::Messages(mut stream) = outcome else {
			panic!("expected messages")
		};
		assert!(matches!(stream.next().await.unwrap().unwrap(),
			ServerJsonRpcMessage::Response(response) if response.id == RequestId::String("list-7".into())));
		assert!(stream.next().await.is_none());
		assert_eq!(host.lists, [expected]);
		assert_eq!(host.calls, ["list"]);
		assert!(finished.load(Ordering::Acquire));
	}
}

fn object_cases() -> Vec<(&'static str, serde_json::Value, ObjectKind)> {
	use serde_json::json;
	vec![
		(
			"tools/call",
			json!({"name":"docs_echo","arguments":{"text":"keep"}}),
			ObjectKind::Tool,
		),
		(
			"prompts/get",
			json!({"name":"docs_guide","arguments":{"topic":"keep"}}),
			ObjectKind::Prompt,
		),
		(
			"resources/read",
			json!({"uri":"docs+file:///guide"}),
			ObjectKind::Resource,
		),
		(
			"resources/subscribe",
			json!({"uri":"docs+file:///guide"}),
			ObjectKind::Resource,
		),
		(
			"resources/unsubscribe",
			json!({"uri":"docs+file:///guide"}),
			ObjectKind::Resource,
		),
		(
			"completion/complete",
			json!({"ref":{"type":"ref/prompt","name":"docs_guide"},
			"argument":{"name":"topic","value":"a"},"context":{"arguments":{"language":"keep"}}}),
			ObjectKind::Prompt,
		),
		(
			"completion/complete",
			json!({"ref":{"type":"ref/resource","uri":"docs+file:///guide"},
			"argument":{"name":"topic","value":"a"}}),
			ObjectKind::Resource,
		),
	]
}

#[tokio::test]
async fn object_dispatch_projects_once_and_preserves_other_parameters() {
	for default_target in [None, Some("docs")] {
		for (method, mut params, kind) in object_cases() {
			let pointer = match method {
				"completion/complete" if kind == ObjectKind::Prompt => "/ref/name",
				"completion/complete" => "/ref/uri",
				_ if kind == ObjectKind::Resource => "/uri",
				_ => "/name",
			};
			let object = if kind == ObjectKind::Resource {
				"file:///guide"
			} else if kind == ObjectKind::Tool {
				"echo"
			} else {
				"guide"
			};
			if default_target.is_some() {
				*params.pointer_mut(pointer).unwrap() = serde_json::json!(object);
			}
			params["_meta"] = serde_json::json!({"trace":"preserve"});
			let input = request(
				serde_json::json!({"jsonrpc":"2.0","id":"object-7","method":method,"params":params}),
			);
			let mut expected = serde_json::to_value(&input.request).unwrap();
			*expected["params"].pointer_mut(pointer).unwrap() = serde_json::json!(object);
			let mut host = FakeHost::default();
			let outcome = dispatch(input, RouteContext { default_target }, &mut host, Context)
				.await
				.unwrap();
			let DispatchOutcome::Messages(mut stream) = outcome else {
				panic!("expected messages")
			};
			assert!(matches!(stream.next().await.unwrap().unwrap(),
				ServerJsonRpcMessage::Response(response) if response.id == RequestId::String("object-7".into())));
			assert_eq!(host.calls, ["call"]);
			assert_eq!(host.kind, Some(kind));
			assert_eq!(host.target.as_deref(), Some("docs"));
			assert_eq!(host.object.as_deref(), Some(object));
			assert_eq!(host.forwarded.as_ref(), Some(&expected));
		}
	}
}

#[tokio::test]
async fn every_object_propagates_host_denial_without_fallback_or_second_attempt() {
	for (method, params, _) in object_cases() {
		let mut host = FakeHost {
			fail: true,
			..Default::default()
		};
		let error = dispatch(
			request(serde_json::json!({"jsonrpc":"2.0","id":7,"method":method,"params":params})),
			RouteContext {
				default_target: None,
			},
			&mut host,
			Context,
		)
		.await
		.unwrap_err();
		assert!(matches!(error, DispatchError::Host(TestError::Host)));
		assert_eq!(host.calls, ["call"]);
	}
}

#[tokio::test]
async fn subscription_batch_projects_all_uris_and_rejects_mixed_targets_before_host() {
	for (resources, expected_target, expected_resources) in [
		(
			serde_json::json!(["docs+file:///a", "docs+file:///b"]),
			Some("docs"),
			serde_json::json!(["file:///a", "file:///b"]),
		),
		(serde_json::json!([]), None, serde_json::json!([])),
	] {
		let mut host = FakeHost::default();
		let input = request(
			serde_json::json!({"jsonrpc":"2.0","id":"sub-1","method":"subscriptions/listen",
			"params":{"notifications":{"resourceSubscriptions":resources},"_meta":{"trace":"keep"}}}),
		);
		let outcome = dispatch(
			input,
			RouteContext {
				default_target: None,
			},
			&mut host,
			Context,
		)
		.await
		.unwrap();
		assert!(matches!(outcome, DispatchOutcome::Messages(_)));
		assert_eq!(host.target.as_deref(), expected_target);
		let forwarded = host.forwarded.unwrap();
		assert_eq!(
			forwarded["params"]["notifications"]["resourceSubscriptions"],
			expected_resources
		);
		assert_eq!(forwarded["params"]["_meta"]["trace"], "keep");
		assert_eq!(host.lists, [FanoutMethod::SubscriptionsListen]);
	}
	let mut host = FakeHost::default();
	let error = dispatch(
		request(
			serde_json::json!({"jsonrpc":"2.0","id":1,"method":"subscriptions/listen",
		"params":{"notifications":{"resourceSubscriptions":["docs+file:///a","other+file:///b"]}}}),
		),
		RouteContext {
			default_target: None,
		},
		&mut host,
		Context,
	)
	.await
	.unwrap_err();
	assert!(matches!(
		error,
		DispatchError::Route(routing::Error::MixedSubscriptionTargets)
	));
	assert!(host.calls.is_empty());
}

#[tokio::test]
async fn task_dispatch_uses_owner_bound_host_operation_and_never_routes_id_as_target() {
	for method in ["tasks/get", "tasks/result", "tasks/cancel"] {
		for fail in [false, true] {
			let mut host = FakeHost {
				fail,
				..Default::default()
			};
			let input = request(
				serde_json::json!({"jsonrpc":"2.0","id":9,"method":method,"params":{"taskId":"opaque-task"}}),
			);
			let expected = serde_json::to_value(&input.request).unwrap();
			let outcome = dispatch(
				input,
				RouteContext {
					default_target: Some("unrelated"),
				},
				&mut host,
				Context,
			)
			.await;
			if fail {
				assert!(matches!(outcome, Err(DispatchError::Host(TestError::Host))));
			} else {
				assert!(matches!(outcome, Ok(DispatchOutcome::Messages(_))));
			}
			assert_eq!(host.calls, ["task"]);
			assert_eq!(host.forwarded, Some(expected));
			assert!(host.target.is_none());
		}
	}
}

#[tokio::test]
async fn discovery_and_controls_use_fanout_and_preserve_host_errors() {
	for (method, params, expected) in [
		(
			"server/discover",
			serde_json::json!({}),
			FanoutMethod::Discover,
		),
		("ping", serde_json::json!({}), FanoutMethod::Ping),
		(
			"logging/setLevel",
			serde_json::json!({"level":"info"}),
			FanoutMethod::SetLevel,
		),
	] {
		for fail in [false, true] {
			let mut host = FakeHost {
				fail,
				..Default::default()
			};
			let outcome = dispatch(
				request(serde_json::json!({"jsonrpc":"2.0","id":1,"method":method,"params":params})),
				RouteContext {
					default_target: None,
				},
				&mut host,
				Context,
			)
			.await;
			if fail {
				assert!(matches!(outcome, Err(DispatchError::Host(TestError::Host))));
			} else {
				assert!(matches!(outcome, Ok(DispatchOutcome::Messages(_))));
			}
			assert_eq!(host.lists, [expected]);
			assert_eq!(host.calls.len(), 1);
		}
	}
}
