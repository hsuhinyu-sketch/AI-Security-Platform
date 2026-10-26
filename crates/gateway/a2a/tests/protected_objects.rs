use gateway_a2a::{
	Error, Method, RequestEnvelope,
	execution::{self, Context, ObjectAccess},
	objects, push, recovery, streaming,
};
use security_types::a2a::{TaskOperation, TaskState};
use serde_json::{Value, json};
#[derive(Debug, PartialEq, Eq)]
enum Failure {
	Wire(Error),
	Denied,
	Storage,
}
#[derive(Default)]
struct Access {
	calls: Vec<String>,
	fail_commit: bool,
	deny_read: bool,
}
impl ObjectAccess for Access {
	type Error = Failure;
	fn reject(&self, e: Error) -> Failure {
		Failure::Wire(e)
	}
	fn stream_reject(&self, e: Error) -> Failure {
		Failure::Wire(e)
	}
	fn finish_task(&mut self, id: &str, context: &str, _state: TaskState) -> Result<(), Failure> {
		self.calls.push(format!("commit:{id}:{context}"));
		if self.fail_commit {
			Err(Failure::Storage)
		} else if id != "task" || context != "context" {
			Err(Failure::Denied)
		} else {
			Ok(())
		}
	}
	fn read_task(&self, _id: &str) -> Result<(), Failure> {
		if self.deny_read {
			Err(Failure::Denied)
		} else {
			Ok(())
		}
	}
	fn artifact_visible(&self, _task: &str, artifact: &str) -> bool {
		artifact == "visible"
	}
}
fn context(operation: TaskOperation) -> Context {
	Context {
		operation,
		task: Some("task".into()),
		context: Some("context".into()),
		downloads: false,
	}
}
fn task() -> Value {
	json!({"kind":"task","id":"task","contextId":"context","status":{"state":"working"},"artifacts":[{"artifactId":"visible","parts":[{"kind":"text","text":"visible"}]},{"artifactId":"hidden","parts":[{"kind":"text","text":"secret"}]}]})
}
fn rpc(result: Value) -> Value {
	json!({"jsonrpc":"2.0","id":1,"result":result})
}
#[test]
fn requests_preserve_method_limits_and_reject_bare_context_references_and_remote_inputs() {
	let request:RequestEnvelope=serde_json::from_value(json!({"jsonrpc":"2.0","id":1,"method":"message/stream","params":{"message":{"kind":"message","role":"user","messageId":"m","parts":[{"kind":"text","text":"hi"}]}}})).unwrap();
	let plan = objects::parse_request(&request).unwrap();
	assert_eq!(plan.operation, TaskOperation::Create);
	assert_eq!(plan.method, Method::Stream);
	assert!(plan.task.is_none());
	for message in [
		json!({"contextId":"foreign"}),
		json!({"referenceTaskIds":["foreign"]}),
		json!({"extensions":[{}]}),
		json!({"parts":[{"kind":"file","file":{"uri":"https://untrusted.example/file"}}]}),
		json!({"parts":[{"kind":"file","file":{"bytes":"invalid base64"}}]}),
	] {
		let mut value = json!({"jsonrpc":"2.0","id":1,"method":"message/send","params":{"message":{"kind":"message","role":"user","messageId":"m","parts":[{"kind":"text","text":"hi"}]}}});
		value["params"]["message"]
			.as_object_mut()
			.unwrap()
			.extend(message.as_object().unwrap().clone());
		assert!(objects::parse_request(&serde_json::from_value(value).unwrap()).is_err());
	}
	for bad in [
		json!({"id":"task","historyLength":-1}),
		json!({"id":" task"}),
		json!({"id":"task","unknown":true}),
	] {
		let request =
			serde_json::from_value(json!({"jsonrpc":"2.0","id":1,"method":"tasks/get","params":bad}))
				.unwrap();
		assert!(objects::parse_request(&request).is_err());
	}
}
#[test]
fn replies_validate_before_commit_project_only_after_read_and_propagate_storage_failure() {
	let mut access = Access::default();
	let mut value = rpc(task());
	execution::process_rpc(
		&mut value,
		&json!(1),
		true,
		&context(TaskOperation::Read),
		&mut access,
	)
	.unwrap();
	assert_eq!(access.calls, ["commit:task:context"]);
	assert_eq!(value["result"]["artifacts"].as_array().unwrap().len(), 1);
	let mut bad = rpc(task());
	bad["result"]["artifacts"][0]["parts"][0]["text"] = json!(7);
	let mut access = Access::default();
	assert!(
		execution::process_rpc(
			&mut bad,
			&json!(1),
			true,
			&context(TaskOperation::Read),
			&mut access
		)
		.is_err()
	);
	assert!(access.calls.is_empty());
	let mut access = Access {
		fail_commit: true,
		..Default::default()
	};
	let mut value = rpc(task());
	assert_eq!(
		execution::process_rpc(
			&mut value,
			&json!(1),
			true,
			&context(TaskOperation::Read),
			&mut access
		),
		Err(Failure::Storage)
	);
	assert_eq!(value["result"]["artifacts"].as_array().unwrap().len(), 2);
	let mut access = Access {
		deny_read: true,
		..Default::default()
	};
	assert_eq!(
		execution::process_rpc(
			&mut rpc(task()),
			&json!(1),
			true,
			&context(TaskOperation::Read),
			&mut access
		),
		Err(Failure::Denied)
	);
}
#[test]
fn correlation_error_sanitization_and_uncommitted_push_never_create_a_task() {
	let mut access = Access::default();
	let mut wrong = rpc(task());
	wrong["id"] = json!(2);
	assert!(
		execution::process_rpc(
			&mut wrong,
			&json!(1),
			true,
			&context(TaskOperation::Create),
			&mut access
		)
		.is_err()
	);
	assert!(access.calls.is_empty());
	let mut error = json!({"jsonrpc":"2.0","id":1,"error":{"code":-1,"message":"denied","data":{"foreign":"secret"}}});
	execution::process_rpc(
		&mut error,
		&json!(1),
		false,
		&context(TaskOperation::Read),
		&mut access,
	)
	.unwrap();
	assert!(error["error"].get("data").is_none());
	assert!(access.calls.is_empty());
	let mut foreign = task();
	foreign["contextId"] = json!("foreign");
	assert!(
		execution::process_result(
			&mut foreign,
			&context(TaskOperation::Read),
			false,
			&mut access
		)
		.is_err()
	);
	assert!(access.calls.is_empty());
	execution::process_result(
		&mut task(),
		&context(TaskOperation::Read),
		false,
		&mut access,
	)
	.unwrap();
	assert!(access.calls.is_empty());
}
#[test]
fn stream_updates_bind_task_context_and_distinguish_terminal_states() {
	let mut access = Access::default();
	let ctx = context(TaskOperation::Subscribe);
	let status = |state: &str, final_event: bool| {
		rpc(
			json!({"kind":"status-update","taskId":"task","contextId":"context","status":{"state":state},"final":final_event}),
		)
	};
	assert_eq!(
		streaming::process_event(&mut status("working", false), &json!(1), &ctx, &mut access).unwrap(),
		(true, false)
	);
	assert_eq!(
		streaming::process_event(
			&mut status("completed", false),
			&json!(1),
			&ctx,
			&mut access
		)
		.unwrap(),
		(true, true)
	);
	let mut foreign = status("working", false);
	foreign["result"]["taskId"] = json!("foreign");
	let before = access.calls.len();
	assert!(streaming::process_event(&mut foreign, &json!(1), &ctx, &mut access).is_err());
	assert_eq!(access.calls.len(), before);
	for (id, expected) in [("visible", true), ("hidden", false)] {
		let mut event = rpc(
			json!({"kind":"artifact-update","taskId":"task","contextId":"context","artifact":{"artifactId":id,"parts":[]}}),
		);
		assert_eq!(
			streaming::process_event(&mut event, &json!(1), &ctx, &mut access).unwrap(),
			(expected, false)
		);
	}
}
#[test]
fn recovery_filters_again_and_never_serializes_global_sequence_or_reopens_task() {
	let events = [
		("cursor-a", task()),
		(
			"cursor-b",
			json!({"kind":"artifact-update","artifact":{"artifactId":"hidden"}}),
		),
	];
	let result = recovery::project_batch(events, |id| id == "visible").unwrap();
	assert_eq!(result.len(), 1);
	assert_eq!(
		result[0]["result"]["artifacts"].as_array().unwrap().len(),
		1
	);
	let body = recovery::response(&json!(1), result, "next", true);
	assert_eq!(body["result"]["scope"], "gateway-observed");
	assert!(body["result"]["events"][0].get("sequence").is_none());
	let cursor = "01234567-89ab-4def-8123-456789abcdef";
	let request:RequestEnvelope=serde_json::from_value(json!({"jsonrpc":"2.0","id":1,"method":"aisp.events/read","params":{"id":"task","after":cursor,"limit":2}})).unwrap();
	assert!(objects::parse_request(&request).is_ok());
	assert_eq!(recovery::request(&request, 2).unwrap(), (cursor.into(), 2));
	assert_eq!(
		recovery::request(&request, 1).unwrap_err(),
		Error::EventCursor
	);
}
#[test]
fn downloads_and_push_preserve_strict_source_binding_without_exposing_transport() {
	let part = json!({"kind":"file","file":{"uri":"https://files.example/a"},"metadata":{"aispDownload":{"sha256":"00".repeat(32),"sizeBytes":2}}});
	assert_eq!(
		gateway_a2a::downloads::FileReference::parse(&part)
			.unwrap()
			.size,
		2
	);
	for uri in [
		"http://files.example/a",
		"https://user@files.example/a",
		"https://files.example/a?token=secret",
		"https://files.example/a#fragment",
	] {
		let mut invalid = part.clone();
		invalid["file"]["uri"] = json!(uri);
		assert!(gateway_a2a::downloads::FileReference::parse(&invalid).is_err());
	}
	assert!(objects::validate_parts(&json!([part.clone()])).is_err());
	objects::validate_parts_with_downloads(&json!([part]), true).unwrap();
	let request=serde_json::from_value(json!({"jsonrpc":"2.0","id":1,"method":"tasks/pushNotificationConfig/set","params":{"taskId":"task","pushNotificationConfig":{"url":"https://gateway.example/v1/a2a/push/"}}})).unwrap();
	let wire = push::registration_request(
		&request,
		Some("task"),
		"channel",
		"https://gateway.example/v1/a2a/push/channel",
		"secret",
	);
	assert_eq!(
		wire["params"]["pushNotificationConfig"]["authentication"]["credentials"],
		"secret"
	);
	let public = push::public_config(
		"task",
		"channel",
		"https://gateway.example/v1/a2a/push/channel",
	);
	assert!(
		public["pushNotificationConfig"]
			.get("authentication")
			.is_none()
	);
	assert!(
		push::validate_registration(
			&public,
			"other",
			"channel",
			"https://gateway.example/v1/a2a/push/channel"
		)
		.is_err()
	);
}
#[test]
fn cleanup_ack_is_not_a_business_grant_and_only_terminal_bound_results_confirm() {
	use execution::CleanupReply;
	let mut value = rpc(task());
	value["id"] = json!("cleanup");
	assert_eq!(
		execution::cleanup_reply(&value, true, "cleanup", "task", Some("context")),
		CleanupReply::Unknown
	);
	value["result"]["status"]["state"] = json!("canceled");
	assert_eq!(
		execution::cleanup_reply(&value, true, "cleanup", "task", Some("context")),
		CleanupReply::Terminal(TaskState::Canceled)
	);
	assert_eq!(
		execution::cleanup_reply(&value, true, "cleanup", "foreign", Some("context")),
		CleanupReply::Unknown
	);
}
