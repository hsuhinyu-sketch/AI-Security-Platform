use super::*;
use futures_util::StreamExt;
use rmcp::model::{
	ListPromptsResult, ListResourceTemplatesResult, ListResourcesResult, ListToolsResult, Prompt,
	Resource, ResourceTemplate, ServerJsonRpcMessage, ServerResult,
};
use std::time::Duration;

#[derive(Debug, PartialEq, Eq)]
struct TestError(String);

impl From<MergeError> for TestError {
	fn from(error: MergeError) -> Self {
		Self(error.to_string())
	}
}

fn tools(server: &str, names: &[&str]) -> (String, ServerResult) {
	let tools = names
		.iter()
		.map(|name| {
			serde_json::from_value(serde_json::json!({
				"name": name,
				"inputSchema": {"type": "object"}
			}))
			.unwrap()
		})
		.collect();
	(
		server.to_string(),
		ListToolsResult {
			tools,
			..Default::default()
		}
		.into(),
	)
}

#[test]
fn list_merge_admits_original_objects_before_projection_and_preserves_order() {
	let mut seen = Vec::new();
	let merged = merge_tools(
		[tools("one", &["echo", "hidden"]), tools("two", &["echo"])],
		None,
		|server, tool| {
			seen.push((server.to_string(), tool.name.to_string()));
			tool.name != "hidden"
		},
	);
	let ServerResult::ListToolsResult(result) = merged else {
		panic!("expected tools");
	};
	assert_eq!(
		seen,
		vec![
			("one".into(), "echo".into()),
			("one".into(), "hidden".into()),
			("two".into(), "echo".into()),
		]
	);
	assert_eq!(
		result
			.tools
			.iter()
			.map(|tool| tool.name.as_ref())
			.collect::<Vec<_>>(),
		vec!["one_echo", "two_echo"]
	);
	assert!(
		result
			.tools
			.iter()
			.all(|tool| !tool.name.contains("hidden"))
	);
}

#[test]
fn every_list_uses_the_same_admit_then_project_order() {
	let prompt: Prompt = serde_json::from_value(serde_json::json!({"name": "p"})).unwrap();
	let resource: Resource =
		serde_json::from_value(serde_json::json!({"uri": "file:///r", "name": "r"})).unwrap();
	let template: ResourceTemplate =
		serde_json::from_value(serde_json::json!({"uriTemplate": "file:///{page}", "name": "t"}))
			.unwrap();
	for target in [None, Some("local")] {
		let mut admitted = Vec::new();
		let merged = merge_prompts(
			[(
				"up",
				ListPromptsResult {
					prompts: vec![prompt.clone()],
					..Default::default()
				}
				.into(),
			)],
			target,
			|server, value| {
				admitted.push((server.to_string(), value.name.clone()));
				true
			},
		);
		assert_eq!(admitted, vec![("up".to_string(), "p".to_string())]);
		let ServerResult::ListPromptsResult(result) = merged else {
			panic!("expected prompts");
		};
		assert_eq!(
			result.prompts[0].name,
			if target.is_none() { "up_p" } else { "p" }
		);

		let merged = merge_resources(
			[(
				"up",
				ListResourcesResult {
					resources: vec![resource.clone()],
					..Default::default()
				}
				.into(),
			)],
			target,
			|_, _| true,
		);
		let ServerResult::ListResourcesResult(result) = merged else {
			panic!("expected resources");
		};
		assert_eq!(
			result.resources[0].uri,
			if target.is_none() {
				"up+file:///r"
			} else {
				"file:///r"
			}
		);

		let merged = merge_resource_templates(
			[(
				"up",
				ListResourceTemplatesResult {
					resource_templates: vec![template.clone()],
					..Default::default()
				}
				.into(),
			)],
			target,
			|_, _| true,
		);
		let ServerResult::ListResourceTemplatesResult(result) = merged else {
			panic!("expected templates");
		};
		assert_eq!(
			result.resource_templates[0].uri_template,
			if target.is_none() {
				"up+file:///{page}"
			} else {
				"file:///{page}"
			}
		);
	}
}

fn response(id: i64) -> ServerJsonRpcMessage {
	ServerJsonRpcMessage::response(ServerResult::empty(()), RequestId::Number(id))
}

fn notification(uri: &str) -> ServerJsonRpcMessage {
	serde_json::from_value(serde_json::json!({
		"jsonrpc": "2.0",
		"method": "notifications/resources/updated",
		"params": {"uri": uri}
	}))
	.unwrap()
}

#[test]
fn lifecycle_results_keep_protocol_shapes() {
	assert_eq!(
		serde_json::to_value(empty_result()).unwrap(),
		serde_json::to_value(ServerResult::empty(())).unwrap()
	);
	let ack = subscription_ack(RequestId::Number(9));
	let serialized = serde_json::to_value(ack).unwrap();
	assert_eq!(
		serialized["_meta"]["io.modelcontextprotocol/subscriptionId"],
		serde_json::json!(9)
	);
}

#[tokio::test]
async fn merge_stream_emits_notifications_then_one_terminal_in_upstream_order() {
	let first: MessageStream<TestError> = MessageStream::from_stream(
		futures_util::stream::iter(vec![Ok(notification("file:///one")), Ok(response(1))]).boxed(),
	);
	let second: MessageStream<TestError> = MessageStream::from(response(2));
	let mut merged = MergeStream::new(
		vec![("one".into(), first), ("two".into(), second)],
		RequestId::Number(7),
		Box::new(|messages| {
			assert_eq!(messages.len(), 2);
			assert_eq!(messages[0].0, "one");
			assert_eq!(messages[1].0, "two");
			Ok(ServerResult::empty(()))
		}),
		MergeFailureMode::FailClosed,
	);

	assert!(matches!(
		merged.next().await.unwrap().unwrap(),
		ServerJsonRpcMessage::Notification(_)
	));
	let terminal = merged.next().await.unwrap().unwrap();
	assert!(matches!(terminal, ServerJsonRpcMessage::Response(_)));
	assert!(merged.next().await.is_none());
}

#[tokio::test]
async fn fail_open_skips_failed_or_ended_streams_and_still_merges() {
	let streams: Vec<(String, MessageStream<TestError>)> = vec![
		(
			"failed".into(),
			MessageStream::from_stream(futures_util::stream::once(async {
				Err(TestError("network".into()))
			})),
		),
		("empty".into(), MessageStream::empty()),
		("good".into(), MessageStream::from(response(1))),
	];
	let mut merged = MergeStream::new(
		streams,
		RequestId::Number(1),
		Box::new(|messages| {
			assert_eq!(messages.len(), 1);
			assert_eq!(messages[0].0, "good");
			Ok(ServerResult::empty(()))
		}),
		MergeFailureMode::FailOpen,
	);
	assert!(merged.next().await.unwrap().is_ok());
	assert!(merged.next().await.is_none());
}

#[tokio::test]
async fn fail_closed_surfaces_the_upstream_error_and_stops() {
	let streams: Vec<(String, MessageStream<TestError>)> = vec![(
		"failed".into(),
		MessageStream::from_stream(futures_util::stream::once(async {
			Err(TestError("network".into()))
		})),
	)];
	let mut merged = MergeStream::new_without_merge(streams, MergeFailureMode::FailClosed);
	assert_eq!(
		merged.next().await.unwrap().unwrap_err(),
		TestError("network".into())
	);
	assert!(merged.next().await.is_none());

	let streams: Vec<(String, MessageStream<TestError>)> =
		vec![("empty".into(), MessageStream::empty())];
	let mut merged = MergeStream::new_without_merge(streams, MergeFailureMode::FailClosed);
	assert_eq!(
		merged.next().await.unwrap().unwrap_err(),
		TestError("upstream stream ended unexpectedly".into())
	);
}

#[tokio::test]
async fn a_hanging_stream_keeps_the_merge_pending() {
	let streams: Vec<(String, MessageStream<TestError>)> =
		vec![("hanging".into(), MessageStream::pending())];
	let mut merged = MergeStream::new_without_merge(streams, MergeFailureMode::FailClosed);
	assert!(
		tokio::time::timeout(Duration::from_millis(10), merged.next())
			.await
			.is_err()
	);
}
