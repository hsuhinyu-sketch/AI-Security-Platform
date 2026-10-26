use super::*;
use serde_json::json;

fn message(value: serde_json::Value) -> ServerJsonRpcMessage {
	serde_json::from_value(value).unwrap()
}

#[test]
fn success_and_error_responses_complete_only_their_own_waiter() {
	let mut pending = PendingResponses::default();
	assert!(pending.register(RequestId::Number(1), "first"));
	assert!(pending.register(RequestId::Number(2), "second"));
	let error =
		message(json!({"jsonrpc":"2.0","id":2,"error":{"code":-32602,"message":"invalid parameters"}}));
	assert!(matches!(
		pending.route(error),
		Inbound::Reply("second", ServerJsonRpcMessage::Error(_))
	));
	let success = message(json!({"jsonrpc":"2.0","id":1,"result":{}}));
	assert!(matches!(
		pending.route(success.clone()),
		Inbound::Reply("first", _)
	));
	assert!(matches!(pending.route(success), Inbound::UnmatchedReply));
}

#[test]
fn duplicate_id_does_not_replace_waiter_and_connections_are_isolated() {
	let mut first = PendingResponses::default();
	let mut second = PendingResponses::default();
	assert!(first.register(RequestId::Number(1), "first"));
	assert!(!first.register(RequestId::Number(1), "replacement"));
	assert!(second.register(RequestId::Number(1), "other-connection"));
	let reply = message(json!({"jsonrpc":"2.0","id":1,"result":{}}));
	assert!(matches!(
		first.route(reply.clone()),
		Inbound::Reply("first", _)
	));
	assert!(matches!(
		second.route(reply),
		Inbound::Reply("other-connection", _)
	));
}

#[test]
fn events_do_not_consume_reply_and_shutdown_releases_waiters() {
	use std::sync::{Arc, Weak};
	let waiter = Arc::new(());
	let released: Weak<()> = Arc::downgrade(&waiter);
	let mut pending = PendingResponses::default();
	assert!(pending.register(RequestId::Number(1), waiter));
	let event = message(json!({"jsonrpc":"2.0","method":"notifications/tools/list_changed"}));
	assert!(matches!(pending.route(event), Inbound::Event(_)));
	assert!(released.upgrade().is_some());
	pending.clear();
	assert!(released.upgrade().is_none());
	assert!(matches!(
		pending.route(message(json!({"jsonrpc":"2.0","id":1,"result":{}}))),
		Inbound::UnmatchedReply
	));
}

#[test]
fn endpoint_projection_preserves_origin_and_query_rules_without_panicking_on_bad_uri() {
	let base: Uri = "http://host.example/base?old=1".parse().unwrap();
	for (endpoint, expected) in [
		("?session=1", "http://host.example/base?session=1"),
		("/messages?id=2", "http://host.example/messages?id=2"),
		("messages", "http://host.example/messages"),
		(
			"https://other.example/messages",
			"https://other.example/messages",
		),
	] {
		assert_eq!(message_endpoint(base.clone(), endpoint).unwrap(), expected);
	}
	assert!(message_endpoint(base.clone(), "http://bad host/").is_err());
	assert!(message_endpoint(base, "bad\npath").is_err());
}

#[test]
fn connection_error_without_id_cannot_complete_an_unrelated_request() {
	let mut pending = PendingResponses::default();
	assert!(pending.register(RequestId::Number(1), "first"));
	let error =
		message(json!({"jsonrpc":"2.0","id":null,"error":{"code":-32700,"message":"parse error"}}));
	assert!(matches!(
		pending.route(error),
		Inbound::Event(ServerJsonRpcMessage::Error(_))
	));
	assert!(matches!(
		pending.route(message(json!({"jsonrpc":"2.0","id":1,"result":{}}))),
		Inbound::Reply("first", _)
	));
}

#[test]
fn unresponsive_connection_has_a_fixed_correlation_capacity() {
	let mut pending = PendingResponses::default();
	for id in 0..MAX_PENDING_RESPONSES {
		assert!(pending.register(RequestId::Number(id as i64), id));
	}
	assert!(!pending.register(RequestId::Number(MAX_PENDING_RESPONSES as i64), 0));
	assert!(pending.any(|id| *id == MAX_PENDING_RESPONSES - 1));
	let reply = message(json!({"jsonrpc":"2.0","id":0,"result":{}}));
	assert!(matches!(pending.route(reply), Inbound::Reply(0, _)));
	assert!(pending.register(RequestId::Number(MAX_PENDING_RESPONSES as i64), 42));
	pending.clear();
	assert!(!pending.any(|_| true));
}
