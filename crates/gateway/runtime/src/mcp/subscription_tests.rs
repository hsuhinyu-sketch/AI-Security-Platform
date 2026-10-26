use super::*;
use serde_json::json;

fn prepare(access: &SessionAccess, subscribe: bool) -> Option<Ticket> {
	let request = serde_json::from_value(json!({"jsonrpc":"2.0","id":1,
		"method":if subscribe { "resources/subscribe" } else { "resources/unsubscribe" },
		"params":{"uri":"file:///guide"}}))
	.unwrap();
	let mut ctx = super::super::tests::context(access);
	prepare_subscription(&request, &mut ctx, "docs").unwrap();
	ctx.extensions_mut().get::<Ticket>().cloned()
}
fn update() -> rmcp::model::ServerJsonRpcMessage {
	serde_json::from_value(json!({"jsonrpc":"2.0","method":"notifications/resources/updated","params":{"uri":"file:///guide"}})).unwrap()
}

#[test]
fn only_active_subscription_can_disclose_updates() {
	let access = super::super::tests::access();
	let ticket = prepare(&access, true).unwrap();
	assert!(notification(&access, "docs", &update()).is_err());
	ticket.commit(&access).unwrap();
	assert!(notification(&access, "docs", &update()).unwrap());
	assert!(notification(&access, "other-server", &update()).is_err());
	prepare(&access, false);
	assert!(notification(&access, "docs", &update()).is_err());
	assert!(ticket.commit(&access).is_err());
}

#[test]
fn cancelled_pending_ack_cannot_activate_replacement_or_foreign_session() {
	let access = super::super::tests::access();
	let stale = prepare(&access, true).unwrap();
	prepare(&access, false);
	let replacement = prepare(&access, true).unwrap();
	assert!(stale.commit(&access).is_err());
	let foreign = super::super::tests::access();
	assert!(replacement.commit(&foreign).is_err());
	assert!(notification(&access, "docs", &update()).is_err());
	replacement.commit(&access).unwrap();
	drop(stale);
	assert!(notification(&access, "docs", &update()).unwrap());
}

#[test]
fn failed_or_abandoned_subscribe_releases_capacity() {
	let mut access = super::super::tests::access();
	access.limits.max_subscriptions = 1;
	let ticket = prepare(&access, true).unwrap();
	drop(ticket);
	let ticket = prepare(&access, true).unwrap();
	Arc::make_mut(&mut access.config).pipeline.policies.push(
		serde_json::from_value(json!({
			"id":"revoke-resource", "enabled":true,"effect":"deny","resourceType":"mcpResource"
		}))
		.unwrap(),
	);
	assert!(ticket.commit(&access).is_err());
	assert!(notification(&access, "docs", &update()).is_err());
	drop(ticket);
	assert!(
		access
			.binding
			.as_ref()
			.unwrap()
			.subscriptions
			.lock()
			.unwrap()
			.is_empty()
	);
}
