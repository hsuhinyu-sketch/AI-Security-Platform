use super::*;

fn create() -> (
	SessionAccess,
	IncomingRequestContext,
	Ticket,
	JsonRpcRequest<ClientRequest>,
) {
	let mut access = super::super::tests::access();
	access.limits.tasks = Some(serde_json::from_value(json!({"tools":["echo"]})).unwrap());
	{
		let mut state = access.binding.as_ref().unwrap().tasks.lock().unwrap();
		state.source = Some(("tools".into(), true));
		state.tools.insert("echo".into(), false);
	}
	let mut ctx = super::super::tests::context(&access);
	let rpc = serde_json::from_value(json!({"jsonrpc":"2.0","id":1,"method":"tools/call",
		"params":{"name":"echo","arguments":{"text":"hello"},"task":{"ttl":60000}}}))
	.unwrap();
	prepare(&rpc, &mut ctx, "tools", false).unwrap();
	let ticket = ctx.extensions_mut().get::<Ticket>().unwrap().clone();
	(access, ctx, ticket, rpc)
}
fn accepted(access: &SessionAccess, ticket: &Ticket) {
	let now = chrono::Utc::now().to_rfc3339();
	let mut result =
		serde_json::from_value(json!({"task":{"taskId":"upstream-task","status":"working",
		"ttl":60000,"createdAt":now,"lastUpdatedAt":now}}))
		.unwrap();
	ticket.response(access, &mut result).unwrap();
}

#[tokio::test]
async fn task_dispatch_rejects_changed_arguments_or_tool_name() {
	let (_, ctx, _ticket, rpc) = create();
	for mutation in ["none", "arguments", "name"] {
		let mut value = serde_json::to_value(&rpc).unwrap();
		if mutation == "arguments" {
			value["params"]["arguments"] = json!({"text":"changed"});
		}
		if mutation == "name" {
			value["params"]["name"] = json!("delete");
		}
		let mut request = ctx.as_request();
		*request.body_mut() = crate::json::to_body(value).unwrap();
		let result = crate::mcp::dispatch::verify(&mut request, &Default::default()).await;
		assert_eq!(result.is_ok(), mutation == "none");
	}
}

#[test]
fn cancel_dispatch_is_single_use_even_without_execution_budget() {
	let (access, mut ctx, ticket, _) = create();
	accepted(&access, &ticket);
	let mut cancel = serde_json::from_value(json!({"jsonrpc":"2.0","id":2,"method":"tasks/cancel",
		"params":{"taskId":ticket.record.id}}))
	.unwrap();
	assert_eq!(route(&mut cancel, &mut ctx).unwrap(), "tools");
	let cancel_ticket = ctx.extensions_mut().get::<Ticket>().unwrap().clone();
	crate::mcp::dispatch::before_send(&ctx.as_request()).unwrap();
	assert!(cancel_ticket.before_send().is_err());
	assert!(ticket.record.cancel.load(Ordering::Acquire));
}

#[test]
fn task_terminal_snapshot_cannot_regress_or_cross_session() {
	let (access, ctx, ticket, _) = create();
	accepted(&access, &ticket);
	let mut snapshot = ticket.record.snapshot.lock().unwrap().clone().unwrap();
	snapshot.status = TaskStatus::Completed;
	ticket.update(&access, &mut snapshot, false).unwrap();
	let mut regression = ticket.record.snapshot.lock().unwrap().clone().unwrap();
	regression.status = TaskStatus::Working;
	assert!(ticket.update(&access, &mut regression, false).is_err());
	assert!(ticket.check(&super::super::tests::access()).is_err());
	let mut no_session = super::super::tests::context(&super::super::tests::access());
	let mut get = serde_json::from_value(json!({"jsonrpc":"2.0","id":2,"method":"tasks/get",
		"params":{"taskId":ticket.record.id}}))
	.unwrap();
	assert!(route(&mut get, &mut no_session).is_err());
	drop(ctx);
}

#[test]
fn legacy_constraint_is_rechecked_for_the_original_task_business_and_arguments() {
	let (mut access, _ctx, ticket, _rpc) = create();
	accepted(&access, &ticket);
	assert!(ticket.check(&access).is_ok());
	let legacy: security_pipeline::SecurityPipelineConfig = serde_json::from_value(json!({
			"policies":[{"id":"allow","effect":"allow","enabled":true}],
			"requiredToolArguments":[{"toolName":"echo","requiredFields":["recordId"]}]
	}))
	.unwrap();
	access.legacy = Some(legacy.into());
	assert!(ticket.check(&access).is_err());
}
