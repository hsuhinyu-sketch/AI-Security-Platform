use super::*;

fn create() -> (
	SessionAccess,
	IncomingRequestContext,
	Ticket,
	JsonRpcRequest<ClientRequest>,
	Admission,
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
	let admission = prepare(&rpc, &mut ctx, "tools", false).unwrap().unwrap();
	let ticket = ctx.extensions_mut().get::<Ticket>().unwrap().clone();
	(access, ctx, ticket, rpc, admission)
}
fn accepted(access: &SessionAccess, ticket: &Ticket) {
	let now = chrono::Utc::now().to_rfc3339();
	let mut result =
		serde_json::from_value(json!({"task":{"taskId":"upstream-task","status":"working",
		"ttl":60000,"createdAt":now,"lastUpdatedAt":now}}))
		.unwrap();
	ticket.response(access, &mut result).unwrap();
}

#[test]
fn unconfirmed_admission_releases_capacity_and_invalidates_outstanding_tickets() {
	let (mut access, ctx, ticket, rpc, admission) = create();
	access.limits.tasks.as_mut().unwrap().max_tasks = 1;
	let slot = Arc::downgrade(&ticket.record._slot);
	let owner = access.binding.as_ref().unwrap();
	let mut next = super::super::tests::context(&access);
	assert!(prepare(&rpc, &mut next, "tools", false).is_err());
	drop(admission);
	assert!(owner.tasks.lock().unwrap().records.is_empty());
	assert!(ticket.check(&access).is_err());
	let replacement = prepare(&rpc, &mut next, "tools", false).unwrap().unwrap();
	assert_ne!(replacement.ticket.record.id, ticket.record.id);
	// A live request clone keeps its own allocation, never a registry capacity slot.
	drop(ticket);
	drop(ctx);
	assert!(slot.upgrade().is_none());
	drop(replacement);
	assert!(owner.tasks.lock().unwrap().records.is_empty());
}

#[test]
fn accepted_admission_retains_task_and_capacity() {
	let (mut access, mut ctx, ticket, rpc, admission) = create();
	access.limits.tasks.as_mut().unwrap().max_tasks = 1;
	accepted(&access, &ticket);
	drop(admission);
	ticket.check(&access).unwrap();
	assert!(prepare(&rpc, &mut ctx, "tools", false).is_err());
	let mut get = serde_json::from_value(json!({"jsonrpc":"2.0","id":2,
		"method":"tasks/get","params":{"taskId":ticket.record.id}}))
	.unwrap();
	assert_eq!(route(&mut get, &mut ctx).unwrap(), "tools");
}

#[tokio::test]
async fn dropping_pending_dispatch_or_unconfirmed_response_releases_record() {
	use futures_util::{FutureExt, StreamExt};
	for phase in ["dispatch", "response"] {
		let (access, ctx, ticket, _, admission) = create();
		if phase == "dispatch" {
			let future = async move {
				let _admission = admission;
				std::future::pending::<()>().await;
			};
			let mut future = Box::pin(future);
			assert!(future.as_mut().now_or_never().is_none());
			drop(future);
		} else {
			let stream = hold_admission(
				Messages::from_stream(futures_util::stream::pending()),
				Some(admission),
			);
			let mut stream = super::super::protect_messages(stream, &ctx, None, "tools");
			assert!(stream.next().now_or_never().is_none());
			drop(stream);
		}
		assert!(
			access
				.binding
				.as_ref()
				.unwrap()
				.tasks
				.lock()
				.unwrap()
				.records
				.is_empty(),
			"{phase}"
		);
		assert!(ticket.check(&access).is_err(), "{phase}");
	}
}

#[test]
fn concurrent_admissions_release_only_unconfirmed_records() {
	let (mut access, ctx, ticket, rpc, admission) = create();
	drop(admission);
	drop(ctx);
	drop(ticket);
	access.limits.tasks.as_mut().unwrap().max_tasks = 4;
	let admissions = std::thread::scope(|scope| {
		let handles: Vec<_> = (0..4)
			.map(|id| {
				let access = access.clone();
				let mut rpc = rpc.clone();
				rpc.id = rmcp::model::RequestId::Number(id);
				scope.spawn(move || {
					let mut ctx = super::super::tests::context(&access);
					prepare(&rpc, &mut ctx, "tools", false).unwrap().unwrap()
				})
			})
			.collect();
		handles
			.into_iter()
			.map(|h| h.join().unwrap())
			.collect::<Vec<_>>()
	});
	assert_eq!(
		access
			.binding
			.as_ref()
			.unwrap()
			.tasks
			.lock()
			.unwrap()
			.records
			.len(),
		4
	);
	accepted(&access, &admissions[0].ticket);
	let retained = admissions[0].ticket.clone();
	let released: Vec<_> = admissions[1..]
		.iter()
		.map(|a| Arc::downgrade(&a.ticket.record._slot))
		.collect();
	std::thread::scope(|scope| {
		for admission in admissions {
			scope.spawn(move || drop(admission));
		}
	});
	assert_eq!(
		access
			.binding
			.as_ref()
			.unwrap()
			.tasks
			.lock()
			.unwrap()
			.records
			.len(),
		1
	);
	retained.check(&access).unwrap();
	assert!(released.iter().all(|slot| slot.upgrade().is_none()));
}

#[tokio::test]
async fn task_dispatch_rejects_changed_arguments_or_tool_name() {
	let (_, ctx, _ticket, rpc, _admission) = create();
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
	let (access, mut ctx, ticket, _, _admission) = create();
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
	let (access, ctx, ticket, _, _admission) = create();
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
	let (mut access, _ctx, ticket, _rpc, _admission) = create();
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

#[test]
fn legacy_denials_apply_to_task_operations_and_transport_before_business() {
	let (mut access, _ctx, mut ticket, _rpc, _admission) = create();
	accepted(&access, &ticket);
	ticket.method = "tasks/get".into();
	for action in ["mcpTaskOperation", "mcpOperation"] {
		access.legacy = None;
		assert!(ticket.check(&access).is_ok());
		let legacy: security_pipeline::SecurityPipelineConfig = serde_json::from_value(json!({
			"policies":[{"id":"allow","enabled":true,"effect":"allow"},
				{"id":"deny","enabled":true,"effect":"deny","actionType":action}]
		}))
		.unwrap();
		access.legacy = Some(legacy.into());
		assert!(ticket.check(&access).is_err(), "{action}");
	}
}

#[test]
fn legacy_task_interaction_constraint_is_rechecked_for_the_specific_phase() {
	let (mut access, mut ctx, mut ticket, _, _admission) = create();
	accepted(&access, &ticket);
	access.limits.tasks.as_mut().unwrap().roots = true;
	access.limits.reverse =
		Some(serde_json::from_value(json!({"roots":["file:///workspace"]})).unwrap());
	ticket.method = "tasks/result".into();
	interaction::reserve_result(&mut ticket, &access, &mut ctx).unwrap();
	let (link, _lease) = interaction::Link::attach(&ticket, &access, "tools")
		.unwrap()
		.unwrap();
	assert!(link.check(&access, "roots/list", "request").is_ok());
	let action = operation(&access, "roots/list/request", "tools", &ticket.record.id);
	let legacy: security_pipeline::SecurityPipelineConfig = serde_json::from_value(json!({
		"policies":[{"id":"allow","enabled":true,"effect":"allow"},
			{"id":"deny-phase","enabled":true,"effect":"deny","actionName":action.action.name}]
	}))
	.unwrap();
	access.legacy = Some(legacy.into());
	assert!(ticket.check(&access).is_ok());
	assert!(link.check(&access, "roots/list", "request").is_err());
	assert!(link.check(&access, "roots/list", "response").is_ok());
}
