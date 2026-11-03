use super::*;

#[test]
fn sampling_negotiation_matches_compiled_model_execution() {
	let (access, parent) = setup();
	let config =
		serde_json::from_value(json!({"samplingModels":["local"],"roots":["file:///workspace"]}))
			.unwrap();
	let mut capabilities = serde_json::from_value(json!({"sampling":{},"roots":{}})).unwrap();
	negotiate(access.binding.as_ref().unwrap(), &config, &mut capabilities).unwrap();
	let value = serde_json::to_value(capabilities).unwrap();
	assert_eq!(
		value.get("sampling").is_some(),
		cfg!(feature = "gateway-llm")
	);
	assert!(value.get("roots").is_some());
	if !cfg!(feature = "gateway-llm") {
		let mut message = serde_json::from_value(json!({"jsonrpc":"2.0","id":9,"method":"sampling/createMessage","params":{"messages":[{"role":"user","content":{"type":"text","text":"hello"}}],"maxTokens":8}})).unwrap();
		assert!(request(&access, Some(&parent), &mut message).is_err());
	}
}

fn setup() -> (SessionAccess, ParentLease) {
	let mut access = super::super::tests::access();
	access.limits.reverse =
		Some(serde_json::from_value(json!({"roots":["file:///workspace"]})).unwrap());
	let mut caps = serde_json::from_value(json!({"roots":{}})).unwrap();
	negotiate(
		access.binding.as_ref().unwrap(),
		access.limits.reverse.as_ref().unwrap(),
		&mut caps,
	)
	.unwrap();
	let rpc: JsonRpcRequest<ClientRequest> = serde_json::from_value(
		json!({"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"echo","arguments":{}}}),
	)
	.unwrap();
	let op = crate::mcp::security::normalize(&rpc, "internal", access.identity.clone(), "tools");
	let parent = parent(
		&access,
		"tools",
		Some(&rpc),
		Some(Arc::new((op.action, op.arguments))),
	)
	.unwrap()
	.unwrap();
	(access, parent)
}
fn question(access: &SessionAccess, parent: &ParentLease) -> String {
	let mut message =
		serde_json::from_value(json!({"jsonrpc":"2.0","id":21,"method":"roots/list","params":{}}))
			.unwrap();
	request(access, Some(parent), &mut message).unwrap();
	serde_json::to_value(message).unwrap()["id"]
		.as_str()
		.unwrap()
		.to_owned()
}
fn answer(id: &str) -> ClientJsonRpcMessage {
	serde_json::from_value(json!({"jsonrpc":"2.0","id":id,"result":{"roots":[{"uri":"file:///workspace"},{"uri":"file:///private"}]}})).unwrap()
}

#[test]
fn reverse_response_is_single_use_and_bound_to_live_parent() {
	let (access, parent) = setup();
	let id = question(&access, &parent);
	let (server, forwarded, _, _) = response(&access, answer(&id)).unwrap();
	assert_eq!(server, "tools");
	let forwarded = serde_json::to_value(forwarded).unwrap();
	assert_eq!(forwarded["id"], 21);
	assert_eq!(forwarded["result"]["roots"].as_array().unwrap().len(), 1);
	assert!(response(&access, answer(&id)).is_err());
	let id = question(&access, &parent);
	drop(parent);
	assert!(response(&access, answer(&id)).is_err());
	assert!(
		access
			.binding
			.as_ref()
			.unwrap()
			.reverse
			.lock()
			.unwrap()
			.pending
			.is_empty()
	);
}

#[test]
fn reverse_response_from_other_session_or_after_deadline_is_denied() {
	let (access, parent) = setup();
	let id = question(&access, &parent);
	let (foreign, _parent) = setup();
	assert!(response(&foreign, answer(&id)).is_err());
	access
		.binding
		.as_ref()
		.unwrap()
		.reverse
		.lock()
		.unwrap()
		.pending
		.get_mut(&id)
		.unwrap()
		.expires = Instant::now() - Duration::from_secs(1);
	assert!(response(&access, answer(&id)).is_err());
}

#[test]
fn legacy_parent_constraint_is_rechecked_before_reverse_response() {
	let (mut access, parent) = setup();
	let id = question(&access, &parent);
	let legacy: security_pipeline::SecurityPipelineConfig =
		serde_json::from_value(json!({"policies":[
				{"id":"allow","effect":"allow","enabled":true},
				{"id":"deny-parent","effect":"deny","enabled":true,"actionType":"toolInvoke"}
		]}))
		.unwrap();
	access.legacy = Some(legacy.into());
	assert!(response(&access, answer(&id)).is_err());
}

fn task_setup() -> (SessionAccess, ParentLease) {
	let (mut access, ordinary) = setup();
	drop(ordinary);
	access.limits.reverse.as_mut().unwrap().max_pending = 1;
	access.limits.tasks =
		Some(serde_json::from_value(json!({"tools":["echo"],"roots":true})).unwrap());
	let initialize = serde_json::from_value(json!({"protocolVersion":"2025-11-25",
		"serverInfo":{"name":"tools","version":"1"},
		"capabilities":{"tasks":{"requests":{"tools":{"call":{}}}}}}))
	.unwrap();
	super::super::tasks::observe_initialize(&access, "tools", &initialize).unwrap();
	let mut tools = serde_json::from_value(json!({"tools":[{"name":"echo",
		"inputSchema":{"type":"object"},"execution":{"taskSupport":"optional"}}]}))
	.unwrap();
	super::super::tasks::observe_tools(&access, "tools", &mut tools).unwrap();
	let mut ctx = super::super::tests::context(&access);
	let rpc = serde_json::from_value(json!({"jsonrpc":"2.0","id":1,"method":"tools/call",
		"params":{"name":"echo","arguments":{},"task":{"ttl":60000}}}))
	.unwrap();
	let admission = super::super::tasks::prepare(&rpc, &mut ctx, "tools", false)
		.unwrap()
		.unwrap();
	let ticket = ctx
		.extensions_mut()
		.get::<super::super::tasks::Ticket>()
		.unwrap()
		.clone();
	let now = chrono::Utc::now().to_rfc3339();
	let mut result = serde_json::from_value(json!({"task":{"taskId":"upstream-task",
		"status":"working","ttl":60000,"createdAt":now,"lastUpdatedAt":now}}))
	.unwrap();
	ticket.response(&access, &mut result).unwrap();
	drop(admission);
	let task_id = serde_json::to_value(result).unwrap()["task"]["taskId"].clone();
	let mut rpc = serde_json::from_value(json!({"jsonrpc":"2.0","id":2,"method":"tasks/result",
		"params":{"taskId":task_id}}))
	.unwrap();
	super::super::tasks::route(&mut rpc, &mut ctx).unwrap();
	let ticket = ctx
		.extensions_mut()
		.get::<super::super::tasks::Ticket>()
		.unwrap()
		.clone();
	let parent = task_parent(&access, "tools", Some(&rpc), &ticket)
		.unwrap()
		.unwrap();
	(access, parent)
}

fn task_question(id: Value) -> ServerJsonRpcMessage {
	crate::mcp::wire::decode_server(json!({"jsonrpc":"2.0","id":id,"method":"roots/list",
		"params":{"_meta":{"io.modelcontextprotocol/related-task":{"taskId":"upstream-task"}}}}))
	.unwrap()
}

fn task_answer(access: &SessionAccess, parent: &ParentLease, question: ServerJsonRpcMessage) {
	let id = serde_json::to_value(question).unwrap()["id"].clone();
	let message = serde_json::from_value(json!({"jsonrpc":"2.0","id":id,"result":{
		"roots":[{"uri":"file:///workspace"}],
		"_meta":{"io.modelcontextprotocol/related-task":{"taskId":parent.parent.task.as_ref().unwrap().gateway_id()}}
	}})).unwrap();
	response(access, message).unwrap();
}

#[test]
fn rejected_capacity_and_negotiation_do_not_consume_task_interaction_ids() {
	for reason in ["capacity", "negotiation"] {
		let (access, parent) = task_setup();
		let mut first = task_question(json!(0));
		if reason == "capacity" {
			request(&access, Some(&parent), &mut first).unwrap();
		} else {
			access
				.binding
				.as_ref()
				.unwrap()
				.reverse
				.lock()
				.unwrap()
				.capabilities = json!({});
		}
		for id in 1..=64 {
			let mut message = task_question(json!(id));
			let original = serde_json::to_value(&message).unwrap();
			assert!(request(&access, Some(&parent), &mut message).is_err());
			assert_eq!(serde_json::to_value(message).unwrap(), original);
		}
		if reason == "capacity" {
			task_answer(&access, &parent, first);
		} else {
			access
				.binding
				.as_ref()
				.unwrap()
				.reverse
				.lock()
				.unwrap()
				.capabilities = json!({"roots":{}});
		}
		let mut retry = task_question(json!(1));
		request(&access, Some(&parent), &mut retry).unwrap();
		task_answer(&access, &parent, retry);
	}
}

#[test]
fn duplicates_remain_single_use_and_the_task_lifetime_limit_is_preserved() {
	let (access, parent) = task_setup();
	for id in 0..64 {
		let mut message = task_question(json!(id));
		request(&access, Some(&parent), &mut message).unwrap();
		let mut duplicate = task_question(json!(id));
		assert!(request(&access, Some(&parent), &mut duplicate).is_err());
		task_answer(&access, &parent, message);
		assert!(request(&access, Some(&parent), &mut duplicate).is_err());
	}
	assert!(request(&access, Some(&parent), &mut task_question(json!(64))).is_err());
	assert!(
		access
			.binding
			.as_ref()
			.unwrap()
			.reverse
			.lock()
			.unwrap()
			.pending
			.is_empty()
	);
}

#[test]
fn concurrent_reverse_admission_reserves_only_available_pending_slots() {
	for same_id in [false, true] {
		let (access, parent) = task_setup();
		let results = std::thread::scope(|scope| {
			let start = Arc::new(std::sync::Barrier::new(8));
			let handles: Vec<_> = (0..8)
				.map(|id| {
					let access = access.clone();
					let parent = &parent;
					let start = start.clone();
					scope.spawn(move || {
						let upstream = if same_id { 0 } else { id };
						let mut message = task_question(json!(upstream));
						start.wait();
						(
							upstream,
							request(&access, Some(parent), &mut message)
								.ok()
								.map(|_| message),
						)
					})
				})
				.collect();
			handles
				.into_iter()
				.map(|h| h.join().unwrap())
				.collect::<Vec<_>>()
		});
		assert_eq!(results.iter().filter(|(_, m)| m.is_some()).count(), 1);
		assert_eq!(
			access
				.binding
				.as_ref()
				.unwrap()
				.reverse
				.lock()
				.unwrap()
				.pending
				.len(),
			1
		);
		let winner = results
			.iter()
			.find_map(|(id, m)| m.as_ref().map(|_| *id))
			.unwrap();
		for (_, message) in &results {
			if let Some(message) = message {
				task_answer(&access, &parent, message.clone());
			}
		}
		for (id, _) in results {
			if id != winner {
				let mut retry = task_question(json!(id));
				request(&access, Some(&parent), &mut retry).unwrap();
				task_answer(&access, &parent, retry);
			}
		}
	}
}

#[test]
fn denied_and_invalid_requests_do_not_claim_task_ids() {
	let (access, parent) = task_setup();
	let mut denied = access.clone();
	denied.legacy = Some(
		serde_json::from_value::<security_pipeline::SecurityPipelineConfig>(json!({
			"policies":[{"id":"deny","effect":"deny","enabled":true}]
		}))
		.unwrap()
		.into(),
	);
	for id in 0..64 {
		assert!(request(&denied, Some(&parent), &mut task_question(json!(id))).is_err());
		let mut invalid = task_question(json!(id));
		if let ServerJsonRpcMessage::Request(r) = &mut invalid {
			r.request = serde_json::from_value(json!({"method":"roots/list","params":{
				"_meta":{"io.modelcontextprotocol/related-task":{"taskId":"foreign"}}}}))
			.unwrap();
		}
		assert!(request(&access, Some(&parent), &mut invalid).is_err());
	}
	let mut message = task_question(json!(0));
	request(&access, Some(&parent), &mut message).unwrap();
	task_answer(&access, &parent, message);
}
