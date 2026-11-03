use super::*;
use serde_json::json;

// Private fixture compiled only for tests; production constructors and visibility are unchanged.
pub(super) fn access() -> SessionAccess {
	let config: SecurityConfig = serde_json::from_value(json!({
		"mode":"enforce", "mcpSessions":{},
		"policies":[{"id":"allow", "enabled":true, "effect":"allow"}]
	}))
	.unwrap();
	let identity = GatewayIdentity {
		user_id: Some("alice".into()),
		tenant_id: Some("tenant-a".into()),
		client_id: Some("client-a".into()),
		..Default::default()
	};
	let owner = VerifiedOwner::from_identity(&identity, "https://issuer.example").unwrap();
	let revision = gateway_contracts::ConfigRevision::default().lease();
	let binding = Arc::new(SessionBinding {
		owner: owner.clone(),
		scope: "route-a".into(),
		created: Instant::now(),
		last_access: Mutex::new(Instant::now()),
		idle_ttl: Duration::from_secs(300),
		max_age: Duration::from_secs(600),
		revision: revision.clone(),
		closed: AtomicBool::new(false),
		_slot: reserve(&Arc::new(AtomicUsize::new(0)), 1).unwrap(),
		subscriptions: Default::default(),
		reverse: Default::default(),
		tasks: Default::default(),
		flow: None,
	});
	SessionAccess {
		limits: config.mcp_sessions.clone().unwrap(),
		config: Arc::new(config),
		owner,
		identity: identity.clone(),
		scope: "route-a".into(),
		expires: chrono::Utc::now().timestamp() + 300,
		revision,
		action: security_pipeline::mcp_session_for_identity("internal", identity, "use", "session"),
		binding: Some(binding),
		_stream: reserve(&Arc::new(AtomicUsize::new(0)), 1).unwrap(),
		flow: None,
		policies: super::super::rbac::McpAuthorizationSet::new(Vec::new().into()),
		legacy: None,
		authorization_request: Arc::new(http::Request::new(())),
	}
}

pub(super) fn context(access: &SessionAccess) -> super::super::upstream::IncomingRequestContext {
	let mut req = http::Request::new(());
	req.extensions_mut().insert(access.clone());
	req
		.extensions_mut()
		.insert(security_types::RequestContext::default());
	super::super::upstream::IncomingRequestContext::new(&req.into_parts().0)
}

#[tokio::test]
async fn session_checks_intersect_common_and_legacy_declarations() {
	let mut access = access();
	assert!(access.check().is_ok());
	assert!(access.check_async().await.is_ok());
	for rules in [
		json!([]),
		json!([
			{"id":"allow","enabled":true,"effect":"allow"},
			{"id":"deny-session","enabled":true,"effect":"deny","actionType":"mcpSessionOperation"}
		]),
	] {
		let legacy: security_pipeline::SecurityPipelineConfig =
			serde_json::from_value(json!({"policies":rules})).unwrap();
		access.legacy = Some(legacy.into());
		assert!(access.check().is_err());
		assert!(access.check_async().await.is_err());
	}
	let legacy: security_pipeline::SecurityPipelineConfig = serde_json::from_value(json!({
		"policies":[{"id":"allow","enabled":true,"effect":"allow"}]
	}))
	.unwrap();
	access.legacy = Some(legacy.into());
	assert!(access.check().is_ok());
	assert!(access.check_async().await.is_ok());
	Arc::make_mut(&mut access.config).pipeline.policies.clear();
	assert!(access.check().is_err());
	assert!(access.check_async().await.is_err());
}

#[test]
fn session_rejects_foreign_owner_scope_expiry_and_closed_binding() {
	let access = access();
	assert!(access.check().is_ok());
	for field in ["user", "tenant", "client", "issuer", "scope"] {
		let mut foreign = access.clone();
		let mut identity = foreign.identity.clone();
		match field {
			"user" => identity.user_id = Some("bob".into()),
			"tenant" => identity.tenant_id = Some("other".into()),
			"client" => identity.client_id = Some("other".into()),
			"scope" => foreign.scope = "other".into(),
			_ => {},
		}
		foreign.owner = VerifiedOwner::from_identity(
			&identity,
			if field == "issuer" {
				"https://other.example"
			} else {
				"https://issuer.example"
			},
		)
		.unwrap();
		assert!(foreign.check().is_err(), "{field}");
	}
	let mut expired = access.clone();
	expired.expires = chrono::Utc::now().timestamp() - 1;
	assert!(expired.check().is_err());
	access
		.binding
		.as_ref()
		.unwrap()
		.closed
		.store(true, Ordering::Release);
	assert!(access.check().is_err());
}

#[tokio::test]
async fn configuration_invalidation_drops_pending_upstream_future() {
	struct OnDrop(Arc<AtomicBool>);
	impl Drop for OnDrop {
		fn drop(&mut self) {
			self.0.store(true, Ordering::Release);
		}
	}
	let mut access = access();
	let revision = gateway_contracts::ConfigRevision::default();
	access.revision = revision.lease();
	let dropped = Arc::new(AtomicBool::new(false));
	let upstream = async {
		let _lease = OnDrop(dropped.clone());
		std::future::pending::<Result<Response, ProxyError>>().await
	};
	let invalidate = async {
		tokio::task::yield_now().await;
		revision.invalidate();
	};
	let (result, ()) = tokio::join!(access.call(upstream), invalidate);
	assert!(result.is_err());
	assert!(dropped.load(Ordering::Acquire));
}

#[tokio::test(start_paused = true)]
async fn idle_response_terminates_and_drops_upstream_on_timeout() {
	struct OnDrop(Arc<AtomicBool>);
	impl Drop for OnDrop {
		fn drop(&mut self) {
			self.0.store(true, Ordering::Release);
		}
	}
	let mut access = access();
	access.limits.stream_idle_seconds = 1;
	let dropped = Arc::new(AtomicBool::new(false));
	let lease = OnDrop(dropped.clone());
	let upstream =
		futures_util::stream::pending::<Result<bytes::Bytes, std::io::Error>>().map(move |item| {
			let _keep = &lease;
			item
		});
	let response = access
		.protect_response(Response::new(Body::from_stream(upstream)))
		.await
		.unwrap();
	assert!(
		crate::http::read_body_with_limit(response.into_body(), 1024)
			.await
			.is_err()
	);
	assert!(dropped.load(Ordering::Acquire));
}

#[tokio::test]
async fn notifications_do_not_lose_terminal_result_or_disclose_unrelated_progress() {
	let access = access();
	let context = context(&access);
	let request = serde_json::from_value(json!({"jsonrpc":"2.0","id":7,"method":"tools/call", "params":{"name":"echo","arguments":{},"_meta":{"progressToken":"mine"}}})).unwrap();
	let messages = [
		json!({"jsonrpc":"2.0","method":"notifications/progress","params":{"progressToken":"other","progress":1}}),
		json!({"jsonrpc":"2.0","method":"notifications/message","params":{"level":"info","data":"private log"}}),
		json!({"jsonrpc":"2.0","method":"notifications/tasks/status","params":{"taskId":"unrelated-task","status":"working","createdAt":"2026-10-29T00:00:00Z","lastUpdatedAt":"2026-10-29T00:00:00Z","ttl":60000}}),
		json!({"jsonrpc":"2.0","method":"notifications/progress","params":{"progressToken":"mine","progress":2}}),
		json!({"jsonrpc":"2.0","id":7,"result":{"content":[{"type":"text","text":"terminal"}]}}),
	];
	let stream = Messages::from_stream(futures_util::stream::iter(
		messages
			.into_iter()
			.map(|v| Ok(serde_json::from_value(v).unwrap())),
	));
	let values = protect_messages(stream, &context, Some(&request), "upstream")
		.try_collect::<Vec<_>>()
		.await
		.unwrap();
	assert_eq!(values.len(), 2);
	assert_eq!(
		serde_json::to_value(&values[0]).unwrap()["params"]["progressToken"],
		"mine"
	);
	assert_eq!(serde_json::to_value(&values[1]).unwrap()["id"], 7);
}

#[tokio::test(start_paused = true)]
async fn ignored_notifications_do_not_extend_idle_deadline() {
	let mut access = access();
	access.limits.stream_idle_seconds = 2;
	let context = context(&access);
	let stream = Messages::from_stream(futures_util::stream::unfold((), |_| async {
		tokio::time::sleep(Duration::from_secs(1)).await;
		Some((Ok(serde_json::from_value(json!({"jsonrpc":"2.0","method":"notifications/message", "params":{"level":"info","data":"ignored"}})).unwrap()), ()))
	}));
	let start = tokio::time::Instant::now();
	assert!(
		protect_messages(stream, &context, None, "upstream")
			.next()
			.await
			.unwrap()
			.is_err()
	);
	assert_eq!(start.elapsed(), Duration::from_secs(2));
}

#[tokio::test]
async fn checks_and_binding_do_not_count_as_activity_but_accepted_requests_do() {
	let mut access = access();
	let binding = access.binding.clone().unwrap();
	let before = Instant::now() - Duration::from_secs(100);
	*binding.last_access.lock().unwrap() = before;
	access.check().unwrap();
	access.check_async().await.unwrap();
	access.bind(binding.clone()).await.unwrap();
	assert!(
		access
			.call(async { Err(ProxyError::AuthorizationFailed) })
			.await
			.is_err()
	);
	assert_eq!(*binding.last_access.lock().unwrap(), before);
	access
		.call(async { Ok(Response::new(Body::empty())) })
		.await
		.unwrap();
	assert!(*binding.last_access.lock().unwrap() > before);
	*binding.last_access.lock().unwrap() = before;
	access
		.call(async {
			Ok(
				http::Response::builder()
					.status(http::StatusCode::ACCEPTED)
					.body(Body::empty())
					.unwrap(),
			)
		})
		.await
		.unwrap();
	assert!(*binding.last_access.lock().unwrap() > before);
}

#[tokio::test]
async fn only_authorized_correlated_messages_refresh_the_binding() {
	for case in ["accepted", "unrelated", "business-denied", "malformed"] {
		let mut access = access();
		if case == "business-denied" {
			Arc::make_mut(&mut access.config).pipeline.policies.push(
				serde_json::from_value(json!({
						"id":"deny-tool", "effect":"deny", "enabled":true, "actionType":"toolInvoke"
				}))
				.unwrap(),
			);
		}
		let binding = access.binding.clone().unwrap();
		let before = Instant::now() - Duration::from_secs(100);
		*binding.last_access.lock().unwrap() = before;
		let context = context(&access);
		let request = serde_json::from_value(json!({"jsonrpc":"2.0","id":7,"method":"tools/call", "params":{"name":"echo","arguments":{},"_meta":{"progressToken":"mine"}}})).unwrap();
		let message = match case {
			"unrelated" => {
				json!({"jsonrpc":"2.0","method":"notifications/progress","params":{"progressToken":"other","progress":1}})
			},
			"malformed" => json!({"jsonrpc":"2.0","id":8,"result":{"content":[]}}),
			_ => {
				json!({"jsonrpc":"2.0","method":"notifications/progress","params":{"progressToken":"mine","progress":1}})
			},
		};
		let messages = Messages::from_stream(futures_util::stream::iter([Ok(
			serde_json::from_value(message).unwrap(),
		)]));
		let result = protect_messages(messages, &context, Some(&request), "upstream")
			.next()
			.await;
		if case == "accepted" {
			assert!(result.unwrap().is_ok());
			assert!(*binding.last_access.lock().unwrap() > before);
		} else {
			if case == "unrelated" {
				assert!(result.is_none());
			} else {
				assert!(result.unwrap().is_err());
			}
			assert_eq!(*binding.last_access.lock().unwrap(), before, "{case}");
		}
	}
}

#[tokio::test]
async fn activity_cannot_revive_idle_old_foreign_revoked_or_denied_sessions() {
	for case in [
		"idle",
		"max-age",
		"owner",
		"closed",
		"revision",
		"credential",
		"policy",
	] {
		let mut access = access();
		let binding = Arc::get_mut(access.binding.as_mut().unwrap()).unwrap();
		binding.last_access = Mutex::new(Instant::now() - Duration::from_secs(100));
		match case {
			"idle" => binding.idle_ttl = Duration::from_secs(1),
			"max-age" => binding.created = Instant::now() - Duration::from_secs(601),
			"owner" => access.scope = "foreign".into(),
			"closed" => binding.closed.store(true, Ordering::Release),
			"revision" => {
				let revision = gateway_contracts::ConfigRevision::default();
				binding.revision = revision.lease();
				revision.invalidate();
			},
			"credential" => access.expires = 0,
			"policy" => Arc::make_mut(&mut access.config).pipeline.policies.clear(),
			_ => unreachable!(),
		}
		let binding = access.binding.as_ref().unwrap();
		let before = *binding.last_access.lock().unwrap();
		assert!(
			access
				.call(async {
					Ok(
						http::Response::builder()
							.status(http::StatusCode::ACCEPTED)
							.body(Body::empty())
							.unwrap(),
					)
				})
				.await
				.is_err(),
			"{case}"
		);
		assert_eq!(*binding.last_access.lock().unwrap(), before, "{case}");
	}
}
