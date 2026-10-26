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
	super::super::upstream::IncomingRequestContext::new(&req.into_parts().0)
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
		.unwrap();
	assert!(
		crate::http::read_body_with_limit(response.into_body(), 1024)
			.await
			.is_err()
	);
	assert!(dropped.load(Ordering::Acquire));
}
