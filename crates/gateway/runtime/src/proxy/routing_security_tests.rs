use super::*;
use crate::http::{Body, Response};
use http_body_util::BodyExt;
use std::sync::atomic::{AtomicBool, Ordering};

#[cfg(feature = "gateway-llm")]
struct PendingWindow {
	started: Arc<AtomicBool>,
	dropped: Arc<AtomicBool>,
}
#[cfg(feature = "gateway-llm")]
#[async_trait::async_trait]
impl gateway_llm::StreamingEvaluator for PendingWindow {
	async fn evaluate(
		&mut self,
		_: &str,
	) -> anyhow::Result<Option<gateway_llm::StreamingGuardrailOutcome>> {
		let lease = OnDrop(self.dropped.clone());
		self.started.store(true, Ordering::SeqCst);
		std::future::pending::<()>().await;
		drop(lease);
		Ok(None)
	}
}

#[cfg(feature = "gateway-llm")]
#[tokio::test]
async fn s6_config_revocation_discards_guard_window_and_cancels_pending_evaluation() {
	use futures_util::StreamExt;
	let (guards, revision, target) = guarded();
	let started = Arc::new(AtomicBool::new(false));
	let evaluation_dropped = Arc::new(AtomicBool::new(false));
	let source_dropped = Arc::new(AtomicBool::new(false));
	let lease = OnDrop(source_dropped.clone());
	let stream = futures_util::stream::iter([Ok::<_, std::io::Error>(bytes::Bytes::from_static(
		b"data: {\"choices\":[{\"delta\":{\"content\":\"withheld-secret\"}}]}\n\n",
	))])
	.chain(futures_util::stream::pending())
	.map(move |item| {
		let _keep = &lease;
		item
	});
	let guarded = gateway_llm::GuardedSseBody::with_threshold(
		Body::from_stream(stream),
		vec![Box::new(PendingWindow {
			started: started.clone(),
			dropped: evaluation_dropped.clone(),
		})],
		4096,
		None::<()>,
		1,
	);
	let mut body = guards
		.protect_response(Response::new(Body::new(guarded)), &target)
		.unwrap()
		.into_body();
	assert!(futures_util::poll!(body.frame()).is_pending());
	assert!(started.load(Ordering::SeqCst));
	revision.invalidate();
	assert!(body.frame().await.unwrap().is_err());
	assert!(body.frame().await.is_none());
	assert!(source_dropped.load(Ordering::SeqCst));
	assert!(evaluation_dropped.load(Ordering::SeqCst));
}

#[cfg(feature = "gateway-llm")]
#[tokio::test]
async fn s6_config_revocation_blocks_already_approved_guard_flush_queue() {
	let (guards, revision, target) = guarded();
	let data=bytes::Bytes::from_static(b"data: {\"choices\":[{\"delta\":{\"content\":\"first\"}}]}\n\ndata: {\"choices\":[{\"delta\":{\"content\":\"withheld-second\"}}]}\n\n");
	let guarded =
		gateway_llm::GuardedSseBody::with_threshold(Body::from(data), vec![], 4096, None::<()>, 1);
	let mut body = guards
		.protect_response(Response::new(Body::new(guarded)), &target)
		.unwrap()
		.into_body();
	let first = body.frame().await.unwrap().unwrap().into_data().unwrap();
	assert!(String::from_utf8_lossy(&first).contains("first"));
	assert!(!String::from_utf8_lossy(&first).contains("withheld-second"));
	revision.invalidate();
	assert!(body.frame().await.unwrap().is_err());
	assert!(body.frame().await.is_none());
}

fn guarded() -> (Guards, gateway_contracts::ConfigRevision, Target) {
	let config = serde_json::from_value(serde_json::json!({"mode":"enforce",
		"policies":[{"id":"allow","enabled":true,"effect":"allow"}]}))
	.unwrap();
	let revision = gateway_contracts::ConfigRevision::default();
	let guards = Guards(vec![Arc::new(Guard {
		config: Arc::new(config),
		flow: None,
		identity: Default::default(),
		request_id: "internal".into(),
		model: Some("local".into()),
		inference: false,
		agent: false,
		expires: Some(chrono::Utc::now().timestamp() + 300),
		revision: Some(revision.lease()),
		attempt: 0,
	})]);
	(guards, revision, Target::from(("127.0.0.1", 8080)))
}

#[tokio::test]
async fn bound_dependency_rechecks_final_target_and_preserves_revocation_context() {
	use crate::proxy::httpproxy::{
		PolicyClient,
		execution_tests::{Server, inputs},
	};
	use crate::telemetry::metrics::{OutboundCallKind, OutboundCallSubtype};
	use gateway_protocol_core::execution::BoundHttpExecution;
	use std::sync::atomic::Ordering;
	let allowed = Server::new("{}").await;
	let foreign = Server::new("{}").await;
	let (mut guards, revision, _) = guarded();
	let config = Arc::make_mut(&mut Arc::get_mut(&mut guards.0[0]).unwrap().config);
	config.data_egress = Some(
		serde_json::from_value(serde_json::json!({
			"classification":"internal", "modelDestinations":[allowed.address.to_string()]
		}))
		.unwrap(),
	);
	let allowed_target = Target::Address(allowed.address);
	guards.0[0].prefilter(Some(&allowed_target)).unwrap();
	let client = PolicyClient::new(inputs(&[allowed.address, foreign.address]))
		.with_outbound(OutboundCallKind::Policy, OutboundCallSubtype::Guardrail);
	for (target, expected) in [(&allowed, true), (&foreign, false), (&allowed, false)] {
		if target.address == allowed.address && !expected {
			revision.invalidate();
		}
		let mut request = ::http::Request::builder()
			.uri("/")
			.body(Body::empty())
			.unwrap();
		request.extensions_mut().insert(guards.clone());
		let result = client
			.bind_reference(&target.target(), &[])
			.execute(request)
			.await;
		assert_eq!(result.is_ok(), expected);
	}
	assert_eq!(allowed.calls.load(Ordering::SeqCst), 1);
	assert_eq!(foreign.calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn bound_dependency_candidate_allow_cannot_bypass_required_audit_failure() {
	use crate::proxy::httpproxy::{
		PolicyClient,
		execution_tests::{Server, inputs},
	};
	use crate::telemetry::metrics::{OutboundCallKind, OutboundCallSubtype};
	use gateway_protocol_core::execution::BoundHttpExecution;
	let server = Server::new("{}").await;
	let (mut guards, _revision, _) = guarded();
	Arc::make_mut(&mut Arc::get_mut(&mut guards.0[0]).unwrap().config).required_audit = Some(
		security_integration_runtime::required_audit::RequiredAuditConfig {
			action_types: vec![security_types::ActionType::ModelInvoke],
		},
	);
	guards.0[0]
		.prefilter(Some(&Target::Address(server.address)))
		.unwrap();
	let client = PolicyClient::new(inputs(&[server.address]))
		.with_outbound(OutboundCallKind::Policy, OutboundCallSubtype::Guardrail);
	let mut request = ::http::Request::builder()
		.uri("/")
		.body(Body::empty())
		.unwrap();
	request.extensions_mut().insert(guards);
	assert!(matches!(
		client
			.bind_reference(&server.target(), &[])
			.execute(request)
			.await,
		Err(ProxyError::AuthorizationFailed)
	));
	assert_eq!(server.calls.load(Ordering::SeqCst), 0);
}
struct OnDrop(Arc<AtomicBool>);
impl Drop for OnDrop {
	fn drop(&mut self) {
		self.0.store(true, Ordering::Release);
	}
}

#[cfg(feature = "gateway-rag")]
#[tokio::test]
async fn revoked_rag_context_blocks_already_buffered_model_output() {
	use gateway_rag::http::ContextConstraintIssuer;
	let (mut guards, _revision, target) = guarded();
	let config: SecurityConfig = serde_json::from_value(serde_json::json!({
		"mode":"enforce", "policies":[{"id":"allow","enabled":true,"effect":"allow"}],
		"crossComponent":{"namespace":uuid::Uuid::new_v4().to_string(), "destinations":[
			{"classification":"public","modelDestinations":[target.to_string()]},
			{"classification":"internal","modelDestinations":[target.to_string()]},
			{"classification":"restricted","modelDestinations":[target.to_string()]}
		]}
	}))
	.unwrap();
	let config = Arc::new(config);
	let claims = crate::http::jwt::Claims {
		inner: serde_json::from_value(serde_json::json!({"iss":"https://issuer.example","sub":"alice","tenantId":"tenant-a","exp":chrono::Utc::now().timestamp()+300})).unwrap(),
		jwt: "not-an-authentication-fixture".into(),
	};
	let issuer = crate::security_flow::rag_issuer(config.clone(), &claims, "query".into()).unwrap();
	let context = security_rag::GuardedContext {
		corpus_id: "docs".into(),
		query_hash: "hash".into(),
		chunks: vec![],
		context_tokens: 0,
		classification: Some(security_types::DataClassification::Restricted),
		removed_chunk_ids: vec![],
		redacted_chunk_ids: vec![],
		findings: vec![],
	};
	let id = issuer.issue(&context, None).unwrap();
	let mut request = ::http::Request::new(());
	request
		.headers_mut()
		.insert(crate::security_flow::HEADER, id.parse().unwrap());
	request.extensions_mut().insert(claims);
	let guard = Arc::get_mut(&mut guards.0[0]).unwrap();
	guard.config = config.clone();
	guard.flow =
		crate::security_flow::prepare(&config, request.headers(), request.extensions()).unwrap();
	let mut body = guards
		.protect_response(Response::new(Body::from("buffered knowledge")), &target)
		.unwrap()
		.into_body();
	issuer.revoke(&id).unwrap();
	assert!(body.frame().await.unwrap().is_err());
	assert!(body.frame().await.is_none());
}

#[tokio::test]
async fn adapted_buffer_cannot_disclose_after_configuration_invalidation() {
	let (guards, revision, target) = guarded();
	let mut body = guards
		.protect_response(Response::new(Body::from("buffered secret")), &target)
		.unwrap()
		.into_body();
	revision.invalidate();
	assert!(body.frame().await.unwrap().is_err());
	assert!(body.frame().await.is_none());
}

#[tokio::test(start_paused = true)]
async fn idle_model_stream_rechecks_and_drops_upstream_on_invalidation() {
	use futures_util::StreamExt;
	let (guards, revision, target) = guarded();
	let dropped = Arc::new(AtomicBool::new(false));
	let lease = OnDrop(dropped.clone());
	let stream =
		futures_util::stream::pending::<Result<bytes::Bytes, std::io::Error>>().map(move |item| {
			let _keep = &lease;
			item
		});
	let mut body = guards
		.protect_response(Response::new(Body::from_stream(stream)), &target)
		.unwrap()
		.into_body();
	let invalidate = async {
		tokio::task::yield_now().await;
		revision.invalidate();
	};
	let (frame, ()) = tokio::join!(body.frame(), invalidate);
	assert!(frame.unwrap().is_err());
	assert!(dropped.load(Ordering::Acquire));
}

#[tokio::test]
async fn response_guard_preserves_trailers_and_consumer_drop_releases_source() {
	let (guards, _revision, target) = guarded();
	let frames = futures_util::stream::iter(vec![
		Ok::<_, std::io::Error>(http_body::Frame::data(bytes::Bytes::from_static(b"ok"))),
		Ok(http_body::Frame::trailers(::http::HeaderMap::from_iter([
			("grpc-status".parse().unwrap(), "0".parse().unwrap()),
		]))),
	]);
	let source = Body::new(http_body_util::StreamBody::new(frames));
	let mut body = guards
		.protect_response(Response::new(source), &target)
		.unwrap()
		.into_body();
	assert_eq!(
		body.frame().await.unwrap().unwrap().into_data().unwrap(),
		"ok"
	);
	assert_eq!(
		body
			.frame()
			.await
			.unwrap()
			.unwrap()
			.into_trailers()
			.unwrap()["grpc-status"],
		"0"
	);
	assert!(body.frame().await.is_none());
	let dropped = Arc::new(AtomicBool::new(false));
	let lease = OnDrop(dropped.clone());
	use futures_util::StreamExt;
	let stream =
		futures_util::stream::pending::<Result<bytes::Bytes, std::io::Error>>().map(move |item| {
			let _keep = &lease;
			item
		});
	let response = guards
		.protect_response(Response::new(Body::from_stream(stream)), &target)
		.unwrap();
	drop(response);
	assert!(dropped.load(Ordering::Acquire));
}

#[tokio::test]
async fn invalidation_while_polling_source_cannot_disclose_the_returned_frame() {
	let (guards, revision, target) = guarded();
	let source = futures_util::stream::once(async move {
		revision.invalidate();
		Ok::<_, std::io::Error>(bytes::Bytes::from_static(b"must not escape"))
	});
	let mut body = guards
		.protect_response(Response::new(Body::from_stream(source)), &target)
		.unwrap()
		.into_body();
	assert!(body.frame().await.unwrap().is_err());
	assert!(body.frame().await.is_none());
}
