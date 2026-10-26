use super::*;
use std::sync::Mutex;
use tower::ServiceExt;

#[derive(Default)]
struct RecordingService(Mutex<Vec<String>>);

#[async_trait::async_trait]
impl RagHttpService for RecordingService {
	async fn authorize_import(
		&self,
		_: String,
		_: GatewayIdentity,
		_: &str,
		_: &str,
		_: &str,
	) -> Result<(), RagGatewayError> {
		Err(RagGatewayError::Lifecycle("not configured".into()))
	}
	fn record_source_fetch_failure(&self, _: String, _: GatewayIdentity, _: &str, _: &str, _: &str) {}
	async fn ingest(
		&self,
		_: String,
		_: GatewayIdentity,
		_: DocumentIngestRequest,
	) -> Result<IngestionResult, RagGatewayError> {
		Err(RagGatewayError::Lifecycle("not configured".into()))
	}
	async fn query(
		&self,
		id: String,
		_: GatewayIdentity,
		_: RagQueryRequest,
	) -> Result<GuardedContext, RagGatewayError> {
		self.0.lock().unwrap().push(id);
		Ok(GuardedContext {
			corpus_id: "docs".into(),
			query_hash: "hash".into(),
			chunks: vec![],
			context_tokens: 0,
			classification: None,
			removed_chunk_ids: vec![],
			redacted_chunk_ids: vec![],
			findings: vec![],
		})
	}
}

fn query() -> Request {
	Request::builder()
		.method("POST")
		.uri("/v1/rag/query")
		.header("content-type", "application/json")
		.header("x-request-id", "reused-client-id")
		.body(axum::body::Body::from(
			r#"{"corpusId":"docs","query":"hi","limit":1}"#,
		))
		.unwrap()
}

#[tokio::test]
async fn caller_ids_cannot_collide_and_returned_id_matches_service() {
	let service = Arc::new(RecordingService::default());
	let app = router(service.clone()).layer(Extension(VerifiedGatewayIdentity(
		GatewayIdentity::default(),
	)));
	let first = app.clone().oneshot(query()).await.unwrap();
	let second = app.oneshot(query()).await.unwrap();
	assert_eq!(first.status(), StatusCode::OK);
	assert_eq!(second.status(), StatusCode::OK);
	let ids = service.0.lock().unwrap();
	assert_eq!(ids.len(), 2);
	assert_ne!(ids[0], ids[1]);
	assert_ne!(ids[0], "reused-client-id");
	assert_eq!(first.headers()["x-request-id"], ids[0]);
	assert_eq!(second.headers()["x-request-id"], ids[1]);
}

#[tokio::test]
async fn trusted_context_survives_but_missing_identity_never_reaches_service() {
	let service = Arc::new(RecordingService::default());
	let context = RequestContext::default();
	let app = router(service.clone());
	let response = app.clone().oneshot(query()).await.unwrap();
	assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
	assert!(service.0.lock().unwrap().is_empty());
	let mut req = query();
	req.extensions_mut().insert(context.clone());
	req
		.extensions_mut()
		.insert(VerifiedGatewayIdentity(Default::default()));
	let response = app.oneshot(req).await.unwrap();
	assert_eq!(response.status(), StatusCode::OK);
	assert_eq!(response.headers()["x-request-id"], context.request_id());
	assert_eq!(
		service.0.lock().unwrap().as_slice(),
		&[context.request_id().to_owned()]
	);
}
