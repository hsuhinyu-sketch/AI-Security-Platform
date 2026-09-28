//! HTTP transport for the secure RAG adapter.
//!
//! This module purposefully has no JWT parser. An authentication middleware must insert
//! [`VerifiedGatewayIdentity`] only after verification; request JSON cannot supply a tenant,
//! user, agent, vector-store filter, or ACL.

use std::sync::Arc;

use axum::{
	Json, Router,
	extract::{Extension, State},
	http::{HeaderMap, StatusCode},
	routing::post,
};
use security_pipeline::GatewayIdentity;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use security_rag::{DocumentIngestRequest, GuardedContext, IngestionResult};

use crate::{RagGatewayAdapter, RagGatewayError, RagQueryRequest};
use security_rag::TrustedHttpsSourceRegistry;

/// Marker wrapper inserted by authentication middleware after identity verification.
#[derive(Debug, Clone)]
pub struct VerifiedGatewayIdentity(pub GatewayIdentity);

/// Object-safe application boundary used by the Axum router. It allows the route module to avoid
/// exposing the concrete policy, audit, vector-store, and chunking types in its public state.
#[async_trait::async_trait]
pub trait RagHttpService: Send + Sync {
	async fn authorize_import(
		&self,
		request_id: String,
		identity: GatewayIdentity,
		corpus_id: &str,
		document_id: &str,
		source_id: &str,
	) -> Result<(), RagGatewayError>;
	fn record_source_fetch_failure(
		&self,
		request_id: String,
		identity: GatewayIdentity,
		corpus_id: &str,
		document_id: &str,
		source_id: &str,
	);
	async fn ingest(
		&self,
		request_id: String,
		identity: GatewayIdentity,
		request: DocumentIngestRequest,
	) -> Result<IngestionResult, RagGatewayError>;

	async fn query(
		&self,
		request_id: String,
		identity: GatewayIdentity,
		request: RagQueryRequest,
	) -> Result<GuardedContext, RagGatewayError>;
}

#[async_trait::async_trait]
impl<IB, RB, IA, IS, IAudit, RA, RS, RAudit, CA> RagHttpService
	for RagGatewayAdapter<
		security_rag::SecureIngestor<IB, IA, IS, IAudit>,
		security_rag::SecureRetriever<RB, RA, RS, RAudit>,
		CA,
	>
where
	IB: security_rag::DocumentIngestBackend,
	RB: security_rag::RetrievalBackend,
	IA: security_pipeline::Authorizer,
	IS: security_audit::AuditSink,
	IAudit: security_rag::IngestionAuditSink,
	RA: security_pipeline::Authorizer,
	RS: security_audit::AuditSink,
	RAudit: security_rag::RetrievalAuditSink,
	CA: security_rag::ContextAuditSink,
{
	async fn authorize_import(
		&self,
		request_id: String,
		identity: GatewayIdentity,
		corpus_id: &str,
		document_id: &str,
		source_id: &str,
	) -> Result<(), RagGatewayError> {
		self.authorize_import(request_id, identity, corpus_id, document_id, source_id)
	}

	fn record_source_fetch_failure(
		&self,
		request_id: String,
		identity: GatewayIdentity,
		corpus_id: &str,
		document_id: &str,
		source_id: &str,
	) {
		self.record_source_fetch_failure(request_id, identity, corpus_id, document_id, source_id)
	}
	async fn ingest(
		&self,
		request_id: String,
		identity: GatewayIdentity,
		request: DocumentIngestRequest,
	) -> Result<IngestionResult, RagGatewayError> {
		self.ingest(request_id, identity, request).await
	}

	async fn query(
		&self,
		request_id: String,
		identity: GatewayIdentity,
		request: RagQueryRequest,
	) -> Result<GuardedContext, RagGatewayError> {
		self.query(request_id, identity, request).await
	}
}

struct RagHttpState {
	service: Arc<dyn RagHttpService>,
	sources: Option<Arc<TrustedHttpsSourceRegistry>>,
}
type SharedState = Arc<RagHttpState>;
type ApiResult<T> = Result<(StatusCode, Json<T>), (StatusCode, Json<ApiError>)>;

/// Builds the secure RAG HTTP routes. A host must layer verified authentication before mounting
/// this router and insert `VerifiedGatewayIdentity` into each authorized request.
pub fn router(service: Arc<dyn RagHttpService>) -> Router {
	router_with_sources(service, None)
}

pub fn router_with_sources(
	service: Arc<dyn RagHttpService>,
	sources: Option<Arc<TrustedHttpsSourceRegistry>>,
) -> Router {
	let has_sources = sources.is_some();
	let mut router = Router::new()
		.route("/v1/rag/documents", post(ingest_document))
		.route("/v1/rag/query", post(query_corpus));
	if has_sources {
		router = router.route("/v1/rag/import", post(import_document));
	}
	router.with_state(Arc::new(RagHttpState { service, sources }))
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct IngestBody {
	corpus_id: String,
	document_id: String,
	source_uri: String,
	content: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct QueryBody {
	corpus_id: String,
	query: String,
	limit: usize,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ImportBody {
	corpus_id: String,
	document_id: String,
	source_id: String,
	path: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct IngestResponse {
	status: &'static str,
	corpus_id: String,
	document_id: String,
	source_hash: String,
	labels: Vec<String>,
	classification: security_rag::DataClassification,
	classification_source: String,
	source_origin: security_rag::SourceOrigin,
	quarantine_rule_ids: Vec<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ContextChunkResponse {
	chunk_id: String,
	document_id: String,
	source_hash: String,
	content: String,
	labels: Vec<String>,
	classification: security_rag::DataClassification,
	classification_source: String,
	source_origin: security_rag::SourceOrigin,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct QueryResponse {
	corpus_id: String,
	query_hash: String,
	context_tokens: u64,
	classification: Option<security_rag::DataClassification>,
	chunks: Vec<ContextChunkResponse>,
	removed_chunk_ids: Vec<String>,
	redacted_chunk_ids: Vec<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ApiError {
	code: &'static str,
	message: &'static str,
}

async fn ingest_document(
	State(state): State<SharedState>,
	identity: Option<Extension<VerifiedGatewayIdentity>>,
	headers: HeaderMap,
	Json(body): Json<IngestBody>,
) -> ApiResult<IngestResponse> {
	let identity = verified_identity(identity)?;
	let result = state
		.service
		.ingest(
			request_id(&headers),
			identity,
			DocumentIngestRequest::new(
				body.corpus_id,
				body.document_id,
				body.source_uri,
				body.content,
			),
		)
		.await
		.map_err(map_error)?;
	Ok(ingest_response(result))
}

async fn import_document(
	State(state): State<SharedState>,
	identity: Option<Extension<VerifiedGatewayIdentity>>,
	headers: HeaderMap,
	Json(body): Json<ImportBody>,
) -> ApiResult<IngestResponse> {
	let identity = verified_identity(identity)?;
	let request_id = request_id(&headers);
	state
		.service
		.authorize_import(
			request_id.clone(),
			identity.clone(),
			&body.corpus_id,
			&body.document_id,
			&body.source_id,
		)
		.await
		.map_err(map_error)?;
	let sources = state.sources.as_ref().ok_or_else(|| {
		api_error(
			StatusCode::NOT_FOUND,
			"source_unavailable",
			"trusted sources are not configured",
		)
	})?;
	let ingest_request = match sources
		.import_request(
			body.corpus_id.clone(),
			body.document_id.clone(),
			&body.source_id,
			&body.path,
		)
		.await
	{
		Ok(request) => request,
		Err(_) => {
			state.service.record_source_fetch_failure(
				request_id,
				identity,
				&body.corpus_id,
				&body.document_id,
				&body.source_id,
			);
			return Err(api_error(
				StatusCode::BAD_GATEWAY,
				"source_fetch_failed",
				"trusted source fetch failed",
			));
		},
	};
	let result = state
		.service
		.ingest(request_id, identity, ingest_request)
		.await
		.map_err(map_error)?;
	Ok(ingest_response(result))
}

fn ingest_response(result: IngestionResult) -> (StatusCode, Json<IngestResponse>) {
	let (status, response) = match result {
		IngestionResult::Indexed(document) => (
			StatusCode::CREATED,
			IngestResponse {
				status: "indexed",
				corpus_id: document.corpus_id,
				document_id: document.document_id,
				source_hash: document.source_hash,
				labels: document.labels,
				classification: document.classification,
				classification_source: document.classification_source,
				source_origin: document.source_origin,
				quarantine_rule_ids: Vec::new(),
			},
		),
		IngestionResult::Quarantined(document) => (
			StatusCode::ACCEPTED,
			IngestResponse {
				status: "quarantined",
				corpus_id: document.document.corpus_id,
				document_id: document.document.document_id,
				source_hash: document.document.source_hash,
				labels: document.document.labels,
				classification: document.document.classification,
				classification_source: document.document.classification_source,
				source_origin: document.document.source_origin,
				quarantine_rule_ids: document
					.findings
					.into_iter()
					.map(|finding| finding.rule_id)
					.collect(),
			},
		),
	};
	(status, Json(response))
}

async fn query_corpus(
	State(state): State<SharedState>,
	identity: Option<Extension<VerifiedGatewayIdentity>>,
	headers: HeaderMap,
	Json(body): Json<QueryBody>,
) -> ApiResult<QueryResponse> {
	let identity = verified_identity(identity)?;
	let context = state
		.service
		.query(
			request_id(&headers),
			identity,
			RagQueryRequest::new(body.corpus_id, body.query, body.limit),
		)
		.await
		.map_err(map_error)?;
	Ok((
		StatusCode::OK,
		Json(QueryResponse {
			corpus_id: context.corpus_id,
			query_hash: context.query_hash,
			context_tokens: context.context_tokens,
			classification: context.classification,
			chunks: context
				.chunks
				.into_iter()
				.map(|chunk| ContextChunkResponse {
					chunk_id: chunk.id,
					document_id: chunk.document_id,
					source_hash: chunk.source_hash,
					content: chunk.content,
					labels: chunk.labels,
					classification: chunk.classification,
					classification_source: chunk.classification_source,
					source_origin: chunk.source_origin,
				})
				.collect(),
			removed_chunk_ids: context.removed_chunk_ids,
			redacted_chunk_ids: context.redacted_chunk_ids,
		}),
	))
}

fn verified_identity(
	identity: Option<Extension<VerifiedGatewayIdentity>>,
) -> Result<GatewayIdentity, (StatusCode, Json<ApiError>)> {
	identity
		.map(|Extension(identity)| identity.0)
		.ok_or_else(|| {
			api_error(
				StatusCode::UNAUTHORIZED,
				"unauthenticated",
				"verified identity is required",
			)
		})
}

fn request_id(headers: &HeaderMap) -> String {
	headers
		.get("x-request-id")
		.and_then(|value| value.to_str().ok())
		.filter(|value| !value.is_empty() && value.len() <= 128)
		.map(str::to_owned)
		.unwrap_or_else(|| Uuid::new_v4().to_string())
}

fn map_error(error: RagGatewayError) -> (StatusCode, Json<ApiError>) {
	match error {
		RagGatewayError::Ingestion(security_rag::IngestionError::GatewayDenied(_))
		| RagGatewayError::Retrieval(security_rag::RetrievalError::GatewayDenied(_))
		| RagGatewayError::Context(security_rag::ContextAssemblyError::GatewayDenied(_)) => api_error(
			StatusCode::FORBIDDEN,
			"access_denied",
			"the RAG security policy denied this request",
		),
		RagGatewayError::Ingestion(security_rag::IngestionError::InvalidSource(_))
		| RagGatewayError::Ingestion(security_rag::IngestionError::DocumentTooLarge { .. })
		| RagGatewayError::Retrieval(security_rag::RetrievalError::RequestedLimitZero)
		| RagGatewayError::Retrieval(security_rag::RetrievalError::RequestedLimitExceedsBudget {
			..
		}) => api_error(
			StatusCode::BAD_REQUEST,
			"invalid_request",
			"the RAG request violates configured input limits",
		),
		RagGatewayError::Ingestion(security_rag::IngestionError::Backend(_))
		| RagGatewayError::Retrieval(security_rag::RetrievalError::Backend(_)) => api_error(
			StatusCode::BAD_GATEWAY,
			"backend_unavailable",
			"the RAG backend could not complete the request",
		),
		_ => api_error(
			StatusCode::INTERNAL_SERVER_ERROR,
			"internal_error",
			"the RAG gateway could not process the request",
		),
	}
}

fn api_error(
	status: StatusCode,
	code: &'static str,
	message: &'static str,
) -> (StatusCode, Json<ApiError>) {
	(status, Json(ApiError { code, message }))
}

#[cfg(test)]
mod tests {
	use std::sync::atomic::{AtomicUsize, Ordering};

	use axum::{
		body::{Body, to_bytes},
		http::Request,
	};
	use tower::ServiceExt;

	use super::*;

	#[derive(Default)]
	struct TestService {
		deny_import: bool,
		fetch_failures: AtomicUsize,
		ingest_calls: AtomicUsize,
	}

	#[async_trait::async_trait]
	impl RagHttpService for TestService {
		async fn authorize_import(
			&self,
			request_id: String,
			_identity: GatewayIdentity,
			_corpus_id: &str,
			_document_id: &str,
			_source_id: &str,
		) -> Result<(), RagGatewayError> {
			if self.deny_import {
				return Err(RagGatewayError::Ingestion(
					security_rag::IngestionError::GatewayDenied(security_pipeline::GatewayError::Denied(
						security_types::Decision {
							request_id,
							effect: security_types::DecisionEffect::Deny,
							policy_id: Some("deny-import".into()),
							policy_version: None,
							expires_at: None,
						},
					)),
				));
			}
			Ok(())
		}

		fn record_source_fetch_failure(
			&self,
			_request_id: String,
			_identity: GatewayIdentity,
			_corpus_id: &str,
			_document_id: &str,
			_source_id: &str,
		) {
			self.fetch_failures.fetch_add(1, Ordering::SeqCst);
		}

		async fn ingest(
			&self,
			_request_id: String,
			_identity: GatewayIdentity,
			request: DocumentIngestRequest,
		) -> Result<IngestionResult, RagGatewayError> {
			self.ingest_calls.fetch_add(1, Ordering::SeqCst);
			Ok(IngestionResult::Indexed(security_rag::IndexedDocument {
				corpus_id: request.corpus_id().to_string(),
				document_id: request.document_id().to_string(),
				tenant_id: "must-not-leak".into(),
				source_uri: request.source_uri().to_string(),
				source_hash: security_integrity::sha256_hex(request.content().as_bytes()),
				source_origin: request.source_origin().clone(),
				content: request.content().to_string(),
				labels: vec!["internal".into()],
				classification: security_rag::DataClassification::Internal,
				classification_source: "default-classification".into(),
			}))
		}

		async fn query(
			&self,
			_request_id: String,
			_identity: GatewayIdentity,
			_request: RagQueryRequest,
		) -> Result<GuardedContext, RagGatewayError> {
			Ok(GuardedContext {
				corpus_id: "support".into(),
				query_hash: "hash".into(),
				chunks: Vec::new(),
				context_tokens: 0,
				classification: None,
				removed_chunk_ids: Vec::new(),
				redacted_chunk_ids: Vec::new(),
				findings: Vec::new(),
			})
		}
	}

	fn identity() -> VerifiedGatewayIdentity {
		VerifiedGatewayIdentity(GatewayIdentity {
			user_id: Some("alice".into()),
			agent_id: None,
			tenant_id: Some("tenant-a".into()),
			delegation_id: None,
			session_id: None,
			client_id: None,
		})
	}

	#[tokio::test]
	async fn routes_reject_missing_verified_identity_and_untrusted_identity_fields() {
		let app = router(Arc::new(TestService::default()));
		let response = app
			.clone()
			.oneshot(
				Request::builder()
					.method("POST")
					.uri("/v1/rag/query")
					.header("content-type", "application/json")
					.body(Body::from(
						r#"{"corpusId":"support","query":"help","limit":1}"#,
					))
					.unwrap(),
			)
			.await
			.unwrap();
		assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

		let response = app
			.oneshot(
				Request::builder()
					.method("POST")
					.uri("/v1/rag/query")
					.header("content-type", "application/json")
					.extension(identity())
					.body(Body::from(
						r#"{"corpusId":"support","query":"help","limit":1,"tenantId":"attacker"}"#,
					))
					.unwrap(),
			)
			.await
			.unwrap();
		assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
		let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
		assert!(
			std::str::from_utf8(&body)
				.unwrap()
				.contains("unknown field")
		);
		let response = router(Arc::new(TestService::default()))
			.oneshot(
				Request::builder()
					.method("POST")
					.uri("/v1/rag/documents")
					.header("content-type", "application/json")
					.extension(identity())
					.body(Body::from(r#"{"corpusId":"support","documentId":"guide","sourceUri":"https://kb.example.test/guide","content":"private","classification":"public"}"#))
					.unwrap(),
			)
			.await
			.unwrap();
		assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
		let response = router(Arc::new(TestService::default()))
			.oneshot(
				Request::builder()
					.method("POST")
					.uri("/v1/rag/documents")
					.header("content-type", "application/json")
					.extension(identity())
					.body(Body::from(r#"{"corpusId":"support","documentId":"guide","sourceUri":"https://kb.example.test/guide","content":"private","sourceOrigin":{"kind":"trustedHttps","sourceId":"kb","version":"fake"}}"#))
					.unwrap(),
			)
			.await
			.unwrap();
		assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
	}

	#[tokio::test]
	async fn import_route_uses_https_source_and_authorizes_before_fetch() {
		use wiremock::tls_certs::MockTlsCertificates;
		use wiremock::{
			Mock, MockServer, ResponseTemplate,
			matchers::{method, path},
		};

		let certs = MockTlsCertificates::random();
		let server = MockServer::builder()
			.start_https(certs.get_server_config())
			.await;
		Mock::given(method("GET"))
			.and(path("/docs/guide.md"))
			.respond_with(ResponseTemplate::new(200).set_body_string("trusted bytes"))
			.mount(&server)
			.await;
		Mock::given(method("GET"))
			.and(path("/docs/redirect"))
			.respond_with(ResponseTemplate::new(302).insert_header("location", "/private"))
			.mount(&server)
			.await;
		let sources = Arc::new(
			TrustedHttpsSourceRegistry::new(
				vec![security_rag::TrustedHttpsSourceConfig {
					id: "kb".into(),
					base_url: format!("{}/docs/", server.uri()),
					bearer_token_env_var: None,
					ca_cert_pem: Some(certs.get_root_ca_cert().pem()),
				}],
				128,
			)
			.unwrap(),
		);
		let make_request = |path: &str, authenticated: bool| {
			let mut builder = Request::builder()
				.method("POST")
				.uri("/v1/rag/import")
				.header("content-type", "application/json");
			if authenticated {
				builder = builder.extension(identity());
			}
			builder
				.body(Body::from(
					serde_json::json!({
						"corpusId":"support", "documentId":"guide", "sourceId":"kb", "path":path,
					})
					.to_string(),
				))
				.unwrap()
		};

		let denied = Arc::new(TestService {
			deny_import: true,
			..Default::default()
		});
		let response = router_with_sources(denied.clone(), Some(sources.clone()))
			.oneshot(make_request("guide.md", true))
			.await
			.unwrap();
		assert_eq!(response.status(), StatusCode::FORBIDDEN);
		assert!(server.received_requests().await.unwrap().is_empty());
		assert_eq!(denied.ingest_calls.load(Ordering::SeqCst), 0);

		let service = Arc::new(TestService::default());
		let app = router_with_sources(service.clone(), Some(sources));
		let response = app
			.clone()
			.oneshot(make_request("guide.md", false))
			.await
			.unwrap();
		assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
		assert!(server.received_requests().await.unwrap().is_empty());
		let response = app
			.clone()
			.oneshot(make_request("guide.md", true))
			.await
			.unwrap();
		assert_eq!(response.status(), StatusCode::CREATED);
		let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
		let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
		assert_eq!(
			body["sourceHash"],
			security_integrity::sha256_hex(b"trusted bytes")
		);
		assert_eq!(body["sourceOrigin"]["kind"], "trustedHttps");
		assert_eq!(body["sourceOrigin"]["sourceId"], "kb");
		assert_eq!(body["sourceOrigin"]["version"], body["sourceHash"]);
		assert_eq!(service.ingest_calls.load(Ordering::SeqCst), 1);

		let response = app
			.clone()
			.oneshot(make_request("../private", true))
			.await
			.unwrap();
		assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
		assert_eq!(service.fetch_failures.load(Ordering::SeqCst), 1);
		assert_eq!(server.received_requests().await.unwrap().len(), 1);
		let response = app.oneshot(make_request("redirect", true)).await.unwrap();
		assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
		assert_eq!(service.fetch_failures.load(Ordering::SeqCst), 2);
		assert_eq!(server.received_requests().await.unwrap().len(), 2);
	}

	#[tokio::test]
	async fn ingest_response_excludes_tenant_and_acl_metadata() {
		let response = router(Arc::new(TestService::default()))
			.oneshot(
				Request::builder()
					.method("POST")
					.uri("/v1/rag/documents")
					.header("content-type", "application/json")
					.extension(identity())
					.body(Body::from(r#"{"corpusId":"support","documentId":"guide","sourceUri":"https://kb.example.test/guide","content":"safe"}"#))
					.unwrap(),
			)
			.await
			.unwrap();
		assert_eq!(response.status(), StatusCode::CREATED);
		let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
		let body = std::str::from_utf8(&body).unwrap();
		assert!(body.contains("\"status\":\"indexed\""));
		assert!(!body.contains("tenant"));
		assert!(!body.contains("allowedUsers"));
		assert!(body.contains("\"classification\":\"internal\""));
	}
}
