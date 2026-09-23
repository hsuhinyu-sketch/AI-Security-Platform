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

/// Marker wrapper inserted by authentication middleware after identity verification.
#[derive(Debug, Clone)]
pub struct VerifiedGatewayIdentity(pub GatewayIdentity);

/// Object-safe application boundary used by the Axum router. It allows the route module to avoid
/// exposing the concrete policy, audit, vector-store, and chunking types in its public state.
#[async_trait::async_trait]
pub trait RagHttpService: Send + Sync {
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

type RagHttpState = Arc<dyn RagHttpService>;
type ApiResult<T> = Result<(StatusCode, Json<T>), (StatusCode, Json<ApiError>)>;

/// Builds the secure RAG HTTP routes. A host must layer verified authentication before mounting
/// this router and insert `VerifiedGatewayIdentity` into each authorized request.
pub fn router(service: RagHttpState) -> Router {
	Router::new()
		.route("/v1/rag/documents", post(ingest_document))
		.route("/v1/rag/query", post(query_corpus))
		.with_state(service)
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

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct IngestResponse {
	status: &'static str,
	corpus_id: String,
	document_id: String,
	source_hash: String,
	labels: Vec<String>,
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
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct QueryResponse {
	corpus_id: String,
	query_hash: String,
	context_tokens: u64,
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
	State(service): State<RagHttpState>,
	identity: Option<Extension<VerifiedGatewayIdentity>>,
	headers: HeaderMap,
	Json(body): Json<IngestBody>,
) -> ApiResult<IngestResponse> {
	let identity = verified_identity(identity)?;
	let result = service
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
	let (status, response) = match result {
		IngestionResult::Indexed(document) => (
			StatusCode::CREATED,
			IngestResponse {
				status: "indexed",
				corpus_id: document.corpus_id,
				document_id: document.document_id,
				source_hash: document.source_hash,
				labels: document.labels,
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
				quarantine_rule_ids: document
					.findings
					.into_iter()
					.map(|finding| finding.rule_id)
					.collect(),
			},
		),
	};
	Ok((status, Json(response)))
}

async fn query_corpus(
	State(service): State<RagHttpState>,
	identity: Option<Extension<VerifiedGatewayIdentity>>,
	headers: HeaderMap,
	Json(body): Json<QueryBody>,
) -> ApiResult<QueryResponse> {
	let identity = verified_identity(identity)?;
	let context = service
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
			chunks: context
				.chunks
				.into_iter()
				.map(|chunk| ContextChunkResponse {
					chunk_id: chunk.id,
					document_id: chunk.document_id,
					source_hash: chunk.source_hash,
					content: chunk.content,
					labels: chunk.labels,
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
	use axum::{
		body::{Body, to_bytes},
		http::Request,
	};
	use tower::ServiceExt;

	use super::*;

	struct TestService;

	#[async_trait::async_trait]
	impl RagHttpService for TestService {
		async fn ingest(
			&self,
			_request_id: String,
			_identity: GatewayIdentity,
			request: DocumentIngestRequest,
		) -> Result<IngestionResult, RagGatewayError> {
			Ok(IngestionResult::Indexed(security_rag::IndexedDocument {
				corpus_id: request.corpus_id,
				document_id: request.document_id,
				tenant_id: "must-not-leak".into(),
				source_uri: request.source_uri,
				source_hash: "hash".into(),
				content: request.content,
				labels: vec!["internal".into()],
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
		let app = router(Arc::new(TestService));
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
	}

	#[tokio::test]
	async fn ingest_response_excludes_tenant_and_acl_metadata() {
		let response = router(Arc::new(TestService))
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
	}
}
