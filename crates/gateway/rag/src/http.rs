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

/// Trusted host hook, installed only after JWT verification. Request JSON cannot supply it.
pub trait ContextConstraintIssuer: Send + Sync {
	fn issue(&self, context: &GuardedContext, parent: Option<&str>) -> Result<String, String>;
	/// The trusted host must separately authorize lifecycle operations. Default is deny.
	fn revoke(&self, _id: &str) -> Result<(), String> {
		Err("context revocation unavailable".into())
	}
}
#[derive(Clone)]
pub struct VerifiedContextIssuer(pub Arc<dyn ContextConstraintIssuer>);

/// Object-safe application boundary used by the Axum router. It allows the route module to avoid
/// exposing the concrete policy, audit, vector-store, and chunking types in its public state.
#[async_trait::async_trait]
pub trait RagHttpService: Send + Sync {
	async fn document_operation(
		&self,
		_request_id: String,
		_identity: GatewayIdentity,
		_corpus: String,
		_document: String,
		_expected: Option<u64>,
		_mutation: Option<security_rag::lifecycle::DocumentMutation>,
	) -> Result<crate::DocumentStatus, RagGatewayError> {
		Err(RagGatewayError::Lifecycle(
			"document lifecycle unavailable".into(),
		))
	}
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
	async fn document_operation(
		&self,
		request_id: String,
		identity: GatewayIdentity,
		corpus: String,
		document: String,
		expected: Option<u64>,
		mutation: Option<security_rag::lifecycle::DocumentMutation>,
	) -> Result<crate::DocumentStatus, RagGatewayError> {
		self
			.document_operation(request_id, identity, corpus, document, expected, mutation)
			.await
	}
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
		.route("/v1/rag/documents/lifecycle", post(document_operation))
		.route("/v1/rag/contexts/revoke", post(revoke_context))
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

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct DocumentOperationBody {
	corpus_id: String,
	document_id: String,
	expected_revision: Option<u64>,
	mutation: Option<security_rag::lifecycle::DocumentMutation>,
}
async fn document_operation(
	State(state): State<SharedState>,
	identity: Option<Extension<VerifiedGatewayIdentity>>,
	headers: HeaderMap,
	Json(body): Json<DocumentOperationBody>,
) -> Result<(StatusCode, HeaderMap, Json<crate::DocumentStatus>), (StatusCode, Json<ApiError>)> {
	let identity = verified_identity(identity)?;
	let status = state
		.service
		.document_operation(
			request_id(&headers),
			identity,
			body.corpus_id,
			body.document_id,
			body.expected_revision,
			body.mutation,
		)
		.await
		.map_err(map_error)?;
	let mut headers = HeaderMap::new();
	headers.insert(
		"cache-control",
		"private, no-store".parse().expect("constant"),
	);
	Ok((StatusCode::OK, headers, Json(status)))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RevokeContextBody {
	context_id: String,
}

async fn revoke_context(
	identity: Option<Extension<VerifiedGatewayIdentity>>,
	issuer: Option<Extension<VerifiedContextIssuer>>,
	Json(body): Json<RevokeContextBody>,
) -> Result<(StatusCode, HeaderMap, Json<serde_json::Value>), (StatusCode, Json<ApiError>)> {
	verified_identity(identity)?;
	let denied = || {
		api_error(
			StatusCode::FORBIDDEN,
			"context_denied",
			"context revocation denied",
		)
	};
	if Uuid::parse_str(&body.context_id).is_err() {
		return Err(denied());
	}
	issuer
		.ok_or_else(denied)?
		.0
		.0
		.revoke(&body.context_id)
		.map_err(|_| denied())?;
	let mut headers = HeaderMap::new();
	headers.insert(
		"cache-control",
		"private, no-store".parse().expect("constant"),
	);
	Ok((
		StatusCode::OK,
		headers,
		Json(serde_json::json!({"revoked":true})),
	))
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
	issuer: Option<Extension<VerifiedContextIssuer>>,
	headers: HeaderMap,
	Json(body): Json<QueryBody>,
) -> Result<(StatusCode, HeaderMap, Json<QueryResponse>), (StatusCode, Json<ApiError>)> {
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
	let mut response_headers = HeaderMap::new();
	if let Some(Extension(issuer)) = issuer {
		let invalid = || {
			api_error(
				StatusCode::FORBIDDEN,
				"context_denied",
				"cross-component context denied",
			)
		};
		if headers.get_all("x-aisp-context-id").iter().count() > 1 {
			return Err(invalid());
		}
		let parent = headers
			.get("x-aisp-context-id")
			.map(|v| v.to_str().map_err(|_| invalid()))
			.transpose()?;
		let id = issuer.0.issue(&context, parent).map_err(|_| invalid())?;
		response_headers.insert("x-aisp-context-id", id.parse().map_err(|_| invalid())?);
	}
	response_headers.insert(
		"cache-control",
		"private, no-store".parse().expect("constant"),
	);
	Ok((
		StatusCode::OK,
		response_headers,
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
		RagGatewayError::Lifecycle(_) => api_error(
			StatusCode::CONFLICT,
			"lifecycle_denied",
			"document lifecycle operation unavailable, stale, or denied",
		),
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
