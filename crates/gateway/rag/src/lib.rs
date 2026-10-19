//! Transport-neutral RAG gateway adapter.
//!
//! HTTP, MCP, or application-specific transports authenticate a request and pass the resulting
//! [`GatewayIdentity`] to this adapter. The adapter never accepts caller-supplied tenant, ACL, or
//! vector-store filter fields: those are derived inside `security-rag` from verified identity.

use security_audit::AuditSink;
use security_pipeline::{Authorizer, GatewayIdentity};
use security_rag::{
	AuthorizedContext, ContextAssemblyError, ContextAuditSink, ContextGuard, DocumentIngestBackend,
	DocumentIngestRequest, GuardedContext, IngestionAuditSink, IngestionError, IngestionResult,
	RetrievalAuditSink, RetrievalBackend, RetrievalError, RetrievalQuery, SecureIngestor,
	SecureRetriever,
};

pub mod config;
pub mod http;

pub mod qdrant;

/// Compatibility path for the configured HTTPS source types.
pub mod sources {
	pub use security_rag::sources::{TrustedHttpsSourceConfig, TrustedHttpsSourceRegistry};
}

pub use config::{HttpEmbeddingProvider, OpenAiCompatibleEmbeddingConfig, RagGatewayConfig};
pub use http::{RagHttpService, VerifiedGatewayIdentity, router, router_with_sources};
pub use qdrant::{
	DocumentChunker, EmbeddingProvider, FixedWindowChunker, QdrantBackend, QdrantBackendConfig,
};
pub use sources::{TrustedHttpsSourceConfig, TrustedHttpsSourceRegistry};

/// Transport payload for a corpus query. Identity is intentionally not included: a transport must
/// derive it from verified authentication and provide it separately to [`RagGatewayAdapter::query`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RagQueryRequest {
	pub corpus_id: String,
	pub query: String,
	pub limit: usize,
}

impl RagQueryRequest {
	pub fn new(corpus_id: impl Into<String>, query: impl Into<String>, limit: usize) -> Self {
		Self {
			corpus_id: corpus_id.into(),
			query: query.into(),
			limit,
		}
	}

	fn into_query(self) -> RetrievalQuery {
		RetrievalQuery::new(self.query, self.limit)
	}
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RagGatewayError {
	Lifecycle(String),
	Ingestion(IngestionError),
	Retrieval(RetrievalError),
	Context(ContextAssemblyError),
}

/// Composes the three RAG security stages into one gateway-facing adapter. The stage types stay
/// generic so a deployment can use different metadata/index implementations for ingestion and
/// retrieval without changing the security contract.
pub struct RagGatewayAdapter<I, R, CA> {
	lifecycle: Option<(
		std::sync::Arc<security_rag::lifecycle::DocumentLifecycleStore>,
		std::sync::Arc<dyn security_rag::lifecycle::DocumentPurger>,
	)>,
	ingestor: I,
	retriever: R,
	context_guard: ContextGuard,
	context_audit: CA,
}

impl<I, R, CA> RagGatewayAdapter<I, R, CA> {
	pub fn new(ingestor: I, retriever: R, context_guard: ContextGuard, context_audit: CA) -> Self {
		Self {
			lifecycle: None,
			ingestor,
			retriever,
			context_guard,
			context_audit,
		}
	}
	pub fn with_lifecycle(
		mut self,
		store: std::sync::Arc<security_rag::lifecycle::DocumentLifecycleStore>,
		purger: std::sync::Arc<dyn security_rag::lifecycle::DocumentPurger>,
	) -> Self {
		self.lifecycle = Some((store, purger));
		self
	}
}

impl<IB, RB, IA, IS, IAudit, RA, RS, RAudit, CA>
	RagGatewayAdapter<SecureIngestor<IB, IA, IS, IAudit>, SecureRetriever<RB, RA, RS, RAudit>, CA>
where
	IB: DocumentIngestBackend,
	RB: RetrievalBackend,
	IA: Authorizer,
	IS: AuditSink,
	IAudit: IngestionAuditSink,
	RA: Authorizer,
	RS: AuditSink,
	RAudit: RetrievalAuditSink,
	CA: ContextAuditSink,
{
	pub fn authorize_import(
		&self,
		request_id: impl Into<String>,
		identity: GatewayIdentity,
		corpus_id: &str,
		document_id: &str,
		source_id: &str,
	) -> Result<(), RagGatewayError> {
		self
			.ingestor
			.authorize_import(request_id, identity, corpus_id, document_id, source_id)
			.map_err(RagGatewayError::Ingestion)
	}

	pub fn record_source_fetch_failure(
		&self,
		request_id: impl Into<String>,
		identity: GatewayIdentity,
		corpus_id: &str,
		document_id: &str,
		source_id: &str,
	) {
		self.ingestor.record_source_fetch_failure(
			request_id,
			identity,
			corpus_id,
			document_id,
			source_id,
		);
	}

	/// Runs the write path through `KnowledgeIngest` before any index backend sees document content.
	pub async fn ingest(
		&self,
		request_id: impl Into<String>,
		identity: GatewayIdentity,
		request: DocumentIngestRequest,
	) -> Result<IngestionResult, RagGatewayError> {
		self
			.ingestor
			.ingest(request_id, identity, request)
			.await
			.map_err(RagGatewayError::Ingestion)
	}

	/// Runs retrieval and context assembly as two separately authorized security actions. The LLM
	/// caller receives only `GuardedContext`, never raw vector-store candidates.
	pub async fn query(
		&self,
		request_id: impl Into<String>,
		identity: GatewayIdentity,
		request: RagQueryRequest,
	) -> Result<GuardedContext, RagGatewayError> {
		let request_id = request_id.into();
		let corpus_id = request.corpus_id.clone();
		let context: AuthorizedContext = self
			.retriever
			.retrieve(
				request_id.clone(),
				identity.clone(),
				corpus_id,
				request.into_query(),
			)
			.await
			.map_err(RagGatewayError::Retrieval)?;
		let subject: security_types::Subject = identity.clone().into();
		let guarded = self
			.context_guard
			.assemble(
				self.retriever.security_pipeline(),
				&self.context_audit,
				request_id,
				identity,
				context,
			)
			.map_err(RagGatewayError::Context)?;
		if let Some((store, _)) = &self.lifecycle {
			use security_types::DocumentVersionValidator;
			let references = guarded
				.chunks
				.iter()
				.map(|chunk| {
					security_rag::lifecycle::document_reference(chunk)
						.ok_or_else(|| RagGatewayError::Lifecycle("unversioned context".into()))
				})
				.collect::<Result<Vec<_>, _>>()?;
			store
				.validate_documents(&subject, &references)
				.map_err(RagGatewayError::Lifecycle)?;
		}
		Ok(guarded)
	}
	pub async fn document_operation(
		&self,
		request_id: String,
		identity: GatewayIdentity,
		corpus: String,
		document: String,
		expected: Option<u64>,
		mutation: Option<security_rag::lifecycle::DocumentMutation>,
	) -> Result<DocumentStatus, RagGatewayError> {
		let tenant = identity
			.tenant_id
			.clone()
			.ok_or_else(|| RagGatewayError::Lifecycle("missing tenant".into()))?;
		let key = security_types::DocumentKey {
			tenant_id: tenant,
			corpus_id: corpus.clone(),
			document_id: document,
		};
		key.validate().map_err(RagGatewayError::Lifecycle)?;
		let mut action = security_pipeline::knowledge_ingest_for_identity(
			request_id,
			identity,
			serde_json::to_string(&(&key.corpus_id, &key.document_id)).expect("strings"),
		);
		action.action.action_type = security_types::ActionType::KnowledgeDocumentOperation;
		action.action.name = mutation
			.as_ref()
			.map_or("document/read-metadata", |m| m.action())
			.into();
		self
			.retriever
			.security_pipeline()
			.authorize(
				&action,
				Some(&serde_json::json!({"corpusId":corpus,"expectedRevision":expected})),
			)
			.map_err(|e| RagGatewayError::Retrieval(RetrievalError::GatewayDenied(e)))?;
		let (store, purger) = self
			.lifecycle
			.as_ref()
			.ok_or_else(|| RagGatewayError::Lifecycle("document lifecycle unavailable".into()))?;
		let deleting = matches!(
			&mutation,
			Some(security_rag::lifecycle::DocumentMutation::Delete)
		);
		let meta = if let Some(mutation) = mutation {
			store.mutate(
				&key,
				expected.ok_or_else(|| RagGatewayError::Lifecycle("expectedRevision required".into()))?,
				mutation,
			)
		} else {
			store.get(&key)
		}
		.map_err(RagGatewayError::Lifecycle)?;
		let purged = if deleting {
			Some(purger.purge_document(&key).await.is_ok())
		} else {
			None
		};
		Ok(DocumentStatus {
			revision: meta.revision,
			version: meta.version,
			state: meta.state,
			source_hash: meta.source_hash,
			purged,
		})
	}

	pub fn ingestor(&self) -> &SecureIngestor<IB, IA, IS, IAudit> {
		&self.ingestor
	}

	pub fn retriever(&self) -> &SecureRetriever<RB, RA, RS, RAudit> {
		&self.retriever
	}
}

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DocumentStatus {
	pub revision: u64,
	pub version: u64,
	pub state: security_rag::lifecycle::DocumentState,
	pub source_hash: String,
	pub purged: Option<bool>,
}
