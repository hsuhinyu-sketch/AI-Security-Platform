//! Transport-neutral RAG gateway adapter.
//!
//! HTTP, MCP, or application-specific transports authenticate a request and pass the resulting
//! [`GatewayIdentity`] to this adapter. The adapter never accepts caller-supplied tenant, ACL, or
//! vector-store filter fields: those are derived inside `security-rag` from verified identity.

use audit_core::AuditSink;
use gateway_adapter::{Authorizer, GatewayIdentity};
use security_rag::{
	AuthorizedContext, ContextAssemblyError, ContextAuditSink, ContextGuard, DocumentIngestBackend,
	DocumentIngestRequest, GuardedContext, IngestionAuditSink, IngestionError, IngestionResult,
	RetrievalAuditSink, RetrievalBackend, RetrievalError, RetrievalQuery, SecureIngestor,
	SecureRetriever,
};

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
	Ingestion(IngestionError),
	Retrieval(RetrievalError),
	Context(ContextAssemblyError),
}

/// Composes the three RAG security stages into one gateway-facing adapter. The stage types stay
/// generic so a deployment can use different metadata/index implementations for ingestion and
/// retrieval without changing the security contract.
pub struct RagGatewayAdapter<I, R, CA> {
	ingestor: I,
	retriever: R,
	context_guard: ContextGuard,
	context_audit: CA,
}

impl<I, R, CA> RagGatewayAdapter<I, R, CA> {
	pub fn new(ingestor: I, retriever: R, context_guard: ContextGuard, context_audit: CA) -> Self {
		Self {
			ingestor,
			retriever,
			context_guard,
			context_audit,
		}
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
		self
			.context_guard
			.assemble(
				self.retriever.security_pipeline(),
				&self.context_audit,
				request_id,
				identity,
				context,
			)
			.map_err(RagGatewayError::Context)
	}

	pub fn ingestor(&self) -> &SecureIngestor<IB, IA, IS, IAudit> {
		&self.ingestor
	}

	pub fn retriever(&self) -> &SecureRetriever<RB, RA, RS, RAudit> {
		&self.retriever
	}
}

#[cfg(test)]
mod tests {
	use std::sync::{Arc, Mutex};

	use audit_core::InMemoryAuditSink;
	use gateway_adapter::{PolicyAuthorizer, SecurityPipeline};
	use security_contracts::{ActionType, DecisionEffect, ResourceType};
	use security_policy::Policy;
	use security_rag::{
		ContentLabelRule, ContextGuardConfig, DocumentIngestBackend, InMemoryContextAuditSink,
		InMemoryIngestionAuditSink, InMemoryRetrievalAuditSink, IndexedDocument, IngestionGuardConfig,
		KnowledgeChunk, QuarantinedDocument, RetrievalBackend, RetrievalFilter, TrustedChunkAccess,
	};

	use super::*;

	#[derive(Default)]
	struct MemoryRagBackend {
		indexed: Mutex<Vec<IndexedDocument>>,
		quarantined: Mutex<Vec<QuarantinedDocument>>,
		chunks: Mutex<Vec<KnowledgeChunk>>,
	}

	#[async_trait::async_trait]
	impl DocumentIngestBackend for MemoryRagBackend {
		async fn index(&self, document: IndexedDocument) -> Result<(), String> {
			let chunk = document.to_chunk(
				format!("{}:0", document.document_id),
				document.content.clone(),
				32,
				TrustedChunkAccess {
					allowed_users: vec!["alice".into()],
					..Default::default()
				},
			);
			self.indexed.lock().unwrap().push(document);
			self.chunks.lock().unwrap().push(chunk);
			Ok(())
		}

		async fn quarantine(&self, document: QuarantinedDocument) -> Result<(), String> {
			self.quarantined.lock().unwrap().push(document);
			Ok(())
		}
	}

	#[async_trait::async_trait]
	impl RetrievalBackend for MemoryRagBackend {
		async fn retrieve(
			&self,
			_query: &RetrievalQuery,
			filter: &RetrievalFilter,
		) -> Result<Vec<KnowledgeChunk>, String> {
			Ok(
				self
					.chunks
					.lock()
					.unwrap()
					.iter()
					.filter(|chunk| {
						chunk.corpus_id == filter.corpus_id
							&& chunk.tenant_id == filter.tenant_id
							&& (chunk.allow_tenant_authenticated
								|| filter
									.user_id
									.as_ref()
									.is_some_and(|user| chunk.allowed_users.iter().any(|allowed| allowed == user))
								|| filter
									.agent_id
									.as_ref()
									.is_some_and(|agent| chunk.allowed_agents.iter().any(|allowed| allowed == agent)))
					})
					.take(filter.max_candidates)
					.cloned()
					.collect(),
			)
		}
	}

	fn identity() -> GatewayIdentity {
		GatewayIdentity {
			user_id: Some("alice".into()),
			agent_id: Some("support-agent".into()),
			tenant_id: Some("tenant-a".into()),
			delegation_id: None,
			session_id: Some("session-1".into()),
			client_id: Some("client-1".into()),
		}
	}

	fn policy(action_type: ActionType, action_name: &str, resource_type: ResourceType) -> Policy {
		Policy {
			id: format!("allow-{action_name}"),
			priority: 0,
			tenant_id: Some("tenant-a".into()),
			user_id: Some("alice".into()),
			agent_id: Some("support-agent".into()),
			action_type: Some(action_type),
			action_name: Some(action_name.into()),
			resource_id: None,
			resource_type: Some(resource_type),
			effect: DecisionEffect::Allow,
			enabled: true,
		}
	}

	#[tokio::test]
	async fn adapter_enforces_ingestion_retrieval_and_context_before_returning_content() {
		let backend = Arc::new(MemoryRagBackend::default());
		let ingestion_audit = InMemoryAuditSink::default();
		let retrieval_audit = InMemoryAuditSink::default();
		let ingestion_events = InMemoryIngestionAuditSink::default();
		let retrieval_events = InMemoryRetrievalAuditSink::default();
		let context_events = InMemoryContextAuditSink::default();
		let ingestion_pipeline = SecurityPipeline::new(
			PolicyAuthorizer::new(vec![policy(
				ActionType::KnowledgeIngest,
				"ingest",
				ResourceType::Document,
			)]),
			&ingestion_audit,
		);
		let retrieval_pipeline = SecurityPipeline::new(
			PolicyAuthorizer::new(vec![
				policy(
					ActionType::KnowledgeRetrieve,
					"retrieve",
					ResourceType::KnowledgeBase,
				),
				policy(
					ActionType::ContextAssemble,
					"assemble",
					ResourceType::KnowledgeBase,
				),
			]),
			&retrieval_audit,
		);
		let ingestor = SecureIngestor::new(
			backend.clone(),
			ingestion_pipeline,
			IngestionGuardConfig {
				label_rules: vec![ContentLabelRule {
					label: "pii".into(),
					pattern: "customer email".into(),
				}],
				..Default::default()
			},
			&ingestion_events,
		)
		.unwrap();
		let retriever = SecureRetriever::new(
			backend,
			retrieval_pipeline,
			Default::default(),
			&retrieval_events,
		)
		.unwrap();
		let adapter = RagGatewayAdapter::new(
			ingestor,
			retriever,
			ContextGuard::new(ContextGuardConfig {
				redact_labels: vec!["pii".into()],
				..Default::default()
			})
			.unwrap(),
			&context_events,
		);

		adapter
			.ingest(
				"request-1",
				identity(),
				DocumentIngestRequest::new(
					"support-corpus",
					"password-guide",
					"https://kb.example.com/password-guide",
					"Customer email is used for password recovery.",
				),
			)
			.await
			.unwrap();
		let context = adapter
			.query(
				"request-2",
				identity(),
				RagQueryRequest::new("support-corpus", "password recovery", 1),
			)
			.await
			.unwrap();
		assert_eq!(context.chunks.len(), 1);
		assert_eq!(
			context.chunks[0].content,
			"[REDACTED BY RAG CONTEXT POLICY]"
		);
		assert_eq!(
			ingestion_events.events()[0].outcome,
			security_rag::IngestionAuditOutcome::Indexed
		);
		assert_eq!(retrieval_events.events()[0].accepted_chunk_ids.len(), 1);
		assert_eq!(
			context_events.events()[0].outcome,
			security_rag::ContextAuditOutcome::Modified
		);
	}
}
