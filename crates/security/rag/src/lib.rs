//! RAG retrieval security brick.
//!
//! `SecureRetriever` makes a vector-store adapter follow one safe sequence: authorize the corpus
//! search, push a trusted tenant/principal filter to the backend, and independently re-check every
//! returned chunk before it is allowed into model context. The second check is intentional: a
//! vector index is not an authorization boundary and may be stale, misconfigured, or return a
//! broader candidate set than requested.

use std::collections::HashSet;
use std::sync::Mutex;

use audit_core::AuditSink;
use chrono::{DateTime, Utc};
use gateway_adapter::{
	Authorizer, GatewayError, GatewayIdentity, SecurityPipeline, knowledge_retrieve_for_identity,
};
use security_contracts::Subject;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// System-level controls for one RAG corpus integration.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct RagSecurityConfig {
	/// Maximum authorized chunks that can enter one model context.
	pub max_chunks: usize,
	/// Maximum trusted token count that can enter one model context.
	pub max_context_tokens: u64,
	/// Chunks carrying any blocked label are never placed in model context.
	#[serde(default, skip_serializing_if = "Vec::is_empty")]
	pub blocked_labels: Vec<String>,
}

impl Default for RagSecurityConfig {
	fn default() -> Self {
		Self {
			max_chunks: 8,
			max_context_tokens: 6_000,
			blocked_labels: Vec::new(),
		}
	}
}

/// A query is retained only for the retrieval backend. Audit and authorization receive its SHA-256
/// digest rather than its contents, so prompts do not leak into security telemetry by default.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RetrievalQuery {
	text: String,
	query_hash: String,
	limit: usize,
}

impl RetrievalQuery {
	pub fn new(text: impl Into<String>, limit: usize) -> Self {
		let text = text.into();
		let query_hash = hex::encode(Sha256::digest(text.as_bytes()));
		Self {
			text,
			query_hash,
			limit,
		}
	}

	pub fn text(&self) -> &str {
		&self.text
	}

	pub fn query_hash(&self) -> &str {
		&self.query_hash
	}

	pub fn limit(&self) -> usize {
		self.limit
	}
}

/// Trusted filter supplied to a vector-store adapter. It is derived from verified gateway identity,
/// not from untrusted query fields. Backends should enforce it during candidate selection; the
/// guard still performs a mandatory post-retrieval check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RetrievalFilter {
	pub corpus_id: String,
	pub tenant_id: String,
	pub user_id: Option<String>,
	pub agent_id: Option<String>,
	pub max_candidates: usize,
}

/// A Chunk returned by a retrieval backend. `content` remains in-process for context assembly and
/// is deliberately absent from [`RetrievalAuditEvent`]; telemetry records only IDs and hashes.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct KnowledgeChunk {
	pub id: String,
	pub document_id: String,
	pub corpus_id: String,
	pub tenant_id: String,
	pub content: String,
	/// Labels inherited from the source document, such as `pii` or `confidential`.
	#[serde(default, skip_serializing_if = "Vec::is_empty")]
	pub labels: Vec<String>,
	/// Explicit user ACL. An empty list grants no user access by itself.
	#[serde(default, skip_serializing_if = "Vec::is_empty")]
	pub allowed_users: Vec<String>,
	/// Explicit Agent ACL. An empty list grants no Agent access by itself.
	#[serde(default, skip_serializing_if = "Vec::is_empty")]
	pub allowed_agents: Vec<String>,
	/// Explicitly permits any authenticated User or Agent in the owning tenant.
	#[serde(default)]
	pub allow_tenant_authenticated: bool,
	/// Expired chunks are excluded even if their index entry still exists.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub expires_at: Option<DateTime<Utc>>,
	/// Content hash recorded at ingestion. A missing hash means provenance is incomplete and fails
	/// closed, preventing untracked index content from reaching the model.
	pub source_hash: String,
	/// Token count calculated during ingestion or trusted tokenization.
	pub token_count: u64,
}

/// Retrieval adapter contract. Implementations receive the trusted filter before similarity search.
pub trait RetrievalBackend: Send + Sync {
	fn retrieve(
		&self,
		query: &RetrievalQuery,
		filter: &RetrievalFilter,
	) -> Result<Vec<KnowledgeChunk>, String>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RetrievalRejection {
	pub chunk_id: String,
	pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizedContext {
	pub corpus_id: String,
	pub query_hash: String,
	pub chunks: Vec<KnowledgeChunk>,
	pub context_tokens: u64,
	pub rejected: Vec<RetrievalRejection>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RetrievalAuditOutcome {
	Authorized,
	Denied,
}

/// Retrieval-specific audit data. It records IDs and hashes, never Chunk or prompt text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RetrievalAuditEvent {
	pub request_id: String,
	pub subject: Subject,
	pub corpus_id: String,
	pub query_hash: String,
	pub outcome: RetrievalAuditOutcome,
	pub accepted_chunk_ids: Vec<String>,
	pub rejected: Vec<RetrievalRejection>,
	pub reason: Option<String>,
	pub timestamp: DateTime<Utc>,
}

pub trait RetrievalAuditSink: Send + Sync {
	fn record(&self, event: RetrievalAuditEvent);
}

impl<T: RetrievalAuditSink + ?Sized> RetrievalAuditSink for &T {
	fn record(&self, event: RetrievalAuditEvent) {
		(*self).record(event);
	}
}

#[derive(Default)]
pub struct InMemoryRetrievalAuditSink {
	events: Mutex<Vec<RetrievalAuditEvent>>,
}

impl InMemoryRetrievalAuditSink {
	pub fn events(&self) -> Vec<RetrievalAuditEvent> {
		self
			.events
			.lock()
			.expect("retrieval audit sink lock poisoned")
			.clone()
	}
}

impl RetrievalAuditSink for InMemoryRetrievalAuditSink {
	fn record(&self, event: RetrievalAuditEvent) {
		self
			.events
			.lock()
			.expect("retrieval audit sink lock poisoned")
			.push(event);
	}
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RetrievalError {
	InvalidConfig(String),
	MissingTenant,
	RequestedLimitZero,
	RequestedLimitExceedsBudget { requested: usize, maximum: usize },
	GatewayDenied(GatewayError),
	Backend(String),
}

/// Enforced retrieval sequence around an arbitrary vector-store adapter.
pub struct SecureRetriever<R, A, S, RS> {
	backend: R,
	pipeline: SecurityPipeline<A, S>,
	config: RagSecurityConfig,
	audit: RS,
}

impl<R, A, S, RS> SecureRetriever<R, A, S, RS>
where
	R: RetrievalBackend,
	A: Authorizer,
	S: AuditSink,
	RS: RetrievalAuditSink,
{
	pub fn new(
		backend: R,
		pipeline: SecurityPipeline<A, S>,
		config: RagSecurityConfig,
		audit: RS,
	) -> Result<Self, RetrievalError> {
		if config.max_chunks == 0 {
			return Err(RetrievalError::InvalidConfig(
				"maxChunks must be greater than zero".into(),
			));
		}
		if config.max_context_tokens == 0 {
			return Err(RetrievalError::InvalidConfig(
				"maxContextTokens must be greater than zero".into(),
			));
		}
		Ok(Self {
			backend,
			pipeline,
			config,
			audit,
		})
	}

	pub fn retrieve(
		&self,
		request_id: impl Into<String>,
		identity: GatewayIdentity,
		corpus_id: impl Into<String>,
		query: RetrievalQuery,
	) -> Result<AuthorizedContext, RetrievalError> {
		let request_id = request_id.into();
		let corpus_id = corpus_id.into();
		let action = knowledge_retrieve_for_identity(request_id, identity, corpus_id.clone());

		if query.limit() == 0 {
			return self.deny(
				&action,
				query.query_hash(),
				RetrievalError::RequestedLimitZero,
			);
		}
		if query.limit() > self.config.max_chunks {
			return self.deny(
				&action,
				query.query_hash(),
				RetrievalError::RequestedLimitExceedsBudget {
					requested: query.limit(),
					maximum: self.config.max_chunks,
				},
			);
		}
		let Some(tenant_id) = action.subject.tenant_id.clone() else {
			return self.deny(&action, query.query_hash(), RetrievalError::MissingTenant);
		};
		let arguments = serde_json::json!({
			"queryHash": query.query_hash(),
			"requestedLimit": query.limit(),
		});
		if let Err(error) = self.pipeline.authorize(&action, Some(&arguments)) {
			return self.deny(
				&action,
				query.query_hash(),
				RetrievalError::GatewayDenied(error),
			);
		}

		let filter = RetrievalFilter {
			corpus_id: corpus_id.clone(),
			tenant_id,
			user_id: action.subject.user_id.clone(),
			agent_id: action.subject.agent_id.clone(),
			max_candidates: query.limit(),
		};
		let candidates = self
			.backend
			.retrieve(&query, &filter)
			.map_err(RetrievalError::Backend)?;
		let context = self.filter_candidates(&action, &query, candidates);
		self.audit.record(RetrievalAuditEvent {
			request_id: action.request_id,
			subject: action.subject,
			corpus_id,
			query_hash: context.query_hash.clone(),
			outcome: RetrievalAuditOutcome::Authorized,
			accepted_chunk_ids: context
				.chunks
				.iter()
				.map(|chunk| chunk.id.clone())
				.collect(),
			rejected: context.rejected.clone(),
			reason: None,
			timestamp: Utc::now(),
		});
		Ok(context)
	}

	fn filter_candidates(
		&self,
		action: &security_contracts::ActionRequest,
		query: &RetrievalQuery,
		candidates: Vec<KnowledgeChunk>,
	) -> AuthorizedContext {
		let mut chunks = Vec::new();
		let mut rejected = Vec::new();
		let mut accepted_chunk_ids = HashSet::new();
		let mut context_tokens = 0;
		for chunk in candidates {
			if let Err(reason) = self.chunk_access_reason(action, &chunk, context_tokens) {
				rejected.push(RetrievalRejection {
					chunk_id: chunk.id,
					reason,
				});
				continue;
			}
			if chunks.len() >= query.limit() {
				rejected.push(RetrievalRejection {
					chunk_id: chunk.id,
					reason: "chunk exceeds the requested retrieval limit".into(),
				});
				continue;
			}
			if !accepted_chunk_ids.insert(chunk.id.clone()) {
				rejected.push(RetrievalRejection {
					chunk_id: chunk.id,
					reason: "duplicate chunk returned by retrieval backend".into(),
				});
				continue;
			}
			context_tokens += chunk.token_count;
			chunks.push(chunk);
		}
		AuthorizedContext {
			corpus_id: action.resource.id.clone(),
			query_hash: query.query_hash().to_string(),
			chunks,
			context_tokens,
			rejected,
		}
	}

	fn chunk_access_reason(
		&self,
		action: &security_contracts::ActionRequest,
		chunk: &KnowledgeChunk,
		current_tokens: u64,
	) -> Result<(), String> {
		if chunk.corpus_id != action.resource.id {
			return Err("chunk belongs to a different corpus".into());
		}
		if action.subject.tenant_id.as_deref() != Some(chunk.tenant_id.as_str()) {
			return Err("chunk tenant does not match verified request tenant".into());
		}
		if chunk
			.expires_at
			.is_some_and(|expires_at| expires_at <= Utc::now())
		{
			return Err("chunk has expired".into());
		}
		if chunk.source_hash.is_empty() {
			return Err("chunk has no ingestion provenance hash".into());
		}
		if chunk.labels.iter().any(|label| {
			self
				.config
				.blocked_labels
				.iter()
				.any(|blocked| blocked == label)
		}) {
			return Err("chunk carries a blocked security label".into());
		}
		let user_allowed = action
			.subject
			.user_id
			.as_ref()
			.is_some_and(|user| chunk.allowed_users.iter().any(|allowed| allowed == user));
		let agent_allowed = action
			.subject
			.agent_id
			.as_ref()
			.is_some_and(|agent| chunk.allowed_agents.iter().any(|allowed| allowed == agent));
		let tenant_authenticated = chunk.allow_tenant_authenticated
			&& (action.subject.user_id.is_some() || action.subject.agent_id.is_some());
		if !(user_allowed || agent_allowed || tenant_authenticated) {
			return Err("chunk ACL does not grant the verified user or agent access".into());
		}
		if current_tokens.saturating_add(chunk.token_count) > self.config.max_context_tokens {
			return Err("chunk exceeds the context token budget".into());
		}
		Ok(())
	}

	fn deny<T>(
		&self,
		action: &security_contracts::ActionRequest,
		query_hash: &str,
		error: RetrievalError,
	) -> Result<T, RetrievalError> {
		self.audit.record(RetrievalAuditEvent {
			request_id: action.request_id.clone(),
			subject: action.subject.clone(),
			corpus_id: action.resource.id.clone(),
			query_hash: query_hash.to_string(),
			outcome: RetrievalAuditOutcome::Denied,
			accepted_chunk_ids: Vec::new(),
			rejected: Vec::new(),
			reason: Some(format!("{error:?}")),
			timestamp: Utc::now(),
		});
		Err(error)
	}
}

#[cfg(test)]
mod tests {
	use std::sync::atomic::{AtomicUsize, Ordering};

	use audit_core::InMemoryAuditSink;
	use gateway_adapter::{GatewayIdentity, PolicyAuthorizer, SecurityPipeline};
	use security_contracts::{ActionType, DecisionEffect, ResourceType};
	use security_policy::Policy;

	use super::*;

	struct FixedBackend {
		chunks: Vec<KnowledgeChunk>,
		calls: AtomicUsize,
		filter: Mutex<Option<RetrievalFilter>>,
	}

	impl FixedBackend {
		fn new(chunks: Vec<KnowledgeChunk>) -> Self {
			Self {
				chunks,
				calls: AtomicUsize::new(0),
				filter: Mutex::new(None),
			}
		}
	}

	impl RetrievalBackend for FixedBackend {
		fn retrieve(
			&self,
			_query: &RetrievalQuery,
			filter: &RetrievalFilter,
		) -> Result<Vec<KnowledgeChunk>, String> {
			self.calls.fetch_add(1, Ordering::Relaxed);
			*self.filter.lock().unwrap() = Some(filter.clone());
			Ok(self.chunks.clone())
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

	fn allow_retrieval_policy() -> Policy {
		Policy {
			id: "allow-alice-support-corpus".into(),
			priority: 0,
			tenant_id: Some("tenant-a".into()),
			user_id: Some("alice".into()),
			agent_id: Some("support-agent".into()),
			action_type: Some(ActionType::KnowledgeRetrieve),
			action_name: Some("retrieve".into()),
			resource_id: Some("support-corpus".into()),
			resource_type: Some(ResourceType::KnowledgeBase),
			effect: DecisionEffect::Allow,
			enabled: true,
		}
	}

	fn chunk(id: &str) -> KnowledgeChunk {
		KnowledgeChunk {
			id: id.into(),
			document_id: format!("document-{id}"),
			corpus_id: "support-corpus".into(),
			tenant_id: "tenant-a".into(),
			content: format!("trusted context for {id}"),
			labels: Vec::new(),
			allowed_users: vec!["alice".into()],
			allowed_agents: Vec::new(),
			allow_tenant_authenticated: false,
			expires_at: None,
			source_hash: "a22d9a9b".into(),
			token_count: 100,
		}
	}

	#[test]
	fn retrieval_pushes_filter_and_rechecks_every_chunk() {
		let mut cross_tenant = chunk("cross-tenant");
		cross_tenant.tenant_id = "tenant-b".into();
		let mut blocked = chunk("blocked");
		blocked.labels = vec!["confidential".into()];
		let mut expired = chunk("expired");
		expired.expires_at = Some(Utc::now() - chrono::Duration::seconds(1));
		let mut unauthorized = chunk("unauthorized");
		unauthorized.allowed_users = vec!["bob".into()];
		let backend = FixedBackend::new(vec![
			chunk("allowed"),
			cross_tenant,
			blocked,
			expired,
			unauthorized,
		]);
		let gateway_audit = InMemoryAuditSink::default();
		let retrieval_audit = InMemoryRetrievalAuditSink::default();
		let pipeline = SecurityPipeline::new(
			PolicyAuthorizer::new(vec![allow_retrieval_policy()]),
			&gateway_audit,
		);
		let retriever = SecureRetriever::new(
			backend,
			pipeline,
			RagSecurityConfig {
				blocked_labels: vec!["confidential".into()],
				..Default::default()
			},
			&retrieval_audit,
		)
		.unwrap();

		let result = retriever
			.retrieve(
				"rag-request-1",
				identity(),
				"support-corpus",
				RetrievalQuery::new("how do I reset my password?", 5),
			)
			.unwrap();

		assert_eq!(
			result
				.chunks
				.iter()
				.map(|chunk| chunk.id.as_str())
				.collect::<Vec<_>>(),
			["allowed"]
		);
		assert_eq!(result.rejected.len(), 4);
		assert_eq!(result.context_tokens, 100);
		let filter = retriever.backend.filter.lock().unwrap().clone().unwrap();
		assert_eq!(filter.tenant_id, "tenant-a");
		assert_eq!(filter.user_id.as_deref(), Some("alice"));
		assert_eq!(filter.max_candidates, 5);
		let audit = retrieval_audit.events();
		assert_eq!(audit.len(), 1);
		assert_eq!(audit[0].outcome, RetrievalAuditOutcome::Authorized);
		assert_eq!(audit[0].accepted_chunk_ids, ["allowed"]);
		assert!(!audit[0].query_hash.contains("password"));
	}

	#[test]
	fn denied_corpus_search_never_calls_the_retrieval_backend() {
		let backend = FixedBackend::new(vec![chunk("should-not-be-fetched")]);
		let gateway_audit = InMemoryAuditSink::default();
		let retrieval_audit = InMemoryRetrievalAuditSink::default();
		let pipeline = SecurityPipeline::new(PolicyAuthorizer::new(Vec::new()), &gateway_audit);
		let retriever = SecureRetriever::new(
			backend,
			pipeline,
			RagSecurityConfig::default(),
			&retrieval_audit,
		)
		.unwrap();

		let error = retriever
			.retrieve(
				"rag-request-2",
				identity(),
				"support-corpus",
				RetrievalQuery::new("private query", 1),
			)
			.unwrap_err();
		assert!(matches!(error, RetrievalError::GatewayDenied(_)));
		assert_eq!(retriever.backend.calls.load(Ordering::Relaxed), 0);
		assert_eq!(
			retrieval_audit.events()[0].outcome,
			RetrievalAuditOutcome::Denied
		);
	}

	#[test]
	fn post_retrieval_check_enforces_requested_limit_when_backend_overreturns() {
		let backend = FixedBackend::new(vec![chunk("first"), chunk("second")]);
		let gateway_audit = InMemoryAuditSink::default();
		let retrieval_audit = InMemoryRetrievalAuditSink::default();
		let pipeline = SecurityPipeline::new(
			PolicyAuthorizer::new(vec![allow_retrieval_policy()]),
			&gateway_audit,
		);
		let retriever = SecureRetriever::new(
			backend,
			pipeline,
			RagSecurityConfig::default(),
			&retrieval_audit,
		)
		.unwrap();

		let result = retriever
			.retrieve(
				"rag-request-limit",
				identity(),
				"support-corpus",
				RetrievalQuery::new("only one result", 1),
			)
			.unwrap();
		assert_eq!(result.chunks.len(), 1);
		assert_eq!(result.chunks[0].id, "first");
		assert_eq!(result.rejected.len(), 1);
		assert_eq!(
			result.rejected[0].reason,
			"chunk exceeds the requested retrieval limit"
		);
	}

	#[test]
	fn requested_chunk_budget_is_checked_before_authorization_or_retrieval() {
		let backend = FixedBackend::new(vec![chunk("should-not-be-fetched")]);
		let gateway_audit = InMemoryAuditSink::default();
		let retrieval_audit = InMemoryRetrievalAuditSink::default();
		let pipeline = SecurityPipeline::new(
			PolicyAuthorizer::new(vec![allow_retrieval_policy()]),
			&gateway_audit,
		);
		let retriever = SecureRetriever::new(
			backend,
			pipeline,
			RagSecurityConfig {
				max_chunks: 1,
				..Default::default()
			},
			&retrieval_audit,
		)
		.unwrap();

		let error = retriever
			.retrieve(
				"rag-request-3",
				identity(),
				"support-corpus",
				RetrievalQuery::new("private query", 2),
			)
			.unwrap_err();
		assert_eq!(
			error,
			RetrievalError::RequestedLimitExceedsBudget {
				requested: 2,
				maximum: 1
			}
		);
		assert_eq!(retriever.backend.calls.load(Ordering::Relaxed), 0);
	}
}
