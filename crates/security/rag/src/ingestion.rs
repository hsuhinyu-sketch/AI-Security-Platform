//! Knowledge ingestion security brick.
//!
//! Documents must be authorized and classified before they are chunked or indexed. A vector index
//! only receives [`IndexedDocument`] values that passed all checks; risky documents use the
//! explicit quarantine path instead.

use std::sync::{Arc, Mutex};

use chrono::{DateTime, Utc};
use security_audit::AuditSink;
use security_pipeline::{
	Authorizer, GatewayError, GatewayIdentity, SecurityPipeline, knowledge_ingest_for_identity,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{DataClassification, KnowledgeChunk};

fn default_allowed_source_schemes() -> Vec<String> {
	vec!["https".into(), "s3".into()]
}

fn default_quarantine_patterns() -> Vec<String> {
	vec!["begin private key".into(), "aws_secret_access_key".into()]
}

fn default_max_document_bytes() -> usize {
	10 * 1024 * 1024
}

/// A deterministic content classifier rule. Matching labels are copied to every Chunk created
/// from the indexed document, making labels an ingestion-time invariant rather than client input.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ContentLabelRule {
	pub label: String,
	pub pattern: String,
}

/// Administrator-owned deterministic escalation rule; client JSON cannot supply this value.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ContentClassificationRule {
	pub id: String,
	pub classification: DataClassification,
	pub pattern: String,
}

/// Source, size, quarantine, and label controls for one document ingestion path.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct IngestionGuardConfig {
	#[serde(default = "default_allowed_source_schemes")]
	pub allowed_source_schemes: Vec<String>,
	#[serde(default = "default_max_document_bytes")]
	pub max_document_bytes: usize,
	/// Case-insensitive signals that send a document to quarantine instead of the index.
	#[serde(default = "default_quarantine_patterns")]
	pub quarantine_patterns: Vec<String>,
	#[serde(default, skip_serializing_if = "Vec::is_empty")]
	pub label_rules: Vec<ContentLabelRule>,
	/// Baseline class of documents entering this RAG deployment. Defaults to restricted.
	#[serde(default)]
	pub default_classification: DataClassification,
	#[serde(default, skip_serializing_if = "Vec::is_empty")]
	pub classification_rules: Vec<ContentClassificationRule>,
}

impl Default for IngestionGuardConfig {
	fn default() -> Self {
		Self {
			allowed_source_schemes: default_allowed_source_schemes(),
			max_document_bytes: default_max_document_bytes(),
			quarantine_patterns: default_quarantine_patterns(),
			label_rules: Vec::new(),
			default_classification: DataClassification::Restricted,
			classification_rules: Vec::new(),
		}
	}
}

/// Raw document presented to the ingestion boundary. It is never written to an audit event.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(
	tag = "kind",
	rename_all = "camelCase",
	rename_all_fields = "camelCase"
)]
pub enum SourceOrigin {
	#[default]
	Submitted,
	TrustedHttps {
		#[serde(alias = "source_id")]
		source_id: String,
		version: String,
	},
	/// Audit-only marker for a configured source fetch that failed before content was available.
	TrustedHttpsFetchAttempt { source_id: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DocumentIngestRequest {
	corpus_id: String,
	document_id: String,
	source_uri: String,
	content: String,
	origin: SourceOrigin,
}

impl DocumentIngestRequest {
	pub fn new(
		corpus_id: impl Into<String>,
		document_id: impl Into<String>,
		source_uri: impl Into<String>,
		content: impl Into<String>,
	) -> Self {
		Self {
			corpus_id: corpus_id.into(),
			document_id: document_id.into(),
			source_uri: source_uri.into(),
			content: content.into(),
			origin: SourceOrigin::Submitted,
		}
	}

	pub fn corpus_id(&self) -> &str {
		&self.corpus_id
	}

	pub fn document_id(&self) -> &str {
		&self.document_id
	}

	pub fn source_uri(&self) -> &str {
		&self.source_uri
	}

	pub fn content(&self) -> &str {
		&self.content
	}

	pub fn source_origin(&self) -> &SourceOrigin {
		&self.origin
	}

	/// Available only to this crate's configured HTTPS source connector.
	pub(crate) fn from_trusted_https(
		corpus_id: impl Into<String>,
		document_id: impl Into<String>,
		source_uri: impl Into<String>,
		content: impl Into<String>,
		source_id: impl Into<String>,
		version: impl Into<String>,
	) -> Self {
		Self {
			corpus_id: corpus_id.into(),
			document_id: document_id.into(),
			source_uri: source_uri.into(),
			content: content.into(),
			origin: SourceOrigin::TrustedHttps {
				source_id: source_id.into(),
				version: version.into(),
			},
		}
	}
}

/// A document that may be chunked and indexed. Its labels and source hash must be inherited by
/// generated Chunks; the retrieval guard fails closed if the resulting Chunk loses provenance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IndexedDocument {
	pub corpus_id: String,
	pub document_id: String,
	pub tenant_id: String,
	pub source_uri: String,
	pub source_hash: String,
	pub source_origin: SourceOrigin,
	pub content: String,
	pub labels: Vec<String>,
	pub classification: DataClassification,
	/// Stable administrator rule identifier; never supplied by the ingest request.
	pub classification_source: String,
}

/// ACL and lifetime facts supplied by a trusted ingestion controller when it chunks an indexed
/// document. Corpus, tenant, labels, and provenance are deliberately absent because they are
/// inherited from [`IndexedDocument`] and cannot be weakened at the Chunk boundary.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct TrustedChunkAccess {
	pub allowed_users: Vec<String>,
	pub allowed_agents: Vec<String>,
	pub allow_tenant_authenticated: bool,
	pub expires_at: Option<DateTime<Utc>>,
}

impl IndexedDocument {
	pub fn to_chunk(
		&self,
		chunk_id: impl Into<String>,
		content: impl Into<String>,
		token_count: u64,
		access: TrustedChunkAccess,
	) -> KnowledgeChunk {
		KnowledgeChunk {
			id: chunk_id.into(),
			document_id: self.document_id.clone(),
			corpus_id: self.corpus_id.clone(),
			tenant_id: self.tenant_id.clone(),
			content: content.into(),
			labels: self.labels.clone(),
			classification: self.classification,
			classification_source: self.classification_source.clone(),
			allowed_users: access.allowed_users,
			allowed_agents: access.allowed_agents,
			allow_tenant_authenticated: access.allow_tenant_authenticated,
			expires_at: access.expires_at,
			source_hash: self.source_hash.clone(),
			source_origin: self.source_origin.clone(),
			token_count,
		}
	}
}

/// A document that intentionally bypasses indexing pending a separate review workflow.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuarantinedDocument {
	pub document: IndexedDocument,
	pub findings: Vec<IngestionFinding>,
}

/// Storage boundary for a RAG ingestion adapter. Indexing and quarantine are deliberately
/// separate operations so a caller cannot accidentally index a document after a quarantine result.
#[async_trait::async_trait]
pub trait DocumentIngestBackend: Send + Sync {
	async fn index(&self, document: IndexedDocument) -> Result<(), String>;
	async fn quarantine(&self, document: QuarantinedDocument) -> Result<(), String>;
}

#[async_trait::async_trait]
impl<T: DocumentIngestBackend + ?Sized> DocumentIngestBackend for Arc<T> {
	async fn index(&self, document: IndexedDocument) -> Result<(), String> {
		(**self).index(document).await
	}

	async fn quarantine(&self, document: QuarantinedDocument) -> Result<(), String> {
		(**self).quarantine(document).await
	}
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum IngestionFindingKind {
	QuarantinePattern,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct IngestionFinding {
	pub kind: IngestionFindingKind,
	/// Stable rule identifier, never the matching text or document content.
	pub rule_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IngestionResult {
	Indexed(IndexedDocument),
	Quarantined(QuarantinedDocument),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IngestionAuditOutcome {
	Indexed,
	Quarantined,
	Denied,
}

/// Ingestion audit contains content identity and processing outcome but no source text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IngestionAuditEvent {
	pub request_id: String,
	pub corpus_id: String,
	pub document_id: String,
	pub tenant_id: Option<String>,
	pub source_scheme: Option<String>,
	pub source_hash: Option<String>,
	pub source_origin: SourceOrigin,
	pub content_bytes: usize,
	pub labels: Vec<String>,
	pub classification: DataClassification,
	pub classification_source: String,
	pub findings: Vec<IngestionFinding>,
	pub outcome: IngestionAuditOutcome,
	pub reason: Option<String>,
	pub timestamp: DateTime<Utc>,
}

pub trait IngestionAuditSink: Send + Sync {
	fn record(&self, event: IngestionAuditEvent);
}

impl<T: IngestionAuditSink + ?Sized> IngestionAuditSink for &T {
	fn record(&self, event: IngestionAuditEvent) {
		(*self).record(event);
	}
}

#[derive(Default)]
pub struct InMemoryIngestionAuditSink {
	events: Mutex<Vec<IngestionAuditEvent>>,
}

impl InMemoryIngestionAuditSink {
	pub fn events(&self) -> Vec<IngestionAuditEvent> {
		self
			.events
			.lock()
			.expect("ingestion audit sink lock poisoned")
			.clone()
	}
}

impl IngestionAuditSink for InMemoryIngestionAuditSink {
	fn record(&self, event: IngestionAuditEvent) {
		self
			.events
			.lock()
			.expect("ingestion audit sink lock poisoned")
			.push(event);
	}
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IngestionError {
	InvalidConfig(String),
	MissingTenant,
	InvalidSource(String),
	DocumentTooLarge { bytes: usize, maximum: usize },
	GatewayDenied(GatewayError),
	Backend(String),
}

/// Enforced ingestion sequence around an arbitrary document/index backend.
pub struct SecureIngestor<B, A, S, IS> {
	backend: B,
	pipeline: SecurityPipeline<A, S>,
	config: IngestionGuardConfig,
	audit: IS,
}

impl<B, A, S, IS> SecureIngestor<B, A, S, IS>
where
	B: DocumentIngestBackend,
	A: Authorizer,
	S: AuditSink,
	IS: IngestionAuditSink,
{
	/// Preflight authorization prevents an unauthorised caller from triggering an outbound source
	/// fetch. The full content-bound authorization still runs after the trusted fetch.
	pub fn authorize_import(
		&self,
		request_id: impl Into<String>,
		identity: GatewayIdentity,
		corpus_id: &str,
		document_id: &str,
		source_id: &str,
	) -> Result<(), IngestionError> {
		let action = knowledge_ingest_for_identity(request_id, identity, document_id);
		if action.subject.tenant_id.is_none() {
			return Err(IngestionError::MissingTenant);
		}
		self
			.pipeline
			.authorize(
				&action,
				Some(&serde_json::json!({
					"corpusId": corpus_id, "sourceId": source_id, "phase": "source-fetch"
				})),
			)
			.map(|_| ())
			.map_err(IngestionError::GatewayDenied)
	}

	/// Records an authorized source fetch that failed before an ingest request could be created.
	/// The failure reason is intentionally fixed so URLs, credentials, and response bodies do not
	/// enter the ingestion audit stream.
	pub fn record_source_fetch_failure(
		&self,
		request_id: impl Into<String>,
		identity: GatewayIdentity,
		corpus_id: &str,
		document_id: &str,
		source_id: &str,
	) {
		let action = knowledge_ingest_for_identity(request_id, identity, document_id);
		self.record(
			&action,
			corpus_id,
			Some("https".into()),
			None,
			0,
			Vec::new(),
			self.config.default_classification,
			"default-classification".into(),
			SourceOrigin::TrustedHttpsFetchAttempt {
				source_id: source_id.into(),
			},
			Vec::new(),
			IngestionAuditOutcome::Denied,
			Some("trusted_source_fetch_failed".into()),
		);
	}

	pub fn new(
		backend: B,
		pipeline: SecurityPipeline<A, S>,
		config: IngestionGuardConfig,
		audit: IS,
	) -> Result<Self, IngestionError> {
		if config.max_document_bytes == 0 {
			return Err(IngestionError::InvalidConfig(
				"maxDocumentBytes must be greater than zero".into(),
			));
		}
		if config
			.allowed_source_schemes
			.iter()
			.any(|scheme| scheme.trim().is_empty())
		{
			return Err(IngestionError::InvalidConfig(
				"allowedSourceSchemes must not contain empty values".into(),
			));
		}
		if config
			.quarantine_patterns
			.iter()
			.any(|pattern| pattern.trim().is_empty())
		{
			return Err(IngestionError::InvalidConfig(
				"quarantinePatterns must not contain empty values".into(),
			));
		}
		if config
			.label_rules
			.iter()
			.any(|rule| rule.label.trim().is_empty() || rule.pattern.trim().is_empty())
		{
			return Err(IngestionError::InvalidConfig(
				"labelRules must have non-empty label and pattern values".into(),
			));
		}
		if config
			.classification_rules
			.iter()
			.any(|rule| rule.id.trim().is_empty() || rule.pattern.trim().is_empty())
		{
			return Err(IngestionError::InvalidConfig(
				"classificationRules must have non-empty id and pattern values".into(),
			));
		}
		let mut rule_ids = std::collections::HashSet::new();
		if config
			.classification_rules
			.iter()
			.any(|rule| !rule_ids.insert(rule.id.as_str()))
		{
			return Err(IngestionError::InvalidConfig(
				"classificationRules ids must be unique".into(),
			));
		}
		Ok(Self {
			backend,
			pipeline,
			config,
			audit,
		})
	}

	pub async fn ingest(
		&self,
		request_id: impl Into<String>,
		identity: GatewayIdentity,
		request: DocumentIngestRequest,
	) -> Result<IngestionResult, IngestionError> {
		let source_scheme = source_scheme(&request.source_uri);
		let content_bytes = request.content.len();
		let source_hash = hex::encode(Sha256::digest(request.content.as_bytes()));
		let action = knowledge_ingest_for_identity(request_id, identity, request.document_id.clone());
		let Some(tenant_id) = action.subject.tenant_id.clone() else {
			return self.deny(
				&action,
				&request,
				source_scheme,
				Some(source_hash),
				content_bytes,
				Vec::new(),
				Vec::new(),
				IngestionError::MissingTenant,
			);
		};
		let Some(source_scheme) = source_scheme else {
			return self.deny(
				&action,
				&request,
				None,
				Some(source_hash),
				content_bytes,
				Vec::new(),
				Vec::new(),
				IngestionError::InvalidSource("source URI must include a scheme".into()),
			);
		};
		if !self
			.config
			.allowed_source_schemes
			.iter()
			.any(|allowed| allowed.eq_ignore_ascii_case(&source_scheme))
		{
			return self.deny(
				&action,
				&request,
				Some(source_scheme),
				Some(source_hash),
				content_bytes,
				Vec::new(),
				Vec::new(),
				IngestionError::InvalidSource("source URI scheme is not allowed".into()),
			);
		}
		if let SourceOrigin::TrustedHttps { version, .. } = &request.origin {
			if source_scheme != "https" || version != &source_hash {
				return self.deny(
					&action,
					&request,
					Some(source_scheme),
					Some(source_hash),
					content_bytes,
					Vec::new(),
					Vec::new(),
					IngestionError::InvalidSource(
						"trusted source version must equal the SHA-256 hash of fetched content".into(),
					),
				);
			}
		}
		if content_bytes > self.config.max_document_bytes {
			return self.deny(
				&action,
				&request,
				Some(source_scheme),
				Some(source_hash),
				content_bytes,
				Vec::new(),
				Vec::new(),
				IngestionError::DocumentTooLarge {
					bytes: content_bytes,
					maximum: self.config.max_document_bytes,
				},
			);
		}
		let arguments = serde_json::json!({
			"corpusId": request.corpus_id,
			"sourceScheme": source_scheme,
			"sourceHash": source_hash,
			"contentBytes": content_bytes,
		});
		if let Err(error) = self.pipeline.authorize(&action, Some(&arguments)) {
			return self.deny(
				&action,
				&request,
				Some(source_scheme),
				Some(source_hash),
				content_bytes,
				Vec::new(),
				Vec::new(),
				IngestionError::GatewayDenied(error),
			);
		}

		let labels = self.classify_labels(&request.content);
		let (classification, classification_source) = self.classify(&request.content);
		let findings = self.quarantine_findings(&request.content);
		let document = IndexedDocument {
			corpus_id: request.corpus_id.clone(),
			document_id: request.document_id.clone(),
			tenant_id,
			source_uri: request.source_uri.clone(),
			source_hash: source_hash.clone(),
			source_origin: request.origin.clone(),
			content: request.content.clone(),
			labels: labels.clone(),
			classification,
			classification_source: classification_source.clone(),
		};
		if findings.is_empty() {
			self
				.backend
				.index(document.clone())
				.await
				.map_err(IngestionError::Backend)?;
			self.record(
				&action,
				&request.corpus_id,
				Some(source_scheme),
				Some(source_hash),
				content_bytes,
				labels,
				classification,
				classification_source.clone(),
				request.origin.clone(),
				Vec::new(),
				IngestionAuditOutcome::Indexed,
				None,
			);
			Ok(IngestionResult::Indexed(document))
		} else {
			let quarantined = QuarantinedDocument { document, findings };
			self
				.backend
				.quarantine(quarantined.clone())
				.await
				.map_err(IngestionError::Backend)?;
			self.record(
				&action,
				&request.corpus_id,
				Some(source_scheme),
				Some(source_hash),
				content_bytes,
				labels,
				classification,
				classification_source,
				request.origin.clone(),
				quarantined.findings.clone(),
				IngestionAuditOutcome::Quarantined,
				None,
			);
			Ok(IngestionResult::Quarantined(quarantined))
		}
	}

	fn classify_labels(&self, content: &str) -> Vec<String> {
		let normalized = content.to_lowercase();
		self
			.config
			.label_rules
			.iter()
			.filter(|rule| normalized.contains(&rule.pattern.to_lowercase()))
			.map(|rule| rule.label.clone())
			.collect()
	}

	fn classify(&self, content: &str) -> (DataClassification, String) {
		let normalized = content.to_lowercase();
		let mut classification = self.config.default_classification;
		let mut source = "default-classification".to_string();
		for rule in &self.config.classification_rules {
			if rule.classification > classification && normalized.contains(&rule.pattern.to_lowercase()) {
				classification = rule.classification;
				source = format!("rule:{}", rule.id);
			}
		}
		(classification, source)
	}

	fn quarantine_findings(&self, content: &str) -> Vec<IngestionFinding> {
		let normalized = content.to_lowercase();
		self
			.config
			.quarantine_patterns
			.iter()
			.enumerate()
			.filter(|(_, pattern)| normalized.contains(&pattern.to_lowercase()))
			.map(|(index, _)| IngestionFinding {
				kind: IngestionFindingKind::QuarantinePattern,
				rule_id: format!("quarantine-pattern-{index}"),
			})
			.collect()
	}

	#[allow(clippy::too_many_arguments)]
	fn deny<T>(
		&self,
		action: &security_types::ActionRequest,
		request: &DocumentIngestRequest,
		source_scheme: Option<String>,
		source_hash: Option<String>,
		content_bytes: usize,
		labels: Vec<String>,
		findings: Vec<IngestionFinding>,
		error: IngestionError,
	) -> Result<T, IngestionError> {
		self.record(
			action,
			&request.corpus_id,
			source_scheme,
			source_hash,
			content_bytes,
			labels,
			self.config.default_classification,
			"default-classification".into(),
			request.origin.clone(),
			findings,
			IngestionAuditOutcome::Denied,
			Some(format!("{error:?}")),
		);
		let _ = request;
		Err(error)
	}

	#[allow(clippy::too_many_arguments)]
	fn record(
		&self,
		action: &security_types::ActionRequest,
		corpus_id: &str,
		source_scheme: Option<String>,
		source_hash: Option<String>,
		content_bytes: usize,
		labels: Vec<String>,
		classification: DataClassification,
		classification_source: String,
		source_origin: SourceOrigin,
		findings: Vec<IngestionFinding>,
		outcome: IngestionAuditOutcome,
		reason: Option<String>,
	) {
		self.audit.record(IngestionAuditEvent {
			request_id: action.request_id.clone(),
			corpus_id: corpus_id.to_string(),
			document_id: action.resource.id.clone(),
			tenant_id: action.subject.tenant_id.clone(),
			source_scheme,
			source_hash,
			content_bytes,
			labels,
			classification,
			classification_source,
			source_origin,
			findings,
			outcome,
			reason,
			timestamp: Utc::now(),
		});
	}
}

fn source_scheme(source_uri: &str) -> Option<String> {
	let (scheme, remainder) = source_uri.split_once(':')?;
	(!scheme.is_empty()
		&& !remainder.is_empty()
		&& scheme
			.chars()
			.all(|character| character.is_ascii_alphanumeric() || matches!(character, '+' | '-' | '.')))
	.then(|| scheme.to_ascii_lowercase())
}

#[cfg(test)]
mod tests {
	use security_audit::InMemoryAuditSink;
	use security_pipeline::PolicyAuthorizer;
	use security_policy::Policy;
	use security_types::{ActionType, DecisionEffect, ResourceType};

	use super::*;

	#[derive(Default)]
	struct RecordingBackend {
		indexed: Mutex<Vec<IndexedDocument>>,
		quarantined: Mutex<Vec<QuarantinedDocument>>,
	}

	#[async_trait::async_trait]
	impl DocumentIngestBackend for RecordingBackend {
		async fn index(&self, document: IndexedDocument) -> Result<(), String> {
			self.indexed.lock().unwrap().push(document);
			Ok(())
		}

		async fn quarantine(&self, document: QuarantinedDocument) -> Result<(), String> {
			self.quarantined.lock().unwrap().push(document);
			Ok(())
		}
	}

	fn identity() -> GatewayIdentity {
		GatewayIdentity {
			user_id: Some("alice".into()),
			agent_id: Some("knowledge-curator".into()),
			tenant_id: Some("tenant-a".into()),
			delegation_id: None,
			session_id: None,
			client_id: None,
		}
	}

	fn allow_ingestion_policy() -> Policy {
		Policy {
			id: "allow-support-document-ingest".into(),
			priority: 0,
			tenant_id: Some("tenant-a".into()),
			user_id: Some("alice".into()),
			agent_id: Some("knowledge-curator".into()),
			action_type: Some(ActionType::KnowledgeIngest),
			action_name: Some("ingest".into()),
			resource_id: Some("password-guide".into()),
			resource_type: Some(ResourceType::Document),
			effect: DecisionEffect::Allow,
			enabled: true,
		}
	}

	fn request(content: &str) -> DocumentIngestRequest {
		DocumentIngestRequest::new(
			"support-corpus",
			"password-guide",
			"https://kb.example.com/password-guide",
			content,
		)
	}

	#[tokio::test]
	async fn authorized_document_is_labeled_and_indexed() {
		let backend = RecordingBackend::default();
		let gateway_audit = InMemoryAuditSink::default();
		let ingestion_audit = InMemoryIngestionAuditSink::default();
		let pipeline = SecurityPipeline::new(
			PolicyAuthorizer::new(vec![allow_ingestion_policy()]),
			&gateway_audit,
		);
		let ingestor = SecureIngestor::new(
			backend,
			pipeline,
			IngestionGuardConfig {
				label_rules: vec![ContentLabelRule {
					label: "pii".into(),
					pattern: "customer email".into(),
				}],
				..Default::default()
			},
			&ingestion_audit,
		)
		.unwrap();

		let result = ingestor
			.ingest(
				"ingest-request-1",
				identity(),
				request("Customer email is used for password recovery."),
			)
			.await
			.unwrap();
		let IngestionResult::Indexed(document) = result else {
			panic!("expected indexed document");
		};
		assert_eq!(document.labels, ["pii"]);
		assert_eq!(ingestor.backend.indexed.lock().unwrap().len(), 1);
		assert!(ingestor.backend.quarantined.lock().unwrap().is_empty());
		let event = ingestion_audit.events().pop().unwrap();
		assert_eq!(event.outcome, IngestionAuditOutcome::Indexed);
		assert_eq!(event.corpus_id, "support-corpus");
		assert_eq!(event.labels, ["pii"]);
		assert!(!event.source_hash.unwrap().contains("Customer"));
	}

	#[tokio::test]
	async fn trusted_source_version_must_match_fetched_content_hash() {
		let backend = RecordingBackend::default();
		let gateway_audit = InMemoryAuditSink::default();
		let ingestion_audit = InMemoryIngestionAuditSink::default();
		let pipeline = SecurityPipeline::new(
			PolicyAuthorizer::new(vec![allow_ingestion_policy()]),
			&gateway_audit,
		);
		let ingestor = SecureIngestor::new(
			backend,
			pipeline,
			IngestionGuardConfig::default(),
			&ingestion_audit,
		)
		.unwrap();
		let request = DocumentIngestRequest::from_trusted_https(
			"support-corpus",
			"password-guide",
			"https://kb.example.com/password-guide",
			"fetched bytes",
			"support-kb",
			"00".repeat(32),
		);
		let result = ingestor
			.ingest("ingest-request-trusted-mismatch", identity(), request)
			.await;
		assert!(matches!(result, Err(IngestionError::InvalidSource(_))));
		assert!(ingestor.backend.indexed.lock().unwrap().is_empty());
		assert_eq!(
			ingestion_audit.events()[0].outcome,
			IngestionAuditOutcome::Denied
		);

		let version = hex::encode(Sha256::digest(b"fetched bytes"));
		let valid = DocumentIngestRequest::from_trusted_https(
			"support-corpus",
			"password-guide",
			"https://kb.example.com/password-guide",
			"fetched bytes",
			"support-kb",
			version.clone(),
		);
		let result = ingestor
			.ingest("ingest-request-trusted-valid", identity(), valid)
			.await
			.unwrap();
		let IngestionResult::Indexed(document) = result else {
			panic!("expected trusted source to be indexed");
		};
		assert_eq!(document.source_hash, version);
		assert_eq!(
			document.source_origin,
			SourceOrigin::TrustedHttps {
				source_id: "support-kb".into(),
				version,
			}
		);
		assert_eq!(ingestor.backend.indexed.lock().unwrap().len(), 1);
		assert_eq!(
			ingestion_audit.events()[1].source_origin,
			document.source_origin
		);
	}

	#[test]
	fn failed_source_fetch_is_audited_without_content_or_source_url() {
		let backend = RecordingBackend::default();
		let gateway_audit = InMemoryAuditSink::default();
		let ingestion_audit = InMemoryIngestionAuditSink::default();
		let pipeline = SecurityPipeline::new(
			PolicyAuthorizer::new(vec![allow_ingestion_policy()]),
			&gateway_audit,
		);
		let ingestor = SecureIngestor::new(
			backend,
			pipeline,
			IngestionGuardConfig::default(),
			&ingestion_audit,
		)
		.unwrap();
		ingestor.record_source_fetch_failure(
			"fetch-failed",
			identity(),
			"support-corpus",
			"password-guide",
			"kb",
		);
		let event = ingestion_audit.events().pop().unwrap();
		assert_eq!(event.outcome, IngestionAuditOutcome::Denied);
		assert_eq!(event.source_hash, None);
		assert_eq!(event.content_bytes, 0);
		assert_eq!(event.reason.as_deref(), Some("trusted_source_fetch_failed"));
		assert_eq!(
			event.source_origin,
			SourceOrigin::TrustedHttpsFetchAttempt {
				source_id: "kb".into(),
			}
		);
		assert!(ingestor.backend.indexed.lock().unwrap().is_empty());
	}

	#[tokio::test]
	async fn risky_document_is_quarantined_not_indexed() {
		let backend = RecordingBackend::default();
		let gateway_audit = InMemoryAuditSink::default();
		let ingestion_audit = InMemoryIngestionAuditSink::default();
		let pipeline = SecurityPipeline::new(
			PolicyAuthorizer::new(vec![allow_ingestion_policy()]),
			&gateway_audit,
		);
		let ingestor = SecureIngestor::new(
			backend,
			pipeline,
			IngestionGuardConfig::default(),
			&ingestion_audit,
		)
		.unwrap();

		let result = ingestor
			.ingest(
				"ingest-request-2",
				identity(),
				request("-----BEGIN PRIVATE KEY----- secret"),
			)
			.await
			.unwrap();
		assert!(matches!(result, IngestionResult::Quarantined(_)));
		assert!(ingestor.backend.indexed.lock().unwrap().is_empty());
		assert_eq!(ingestor.backend.quarantined.lock().unwrap().len(), 1);
		let event = ingestion_audit.events().pop().unwrap();
		assert_eq!(event.outcome, IngestionAuditOutcome::Quarantined);
		assert_eq!(event.findings[0].rule_id, "quarantine-pattern-0");
	}

	#[test]
	fn chunks_inherit_document_tenant_labels_and_provenance() {
		let document = IndexedDocument {
			corpus_id: "support-corpus".into(),
			document_id: "password-guide".into(),
			tenant_id: "tenant-a".into(),
			source_uri: "https://kb.example.com/password-guide".into(),
			source_hash: "immutable-source-hash".into(),
			source_origin: SourceOrigin::Submitted,
			content: "source content".into(),
			labels: vec!["pii".into(), "internal".into()],
			classification: DataClassification::Internal,
			classification_source: "default-classification".into(),
		};

		let chunk = document.to_chunk(
			"password-guide:0",
			"password reset instructions",
			42,
			TrustedChunkAccess {
				allowed_users: vec!["alice".into()],
				..Default::default()
			},
		);
		assert_eq!(chunk.corpus_id, "support-corpus");
		assert_eq!(chunk.tenant_id, "tenant-a");
		assert_eq!(chunk.labels, ["pii", "internal"]);
		assert_eq!(chunk.classification, DataClassification::Internal);
		assert_eq!(chunk.classification_source, "default-classification");
		assert_eq!(chunk.source_hash, "immutable-source-hash");
		assert_eq!(chunk.allowed_users, ["alice"]);
	}

	#[tokio::test]
	async fn denied_document_never_reaches_index_or_quarantine() {
		let backend = RecordingBackend::default();
		let gateway_audit = InMemoryAuditSink::default();
		let ingestion_audit = InMemoryIngestionAuditSink::default();
		let pipeline = SecurityPipeline::new(PolicyAuthorizer::new(Vec::new()), &gateway_audit);
		let ingestor = SecureIngestor::new(
			backend,
			pipeline,
			IngestionGuardConfig::default(),
			&ingestion_audit,
		)
		.unwrap();

		let error = ingestor
			.ingest("ingest-request-3", identity(), request("benign document"))
			.await
			.unwrap_err();
		assert!(matches!(error, IngestionError::GatewayDenied(_)));
		assert!(ingestor.backend.indexed.lock().unwrap().is_empty());
		assert!(ingestor.backend.quarantined.lock().unwrap().is_empty());
		assert_eq!(
			ingestion_audit.events()[0].outcome,
			IngestionAuditOutcome::Denied
		);
	}
}
