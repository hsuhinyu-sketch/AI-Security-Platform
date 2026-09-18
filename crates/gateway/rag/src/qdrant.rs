//! Qdrant implementation of the RAG backend traits.
//!
//! The caller injects a `reqwest::Client`, so deployment code can require mTLS, custom CA roots,
//! proxies, and timeouts without coupling those transport details to RAG security semantics.

use std::sync::Arc;

use chrono::{DateTime, Utc};
use reqwest::Client;
use security_rag::{
	DocumentIngestBackend, IndexedDocument, KnowledgeChunk, QuarantinedDocument, RetrievalBackend,
	RetrievalFilter, RetrievalQuery, TrustedChunkAccess,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

/// Converts document and query text into the dense vector used by the pre-provisioned Qdrant
/// collection. The embedding service is intentionally outside the vector adapter: deployments can
/// select edge, cloud, or local inference without changing retrieval authorization.
#[async_trait::async_trait]
pub trait EmbeddingProvider: Send + Sync {
	async fn embed(&self, text: &str) -> Result<Vec<f32>, String>;
}

#[async_trait::async_trait]
impl<T: EmbeddingProvider + ?Sized> EmbeddingProvider for Arc<T> {
	async fn embed(&self, text: &str) -> Result<Vec<f32>, String> {
		(**self).embed(text).await
	}
}

/// Trusted document splitter. Every implementation must build Chunks with
/// `IndexedDocument::to_chunk`, preserving ingestion-time Tenant, labels, and provenance.
pub trait DocumentChunker: Send + Sync {
	fn split(
		&self,
		document: &IndexedDocument,
		access: &TrustedChunkAccess,
	) -> Result<Vec<KnowledgeChunk>, String>;
}

/// Deterministic UTF-8-safe fixed-window splitter for the first provider implementation. It is
/// deliberately small; semantic splitters can implement the same trait without altering security
/// metadata propagation.
#[derive(Debug, Clone)]
pub struct FixedWindowChunker {
	max_chars: usize,
}

impl FixedWindowChunker {
	pub fn new(max_chars: usize) -> Result<Self, String> {
		if max_chars == 0 {
			return Err("max chunk characters must be greater than zero".into());
		}
		Ok(Self { max_chars })
	}
}

impl DocumentChunker for FixedWindowChunker {
	fn split(
		&self,
		document: &IndexedDocument,
		access: &TrustedChunkAccess,
	) -> Result<Vec<KnowledgeChunk>, String> {
		if document.content.trim().is_empty() {
			return Err("document content must not be empty".into());
		}
		let characters = document.content.chars().collect::<Vec<_>>();
		let mut chunks = Vec::new();
		let mut start = 0;
		while start < characters.len() {
			let mut end = (start + self.max_chars).min(characters.len());
			if end < characters.len()
				&& let Some(relative_break) = characters[start..end]
					.iter()
					.rposition(|character| character.is_whitespace())
					.filter(|relative_break| *relative_break > 0)
			{
				end = start + relative_break;
			}
			let content = characters[start..end].iter().collect::<String>();
			let token_count = content.split_whitespace().count() as u64;
			chunks.push(document.to_chunk(
				format!("{}:{start}", document.document_id),
				content,
				token_count.max(1),
				access.clone(),
			));
			start = end;
		}
		Ok(chunks)
	}
}

/// Qdrant collection configuration. The primary and quarantine collections must be provisioned
/// with the selected vector dimension. Create keyword payload indexes for `tenantId`, `corpusId`,
/// `allowedUsers`, and `allowedAgents` before loading production data.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct QdrantBackendConfig {
	pub endpoint: String,
	pub collection: String,
	pub quarantine_collection: String,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub api_key: Option<String>,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub vector_name: Option<String>,
	/// ACL assigned by the trusted ingestion controller to chunks from this backend.
	#[serde(default)]
	pub default_chunk_access: TrustedChunkAccess,
}

/// Async REST backend using Qdrant's points upsert and query endpoints.
pub struct QdrantBackend<E, C> {
	client: Client,
	config: QdrantBackendConfig,
	embeddings: E,
	chunker: C,
}

impl<E, C> QdrantBackend<E, C> {
	pub fn new(
		client: Client,
		config: QdrantBackendConfig,
		embeddings: E,
		chunker: C,
	) -> Result<Self, String> {
		if !(config.endpoint.starts_with("https://") || config.endpoint.starts_with("http://")) {
			return Err("Qdrant endpoint must use http or https".into());
		}
		if !valid_collection_name(&config.collection)
			|| !valid_collection_name(&config.quarantine_collection)
		{
			return Err(
				"Qdrant collection names may contain only letters, digits, '_', '-', and '.'".into(),
			);
		}
		Ok(Self {
			client,
			config,
			embeddings,
			chunker,
		})
	}

	fn endpoint(&self, collection: &str, suffix: &str) -> String {
		format!(
			"{}/collections/{collection}/points{suffix}",
			self.config.endpoint.trim_end_matches('/')
		)
	}

	fn request(&self, method: reqwest::Method, url: String) -> reqwest::RequestBuilder {
		let request = self.client.request(method, url);
		match &self.config.api_key {
			Some(api_key) => request.header("api-key", api_key),
			None => request,
		}
	}

	async fn upsert(
		&self,
		collection: &str,
		chunks: Vec<KnowledgeChunk>,
		quarantine_rule_ids: Vec<String>,
	) -> Result<(), String>
	where
		E: EmbeddingProvider,
	{
		let mut points = Vec::with_capacity(chunks.len());
		for chunk in chunks {
			let vector = self.embeddings.embed(&chunk.content).await?;
			if vector.is_empty() {
				return Err("embedding provider returned an empty vector".into());
			}
			let vector = qdrant_vector(vector, self.config.vector_name.as_deref());
			points.push(json!({
				"id": chunk.id,
				"vector": vector,
				"payload": qdrant_payload(&chunk, &quarantine_rule_ids),
			}));
		}
		let body = serde_json::to_vec(&json!({ "points": points }))
			.map_err(|error| format!("failed to serialize Qdrant upsert request: {error}"))?;
		let response = self
			.request(
				reqwest::Method::PUT,
				format!("{}?wait=true", self.endpoint(collection, "")),
			)
			.header(reqwest::header::CONTENT_TYPE, "application/json")
			.body(body)
			.send()
			.await
			.map_err(|error| format!("Qdrant upsert request failed: {error}"))?;
		if response.status().is_success() {
			Ok(())
		} else {
			Err(format!(
				"Qdrant upsert failed with HTTP {}",
				response.status()
			))
		}
	}
}

#[async_trait::async_trait]
impl<E, C> DocumentIngestBackend for QdrantBackend<E, C>
where
	E: EmbeddingProvider,
	C: DocumentChunker,
{
	async fn index(&self, document: IndexedDocument) -> Result<(), String> {
		let chunks = self
			.chunker
			.split(&document, &self.config.default_chunk_access)?;
		self
			.upsert(&self.config.collection, chunks, Vec::new())
			.await
	}

	async fn quarantine(&self, document: QuarantinedDocument) -> Result<(), String> {
		let chunks = self
			.chunker
			.split(&document.document, &self.config.default_chunk_access)?;
		let rule_ids = document
			.findings
			.into_iter()
			.map(|finding| finding.rule_id)
			.collect();
		self
			.upsert(&self.config.quarantine_collection, chunks, rule_ids)
			.await
	}
}

#[async_trait::async_trait]
impl<E, C> RetrievalBackend for QdrantBackend<E, C>
where
	E: EmbeddingProvider,
	C: Send + Sync,
{
	async fn retrieve(
		&self,
		query: &RetrievalQuery,
		filter: &RetrievalFilter,
	) -> Result<Vec<KnowledgeChunk>, String> {
		let vector = self.embeddings.embed(query.text()).await?;
		if vector.is_empty() {
			return Err("embedding provider returned an empty vector".into());
		}
		let mut body = json!({
			"query": vector,
			"limit": filter.max_candidates,
			"filter": qdrant_filter(filter),
			"with_payload": true,
			"with_vector": false,
		});
		if let Some(vector_name) = &self.config.vector_name {
			body["using"] = Value::String(vector_name.clone());
		}
		let body = serde_json::to_vec(&body)
			.map_err(|error| format!("failed to serialize Qdrant query request: {error}"))?;
		let response = self
			.request(
				reqwest::Method::POST,
				self.endpoint(&self.config.collection, "/query"),
			)
			.header(reqwest::header::CONTENT_TYPE, "application/json")
			.body(body)
			.send()
			.await
			.map_err(|error| format!("Qdrant query request failed: {error}"))?;
		if !response.status().is_success() {
			return Err(format!(
				"Qdrant query failed with HTTP {}",
				response.status()
			));
		}
		let response_body = response
			.bytes()
			.await
			.map_err(|error| format!("failed to read Qdrant query response: {error}"))?;
		let response: QdrantQueryResponse = serde_json::from_slice(&response_body)
			.map_err(|error| format!("invalid Qdrant query response: {error}"))?;
		response
			.result
			.points
			.into_iter()
			.map(|point| chunk_from_payload(point.id, point.payload))
			.collect()
	}
}

fn qdrant_payload(chunk: &KnowledgeChunk, quarantine_rule_ids: &[String]) -> Value {
	json!({
		"chunkId": chunk.id,
		"documentId": chunk.document_id,
		"corpusId": chunk.corpus_id,
		"tenantId": chunk.tenant_id,
		"content": chunk.content,
		"labels": chunk.labels,
		"allowedUsers": chunk.allowed_users,
		"allowedAgents": chunk.allowed_agents,
		"allowTenantAuthenticated": chunk.allow_tenant_authenticated,
		"expiresAt": chunk.expires_at.as_ref().map(DateTime::to_rfc3339),
		"sourceHash": chunk.source_hash,
		"tokenCount": chunk.token_count,
		"quarantineRuleIds": quarantine_rule_ids,
	})
}

fn qdrant_vector(vector: Vec<f32>, vector_name: Option<&str>) -> Value {
	match vector_name {
		Some(vector_name) => json!({ vector_name: vector }),
		None => json!(vector),
	}
}

fn qdrant_filter(filter: &RetrievalFilter) -> Value {
	let mut acl_conditions = vec![json!({
		"key": "allowTenantAuthenticated",
		"match": { "value": true },
	})];
	if let Some(user_id) = &filter.user_id {
		acl_conditions.push(json!({
			"key": "allowedUsers",
			"match": { "value": user_id },
		}));
	}
	if let Some(agent_id) = &filter.agent_id {
		acl_conditions.push(json!({
			"key": "allowedAgents",
			"match": { "value": agent_id },
		}));
	}
	json!({
		"must": [
			{ "key": "corpusId", "match": { "value": filter.corpus_id } },
			{ "key": "tenantId", "match": { "value": filter.tenant_id } },
		],
		"min_should": {
			"conditions": acl_conditions,
			"min_count": 1,
		},
	})
}

#[derive(Deserialize)]
struct QdrantQueryResponse {
	result: QdrantQueryResult,
}

#[derive(Deserialize)]
struct QdrantQueryResult {
	points: Vec<QdrantPoint>,
}

#[derive(Deserialize)]
struct QdrantPoint {
	id: Value,
	payload: Value,
}

fn chunk_from_payload(point_id: Value, payload: Value) -> Result<KnowledgeChunk, String> {
	let object = payload
		.as_object()
		.ok_or_else(|| "Qdrant point payload must be an object".to_string())?;
	let string = |key: &str| {
		object
			.get(key)
			.and_then(Value::as_str)
			.map(str::to_string)
			.ok_or_else(|| format!("Qdrant point payload is missing string '{key}'"))
	};
	let strings = |key: &str| -> Result<Vec<String>, String> {
		object
			.get(key)
			.and_then(Value::as_array)
			.ok_or_else(|| format!("Qdrant point payload is missing array '{key}'"))?
			.iter()
			.map(|value| {
				value
					.as_str()
					.map(str::to_string)
					.ok_or_else(|| format!("Qdrant point payload field '{key}' contains a non-string"))
			})
			.collect()
	};
	let chunk_id = object
		.get("chunkId")
		.and_then(Value::as_str)
		.map(str::to_string)
		.or_else(|| point_id.as_str().map(str::to_string))
		.ok_or_else(|| "Qdrant point has no string id or chunkId".to_string())?;
	let expires_at = match object.get("expiresAt") {
		Some(Value::String(value)) => Some(
			DateTime::parse_from_rfc3339(value)
				.map_err(|error| format!("invalid expiresAt in Qdrant payload: {error}"))?
				.with_timezone(&Utc),
		),
		Some(Value::Null) | None => None,
		Some(_) => return Err("Qdrant point payload expiresAt must be string or null".into()),
	};
	Ok(KnowledgeChunk {
		id: chunk_id,
		document_id: string("documentId")?,
		corpus_id: string("corpusId")?,
		tenant_id: string("tenantId")?,
		content: string("content")?,
		labels: strings("labels")?,
		allowed_users: strings("allowedUsers")?,
		allowed_agents: strings("allowedAgents")?,
		allow_tenant_authenticated: object
			.get("allowTenantAuthenticated")
			.and_then(Value::as_bool)
			.ok_or_else(|| {
				"Qdrant point payload is missing bool 'allowTenantAuthenticated'".to_string()
			})?,
		expires_at,
		source_hash: string("sourceHash")?,
		token_count: object
			.get("tokenCount")
			.and_then(Value::as_u64)
			.ok_or_else(|| "Qdrant point payload is missing unsigned 'tokenCount'".to_string())?,
	})
}

fn valid_collection_name(value: &str) -> bool {
	!value.is_empty()
		&& value
			.chars()
			.all(|character| character.is_ascii_alphanumeric() || matches!(character, '_' | '-' | '.'))
}

#[cfg(test)]
mod tests {
	use security_rag::{IndexedDocument, TrustedChunkAccess};

	use super::*;

	#[test]
	fn fixed_window_chunker_preserves_document_security_metadata() {
		let document = IndexedDocument {
			corpus_id: "support".into(),
			document_id: "password-guide".into(),
			tenant_id: "tenant-a".into(),
			source_uri: "https://kb.example.com/password-guide".into(),
			source_hash: "hash".into(),
			content: "one two three four five six".into(),
			labels: vec!["internal".into()],
		};
		let chunks = FixedWindowChunker::new(8)
			.unwrap()
			.split(
				&document,
				&TrustedChunkAccess {
					allowed_users: vec!["alice".into()],
					..Default::default()
				},
			)
			.unwrap();
		assert!(chunks.len() > 1);
		assert!(chunks.iter().all(|chunk| {
			chunk.corpus_id == "support"
				&& chunk.tenant_id == "tenant-a"
				&& chunk.labels == ["internal"]
				&& chunk.source_hash == "hash"
				&& chunk.allowed_users == ["alice"]
		}));
	}

	#[test]
	fn qdrant_filter_requires_tenant_corpus_and_one_acl_condition() {
		let filter = qdrant_filter(&RetrievalFilter {
			corpus_id: "support".into(),
			tenant_id: "tenant-a".into(),
			user_id: Some("alice".into()),
			agent_id: Some("support-agent".into()),
			max_candidates: 3,
		});
		assert_eq!(filter["must"].as_array().unwrap().len(), 2);
		assert_eq!(filter["min_should"]["min_count"], 1);
		assert_eq!(
			filter["min_should"]["conditions"].as_array().unwrap().len(),
			3
		);
	}

	#[test]
	fn qdrant_payload_round_trip_preserves_security_fields() {
		let chunk = KnowledgeChunk {
			id: "chunk-1".into(),
			document_id: "document-1".into(),
			corpus_id: "support".into(),
			tenant_id: "tenant-a".into(),
			content: "safe text".into(),
			labels: vec!["internal".into()],
			allowed_users: vec!["alice".into()],
			allowed_agents: vec!["support-agent".into()],
			allow_tenant_authenticated: false,
			expires_at: None,
			source_hash: "source-hash".into(),
			token_count: 12,
		};
		let restored =
			chunk_from_payload(Value::String("point-1".into()), qdrant_payload(&chunk, &[])).unwrap();
		assert_eq!(restored, chunk);
	}

	#[test]
	fn named_vector_payload_uses_the_configured_vector_name() {
		let default_vector = qdrant_vector(vec![0.1, 0.2], None);
		assert!(default_vector.is_array());
		assert_eq!(default_vector.as_array().unwrap().len(), 2);
		let named_vector = qdrant_vector(vec![0.1, 0.2], Some("dense"));
		assert_eq!(named_vector.as_object().unwrap().len(), 1);
		assert_eq!(named_vector["dense"].as_array().unwrap().len(), 2);
	}
}
