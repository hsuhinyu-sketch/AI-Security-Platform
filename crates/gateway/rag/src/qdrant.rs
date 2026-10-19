//! Qdrant implementation of the RAG backend traits.
//!
//! The caller injects a `reqwest::Client`, so deployment code can require mTLS, custom CA roots,
//! proxies, and timeouts without coupling those transport details to RAG security semantics.

use std::sync::Arc;

use chrono::{DateTime, Utc};
use reqwest::Client;
use security_integrity::{IntegrityKey, IntegrityProof};
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
	/// When set, every stored Chunk must carry a valid MAC over the complete payload.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub integrity: Option<MetadataIntegrityConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MetadataIntegrityConfig {
	pub key_id: String,
	/// Name of an environment variable containing at least 32 random secret bytes as hex.
	pub key_env_var: String,
}

/// Async REST backend using Qdrant's points upsert and query endpoints.
pub struct QdrantBackend<E, C> {
	client: Client,
	config: QdrantBackendConfig,
	embeddings: E,
	chunker: C,
	integrity: Option<IntegrityKey>,
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
		let integrity = match &config.integrity {
			Some(integrity) => {
				if integrity.key_env_var.is_empty()
					|| !integrity
						.key_env_var
						.chars()
						.all(|character| character.is_ascii_alphanumeric() || character == '_')
				{
					return Err("Qdrant integrity keyEnvVar must be an environment variable name".into());
				}
				let secret = std::env::var(&integrity.key_env_var).map_err(|_| {
					format!(
						"Qdrant integrity key environment variable '{}' is unavailable",
						integrity.key_env_var
					)
				})?;
				Some(IntegrityKey::from_hex(integrity.key_id.clone(), &secret)?)
			},
			None => None,
		};
		Ok(Self {
			client,
			config,
			embeddings,
			chunker,
			integrity,
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
			let mut payload = qdrant_payload(&chunk, &quarantine_rule_ids);
			if let Some(key) = &self.integrity {
				let proof = key.sign_json("rag-qdrant-chunk", &payload)?;
				payload["integrity"] = serde_json::to_value(proof)
					.map_err(|error| format!("cannot encode integrity proof: {error}"))?;
			}
			points.push(json!({
				"id": chunk.id,
				"vector": vector,
				"payload": payload,
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
		let response_body = crate::config::read_bounded_response(response, 4 * 1024 * 1024).await?;
		let response: QdrantQueryResponse = serde_json::from_slice(&response_body)
			.map_err(|error| format!("invalid Qdrant query response: {error}"))?;
		response
			.result
			.points
			.into_iter()
			.map(|point| verified_chunk_from_payload(point.id, point.payload, self.integrity.as_ref()))
			.collect()
	}
}

#[async_trait::async_trait]
impl<E: Send + Sync, C: Send + Sync> security_rag::lifecycle::DocumentPurger
	for QdrantBackend<E, C>
{
	async fn purge_document(&self, key: &security_types::DocumentKey) -> Result<(), String> {
		key.validate()?;
		let filter = json!({"must":[{"key":"tenantId","match":{"value":key.tenant_id}},{"key":"corpusId","match":{"value":key.corpus_id}},{"key":"documentId","match":{"value":key.document_id}}]});
		for collection in [&self.config.collection, &self.config.quarantine_collection] {
			let mut response = self
				.request(
					reqwest::Method::POST,
					format!("{}?wait=true", self.endpoint(collection, "/delete")),
				)
				.json(&json!({"filter":filter}))
				.send()
				.await
				.map_err(|_| "document purge transport failed")?;
			if !response.status().is_success() {
				return Err("document purge not confirmed".into());
			}
			let mut bytes = Vec::new();
			while let Some(chunk) = response
				.chunk()
				.await
				.map_err(|_| "document purge response unavailable")?
			{
				if bytes.len().saturating_add(chunk.len()) > 16384 {
					return Err("document purge response exceeds limit".into());
				}
				bytes.extend_from_slice(&chunk);
			}
			let result: Value =
				serde_json::from_slice(&bytes).map_err(|_| "invalid document purge acknowledgement")?;
			if result.pointer("/result/status").and_then(Value::as_str) != Some("completed") {
				return Err("document purge not completed".into());
			}
		}
		Ok(())
	}
}

fn verified_chunk_from_payload(
	point_id: Value,
	mut payload: Value,
	key: Option<&IntegrityKey>,
) -> Result<KnowledgeChunk, String> {
	if let Some(key) = key {
		let proof = payload
			.as_object_mut()
			.and_then(|fields| fields.remove("integrity"))
			.ok_or_else(|| "Qdrant chunk has no integrity proof".to_string())?;
		let proof: IntegrityProof =
			serde_json::from_value(proof).map_err(|_| "invalid Qdrant integrity proof".to_string())?;
		key.verify_json("rag-qdrant-chunk", &payload, &proof)?;
	}
	let payload_chunk_id = payload
		.get("chunkId")
		.and_then(Value::as_str)
		.ok_or_else(|| "Qdrant point payload is missing string 'chunkId'".to_string())?;
	let point_id = point_id
		.as_str()
		.ok_or_else(|| "Qdrant point id must be a string".to_string())?;
	if payload_chunk_id != point_id {
		return Err("Qdrant point id does not match signed chunkId".into());
	}
	chunk_from_payload(Value::String(point_id.to_string()), payload)
}

fn qdrant_payload(chunk: &KnowledgeChunk, quarantine_rule_ids: &[String]) -> Value {
	json!({
		"chunkId": chunk.id,
		"documentId": chunk.document_id,
		"corpusId": chunk.corpus_id,
		"tenantId": chunk.tenant_id,
		"content": chunk.content,
		"labels": chunk.labels,
		"classification": chunk.classification,
		"classificationSource": chunk.classification_source,
		"allowedUsers": chunk.allowed_users,
		"allowedAgents": chunk.allowed_agents,
		"allowTenantAuthenticated": chunk.allow_tenant_authenticated,
		"expiresAt": chunk.expires_at.as_ref().map(DateTime::to_rfc3339),
		"sourceHash": chunk.source_hash,
		"sourceOrigin": chunk.source_origin,
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
	if filter.authoritative_acl {
		return json!({"must":[{"key":"corpusId","match":{"value":filter.corpus_id}},{"key":"tenantId","match":{"value":filter.tenant_id}}]});
	}
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
	let classification_source = object
		.get("classificationSource")
		.and_then(Value::as_str)
		.filter(|source| !source.is_empty())
		.unwrap_or("legacy-unverified")
		.to_string();
	let classification = if classification_source == "legacy-unverified" {
		security_rag::DataClassification::Restricted
	} else {
		object
			.get("classification")
			.map(|value| {
				serde_json::from_value(value.clone())
					.map_err(|_| "invalid Qdrant classification".to_string())
			})
			.transpose()?
			.unwrap_or_default()
	};
	Ok(KnowledgeChunk {
		id: chunk_id,
		document_id: string("documentId")?,
		corpus_id: string("corpusId")?,
		tenant_id: string("tenantId")?,
		content: string("content")?,
		labels: strings("labels")?,
		classification,
		classification_source,
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
		source_origin: object
			.get("sourceOrigin")
			.map(|value| {
				serde_json::from_value(value.clone())
					.map_err(|_| "invalid Qdrant source origin".to_string())
			})
			.transpose()?
			.unwrap_or_default(),
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
