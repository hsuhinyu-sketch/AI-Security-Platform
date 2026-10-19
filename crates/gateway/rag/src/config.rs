//! Deployment configuration for the standalone RAG gateway surface.
//!
//! Authorization policy and verified identity remain outside this structure: they are shared
//! gateway concerns. This configuration only selects the backing services and RAG-specific
//! safety budgets.

use reqwest::Client;
use serde::{Deserialize, Serialize};

use security_rag::{ContextGuardConfig, IngestionGuardConfig, RagSecurityConfig};

use crate::{EmbeddingProvider, FixedWindowChunker, QdrantBackend, QdrantBackendConfig};
use security_rag::{TrustedHttpsSourceConfig, TrustedHttpsSourceRegistry};

fn default_bind_address() -> String {
	"127.0.0.1".into()
}

fn default_chunk_max_chars() -> usize {
	2_000
}

/// OpenAI-compatible embeddings endpoint. The endpoint is supplied by the deployment, so it can
/// target a local embedding model, an enterprise proxy, or a cloud provider.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct OpenAiCompatibleEmbeddingConfig {
	pub endpoint: String,
	pub model: String,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub api_key: Option<String>,
}

/// A deployment-ready RAG endpoint and backend configuration.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct RagGatewayConfig {
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub lifecycle: Option<security_rag::lifecycle::DocumentLifecycleConfig>,
	#[serde(default = "default_bind_address")]
	pub bind_address: String,
	pub port: u16,
	pub qdrant: QdrantBackendConfig,
	pub embedding: OpenAiCompatibleEmbeddingConfig,
	#[serde(default = "default_chunk_max_chars")]
	pub chunk_max_chars: usize,
	#[serde(default)]
	pub ingestion: IngestionGuardConfig,
	#[serde(default)]
	pub retrieval: RagSecurityConfig,
	#[serde(default)]
	pub context_guard: ContextGuardConfig,
	#[serde(default, skip_serializing_if = "Vec::is_empty")]
	pub trusted_sources: Vec<TrustedHttpsSourceConfig>,
}

impl RagGatewayConfig {
	/// Validates local values before a listener is created or remote credentials are used.
	pub fn validate(&self) -> Result<(), String> {
		if let Some(lifecycle) = &self.lifecycle {
			lifecycle.validate()?;
			if self.qdrant.integrity.is_none() {
				return Err("RAG lifecycle requires qdrant.integrity".into());
			}
		}
		if self.bind_address.trim().is_empty() {
			return Err("RAG bindAddress must not be empty".into());
		}
		if self.port == 0 {
			return Err("RAG port must not be zero".into());
		}
		if self.chunk_max_chars == 0 {
			return Err("RAG chunkMaxChars must be greater than zero".into());
		}
		if !valid_http_url(&self.embedding.endpoint) {
			return Err("RAG embedding endpoint must use http or https".into());
		}
		if self.embedding.model.trim().is_empty() {
			return Err("RAG embedding model must not be empty".into());
		}
		// Constructing these components applies their own invariant validation too.
		let _ = FixedWindowChunker::new(self.chunk_max_chars)?;
		let _ = security_rag::ContextGuard::new(self.context_guard.clone())
			.map_err(|error| format!("invalid RAG context guard configuration: {error:?}"))?;
		if self.ingestion.max_document_bytes == 0
			|| self.retrieval.max_chunks == 0
			|| self.retrieval.max_context_tokens == 0
		{
			return Err("RAG security budgets must be greater than zero".into());
		}
		let mut classification_ids = std::collections::HashSet::new();
		if self.ingestion.classification_rules.iter().any(|rule| {
			rule.id.trim().is_empty()
				|| rule.pattern.trim().is_empty()
				|| !classification_ids.insert(rule.id.as_str())
		}) {
			return Err(
				"RAG classification rules require unique non-empty ids and non-empty patterns".into(),
			);
		}
		TrustedHttpsSourceRegistry::validate_config(&self.trusted_sources)?;
		if !self.trusted_sources.is_empty() && self.qdrant.integrity.is_none() {
			return Err("trustedSources requires qdrant.integrity so source evidence cannot be modified in the index".into());
		}
		Ok(())
	}

	pub fn build_trusted_sources(&self) -> Result<Option<TrustedHttpsSourceRegistry>, String> {
		if self.trusted_sources.is_empty() {
			return Ok(None);
		}
		TrustedHttpsSourceRegistry::new(
			self.trusted_sources.clone(),
			self.ingestion.max_document_bytes,
		)
		.map(Some)
	}

	/// Builds the Qdrant adapter using a caller-provided client. The caller owns mTLS, proxy,
	/// timeout, and custom-root configuration for both Qdrant and the embedding endpoint.
	pub fn build_qdrant_backend(
		&self,
		client: Client,
	) -> Result<QdrantBackend<HttpEmbeddingProvider, FixedWindowChunker>, String> {
		self.validate()?;
		QdrantBackend::new(
			client.clone(),
			self.qdrant.clone(),
			HttpEmbeddingProvider::new(client, self.embedding.clone())?,
			FixedWindowChunker::new(self.chunk_max_chars)?,
		)
	}
}

/// A small OpenAI-compatible embedding client. It deliberately contains no tenant, ACL, or RAG
/// security logic; those facts never leave the security pipeline for a model provider.
pub struct HttpEmbeddingProvider {
	client: Client,
	config: OpenAiCompatibleEmbeddingConfig,
}

pub(crate) async fn read_bounded_response(
	mut response: reqwest::Response,
	limit: usize,
) -> Result<Vec<u8>, String> {
	if response
		.content_length()
		.is_some_and(|length| length > limit as u64)
	{
		return Err("RAG backend response exceeds byte budget".into());
	}
	let mut bytes = Vec::new();
	while let Some(chunk) = response
		.chunk()
		.await
		.map_err(|_| "RAG backend response unavailable")?
	{
		if bytes.len().saturating_add(chunk.len()) > limit {
			return Err("RAG backend response exceeds byte budget".into());
		}
		bytes.extend_from_slice(&chunk);
	}
	Ok(bytes)
}

impl HttpEmbeddingProvider {
	pub fn new(client: Client, config: OpenAiCompatibleEmbeddingConfig) -> Result<Self, String> {
		if !valid_http_url(&config.endpoint) {
			return Err("embedding endpoint must use http or https".into());
		}
		if config.model.trim().is_empty() {
			return Err("embedding model must not be empty".into());
		}
		Ok(Self { client, config })
	}
}

#[derive(Deserialize)]
struct EmbeddingResponse {
	data: Vec<EmbeddingData>,
}

#[derive(Deserialize)]
struct EmbeddingData {
	embedding: Vec<f32>,
}

#[async_trait::async_trait]
impl EmbeddingProvider for HttpEmbeddingProvider {
	async fn embed(&self, text: &str) -> Result<Vec<f32>, String> {
		let body = serde_json::to_vec(&serde_json::json!({
			"model": self.config.model,
			"input": text,
		}))
		.map_err(|error| format!("failed to serialize embedding request: {error}"))?;
		let mut request = self
			.client
			.post(&self.config.endpoint)
			.header(reqwest::header::CONTENT_TYPE, "application/json")
			.body(body);
		if let Some(api_key) = &self.config.api_key {
			request = request.bearer_auth(api_key);
		}
		let response = request
			.send()
			.await
			.map_err(|error| format!("embedding request failed: {error}"))?;
		if !response.status().is_success() {
			return Err(format!(
				"embedding request failed with HTTP {}",
				response.status()
			));
		}
		let bytes = read_bounded_response(response, 4 * 1024 * 1024).await?;
		let response: EmbeddingResponse = serde_json::from_slice(&bytes)
			.map_err(|error| format!("invalid embedding response: {error}"))?;
		response
			.data
			.into_iter()
			.next()
			.map(|item| item.embedding)
			.filter(|embedding| !embedding.is_empty())
			.ok_or_else(|| "embedding response did not contain a non-empty vector".into())
	}
}

fn valid_http_url(value: &str) -> bool {
	value.starts_with("https://") || value.starts_with("http://")
}
