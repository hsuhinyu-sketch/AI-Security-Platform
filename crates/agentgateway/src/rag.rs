//! Runtime host for configured secure RAG listeners.
//!
//! The RAG core owns authorization sequencing and backend contracts. This module supplies the
//! compatibility runtime concerns: validated JWT claims, listener lifecycle, resource-backed JWKS
//! loading, and structured gateway audit logging.

use std::sync::Arc;

use agent_core::drain;
use axum::{
	extract::{Request, State},
	http::{StatusCode, header},
	middleware::{self, Next},
	response::{IntoResponse, Response},
};
use gateway_adapter::{GatewayIdentity, SecurityPipeline};
use security_integration_agentgateway::{SecurityConfigAuthorizer, TracingAuditSink};
use security_rag::{
	ContextAuditEvent, ContextAuditSink, ContextGuard, IngestionAuditEvent, IngestionAuditSink,
	RetrievalAuditEvent, RetrievalAuditSink, SecureIngestor, SecureRetriever,
};
use tracing::{info, warn};

use crate::{Config, http::jwt::Claims, resource_manager::ResourceFetcher, serdes};

#[derive(Clone, Copy)]
struct TracingIngestionAudit;

impl IngestionAuditSink for TracingIngestionAudit {
	fn record(&self, event: IngestionAuditEvent) {
		info!(
			target: "rag_audit",
			request_id = %event.request_id,
			corpus_id = %event.corpus_id,
			document_id = %event.document_id,
			tenant_id = ?event.tenant_id,
			source_hash = ?event.source_hash,
			outcome = ?event.outcome,
			"RAG ingestion decision"
		);
	}
}

#[derive(Clone, Copy)]
struct TracingRetrievalAudit;

impl RetrievalAuditSink for TracingRetrievalAudit {
	fn record(&self, event: RetrievalAuditEvent) {
		info!(
			target: "rag_audit",
			request_id = %event.request_id,
			corpus_id = %event.corpus_id,
			query_hash = %event.query_hash,
			outcome = ?event.outcome,
			accepted_chunks = event.accepted_chunk_ids.len(),
			rejected_chunks = event.rejected.len(),
			"RAG retrieval decision"
		);
	}
}

#[derive(Clone, Copy)]
struct TracingContextAudit;

impl ContextAuditSink for TracingContextAudit {
	fn record(&self, event: ContextAuditEvent) {
		info!(
			target: "rag_audit",
			request_id = %event.request_id,
			corpus_id = %event.corpus_id,
			query_hash = %event.query_hash,
			outcome = ?event.outcome,
			accepted_chunks = event.accepted_chunk_ids.len(),
			removed_chunks = event.removed_chunk_ids.len(),
			redacted_chunks = event.redacted_chunk_ids.len(),
			"RAG context assembly decision"
		);
	}
}

/// Starts every `aiSystems[].rag` listener declared in the local configuration. A listener is
/// independently authenticated and drained; one system cannot route requests into another system's
/// corpus namespace.
pub(crate) async fn start_configured_gateways(
	config: &Config,
	resources: &ResourceFetcher,
	drain: drain::DrainWatcher,
) -> anyhow::Result<usize> {
	let Some(source) = &config.local_config else {
		return Ok(0);
	};
	let contents = source.read_to_string().await?;
	let contents = contents.replace("# yaml-language-server: $schema", "#");
	let local: crate::types::local::LocalConfig = serdes::yamlviajson::from_str(&contents)?;
	let systems = local.into_rag_systems()?;
	let count = systems.len();

	for system in systems {
		let jwt = Arc::new(
			system
				.authentication
				.try_into(resources)
				.await
				.map_err(|error| anyhow::anyhow!("RAG JWT configuration for '{}': {error}", system.name))?,
		);
		let listener =
			tokio::net::TcpListener::bind((system.gateway.bind_address.as_str(), system.gateway.port))
				.await
				.map_err(|error| anyhow::anyhow!("RAG listener for '{}': {error}", system.name))?;
		let address = listener.local_addr()?;
		let backend = Arc::new(
			system
				.gateway
				.build_qdrant_backend(reqwest::Client::new())
				.map_err(|error| anyhow::anyhow!("RAG backend for '{}': {error}", system.name))?,
		);
		let security = Arc::new(system.security);
		let ingestor = SecureIngestor::new(
			backend.clone(),
			SecurityPipeline::new(
				SecurityConfigAuthorizer::new(security.clone()),
				TracingAuditSink,
			),
			system.gateway.ingestion.clone(),
			TracingIngestionAudit,
		)
		.map_err(|error| anyhow::anyhow!("RAG ingestion guard for '{}': {error:?}", system.name))?;
		let retriever = SecureRetriever::new(
			backend,
			SecurityPipeline::new(SecurityConfigAuthorizer::new(security), TracingAuditSink),
			system.gateway.retrieval.clone(),
			TracingRetrievalAudit,
		)
		.map_err(|error| anyhow::anyhow!("RAG retrieval guard for '{}': {error:?}", system.name))?;
		let context_guard = ContextGuard::new(system.gateway.context_guard.clone())
			.map_err(|error| anyhow::anyhow!("RAG context guard for '{}': {error:?}", system.name))?;
		let service: Arc<dyn gateway_rag::RagHttpService> = Arc::new(
			gateway_rag::RagGatewayAdapter::new(ingestor, retriever, context_guard, TracingContextAudit),
		);
		let router =
			gateway_rag::router(service).layer(middleware::from_fn_with_state(jwt, verify_rag_jwt));
		let system_name = system.name;
		let task_system_name = system_name.clone();
		let drain = drain.clone();
		tokio::spawn(async move {
			let result = axum::serve(listener, router.into_make_service())
				.with_graceful_shutdown(async move {
					let _drain_blocker = drain.wait_for_drain().await;
				})
				.await;
			if let Err(error) = result {
				warn!(system = %task_system_name, %error, "RAG listener stopped unexpectedly");
			}
		});
		info!(system = %system_name, %address, "secure RAG gateway listener started");
	}
	Ok(count)
}

async fn verify_rag_jwt(
	State(jwt): State<Arc<crate::http::jwt::Jwt>>,
	mut request: Request,
	next: Next,
) -> Response {
	let Some(token) = bearer_token(request.headers()) else {
		return StatusCode::UNAUTHORIZED.into_response();
	};
	let claims = match jwt.validate_claims(token) {
		Ok(claims) => claims,
		Err(_) => return StatusCode::UNAUTHORIZED.into_response(),
	};
	request
		.extensions_mut()
		.insert(gateway_rag::VerifiedGatewayIdentity(identity_from_claims(
			&claims,
		)));
	next.run(request).await
}

fn bearer_token(headers: &axum::http::HeaderMap) -> Option<&str> {
	headers
		.get(header::AUTHORIZATION)
		.and_then(|value| value.to_str().ok())
		.and_then(|value| value.strip_prefix("Bearer "))
		.filter(|token| !token.is_empty())
}

fn identity_from_claims(claims: &Claims) -> GatewayIdentity {
	GatewayIdentity {
		user_id: string_claim(claims, &["sub", "user_id", "userId"]),
		agent_id: string_claim(claims, &["agent_id", "agentId"]),
		tenant_id: string_claim(claims, &["tenant_id", "tenantId"]),
		delegation_id: string_claim(claims, &["delegation_id", "delegationId"]),
		session_id: string_claim(claims, &["sid", "session_id", "sessionId"]),
		client_id: string_claim(claims, &["azp", "client_id", "clientId"]),
	}
}

fn string_claim(claims: &Claims, names: &[&str]) -> Option<String> {
	names.iter().find_map(|name| {
		claims
			.inner
			.get(*name)
			.and_then(serde_json::Value::as_str)
			.map(ToOwned::to_owned)
	})
}
