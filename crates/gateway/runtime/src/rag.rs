//! Runtime host for configured secure RAG listeners.
//!
//! The RAG core owns authorization sequencing and backend contracts. This module supplies the
//! compatibility runtime concerns: validated JWT claims, listener lifecycle, resource-backed JWKS
//! loading, and structured gateway audit logging.

use std::sync::Arc;

use axum::{
	extract::{Request, State},
	http::{StatusCode, header},
	middleware::{self, Next},
	response::{IntoResponse, Response},
};
use security_audit::AuditSink;
use security_integration_runtime::SecurityConfigAuthorizer;
use security_pipeline::{GatewayIdentity, SecurityPipeline};
use security_rag::{
	ContextAuditEvent, ContextAuditOutcome, ContextAuditSink, ContextGuard, IngestionAuditEvent,
	IngestionAuditOutcome, IngestionAuditSink, RetrievalAuditEvent, RetrievalAuditOutcome,
	RetrievalAuditSink, SecureIngestor, SecureRetriever,
};
use security_types::{DecisionEffect, SecurityEvent};
use serde_json::json;
use tracing::info;

use crate::security_events::{SecurityEventKind, UiSecurityAuditSink};
use crate::{Config, http::jwt::Claims, resource_manager::ResourceFetcher};

mod service;
pub(crate) use service::Runtime;

/// The RAG adapter requires an outer `SecurityPipeline`, while `SecurityConfigAuthorizer` already
/// executes and audits the configured policy pipeline. Suppressing the adapter's wrapper event
/// prevents one authorization decision from appearing twice in the Security Console.
#[derive(Clone, Copy)]
struct DiscardAudit;

impl AuditSink for DiscardAudit {
	fn record(&self, _: SecurityEvent) {}
}

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
		crate::security_events::store().record_rag_stage(
			SecurityEventKind::RagIngestion,
			event.request_id,
			event.timestamp,
			event.tenant_id,
			"KnowledgeIngest:ingest",
			"Document",
			event.document_id,
			Some(match event.outcome {
				IngestionAuditOutcome::Denied => DecisionEffect::Deny,
				IngestionAuditOutcome::Indexed | IngestionAuditOutcome::Quarantined => {
					DecisionEffect::Allow
				},
			}),
			std::collections::BTreeMap::from([
				("outcome".into(), json!(format!("{:?}", event.outcome))),
				("sourceHash".into(), json!(event.source_hash)),
				("contentBytes".into(), json!(event.content_bytes)),
				("labels".into(), json!(event.labels)),
				("classification".into(), json!(event.classification)),
				("sourceOrigin".into(), json!(event.source_origin)),
				("reason".into(), json!(event.reason)),
				(
					"classificationSource".into(),
					json!(event.classification_source),
				),
				(
					"findingRuleIds".into(),
					json!(
						event
							.findings
							.into_iter()
							.map(|finding| finding.rule_id)
							.collect::<Vec<_>>()
					),
				),
			]),
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
		crate::security_events::store().record_rag_stage(
			SecurityEventKind::RagRetrieval,
			event.request_id,
			event.timestamp,
			event.subject.tenant_id,
			"KnowledgeRetrieve:retrieve",
			"KnowledgeBase",
			event.corpus_id,
			Some(match event.outcome {
				RetrievalAuditOutcome::Denied => DecisionEffect::Deny,
				RetrievalAuditOutcome::Authorized => DecisionEffect::Allow,
			}),
			std::collections::BTreeMap::from([
				("queryHash".into(), json!(event.query_hash)),
				("acceptedChunkIds".into(), json!(event.accepted_chunk_ids)),
				("classification".into(), json!(event.classification)),
				(
					"rejectedChunks".into(),
					json!(
						event
							.rejected
							.into_iter()
							.map(|rejection| json!({
								"chunkId": rejection.chunk_id,
								"reason": rejection.reason,
							}))
							.collect::<Vec<_>>()
					),
				),
			]),
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
		crate::security_events::store().record_rag_stage(
			SecurityEventKind::RagContextAssembly,
			event.request_id,
			event.timestamp,
			None,
			"ContextAssemble:assemble",
			"KnowledgeBase",
			event.corpus_id,
			Some(match event.outcome {
				ContextAuditOutcome::Denied => DecisionEffect::Deny,
				ContextAuditOutcome::Allowed | ContextAuditOutcome::Modified => DecisionEffect::Allow,
			}),
			std::collections::BTreeMap::from([
				("queryHash".into(), json!(event.query_hash)),
				("acceptedChunkIds".into(), json!(event.accepted_chunk_ids)),
				("classification".into(), json!(event.classification)),
				("removedChunkIds".into(), json!(event.removed_chunk_ids)),
				("redactedChunkIds".into(), json!(event.redacted_chunk_ids)),
				(
					"findings".into(),
					json!(
						event
							.findings
							.into_iter()
							.map(|finding| json!({
								"chunkId": finding.chunk_id,
								"kind": format!("{:?}", finding.kind),
								"ruleId": finding.rule_id,
							}))
							.collect::<Vec<_>>()
					),
				),
			]),
		);
	}
}

/// Prepare a complete listener generation before any live configuration is replaced.
async fn build_router(
	config: &Config,
	resources: &ResourceFetcher,
	mut system: crate::types::local::RagSystemConfig,
	lease: gateway_contracts::ConfigLease,
) -> anyhow::Result<axum::Router> {
	if system.security.required_audit.is_some() && config.security_audit.is_none() {
		anyhow::bail!("RAG requiredAudit requires config.securityAudit");
	}
	use security_integration_runtime::dependency_egress::DependencyKind as D;
	system
		.security
		.validate_composition()
		.map_err(anyhow::Error::msg)?;
	if let Some(policy) = &system.security.dependency_egress {
		policy
			.check_url(D::Qdrant, &system.gateway.qdrant.endpoint)
			.map_err(anyhow::Error::msg)?;
		policy
			.check_url(D::Embedding, &system.gateway.embedding.endpoint)
			.map_err(anyhow::Error::msg)?;
		for source in &system.gateway.trusted_sources {
			policy
				.check_url(D::TrustedSource, &source.base_url)
				.map_err(anyhow::Error::msg)?;
		}
	}
	system
		.security
		.prepare_runtime_stores()
		.map_err(anyhow::Error::msg)?;
	let jwt = Arc::new(
		system
			.authentication
			.try_into(resources)
			.await
			.map_err(|error| anyhow::anyhow!("RAG JWT configuration for '{}': {error}", system.name))?,
	);
	let backend = Arc::new(
		system
			.gateway
			.build_qdrant_backend(
				reqwest::Client::builder()
					.redirect(reqwest::redirect::Policy::none())
					.no_proxy()
					.timeout(std::time::Duration::from_secs(30))
					.build()?,
			)
			.map_err(|error| anyhow::anyhow!("RAG backend for '{}': {error}", system.name))?,
	);
	let lifecycle = system
		.gateway
		.lifecycle
		.clone()
		.map(security_rag::lifecycle::DocumentLifecycleStore::open)
		.transpose()
		.map_err(anyhow::Error::msg)?;
	if let (Some(store), Some(flow)) = (&lifecycle, &system.security.cross_component) {
		flow
			.context_store()
			.map_err(|_| anyhow::anyhow!("context store unavailable"))?
			.register_document_validator(&flow.namespace, store.clone())
			.map_err(|_| anyhow::anyhow!("document validator registration failed"))?;
	}
	let purger: Arc<dyn security_rag::lifecycle::DocumentPurger> = backend.clone();
	let backend = Arc::new(security_rag::lifecycle::LifecycleBackend {
		backend,
		store: lifecycle.clone(),
		default_access: system.gateway.qdrant.default_chunk_access.clone(),
	});
	let trusted_sources = system
		.gateway
		.build_trusted_sources()
		.map_err(|error| anyhow::anyhow!("RAG trusted sources for '{}': {error}", system.name))?
		.map(Arc::new);
	let security = Arc::new(system.security);
	let ingestor = SecureIngestor::new(
		backend.clone(),
		SecurityPipeline::new(
			SecurityConfigAuthorizer::with_audit(security.clone(), UiSecurityAuditSink),
			DiscardAudit,
		),
		system.gateway.ingestion.clone(),
		TracingIngestionAudit,
	)
	.map_err(|error| anyhow::anyhow!("RAG ingestion guard for '{}': {error:?}", system.name))?;
	let retriever = SecureRetriever::new(
		backend,
		SecurityPipeline::new(
			SecurityConfigAuthorizer::with_audit(security.clone(), UiSecurityAuditSink),
			DiscardAudit,
		),
		system.gateway.retrieval.clone(),
		TracingRetrievalAudit,
	)
	.map_err(|error| anyhow::anyhow!("RAG retrieval guard for '{}': {error:?}", system.name))?;
	let context_guard = ContextGuard::new(system.gateway.context_guard.clone())
		.map_err(|error| anyhow::anyhow!("RAG context guard for '{}': {error:?}", system.name))?;
	let mut service =
		gateway_rag::RagGatewayAdapter::new(ingestor, retriever, context_guard, TracingContextAudit);
	if let Some(store) = lifecycle {
		service = service.with_lifecycle(store, purger);
	}
	let service: Arc<dyn gateway_rag::RagHttpService> = Arc::new(service);
	let router = gateway_rag::router_with_sources(service, trusted_sources).layer(
		middleware::from_fn_with_state(
			Arc::new(RagAuthState {
				jwt,
				security,
				lease,
			}),
			verify_rag_jwt,
		),
	);
	Ok(router)
}

struct RagAuthState {
	jwt: Arc<crate::http::jwt::Jwt>,
	security: Arc<security_integration_runtime::SecurityConfig>,
	lease: gateway_contracts::ConfigLease,
}
async fn verify_rag_jwt(
	State(state): State<Arc<RagAuthState>>,
	mut request: Request,
	next: Next,
) -> Response {
	if !state.lease.is_current() {
		return StatusCode::FORBIDDEN.into_response();
	}
	let Some(token) = bearer_token(request.headers()) else {
		return StatusCode::UNAUTHORIZED.into_response();
	};
	let claims = match state.jwt.validate_claims(token) {
		Ok(claims) => claims,
		Err(_) => return StatusCode::UNAUTHORIZED.into_response(),
	};
	if state.security.cross_component.is_some() {
		let request_id = crate::security::request_id(request.extensions_mut());
		let issuer = match crate::security_flow::rag_issuer(state.security.clone(), &claims, request_id)
		{
			Ok(issuer) => issuer,
			Err(_) => return StatusCode::FORBIDDEN.into_response(),
		};
		request
			.extensions_mut()
			.insert(gateway_rag::http::VerifiedContextIssuer(Arc::new(issuer)));
	}
	request
		.extensions_mut()
		.insert(gateway_rag::VerifiedGatewayIdentity(identity_from_claims(
			&claims,
		)));
	let mut lease = state.lease.clone();
	let response = tokio::select! {
		biased;
		_ = lease.changed() => return StatusCode::FORBIDDEN.into_response(),
		response = next.run(request) => response,
	};
	if !state.lease.is_current() {
		return StatusCode::FORBIDDEN.into_response();
	}
	let (parts, body) = response.into_parts();
	Response::from_parts(
		parts,
		axum::body::Body::new(service::RevocableBody::new(body, state.lease.clone())),
	)
}

fn bearer_token(headers: &axum::http::HeaderMap) -> Option<&str> {
	headers
		.get(header::AUTHORIZATION)
		.and_then(|value| value.to_str().ok())
		.and_then(|value| value.strip_prefix("Bearer "))
		.filter(|token| !token.is_empty())
}

fn identity_from_claims(claims: &Claims) -> GatewayIdentity {
	crate::security::identity_from_claims(&claims.inner)
}
