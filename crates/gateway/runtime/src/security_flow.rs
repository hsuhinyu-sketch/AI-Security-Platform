//! Identity-bound RAG context lineage. No caller-supplied labels are trusted.
use crate::proxy::ProxyError;
use security_integration_runtime::{
	SecurityConfig,
	context_store::{ContextBinding, LocalSecurityContextStore, SecurityContextStore},
	cross_component::CrossComponentConfig,
	identity_binding::VerifiedOwner,
};
use security_types::{ActionRequest, DataClassification};
use std::sync::{Arc, OnceLock};

pub(crate) const HEADER: &str = "x-aisp-context-id";
#[derive(Default)]
struct Registry(Arc<LocalSecurityContextStore>);
static REGISTRY: OnceLock<Registry> = OnceLock::new();
fn registry() -> &'static Registry {
	REGISTRY
		.get_or_init(|| Registry(security_integration_runtime::context_store::shared_memory_store()))
}

#[derive(Clone)]
pub(crate) struct FlowAccess {
	store: Arc<dyn SecurityContextStore>,
	binding: Arc<ContextBinding>,
	policy: Arc<CrossComponentConfig>,
	correlation: String,
	id: String,
}
impl std::fmt::Debug for FlowAccess {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.debug_struct("FlowAccess")
			.field("correlation", &self.correlation)
			.finish_non_exhaustive()
	}
}
impl FlowAccess {
	pub fn recovery_binding(&self) -> Result<String, ProxyError> {
		serde_json::to_string(&(&self.id, &self.binding, &self.policy))
			.map(|v| crate::security::digest(&v))
			.map_err(|_| ProxyError::AuthorizationFailed)
	}
	pub fn same_context(&self, other: &Self) -> bool {
		Arc::ptr_eq(&self.store, &other.store) && self.id == other.id && self.binding == other.binding
	}
	pub fn current(&self) -> Result<(), ProxyError> {
		self.classification().map(|_| ())
	}
	fn classification(&self) -> Result<DataClassification, ProxyError> {
		self
			.store
			.classification(&self.id, &self.binding)
			.map_err(|_| ProxyError::AuthorizationFailed)
	}
	/// Candidate prefilter: reads live classification without minting a decision or credential.
	pub fn permits(&self, action: &ActionRequest, destination: &str) -> Result<bool, ProxyError> {
		let class = self.classification()?;
		Ok(
			self
				.policy
				.destinations
				.iter()
				.filter(|p| p.classification <= class)
				.all(|p| p.permits(action, destination)),
		)
	}
	pub fn check(&self, action: &ActionRequest, destination: &str) -> Result<(), ProxyError> {
		let class = self.classification()?;
		// Intersection, not replacement: an elevated label can only reduce available exits.
		let result: Result<(), ProxyError> = (|| {
			for policy in self
				.policy
				.destinations
				.iter()
				.filter(|p| p.classification <= class)
			{
				security_integration_runtime::check_data_egress(
					policy,
					action,
					destination,
					&crate::security_events::UiSecurityAuditSink,
				)
				.map_err(|_| ProxyError::AuthorizationFailed)?;
			}
			Ok(())
		})();
		use security_audit::AuditSink;
		let decision = security_types::Decision {
			request_id: action.request_id.clone(),
			effect: if result.is_ok() {
				security_types::DecisionEffect::Allow
			} else {
				security_types::DecisionEffect::Deny
			},
			policy_id: Some(format!("cross-component:{}", self.correlation)),
			policy_version: None,
			expires_at: None,
		};
		let mut audited = action.clone();
		audited.resource.id = destination.into();
		crate::security_events::UiSecurityAuditSink.record(security_audit::event_from_decision(
			uuid::Uuid::new_v4().to_string(),
			&audited,
			&decision,
		));
		result?;
		tracing::debug!(context = %self.correlation, request_id = %action.request_id, ?class, "cross-component destination authorized");
		Ok(())
	}
}
fn fingerprint(config: &SecurityConfig) -> Result<String, ProxyError> {
	config
		.validate_composition()
		.map_err(|_| ProxyError::AuthorizationFailed)?;
	serde_json::to_string(config)
		.map(|s| crate::security::digest(&s))
		.map_err(|_| ProxyError::AuthorizationFailed)
}
fn owner(extensions: &http::Extensions) -> Result<VerifiedOwner, ProxyError> {
	let claims = extensions
		.get::<crate::http::jwt::Claims>()
		.ok_or(ProxyError::AuthorizationFailed)?;
	if claims
		.inner
		.get("exp")
		.and_then(|v| v.as_i64())
		.is_none_or(|exp| exp <= chrono::Utc::now().timestamp())
	{
		return Err(ProxyError::AuthorizationFailed);
	}
	let issuer = claims
		.inner
		.get("iss")
		.and_then(|v| v.as_str())
		.ok_or(ProxyError::AuthorizationFailed)?;
	VerifiedOwner::from_identity(
		&crate::security::identity_from_extensions(extensions),
		issuer,
	)
	.map_err(|_| ProxyError::AuthorizationFailed)
}
fn context_id(headers: &http::HeaderMap) -> Result<Option<&str>, ProxyError> {
	if headers.get_all(HEADER).iter().count() > 1 {
		return Err(ProxyError::AuthorizationFailed);
	}
	headers
		.get(HEADER)
		.map(|v| v.to_str().map_err(|_| ProxyError::AuthorizationFailed))
		.transpose()
}
impl Registry {
	fn store(
		&self,
		policy: &CrossComponentConfig,
	) -> Result<Arc<dyn SecurityContextStore>, ProxyError> {
		if policy.storage.is_some() || policy.store.get().is_some() {
			policy
				.context_store()
				.map_err(|_| ProxyError::AuthorizationFailed)
		} else {
			Ok(self.0.clone())
		}
	}
	fn resolve(
		&self,
		id: &str,
		owner: &VerifiedOwner,
		config: &SecurityConfig,
	) -> Result<FlowAccess, ProxyError> {
		if uuid::Uuid::parse_str(id).is_err() {
			return Err(ProxyError::AuthorizationFailed);
		}
		let policy = config
			.cross_component
			.as_ref()
			.ok_or(ProxyError::AuthorizationFailed)?;
		let binding = Arc::new(ContextBinding {
			owner: owner.clone(),
			namespace: policy.namespace.clone(),
			fingerprint: fingerprint(config)?,
		});
		let access = FlowAccess {
			store: self.store(policy)?,
			binding,
			policy: Arc::new(policy.clone()),
			correlation: crate::security::digest(id),
			id: id.into(),
		};
		access.current()?;
		Ok(access)
	}
	fn issue_documents(
		&self,
		owner: VerifiedOwner,
		config: &SecurityConfig,
		classification: DataClassification,
		parent: Option<&str>,
		documents: Vec<security_types::DocumentVersion>,
	) -> Result<String, ProxyError> {
		if let Some(id) = parent {
			let access = self.resolve(id, &owner, config)?;
			access
				.store
				.elevate_documents(id, &access.binding, classification, documents)
				.map_err(|_| ProxyError::AuthorizationFailed)?;
			return Ok(id.into()); // No renewal, downgrade, or new weaker copy.
		}
		let fingerprint = fingerprint(config)?;
		let policy = config
			.cross_component
			.as_ref()
			.ok_or(ProxyError::AuthorizationFailed)?;
		self
			.store(policy)?
			.issue_documents(
				ContextBinding {
					owner,
					namespace: policy.namespace.clone(),
					fingerprint,
				},
				policy.ttl_seconds,
				policy.max_contexts,
				classification,
				documents,
			)
			.map_err(|_| ProxyError::AuthorizationFailed)
	}
}

pub(crate) fn prepare(
	config: &SecurityConfig,
	headers: &http::HeaderMap,
	extensions: &http::Extensions,
) -> Result<Option<FlowAccess>, ProxyError> {
	if config.cross_component.is_none() {
		return Ok(None);
	}
	let result = (|| {
		let id = context_id(headers)?
			.or_else(|| extensions.get::<FlowAccess>().map(|f| f.id.as_str()))
			.ok_or(ProxyError::AuthorizationFailed)?;
		registry().resolve(id, &owner(extensions)?, config)
	})();
	if result.is_err() {
		tracing::warn!(
			"cross-component context missing, expired, foreign, or configuration-mismatched"
		);
		let mut extensions = extensions.clone();
		let mut action = security_pipeline::context_assemble_for_identity(
			crate::security::request_id(&mut extensions),
			crate::security::identity_from_extensions(&extensions),
			config
				.cross_component
				.as_ref()
				.expect("enabled")
				.namespace
				.clone(),
		);
		action.action.name = "context/use".into();
		audit_context(&action, false, "cross-component:invalid-context".into());
	}
	result.map(Some)
}

pub(crate) struct RagIssuer {
	pub config: Arc<SecurityConfig>,
	pub owner: VerifiedOwner,
}
pub(crate) fn rag_issuer(
	config: Arc<SecurityConfig>,
	claims: &crate::http::jwt::Claims,
) -> Result<RagIssuer, ProxyError> {
	let mut extensions = http::Extensions::new();
	extensions.insert(claims.clone());
	Ok(RagIssuer {
		owner: owner(&extensions)?,
		config,
	})
}
impl gateway_rag::http::ContextConstraintIssuer for RagIssuer {
	fn revoke(&self, id: &str) -> Result<(), String> {
		let policy = self
			.config
			.cross_component
			.as_ref()
			.ok_or("context controls unavailable")?;
		let mut action = security_pipeline::context_assemble_for_identity(
			uuid::Uuid::new_v4().to_string(),
			self.owner.identity(),
			policy.namespace.clone(),
		);
		action.action.action_type = security_types::ActionType::ContextOperation;
		action.action.name = "context/revoke".into();
		action.resource.resource_type = security_types::ResourceType::SecurityContext;
		security_integration_runtime::evaluate_with_audit(
			&self.config,
			&action,
			None,
			&crate::security_events::UiSecurityAuditSink,
		)
		.map_err(|_| "context revocation denied")?;
		let binding = ContextBinding {
			owner: self.owner.clone(),
			namespace: policy.namespace.clone(),
			fingerprint: fingerprint(&self.config).map_err(|_| "invalid context configuration")?,
		};
		let result = registry().store(policy).and_then(|store| {
			store
				.revoke(id, &binding)
				.map_err(|_| ProxyError::AuthorizationFailed)
		});
		audit_context(
			&action,
			result.is_ok(),
			format!("cross-component:revoke:{}", crate::security::digest(id)),
		);
		result.map_err(|_| "context revocation denied".into())
	}
	fn issue(
		&self,
		context: &security_rag::GuardedContext,
		parent: Option<&str>,
	) -> Result<String, String> {
		let result = registry()
			.issue_documents(
				self.owner.clone(),
				&self.config,
				context
					.classification
					.unwrap_or(DataClassification::Restricted),
				parent,
				context
					.chunks
					.iter()
					.filter_map(security_rag::lifecycle::document_reference)
					.collect(),
			)
			.map_err(|_| "cross-component context issuance denied".to_string());
		let action = security_pipeline::context_assemble_for_identity(
			uuid::Uuid::new_v4().to_string(),
			self.owner.identity(),
			context.corpus_id.clone(),
		);
		let rule = match &result {
			Ok(id) => format!("cross-component:issue:{}", crate::security::digest(id)),
			Err(_) => "cross-component:issue-denied".into(),
		};
		audit_context(&action, result.is_ok(), rule);
		result
	}
}

fn audit_context(action: &ActionRequest, allowed: bool, rule: String) {
	use security_audit::AuditSink;
	let decision = security_types::Decision {
		request_id: action.request_id.clone(),
		effect: if allowed {
			security_types::DecisionEffect::Allow
		} else {
			security_types::DecisionEffect::Deny
		},
		policy_id: Some(rule),
		policy_version: None,
		expires_at: None,
	};
	crate::security_events::UiSecurityAuditSink.record(security_audit::event_from_decision(
		uuid::Uuid::new_v4().to_string(),
		action,
		&decision,
	));
}
