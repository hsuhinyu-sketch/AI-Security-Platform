//! One request inspection point after enrichment/guards, before provider encoding.
//! Sampling re-enters this path. Authorization and final-send checks remain Host-owned.
use super::{AIError, InputFormat, RouteType, types::RequestType};
use crate::{http::Request, proxy::ProxyError, store::BackendPolicies};
use security_integration_runtime::SecurityConfig;
use security_pii::{PiiError, PiiMode};
use serde_json::{Value, json};
use std::{collections::BTreeMap, sync::Arc, time::Duration};

#[derive(Clone)]
struct Bindings {
	configs: Vec<Arc<SecurityConfig>>,
	model: String,
}

pub(crate) fn install(
	req: &mut Request,
	policies: &BackendPolicies,
	route: RouteType,
) -> Result<(), ProxyError> {
	let mut configs = Vec::new();
	if let Some(guards) = req.extensions().get::<crate::proxy::RoutingGuards>() {
		for guard in &guards.0 {
			let config = guard.pii_config();
			if security_integration_runtime::pii::active(config.pii.as_ref())
				&& !configs.iter().any(|c| Arc::ptr_eq(c, config))
			{
				configs.push(config.clone());
			}
		}
	}
	if let Some(config) = &policies.security_audit
		&& security_integration_runtime::pii::active(config.pii.as_ref())
		&& !configs.iter().any(|c| Arc::ptr_eq(c, config))
	{
		configs.push(config.clone());
	}
	if configs.is_empty() {
		return Ok(());
	}
	let model = policies
		.model_name()
		.ok_or(ProxyError::AuthorizationFailed)?
		.to_owned();
	if !matches!(
		route,
		RouteType::Completions | RouteType::Messages | RouteType::Responses
	) {
		for config in &configs {
			record(
				config,
				req.extensions(),
				&model,
				&BTreeMap::new(),
				false,
				Some("unsupported"),
			)
			.map_err(|_| ProxyError::AuthorizationFailed)?;
			if config
				.pii
				.as_ref()
				.is_some_and(|p| p.mode == PiiMode::Enforce)
			{
				return Err(ProxyError::AuthorizationFailed);
			}
		}
		return Ok(());
	}
	req.extensions_mut().insert(Bindings { configs, model });
	Ok(())
}

/// Returns true for an Enforce content-policy block; this is never an execution grant.
pub(super) async fn inspect<R: RequestType>(
	req: &mut R,
	format: InputFormat,
	parts: &http::request::Parts,
) -> Result<bool, AIError> {
	let Some(binding) = parts.extensions.get::<Bindings>() else {
		return Ok(false);
	};
	for config in &binding.configs {
		let pii = config.pii.as_ref().ok_or(AIError::PiiInspection)?;
		let engine = config.pii_runtime.get(pii).ok_or(AIError::PiiInspection)?;
		// Never disclose a prompt to the detector on an unauthorized model operation.
		let mut extensions = parts.extensions.clone();
		let action = security_pipeline::model_invoke_for_identity(
			crate::security::request_id(&mut extensions),
			crate::security::identity_from_extensions(&parts.extensions),
			binding.model.clone(),
		);
		crate::security::evaluate(config, &action).map_err(|_| AIError::PiiInspection)?;
		let mut entities = BTreeMap::<String, usize>::new();
		let mut modified = false;
		let mut observed_error = None;
		let work = async {
			let mut body = req.pii_body().map_err(|_| PiiError::InvalidResponse)?;
			security_audit::StateJournal::encoded_len(&body, pii.max_text_bytes)
				.map_err(|_| PiiError::InputLimit)?;
			let projection = gateway_llm::content::project_request(&body, format)
				.map_err(|_| PiiError::InvalidResponse)?;
			let mut replacements = Vec::new();
			let mut total = 0usize;
			for text in projection.texts() {
				let outcome = engine.inspect(text).await?;
				total = total.saturating_add(outcome.findings.len());
				if total > pii.max_findings {
					return Err(PiiError::FindingLimit);
				}
				for finding in outcome.findings {
					*entities.entry(finding.entity_type).or_default() += 1;
				}
				if let Some(error) = outcome.detector_error {
					observed_error = Some(format!("{error:?}"));
				}
				if outcome.blocked {
					return Ok(None);
				}
				modified |= outcome.modified;
				replacements.push(outcome.text);
			}
			projection
				.replace(&mut body, replacements)
				.map_err(|_| PiiError::InvalidResponse)?;
			security_audit::StateJournal::encoded_len(&body, pii.max_output_bytes)
				.map_err(|_| PiiError::OutputLimit)?;
			Ok(Some(body))
		};
		let result = tokio::time::timeout(Duration::from_millis(pii.timeout_ms), work)
			.await
			.unwrap_or(Err(PiiError::Timeout));
		let (body, failure, blocked) = match result {
			Ok(Some(body)) => (Some(body), observed_error, false),
			Ok(None) => (None, Some("blocked".into()), true),
			Err(error) => (None, Some(format!("{error:?}")), false),
		};
		record(
			config,
			&parts.extensions,
			&binding.model,
			&entities,
			modified && body.is_some(),
			failure.as_deref(),
		)
		.map_err(|_| AIError::PiiInspection)?;
		if pii.mode == PiiMode::Enforce {
			if blocked {
				return Ok(true);
			}
			let body = body.ok_or(AIError::PiiInspection)?;
			req.replace_pii_body(body)?;
		}
	}
	Ok(false)
}

fn record(
	config: &SecurityConfig,
	extensions: &http::Extensions,
	model: &str,
	entities: &BTreeMap<String, usize>,
	modified: bool,
	failure: Option<&str>,
) -> Result<(), String> {
	use crate::security_events::{SecurityEventKind, SecurityTimelineEvent};
	let mut extensions = extensions.clone();
	let pii = config.pii.as_ref().ok_or("PII configuration missing")?;
	let denied = pii.mode == PiiMode::Enforce && failure.is_some();
	let event = SecurityTimelineEvent {
		sequence: 0,
		kind: SecurityEventKind::PiiInspection,
		request_id: crate::security::request_id(&mut extensions),
		timestamp: chrono::Utc::now(),
		user_id: None,
		agent_id: None,
		tenant_id: None,
		delegation_id: None,
		action: "ModelInvoke:invoke".into(),
		resource_type: "Model".into(),
		resource_id: model.into(),
		policy_id: None,
		policy_version: None,
		decision: Some(if denied {
			security_types::DecisionEffect::Deny
		} else {
			security_types::DecisionEffect::Allow
		}),
		details: BTreeMap::from([
			("mode".into(), json!(pii.mode)),
			("entities".into(), json!(entities)),
			("modified".into(), Value::Bool(modified)),
			("failure".into(), json!(failure)),
		]),
	};
	if config.required_audit.as_ref().is_some_and(|a| {
		a.action_types
			.contains(&security_types::ActionType::ModelInvoke)
	}) {
		crate::security_events::store().record_content_required(event)
	} else {
		crate::security_events::store().record(event);
		Ok(())
	}
}
