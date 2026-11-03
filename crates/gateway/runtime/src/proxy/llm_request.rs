//! Host-owned LLM request preparation. This stage does not send the model request.
use ::http::HeaderMap;
use platform_core::prelude::AssertSize;
use platform_core::strng;

use super::httpproxy::OptLogger;
use super::{ProxyError, ProxyResponse, dtrace, policy_client::PolicyClient};
use crate::http::{self, Request, Response, auth, x_headers::TRACEPARENT};
use crate::llm::{self, InputFormat, LLMRequest, NamedAIProvider, RequestResult, RouteType};
use crate::store::{BackendPolicies, LLMRequestPolicies, LLMResponsePolicies};
use crate::telemetry::log::RequestLog;

pub(super) enum PreparedRequest {
	Forward {
		request: Request,
		response_policies: LLMResponsePolicies,
		llm_request: Option<LLMRequest>,
	},
	Response(Response),
}

/// Body controls enforce their own contract, independently of common Audit/Shadow mode.
/// Realtime needs a duplex execution adapter; the HTTP handshake cannot grant it.
#[allow(clippy::too_many_arguments)]
pub(super) fn check_controls(
	route: RouteType,
	provider: &NamedAIProvider,
	backend_policies: &BackendPolicies,
	request_policies: &LLMRequestPolicies,
	has_guardrails: bool,
	request_id: &str,
	identity: &security_pipeline::GatewayIdentity,
) -> Result<(), ProxyResponse> {
	let unsupported = if route == RouteType::Realtime
		&& (backend_policies.security_audit.is_some()
			|| backend_policies.security_pipeline.is_some()
			|| request_policies.requires_structured_adapter()
			|| has_guardrails)
	{
		Some(("realtime", "llm-realtime"))
	} else if (matches!(route, RouteType::Passthrough | RouteType::Detect)
		&& request_policies.requires_structured_adapter())
		|| (!route.supports_content_controls()
			&& (request_policies.requires_content_adapter() || has_guardrails))
	{
		Some((provider.name.as_str(), "llm-unsupported-controls"))
	} else {
		None
	};
	if let Some((model, adapter)) = unsupported {
		let action =
			security_pipeline::model_invoke_for_identity(request_id.to_owned(), identity.clone(), model);
		let enforce = security_integration_runtime::SecurityConfig::from(
			security_integration_runtime::SecurityConfigData {
				mode: security_integration_runtime::SecurityMode::Enforce,
				..Default::default()
			},
		);
		security_integration_runtime::unsupported_operation_with_audit(
			&enforce,
			&action,
			adapter,
			&crate::security_events::UiSecurityAuditSink,
		)
		.map_err(|_| ProxyResponse::from(ProxyError::AuthorizationFailed))?;
	}
	Ok(())
}

/// Runs after snapshotting and route-control admission, before late auth/final dispatch.
#[allow(clippy::too_many_arguments)]
pub(super) async fn prepare(
	route_type: RouteType,
	llm: &NamedAIProvider,
	llm_request_policies: &LLMRequestPolicies,
	backend_info: &auth::BackendInfo,
	policy_client: PolicyClient,
	mut req: Request,
	log: &mut Option<&mut RequestLog>,
	response_headers: &mut HeaderMap,
) -> Result<PreparedRequest, ProxyResponse> {
	let llm_provider = llm.provider.provider().to_string();
	dtrace::trace(|trace| trace.llm_route_resolved(llm_provider.clone(), format!("{route_type:?}")));
	// First, we process the incoming request. This entails translating to the relevant provider,
	// and parsing the request to build the LLMRequest for logging/etc, and applying LLM policies like
	// prompt enrichment, prompt guard, etc.
	let (request, response_policies, llm_request) = match route_type {
		RouteType::Completions
		| RouteType::Messages
		| RouteType::Responses
		| RouteType::AnthropicTokenCount
		| RouteType::Embeddings
		| RouteType::Rerank
		| RouteType::Detect => {
			let request_body_limit = crate::http::buffer_limit(&req);
			let req = req.map(|b| {
				dtrace::TracingBody::maybe_wrap("llm request before translation", b, request_body_limit)
			});
			let r = match route_type {
				RouteType::Completions => {
					Box::pin(llm.provider.process_completions_request(
						backend_info,
						llm_request_policies.llm.as_deref(),
						req,
						llm.tokenize,
						log,
					))
					.await
				},
				RouteType::Messages => {
					Box::pin(llm.provider.process_messages_request(
						backend_info,
						llm_request_policies.llm.as_deref(),
						req,
						llm.tokenize,
						log,
					))
					.await
				},
				RouteType::Responses => {
					Box::pin(llm.provider.process_responses_request(
						backend_info,
						llm_request_policies.llm.as_deref(),
						req,
						llm.tokenize,
						log,
					))
					.await
				},
				RouteType::Embeddings => {
					Box::pin(llm.provider.process_embeddings_request(
						backend_info,
						llm_request_policies.llm.as_deref(),
						req,
						llm.tokenize,
						log,
					))
					.await
				},
				RouteType::Rerank => {
					Box::pin(llm.provider.process_rerank_request(
						backend_info,
						llm_request_policies.llm.as_deref(),
						req,
						llm.tokenize,
						log,
					))
					.await
				},
				RouteType::AnthropicTokenCount => {
					Box::pin(llm.provider.process_count_tokens_request(
						backend_info,
						req,
						llm_request_policies.llm.as_deref(),
						log,
					))
					.await
				},
				RouteType::Detect => {
					Box::pin(llm.provider.process_detect_request(
						backend_info,
						llm_request_policies.llm.as_deref(),
						req,
						log,
					))
					.await
				},
				_ => unreachable!(),
			}
			.map_err(|e| ProxyError::Processing(e.into()))?;
			let (mut req, llm_request) = match r {
				RequestResult::Success(r, lr) => (r, lr),
				RequestResult::Rejected(dr) => return Err(ProxyResponse::DirectResponse(Box::new(dr))),
			};
			dtrace::trace(|trace| {
				trace.llm_request_detected(
					llm_provider.clone(),
					format!("{:?}", llm_request.input_format),
					llm_request.native_format.map(|f| format!("{f:?}")),
					llm_request.request_model.to_string(),
					llm_request.streaming,
				);
			});
			// If a user doesn't configure explicit overrides for connecting to a provider, setup default
			// paths, TLS, etc.
			llm
				.provider
				.setup_request(
					&mut req,
					route_type,
					Some(&llm_request),
					llm.path_override.as_deref(),
					llm.path_prefix.as_deref(),
					llm.host_override.is_some(),
				)
				.map_err(ProxyError::Processing)?;

			// Apply all policies (rate limits, prompt guards, enrichment)
			// count_tokens skips policies (no tokens generated, no prompts to manipulate)
			let response_policies = if route_type == RouteType::AnthropicTokenCount {
				LLMResponsePolicies::default()
			} else {
				Box::pin(
					apply_request_policies(
						llm_request_policies,
						policy_client,
						&mut req,
						&llm_request,
						response_headers,
					)
					.assert_size::<{ 3 * 1024 }>(),
				)
				.await?
			};
			log.add(|l| l.llm_request = Some(llm_request.clone()));
			(req, response_policies, Some(llm_request))
		},
		RouteType::Models => {
			return Ok(PreparedRequest::Response(
				::http::Response::builder()
					.status(::http::StatusCode::NOT_IMPLEMENTED)
					.header(::http::header::CONTENT_TYPE, "application/json")
					.body(http::Body::from(format!(
						"{{\"error\":\"Route '{route_type:?}' not implemented\"}}"
					)))
					.expect("Failed to build response"),
			));
		},
		RouteType::Passthrough | RouteType::Realtime => {
			// For passthrough, we only need to setup the response so we get default TLS, hostname, etc set.
			// We do not need LLM policies nor token-based rate limits, etc.
			// For realtime we do the same and handle everything in the Websocket handler
			llm
				.provider
				.setup_request(
					&mut req,
					route_type,
					None,
					llm.path_override.as_deref(),
					llm.path_prefix.as_deref(),
					llm.host_override.is_some(),
				)
				.map_err(ProxyError::Processing)?;
			if route_type == RouteType::Realtime {
				let request_model = http::as_url(req.uri())
					.map_err(ProxyError::Processing)?
					.query_pairs()
					.find(|(k, _v)| k == "model")
					.map(|(_, v)| strng::new(v))
					.unwrap_or_default();
				log.add(|l| {
					l.llm_request = Some(LLMRequest {
						input_format: InputFormat::Realtime,
						native_format: Some(llm::custom::ProviderFormat::Realtime),
						cache_convention: llm::CacheTokenConvention::pending(),
						request_model,
						streaming: true,
						provider: llm.provider.provider(),
						input_tokens: None,
						params: Default::default(),
						prompt: Default::default(),
						provider_state: None,
					})
				});
			}
			(req, LLMResponsePolicies::default(), None)
		},
	};
	Ok(PreparedRequest::Forward {
		request,
		response_policies,
		llm_request,
	})
}

async fn apply_request_policies(
	policies: &LLMRequestPolicies,
	client: PolicyClient,
	req: &mut Request,
	llm_req: &LLMRequest,
	response_headers: &mut HeaderMap,
) -> Result<LLMResponsePolicies, ProxyResponse> {
	let local_rate_limit = policies
		.local_rate_limit
		.as_deref()
		.into_iter()
		.flatten()
		.filter(|rate_limit| rate_limit.spec.limit_type == http::localratelimit::RateLimitType::Tokens)
		.cloned()
		.collect::<Vec<_>>();
	if llm_req.streaming
		&& policies
			.llm
			.as_ref()
			.and_then(|p| p.prompt_guard.as_ref())
			.is_some_and(|g| !g.response.is_empty() && !g.streaming.is_enabled())
	{
		return Err(ProxyError::AuthorizationFailed.into());
	}
	for lrl in &local_rate_limit {
		lrl.check_llm_request(llm_req)?;
	}
	let (rl_resp, response) = if let Some(rrl) = &policies.remote_rate_limit {
		// For the LLM request side, request either the count of the input tokens (if tokenization was done)
		// or 0.
		// Either way, we will 'true up' on the response side.
		rrl
			.check_llm(client, req, llm_req.input_tokens.unwrap_or_default())
			.await?
	} else {
		(http::PolicyResponse::default(), None)
	};
	rl_resp.apply(response_headers)?;
	let prompt_guard = policies
		.llm
		.as_deref()
		.and_then(|llm| llm.prompt_guard.as_ref());
	Ok(LLMResponsePolicies {
		streaming_limits: policies
			.llm
			.as_deref()
			.and_then(|llm| llm.streaming_limits)
			.unwrap_or_default(),
		local_rate_limit,
		remote_rate_limit: response,
		request_traceparent: req.headers().get(TRACEPARENT).cloned(),
		prompt_guard: prompt_guard.map(|g| g.response.clone()).unwrap_or_default(),
		streaming_prompt_guard_enabled: prompt_guard.is_some_and(|g| g.streaming.is_enabled()),
	})
}

#[cfg(test)]
mod tests {
	use super::*;
	use security_integration_runtime::{SecurityConfigData, SecurityMode};
	use std::sync::Arc;

	fn provider() -> NamedAIProvider {
		NamedAIProvider {
			name: "local".into(),
			provider: crate::llm::AIProvider::OpenAI(crate::llm::openai::Provider { model: None }),
			provider_backend: None,
			host_override: None,
			path_override: None,
			path_prefix: None,
			tokenize: false,
			inline_policies: Vec::new(),
		}
	}

	fn policies(value: serde_json::Value) -> LLMRequestPolicies {
		LLMRequestPolicies {
			llm: Some(Arc::new(serde_json::from_value(value).unwrap())),
			..Default::default()
		}
	}

	#[test]
	fn route_controls_enforce_the_same_contract_in_all_common_modes() {
		use RouteType::*;
		let provider = provider();
		let identity = security_pipeline::GatewayIdentity::default();
		let structured = policies(serde_json::json!({"defaults":{"max_tokens":10}}));
		let content = policies(serde_json::json!({"promptGuard":{"request":[
				{"regex":{"action":"reject","rules":[{"pattern":"secret"}]}}
		]}}));
		let empty = LLMRequestPolicies::default();
		for mode in [
			SecurityMode::Enforce,
			SecurityMode::Audit,
			SecurityMode::Shadow,
		] {
			let backend = BackendPolicies {
				security_audit: Some(Arc::new(
					SecurityConfigData {
						mode,
						..Default::default()
					}
					.into(),
				)),
				..Default::default()
			};
			for route in [
				Completions,
				Messages,
				Responses,
				Models,
				Passthrough,
				Detect,
				Embeddings,
				Realtime,
				AnthropicTokenCount,
				Rerank,
			] {
				for (policy, denied) in [
					(&empty, route == Realtime),
					(
						&structured,
						matches!(route, Passthrough | Detect | Realtime),
					),
					(
						&content,
						!matches!(route, Completions | Messages | Responses),
					),
				] {
					let result = check_controls(
						route,
						&provider,
						&backend,
						policy,
						false,
						"route-matrix",
						&identity,
					);
					assert_eq!(result.is_err(), denied, "{route:?} / {mode:?}");
				}
			}
		}
	}

	#[test]
	fn vehicle_and_legacy_controls_cannot_silently_tunnel_uninspectable_requests() {
		let provider = provider();
		let identity = security_pipeline::GatewayIdentity::default();
		let empty = LLMRequestPolicies::default();
		let backend = BackendPolicies::default();
		assert!(
			check_controls(
				RouteType::Realtime,
				&provider,
				&backend,
				&empty,
				false,
				"bare-realtime",
				&identity
			)
			.is_ok()
		);
		for route in [
			RouteType::Realtime,
			RouteType::Embeddings,
			RouteType::Detect,
		] {
			assert!(
				check_controls(
					route, &provider, &backend, &empty, true, "vehicle", &identity
				)
				.is_err()
			);
		}
		assert!(
			check_controls(
				RouteType::Completions,
				&provider,
				&backend,
				&empty,
				true,
				"vehicle",
				&identity
			)
			.is_ok()
		);
		let legacy = BackendPolicies {
			security_pipeline: Some(security_pipeline::SecurityPipelineConfig::default().into()),
			..Default::default()
		};
		assert!(
			check_controls(
				RouteType::Realtime,
				&provider,
				&legacy,
				&empty,
				false,
				"legacy-realtime",
				&identity
			)
			.is_err()
		);
	}
}
