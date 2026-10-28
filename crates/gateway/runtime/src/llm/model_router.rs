use std::sync::Arc;

#[cfg(feature = "gateway-llm")]
use bytes::Bytes;
#[cfg(feature = "gateway-llm")]
use futures_util::stream;
use gateway_llm::routing;
#[cfg(feature = "gateway-llm")]
use gateway_llm::routing::path::rewrite_path_model;
use platform_core::prelude::Strng;
#[cfg(feature = "gateway-llm")]
use platform_core::strng;
pub use routing::{ModelVisibility, WeightedTarget};
#[cfg(feature = "gateway-llm")]
use serde_json::Value;

use crate::http::Response;
#[cfg(feature = "gateway-llm")]
use crate::http::transformation_cel::TransformationMetadata;
#[cfg(feature = "gateway-llm")]
use crate::http::{self, Request};
use crate::types::agent::{
	Authorization, BackendTrafficPolicy, HeaderMatch, RouteBackendReference,
};
#[cfg(feature = "gateway-llm")]
use crate::types::agent::{BackendReference, HeaderValueMatch};
use crate::{cel, llm};

#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ModelRoute {
	pub name: String,
	pub visibility: ModelVisibility,
	pub header_matches: Vec<Vec<HeaderMatch>>,
	pub backend_key: Strng,
	pub policies: ModelRoutePolicies,
	pub backend_policies: Vec<BackendTrafficPolicy>,
}

#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ModelRoutePolicies {
	pub llm: Arc<llm::Policy>,
	pub authorization: Option<Authorization>,
}

#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VirtualModelRoute {
	pub name: String,
	pub llm_policy: Arc<llm::Policy>,
	pub routing: VirtualModelRouting,
}

#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub enum VirtualModelRouting {
	Weighted(Vec<WeightedTarget>),
	Failover { backend_key: Strng },
	Conditional(Vec<ConditionalTarget>),
}

#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConditionalTarget {
	pub model: String,
	pub when: Option<Arc<cel::Expression>>,
}

#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct ModelBinding {
	header_matches: Vec<Vec<HeaderMatch>>,
	backend_key: Strng,
	policies: ModelRoutePolicies,
	backend_policies: Vec<BackendTrafficPolicy>,
}
#[derive(Debug, Clone)]
struct VirtualBinding {
	llm_policy: Arc<llm::Policy>,
	routing: VirtualRoutingBinding,
}
#[derive(Debug, Clone)]
enum VirtualRoutingBinding {
	Weighted,
	Conditional(Vec<Option<Arc<cel::Expression>>>),
	Failover { backend_key: Strng },
}

#[derive(Debug, Clone)]
pub struct ModelRouter {
	routes: routing::RoutingTable,
	models: Vec<ModelBinding>,
	virtual_models: Vec<VirtualBinding>,
	created: u64,
}

// Preserve the existing diagnostic/configuration HTTP serialization without retaining
// a second copy of route names, visibility, weights or conditional target models.
impl serde::Serialize for ModelRouter {
	fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
		use serde::ser::SerializeStruct;
		#[derive(serde::Serialize)]
		#[serde(rename_all = "camelCase")]
		struct Model<'a> {
			name: &'a str,
			visibility: ModelVisibility,
			#[serde(flatten)]
			binding: &'a ModelBinding,
		}
		#[derive(serde::Serialize)]
		#[serde(rename_all = "camelCase")]
		struct Virtual<'a> {
			name: &'a str,
			llm_policy: &'a Arc<llm::Policy>,
			routing: Routing<'a>,
		}
		#[derive(serde::Serialize)]
		#[serde(rename_all = "camelCase")]
		enum Routing<'a> {
			Weighted(&'a [WeightedTarget]),
			Conditional(Vec<Conditional<'a>>),
			Failover { backend_key: &'a Strng },
		}
		#[derive(serde::Serialize)]
		struct Conditional<'a> {
			model: &'a str,
			when: &'a Option<Arc<cel::Expression>>,
		}
		let models: Vec<_> = self
			.routes
			.models()
			.zip(&self.models)
			.map(|((_, route), binding)| Model {
				name: &route.name,
				visibility: route.visibility,
				binding,
			})
			.collect();
		let virtuals: Vec<_> = self
			.routes
			.virtual_models()
			.zip(&self.virtual_models)
			.map(|((_, route), binding)| {
				let routing = match (&route.routing, &binding.routing) {
					(routing::VirtualModelRouting::Weighted(targets), VirtualRoutingBinding::Weighted) => {
						Routing::Weighted(targets)
					},
					(
						routing::VirtualModelRouting::Conditional(targets),
						VirtualRoutingBinding::Conditional(conditions),
					) => Routing::Conditional(
						targets
							.iter()
							.zip(conditions)
							.map(|(target, when)| Conditional {
								model: &target.model,
								when,
							})
							.collect(),
					),
					(
						routing::VirtualModelRouting::Failover,
						VirtualRoutingBinding::Failover { backend_key },
					) => Routing::Failover { backend_key },
					_ => unreachable!("router definitions and bindings are assembled together"),
				};
				Virtual {
					name: &route.name,
					llm_policy: &binding.llm_policy,
					routing,
				}
			})
			.collect();
		let mut state = serializer.serialize_struct("ModelRouter", 3)?;
		state.serialize_field("models", &models)?;
		state.serialize_field("virtualModels", &virtuals)?;
		state.serialize_field("created", &self.created)?;
		state.end()
	}
}

#[derive(Debug, Clone)]
pub struct ResolvedBackend {
	pub backend: RouteBackendReference,
	pub llm_policy: Arc<llm::Policy>,
}

pub enum ResolveResult {
	DirectResponse(Response),
	Backend(ResolvedBackend),
}

#[cfg(feature = "gateway-llm")]
type RouterResult<T> = Result<T, Box<Response>>;

#[cfg(feature = "gateway-llm")]
struct RequestedModel {
	model: String,
	location: RequestedModelLocation,
}

#[cfg(feature = "gateway-llm")]
enum RequestedModelLocation {
	Body(Value),
	Multipart,
	Path,
}

impl ModelRouter {
	pub(crate) fn backend_policies(&self) -> impl Iterator<Item = &BackendTrafficPolicy> {
		self.models.iter().flat_map(|model| &model.backend_policies)
	}

	pub fn new(
		models: Vec<ModelRoute>,
		virtual_models: Vec<VirtualModelRoute>,
		created: u64,
	) -> Self {
		let (routes, models) = models
			.into_iter()
			.map(
				|ModelRoute {
				   name,
				   visibility,
				   header_matches,
				   backend_key,
				   policies,
				   backend_policies,
				 }| {
					(
						routing::ModelRoute { name, visibility },
						ModelBinding {
							header_matches,
							backend_key,
							policies,
							backend_policies,
						},
					)
				},
			)
			.unzip();
		let (virtual_routes, virtual_models) = virtual_models
			.into_iter()
			.map(
				|VirtualModelRoute {
				   name,
				   llm_policy,
				   routing,
				 }| {
					let (routing, binding) = match routing {
						VirtualModelRouting::Weighted(targets) => (
							routing::VirtualModelRouting::Weighted(targets),
							VirtualRoutingBinding::Weighted,
						),
						VirtualModelRouting::Failover { backend_key } => (
							routing::VirtualModelRouting::Failover,
							VirtualRoutingBinding::Failover { backend_key },
						),
						VirtualModelRouting::Conditional(targets) => {
							let (targets, conditions) = targets
								.into_iter()
								.map(|ConditionalTarget { model, when }| {
									(
										routing::ConditionalTarget {
											model,
											has_condition: when.is_some(),
										},
										when,
									)
								})
								.unzip();
							(
								routing::VirtualModelRouting::Conditional(targets),
								VirtualRoutingBinding::Conditional(conditions),
							)
						},
					};
					(
						routing::VirtualModelRoute { name, routing },
						VirtualBinding {
							llm_policy,
							routing: binding,
						},
					)
				},
			)
			.unzip();
		Self {
			routes: routing::RoutingTable::new(routes, virtual_routes),
			models,
			virtual_models,
			created,
		}
	}
}

#[cfg(feature = "gateway-llm")]
impl ModelRouter {
	pub async fn resolve(&self, req: &mut Request) -> ResolveResult {
		if is_model_list_request(req) {
			return ResolveResult::DirectResponse(self.model_list_response(req));
		}
		let requested_model = match requested_model(req).await {
			Ok(requested_model) => requested_model,
			Err(resp) => return ResolveResult::DirectResponse(*resp),
		};
		req
			.extensions_mut()
			.get_or_insert_with(TransformationMetadata::default)
			.0
			.insert(
				"agentgateway_user_model".to_string(),
				Value::String(requested_model.model.clone()),
			);
		if let Some(id) = self.routes.virtual_model(&requested_model.model) {
			return self
				.resolve_virtual_model(id, &requested_model.model, req, requested_model.location)
				.await;
		}
		tracing::trace!(
			requested_model = %requested_model.model,
			virtual_model_count = self.routes.virtual_models().len(),
			"unable to find declared virtual model; trying concrete model routes",
		);

		match self.resolve_concrete_model(&requested_model.model, false, req) {
			Some(route) => ResolveResult::Backend(route),
			None => ResolveResult::DirectResponse(model_not_found_response()),
		}
	}

	fn model_list_response(&self, req: &Request) -> Response {
		let data = self
			.routes
			.listed_models(|id| {
				let index = self.routes.model_index(id).expect("same routing snapshot");
				model_authorized(&self.models[index], req)
			})
			.into_iter()
			.map(|name| model_list_entry(name, self.created))
			.collect::<Vec<_>>();
		let body = serde_json::json!({
			"data": data,
			"object": "list",
		})
		.to_string();
		::http::Response::builder()
			.status(::http::StatusCode::OK)
			.header(::http::header::CONTENT_TYPE, "application/json")
			.body(http::Body::from(body))
			.expect("LLM model list response is valid")
	}

	async fn resolve_virtual_model(
		&self,
		id: routing::VirtualModelId<'_>,
		name: &str,
		req: &mut Request,
		location: RequestedModelLocation,
	) -> ResolveResult {
		let Some(index) = self.routes.virtual_model_index(id) else {
			return ResolveResult::DirectResponse(llm_error_response(
				::http::StatusCode::INTERNAL_SERVER_ERROR,
				"Routing snapshot mismatch",
				"routing_snapshot_mismatch",
			));
		};
		let binding = &self.virtual_models[index];
		let target = {
			let exec = matches!(&binding.routing, VirtualRoutingBinding::Conditional(_))
				.then(|| cel::Executor::new_request(req));
			self.routes.select_virtual(
				id,
				|index| {
					let VirtualRoutingBinding::Conditional(conditions) = &binding.routing else {
						unreachable!("only conditional routes evaluate conditions");
					};
					conditions[index]
						.as_ref()
						.map(|expr| {
							exec
								.as_ref()
								.expect("conditional evaluator")
								.eval_bool(expr)
						})
						.unwrap_or(true)
				},
				rand::rng,
			)
		};
		let target = match target {
			Ok(routing::VirtualTarget::Model(target)) => target,
			Ok(routing::VirtualTarget::Failover) => {
				let VirtualRoutingBinding::Failover { backend_key } = &binding.routing else {
					unreachable!("failover binding");
				};
				return ResolveResult::Backend(ResolvedBackend {
					backend: RouteBackendReference {
						weight: 1,
						target: BackendReference::Backend(strng::format!("/{}", backend_key)).into(),
						inline_policies: vec![],
					},
					llm_policy: binding.llm_policy.clone(),
				});
			},
			Err(routing::SelectionError::InvalidWeights(err)) => {
				tracing::debug!(%err,"failed to select weighted virtual model target");
				return ResolveResult::DirectResponse(llm_error_response(
					::http::StatusCode::NOT_FOUND,
					&format!("Virtual model {name} could not be resolved"),
					"virtual_model_not_resolved",
				));
			},
			Err(routing::SelectionError::NoMatchingTarget) => {
				return ResolveResult::DirectResponse(llm_error_response(
					::http::StatusCode::BAD_REQUEST,
					&format!("Virtual model {name} did not match any conditional target"),
					"virtual_model_no_matching_target",
				));
			},
			Err(routing::SelectionError::ForeignSnapshot) => {
				return ResolveResult::DirectResponse(llm_error_response(
					::http::StatusCode::INTERNAL_SERVER_ERROR,
					"Routing snapshot mismatch",
					"routing_snapshot_mismatch",
				));
			},
		};
		if let Err(resp) = rewrite_request_model(req, location, target) {
			return ResolveResult::DirectResponse(*resp);
		}
		match self.resolve_concrete_model(target, true, req) {
			Some(route) => ResolveResult::Backend(route),
			None => {
				tracing::debug!(virtual_model=%name,target_model=%target,"virtual model selected target with no declared concrete model");
				ResolveResult::DirectResponse(llm_error_response(
					::http::StatusCode::NOT_FOUND,
					&format!(
						"Virtual model {name} selected target {target}, but no matching model was found"
					),
					"virtual_model_target_not_found",
				))
			},
		}
	}

	fn resolve_concrete_model(
		&self,
		requested_model: &str,
		allow_internal: bool,
		req: &Request,
	) -> Option<ResolvedBackend> {
		let id = self
			.routes
			.resolve_concrete(requested_model, allow_internal, |id| {
				let index = self.routes.model_index(id).expect("same routing snapshot");
				header_matches(&self.models[index].header_matches, req)
			})?;
		let model = &self.models[self.routes.model_index(id)?];
		Some(ResolvedBackend {
			backend: RouteBackendReference {
				weight: 1,
				target: BackendReference::Backend(strng::format!("/{}", model.backend_key)).into(),
				inline_policies: model.backend_policies.clone(),
			},
			llm_policy: model.policies.llm.clone(),
		})
	}
}

#[cfg(feature = "gateway-llm")]
fn model_not_found_response() -> Response {
	llm_error_response(
		::http::StatusCode::NOT_FOUND,
		"Model not found",
		"model_not_found",
	)
}

#[cfg(feature = "gateway-llm")]
fn request_body_too_large_response() -> Response {
	llm_error_response(
		::http::StatusCode::PAYLOAD_TOO_LARGE,
		"LLM request body exceeded the buffer limit",
		"request_body_too_large",
	)
}

#[cfg(feature = "gateway-llm")]
fn llm_error_response(status: ::http::StatusCode, message: &str, code: &str) -> Response {
	::http::Response::builder()
		.status(status)
		.header(::http::header::CONTENT_TYPE, "application/json")
		.body(http::Body::from(
			serde_json::json!({
				"error": {
					"message": message,
					"type": "invalid_request_error",
					"code": code,
				}
			})
			.to_string(),
		))
		.expect("LLM error response is valid")
}

#[cfg(feature = "gateway-llm")]
fn model_authorized(model: &ModelBinding, req: &Request) -> bool {
	let rules = model
		.policies
		.authorization
		.iter()
		.map(|authorization| authorization.0.clone())
		.collect::<Vec<_>>();
	if rules.is_empty() {
		return true;
	}
	crate::http::authorization::HTTPAuthorizationSet::new(
		crate::http::authorization::RuleSets::from_arcs(rules),
	)
	.apply(req)
	.is_ok()
}

#[cfg(feature = "gateway-llm")]
fn model_list_entry(id: &str, created: u64) -> serde_json::Value {
	serde_json::json!({
		"id": id,
		"object": "model",
		"created": created,
		// TODO: this matches some other gateways but seems odd. Should we use the real provide here?
		"owned_by": "openai",
	})
}

#[cfg(feature = "gateway-llm")]
fn is_model_list_request(req: &Request) -> bool {
	let path = req.uri().path().trim_end_matches('/');
	path == "/v1/models"
		|| path
			.strip_prefix("/v1/models")
			.is_some_and(|suffix| suffix.starts_with('/'))
		|| path == "/models"
		|| path
			.strip_prefix("/models")
			.is_some_and(|suffix| suffix.starts_with('/'))
}

#[cfg(feature = "gateway-llm")]
fn header_matches(matches: &[Vec<HeaderMatch>], req: &Request) -> bool {
	if matches.is_empty() {
		return true;
	}
	matches.iter().any(|headers| headers_match(headers, req))
}

#[cfg(feature = "gateway-llm")]
fn headers_match(headers: &[HeaderMatch], req: &Request) -> bool {
	for HeaderMatch { name, value } in headers {
		let Some(have) = http::get_pseudo_or_header_value(name, req) else {
			return false;
		};
		match value {
			HeaderValueMatch::Exact(want) => {
				if have.as_ref() != *want {
					return false;
				}
			},
			HeaderValueMatch::Regex(want) => {
				let Some(have_str) = have.to_str().ok() else {
					return false;
				};
				let Some(m) = want.find(have_str) else {
					return false;
				};
				if !(m.start() == 0 && m.end() == have_str.len()) {
					return false;
				}
			},
			HeaderValueMatch::Invalid => return false,
		}
	}
	true
}

#[cfg(feature = "gateway-llm")]
async fn requested_model(req: &mut Request) -> RouterResult<RequestedModel> {
	let path = req.uri().path();
	if let Some(model) = crate::llm::types::detect::extract_model_from_path(path) {
		return Ok(RequestedModel {
			model: model.to_string(),
			location: RequestedModelLocation::Path,
		});
	}

	let body = body_bytes(req).await?;
	if let Some(boundary) = multipart_boundary(req) {
		let model = multipart_model(&body, &boundary).await?;
		return Ok(RequestedModel {
			model,
			location: RequestedModelLocation::Multipart,
		});
	}
	let body: Value = serde_json::from_slice(&body).map_err(|err| {
		tracing::debug!(%err, "failed to parse LLM request body");
		Box::new(llm_error_response(
			::http::StatusCode::BAD_REQUEST,
			"LLM request body must be valid JSON",
			"invalid_request_body",
		))
	})?;
	let model = body
		.get("model")
		.and_then(Value::as_str)
		.map(ToString::to_string)
		.ok_or_else(|| {
			Box::new(llm_error_response(
				::http::StatusCode::BAD_REQUEST,
				"LLM request body is missing string field 'model'",
				"missing_model",
			))
		})?;
	Ok(RequestedModel {
		model,
		location: RequestedModelLocation::Body(body),
	})
}

#[cfg(feature = "gateway-llm")]
fn rewrite_request_model(
	req: &mut Request,
	location: RequestedModelLocation,
	target: &str,
) -> RouterResult<()> {
	match location {
		RequestedModelLocation::Body(body) => rewrite_body_model(req, body, target),
		RequestedModelLocation::Path => rewrite_uri_model(req, target),
		// TODO: Rewrite multipart model fields for virtual model routing.
		RequestedModelLocation::Multipart => Ok(()),
	}
}

#[cfg(feature = "gateway-llm")]
fn rewrite_body_model(req: &mut Request, mut body: Value, target: &str) -> RouterResult<()> {
	let Some(obj) = body.as_object_mut() else {
		return Ok(());
	};
	obj.insert("model".to_string(), Value::String(target.to_string()));
	let body = serde_json::to_vec(&body).map_err(|err| {
		tracing::debug!(%err, "failed to serialize rewritten LLM request body");
		Box::new(llm_error_response(
			::http::StatusCode::BAD_REQUEST,
			"Failed to rewrite LLM request body model",
			"request_body_rewrite_failed",
		))
	})?;
	*req.body_mut() = http::Body::from(body);
	req.headers_mut().remove(::http::header::CONTENT_LENGTH);
	req.extensions_mut().remove::<cel::BufferedBody>();
	Ok(())
}

#[cfg(feature = "gateway-llm")]
fn rewrite_uri_model(req: &mut Request, target: &str) -> RouterResult<()> {
	let Some(path_and_query) = req.uri().path_and_query() else {
		return Ok(());
	};
	let Some(path) = rewrite_path_model(path_and_query.path(), target) else {
		return Ok(());
	};
	let path_and_query = if let Some(query) = path_and_query.query() {
		format!("{path}?{query}")
	} else {
		path
	};
	let path_and_query = path_and_query.parse().map_err(|err| {
		tracing::debug!(%err, "failed to rewrite LLM request URI model");
		Box::new(llm_error_response(
			::http::StatusCode::BAD_REQUEST,
			"Failed to rewrite LLM request URI model",
			"request_uri_rewrite_failed",
		))
	})?;
	let mut parts = req.uri().clone().into_parts();
	parts.path_and_query = Some(path_and_query);
	*req.uri_mut() = ::http::Uri::from_parts(parts).map_err(|err| {
		tracing::debug!(%err, "failed to rebuild LLM request URI");
		Box::new(llm_error_response(
			::http::StatusCode::BAD_REQUEST,
			"Failed to rewrite LLM request URI model",
			"request_uri_rewrite_failed",
		))
	})?;
	Ok(())
}

#[cfg(feature = "gateway-llm")]
#[cfg(feature = "gateway-llm")]
fn multipart_boundary(req: &Request) -> Option<String> {
	req
		.headers()
		.get(::http::header::CONTENT_TYPE)
		.and_then(|content_type| content_type.to_str().ok())
		.and_then(|content_type| multer::parse_boundary(content_type).ok())
}

#[cfg(feature = "gateway-llm")]
async fn multipart_model(body: &Bytes, boundary: &str) -> RouterResult<String> {
	let stream = stream::once(std::future::ready(Ok::<Bytes, multer::Error>(body.clone())));
	let mut multipart = multer::Multipart::new(stream, boundary);
	while let Some(field) = multipart.next_field().await.map_err(|err| {
		tracing::debug!(%err, "failed to parse LLM multipart request body");
		Box::new(llm_error_response(
			::http::StatusCode::BAD_REQUEST,
			"LLM multipart request body must be valid multipart/form-data",
			"invalid_request_body",
		))
	})? {
		if field.name() == Some("model") {
			return field.text().await.map_err(|err| {
				tracing::debug!(%err, "failed to parse LLM multipart model field");
				Box::new(llm_error_response(
					::http::StatusCode::BAD_REQUEST,
					"LLM multipart request body has invalid string field 'model'",
					"invalid_model",
				))
			});
		}
	}
	Err(Box::new(llm_error_response(
		::http::StatusCode::BAD_REQUEST,
		"LLM multipart request body is missing string field 'model'",
		"missing_model",
	)))
}

#[cfg(feature = "gateway-llm")]
async fn body_bytes(req: &mut Request) -> RouterResult<Bytes> {
	let limit = http::buffer_limit(req);
	if let Some(body) = req.extensions().get::<cel::BufferedBody>() {
		if body.0.len() < limit {
			return Ok(body.0.clone());
		}
		if body.0.len() > limit {
			return Err(Box::new(request_body_too_large_response()));
		}
	}
	let inspect_limit = limit.saturating_add(1);
	let mut body = http::inspect_body_with_limit(req.body_mut(), inspect_limit)
		.await
		.map_err(|err| {
			tracing::debug!(%err, "failed to read LLM request body");
			Box::new(llm_error_response(
				::http::StatusCode::BAD_REQUEST,
				"Failed to read LLM request body",
				"request_body_read_failed",
			))
		})?;
	if body.len() > limit {
		return Err(Box::new(request_body_too_large_response()));
	}
	if body.len() == inspect_limit {
		body.truncate(limit);
	}
	req.extensions_mut().insert(cel::BufferedBody(body.clone()));
	Ok(body)
}

#[cfg(all(test, feature = "gateway-llm"))]
#[path = "model_router_tests.rs"]
mod tests;
