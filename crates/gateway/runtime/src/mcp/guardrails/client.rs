use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;

use ::http::HeaderName;
use bytes::Bytes;
use prost_wkt_types::Struct;
use rmcp::model::{ErrorCode, ErrorData, ServerResult};
use serde_json::Value;
use tracing::{debug, warn};

use crate::cel;
use crate::http::envoy_proto_common::json_to_prost_value;
use crate::http::ext_proc::GrpcReferenceChannel;
use crate::http::filters::BackendRequestTimeout;
use crate::mcp::guardrails::wire::ext_mcp_client::ExtMcpClient;
use crate::mcp::guardrails::wire::{
	self, AuthorizationError, McpRequest, McpResponse, mcp_request_result, mcp_response_result,
};
use crate::mcp::guardrails::{
	FailureMode, HeaderFilter, McpGuardrailsDynamicMetadata, Outcome, Remote,
};
use crate::mcp::upstream::IncomingRequestContext;
use crate::proxy::httpproxy::PolicyClient;

fn with_default_timeout<T>(msg: T) -> tonic::Request<T> {
	let mut req = tonic::Request::new(msg);
	req
		.extensions_mut()
		.insert(BackendRequestTimeout(Duration::from_secs(10)));
	req
}

pub(crate) async fn check_request<P: serde::de::DeserializeOwned>(
	remote: &Remote,
	method: &str,
	backends: &[String],
	body: Option<&mut Bytes>,
	req_ctx: &mut IncomingRequestContext,
	client: &PolicyClient,
) -> Outcome<P> {
	let mcp_request = body.as_deref().cloned();
	let http_req = req_ctx.as_request();
	let metadata_context = build_metadata(&remote.metadata, &http_req);
	let headers = collect_headers(&remote.request_headers, &http_req);
	let req = McpRequest {
		service_names: backends.to_vec(),
		method: method.to_string(),
		metadata_context,
		mcp_request,
		headers,
	};
	let mut grpc = build_client(remote, client.clone());
	let tonic_req = with_default_timeout(req);
	let resp = match grpc.check_request(tonic_req).await {
		Ok(resp) => resp.into_inner(),
		Err(status) => return on_grpc_error(remote, method, backends, "checkRequest", status),
	};
	let wire::McpRequestResult {
		result,
		header_mutation,
		metadata,
	} = resp;
	match result {
		Some(mcp_request_result::Result::Pass(_)) => {
			apply_request_side(method, backends, header_mutation, metadata, req_ctx);
			Outcome::Pass
		},
		Some(mcp_request_result::Result::Mutated(b)) => match body {
			// `*/list` carries no params to rewrite; the mutation is discarded by
			// contract before validation, so its bytes can never fail the call.
			// Header/metadata side effects still apply; list filtering is a
			// response-phase concern.
			None => {
				debug!(
					method,
					?backends,
					"mcpGuardrails: ignoring mutation on request without body"
				);
				apply_request_side(method, backends, header_mutation, metadata, req_ctx);
				Outcome::Pass
			},
			Some(dest) => match serde_json::from_slice::<P>(&b) {
				Ok(p) => {
					apply_request_side(method, backends, header_mutation, metadata, req_ctx);
					*dest = b;
					Outcome::Mutated(p)
				},
				Err(e) => on_protocol_violation(remote, method, backends, &format!("mutated decode: {e}")),
			},
		},
		Some(mcp_request_result::Result::Error(e)) => {
			Outcome::Reject(translate_error(method, backends, e))
		},
		None => on_protocol_violation(remote, method, backends, "missing result oneof"),
	}
}

// Header mutations + metadata flow into the request context so they reach the
// upstream and request-side CEL. Callers skip this on reject: partial side
// effects on a denied request would surprise.
fn apply_request_side(
	method: &str,
	backends: &[String],
	header_mutation: Option<wire::HeaderMutation>,
	metadata: Option<Struct>,
	req_ctx: &mut IncomingRequestContext,
) {
	if let Some(hm) = header_mutation {
		apply_header_mutation(method, backends, hm, req_ctx.headers_mut());
	}
	if let Some(m) = metadata {
		merge_metadata_into_extensions(method, backends, &m, req_ctx.extensions_mut());
	}
}

fn apply_header_mutation(
	method: &str,
	backends: &[String],
	hm: wire::HeaderMutation,
	headers: &mut ::http::HeaderMap,
) {
	// Multiple `set` entries with the same name replace that header with the list
	// they form: the first occurrence overwrites any existing values, the rest
	// append. `seen` is only marked after a successful write, so a skipped (invalid)
	// first entry doesn't turn a later valid one into a stray append.
	let mut seen: HashSet<HeaderName> = HashSet::new();
	for h in hm.set {
		let name = match HeaderName::from_bytes(h.key.as_bytes()) {
			Ok(n) => n,
			Err(_) => {
				warn!(method, ?backends, key = %h.key, "mcpGuardrails: header_mutation.set: invalid header name");
				continue;
			},
		};
		let v = match ::http::HeaderValue::from_maybe_shared(h.value) {
			Ok(v) => v,
			Err(_) => {
				warn!(method, ?backends, key = %name, "mcpGuardrails: header_mutation.set: invalid header value");
				continue;
			},
		};
		if seen.insert(name.clone()) {
			headers.insert(name, v);
		} else {
			headers.append(name, v);
		}
	}
	for name in hm.remove {
		match HeaderName::from_bytes(name.as_bytes()) {
			Ok(n) => {
				headers.remove(&n);
			},
			Err(_) => {
				warn!(method, ?backends, key = %name, "mcpGuardrails: header_mutation.remove: invalid header name");
			},
		}
	}
}

fn merge_metadata_into_extensions(
	method: &str,
	backends: &[String],
	s: &Struct,
	ext: &mut ::http::Extensions,
) {
	let mut acc = ext
		.remove::<McpGuardrailsDynamicMetadata>()
		.unwrap_or_default();
	for (k, v) in &s.fields {
		match serde_json::to_value(v) {
			Ok(j) => {
				acc.0.insert(k.clone(), j);
			},
			Err(e) => {
				warn!(method, ?backends, key = %k, error = %e, "mcpGuardrails: metadata: failed to convert value");
			},
		}
	}
	if !acc.0.is_empty() {
		ext.insert(acc);
	}
}

pub(crate) async fn check_response(
	remote: &Remote,
	method: &str,
	backends: &[String],
	body: &mut Bytes,
	req_ctx: &IncomingRequestContext,
	client: &PolicyClient,
) -> Outcome<ServerResult> {
	let mcp_response = body.clone();
	let metadata_context = (!remote.metadata.is_empty())
		.then(|| build_metadata(&remote.metadata, &req_ctx.as_request()))
		.flatten();
	let req = McpResponse {
		service_names: backends.to_vec(),
		method: method.to_string(),
		metadata_context,
		mcp_response,
	};
	let mut grpc = build_client(remote, client.clone());
	let tonic_req = with_default_timeout(req);
	let result = match grpc.check_response(tonic_req).await {
		Ok(resp) => resp.into_inner().result,
		Err(status) => return on_grpc_error(remote, method, backends, "checkResponse", status),
	};
	match result {
		Some(mcp_response_result::Result::Pass(_)) => Outcome::Pass,
		Some(mcp_response_result::Result::Mutated(b)) => {
			match serde_json::from_slice::<ServerResult>(&b) {
				Ok(r) => {
					*body = b;
					Outcome::Mutated(r)
				},
				Err(e) => on_protocol_violation(remote, method, backends, &format!("mutated decode: {e}")),
			}
		},
		Some(mcp_response_result::Result::Error(e)) => {
			Outcome::Reject(translate_error(method, backends, e))
		},
		None => on_protocol_violation(remote, method, backends, "missing result oneof"),
	}
}

fn build_metadata(
	cfg: &HashMap<String, Arc<cel::Expression>>,
	req: &crate::http::Request,
) -> Option<Struct> {
	if cfg.is_empty() {
		return None;
	}
	let exec = cel::Executor::new_request(req);
	let fields = cfg
		.iter()
		.filter_map(|(k, expr)| match eval_to_value(&exec, expr) {
			Ok(v) => Some((k.clone(), v)),
			Err(e) => {
				debug!(key = %k, error = %e, "mcpGuardrails: metadata CEL expression failed; skipping");
				None
			},
		})
		.collect();
	Some(Struct { fields })
}

fn eval_to_value(
	exec: &cel::Executor<'_>,
	expr: &cel::Expression,
) -> anyhow::Result<prost_wkt_types::Value> {
	let v = exec.eval(expr)?;
	let js = v.json().map_err(|_| cel::Error::JsonConvert)?;
	Ok(json_to_prost_value(js)?)
}

fn build_client(remote: &Remote, client: PolicyClient) -> ExtMcpClient<GrpcReferenceChannel> {
	ExtMcpClient::new(GrpcReferenceChannel {
		target: remote.target.clone(),
		client: client.with_outbound(
			crate::telemetry::metrics::OutboundCallKind::Policy,
			crate::telemetry::metrics::OutboundCallSubtype::Guardrail,
		),
		policies: Arc::new(remote.policies.clone()),
	})
}

// Snapshot the incoming request headers for the policy server, applying the
// configured allow/deny filter. Like ext_authz, pseudo-headers are forwarded
// too. Values are raw bytes: header values are not guaranteed to be UTF-8.
fn collect_headers(filter: &HeaderFilter, req: &crate::http::Request) -> Vec<wire::McpHeader> {
	let mut out = Vec::new();
	// Pseudo-headers are single-valued.
	for (pseudo, value) in crate::http::get_request_pseudo_headers(req) {
		if filter.allows(&pseudo) {
			out.push(wire::McpHeader {
				key: pseudo.to_string(),
				value: value.into_bytes(),
			});
		}
	}
	// Real headers: one entry per value to preserve multi-value semantics.
	for (name, value) in req.headers() {
		if filter.allows(&crate::http::HeaderOrPseudo::Header(name.clone())) {
			out.push(wire::McpHeader {
				key: name.as_str().to_string(),
				value: value.as_bytes().to_vec(),
			});
		}
	}
	out
}

// mcpGuardrails authorization outcomes that have no standard JSON-RPC/MCP code map to
// application-defined codes in the server-error range (-32000..=-32099).
// -32002 is intentionally skipped: rmcp assigns it to RESOURCE_NOT_FOUND.
const PERMISSION_DENIED: ErrorCode = ErrorCode(-32001);
const RESOURCE_EXHAUSTED: ErrorCode = ErrorCode(-32003);

fn translate_error(method: &str, backends: &[String], e: AuthorizationError) -> ErrorData {
	use wire::authorization_error::Code as C;
	let code = match C::try_from(e.code).unwrap_or(C::Unknown) {
		C::PermissionDenied => PERMISSION_DENIED,
		C::ResourceExhausted => RESOURCE_EXHAUSTED,
		C::Invalid => ErrorCode::INVALID_REQUEST,
		C::Unknown => ErrorCode::INTERNAL_ERROR,
	};
	let data = e.mcp_error.as_deref().and_then(|b| {
		serde_json::from_slice::<Value>(b)
			.map_err(
				|err| warn!(method, ?backends, error = %err, "mcpGuardrails: ignoring unparseable mcp_error payload"),
			)
			.ok()
	});
	ErrorData::new(code, e.reason, data)
}

fn on_grpc_error<T>(
	remote: &Remote,
	method: &str,
	backends: &[String],
	rpc: &str,
	status: tonic::Status,
) -> Outcome<T> {
	debug!(method, ?backends, rpc, code = ?status.code(), message = %status.message(), "mcpGuardrails: gRPC error");
	match remote.failure_mode {
		FailureMode::FailOpen => Outcome::Pass,
		FailureMode::FailClosed => Outcome::Reject(ErrorData::new(
			ErrorCode::INTERNAL_ERROR,
			format!("mcpGuardrails {rpc} failed: {}", status.message()),
			None,
		)),
	}
}

fn on_protocol_violation<T>(
	remote: &Remote,
	method: &str,
	backends: &[String],
	reason: &str,
) -> Outcome<T> {
	warn!(
		method,
		?backends,
		reason,
		"mcpGuardrails: protocol violation"
	);
	match remote.failure_mode {
		FailureMode::FailOpen => Outcome::Pass,
		FailureMode::FailClosed => Outcome::Reject(ErrorData::new(
			ErrorCode::INTERNAL_ERROR,
			format!("mcpGuardrails protocol violation: {reason}"),
			None,
		)),
	}
}
