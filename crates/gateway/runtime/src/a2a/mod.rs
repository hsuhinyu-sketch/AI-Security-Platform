#[cfg(feature = "gateway-a2a")]
use http::{Request, header};
use platform_core::strng::Strng;
#[cfg(feature = "gateway-a2a")]
use serde_json::Value;
#[cfg(feature = "gateway-a2a")]
use tracing::warn;

#[cfg(feature = "gateway-a2a")]
use crate::http::{Body, Response, filters};
#[cfg(feature = "gateway-a2a")]
use crate::json;
#[cfg(feature = "gateway-a2a")]
use crate::types::agent::A2aPolicy;

#[cfg(feature = "gateway-a2a")]
pub(crate) mod objects;
/// Internal marker installed only by an object-protected backend's response path.
#[derive(Clone)]
#[cfg(feature = "gateway-a2a")]
pub(crate) struct ProtectedCard;
#[derive(Clone)]
#[cfg(feature = "gateway-a2a")]
pub(crate) struct PushEnabled;

#[cfg(feature = "gateway-a2a")]
pub async fn apply_to_request(_: &A2aPolicy, req: &mut Request<Body>) -> RequestType {
	// Possible options are POST a JSON-RPC message or GET /.well-known/agent.json
	// For agent card, we will process only on the response
	classify_request(req).await
}

#[cfg(feature = "gateway-a2a")]
async fn classify_request(req: &mut Request<Body>) -> RequestType {
	// Possible options are POST a JSON-RPC message or GET /.well-known/agent.json
	// For agent card, we will process only on the response
	match gateway_a2a::classify_http(req.method(), req.uri().path()) {
		gateway_a2a::HttpKind::AgentCard => {
			// In case of rewrite, use the original so we know where to send them back to
			let uri = req
				.extensions()
				.get::<filters::OriginalUrl>()
				.map(|u| u.0.clone())
				.unwrap_or_else(|| req.uri().clone());
			let uri = crate::http::x_headers::apply_forwarded_scheme(uri, req.headers());
			RequestType::AgentCard(uri)
		},
		gateway_a2a::HttpKind::Rpc => {
			if !matches!(
				crate::http::classify_content_type(req.headers()),
				crate::http::WellKnownContentTypes::Json
			) {
				return RequestType::Invalid;
			}
			match inspect_method(req).await {
				Ok(method) if gateway_a2a::supported_method(&method) => RequestType::Call(method),
				Ok(_) => RequestType::Unknown,
				Err(error) => {
					warn!(%error, "invalid A2A envelope");
					RequestType::Invalid
				},
			}
		},
		gateway_a2a::HttpKind::Unknown => RequestType::Unknown,
	}
}

#[derive(Debug, Clone, Default)]
pub enum RequestType {
	#[default]
	Unknown,
	Invalid,
	AgentCard(http::Uri),
	Call(Strng),
}

#[cfg(feature = "gateway-a2a")]
pub async fn apply_to_response(
	pol: Option<&A2aPolicy>,
	a2a_type: RequestType,
	resp: &mut Response,
) -> anyhow::Result<()> {
	if pol.is_none() {
		return Ok(());
	};
	match a2a_type {
		RequestType::AgentCard(uri) => {
			let protected = resp.extensions().get::<ProtectedCard>().is_some();
			// For agent card, we need to mutate the request to insert the proper URL to reach it
			// through the gateway.
			let buffer_limit = crate::http::response_buffer_limit(resp);
			let body = std::mem::replace(resp.body_mut(), Body::empty());
			let Ok(mut agent_card) = json::from_body_with_limit::<Value>(body, buffer_limit).await else {
				anyhow::bail!("agent card invalid JSON");
			};
			gateway_a2a::rewrite_card(
				&mut agent_card,
				uri,
				protected,
				resp.extensions().get::<PushEnabled>().is_some(),
			)?;
			if protected {
				resp.headers_mut().insert(
					header::CACHE_CONTROL,
					"private, no-store".parse().expect("constant"),
				);
				for header in ["etag", "digest", "content-digest", "content-md5"] {
					resp.headers_mut().remove(header);
				}
			}

			resp.headers_mut().remove(header::CONTENT_LENGTH);
			*resp.body_mut() = json::to_body(agent_card)?;
			Ok(())
		},
		RequestType::Call(_) => {
			// We don't currently inspect A2A responses.
			Ok(())
		},
		RequestType::Unknown | RequestType::Invalid => Ok(()),
	}
}

#[cfg(feature = "gateway-a2a")]
async fn inspect_method(req: &mut Request<Body>) -> anyhow::Result<Strng> {
	// Bounded inspection preserves the original wire body for dispatch.
	let rpc: gateway_a2a::RequestEnvelope = json::inspect_body(req).await?;
	rpc.validated_method().map(Into::into)
}

#[cfg(test)]
#[path = "tests.rs"]
#[cfg(feature = "gateway-a2a")]
mod tests;
