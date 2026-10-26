use ::http::Uri;
use ::http::header::ACCEPT;
use futures::StreamExt;
use gateway_mcp::streamable_http::{self as codec, ResponseError, ResponseKind};
use headers::HeaderMapExt;
use rmcp::model::{ClientJsonRpcMessage, ClientNotification, ClientRequest, JsonRpcRequest};
use rmcp::transport::common::http_header::{EVENT_STREAM_MIME_TYPE, HEADER_SESSION_ID};
use sse_stream::SseStream;

use crate::client::ResolvedDestination;
use crate::http::Request;
use crate::mcp::ClientError;
use crate::mcp::streamablehttp::{StreamableHttpPostResponse, emit_standard_headers};
use crate::mcp::upstream::IncomingRequestContext;
use crate::*;

#[derive(Clone, Debug)]
pub struct Client {
	http_client: super::McpHttpClient,
	uri: Uri,
	session_id: AtomicOption<String>,
}

impl Client {
	pub fn new(http_client: super::McpHttpClient, path: Strng) -> anyhow::Result<Self> {
		let hp = http_client.backend().hostport();
		Ok(Self {
			http_client,
			uri: ("http://".to_string() + &hp + path.as_str()).parse()?,
			session_id: Default::default(),
		})
	}

	pub fn get_session_state(&self) -> http::sessionpersistence::MCPSession {
		let session_id = self.session_id.load().clone();
		let backend = self.http_client.pinned_backend();
		http::sessionpersistence::MCPSession {
			target_name: Some(self.http_client.target_name().to_string()),
			session: session_id.map(|s| s.to_string()),
			backend,
		}
	}

	pub fn set_session_id(&self, s: Option<&str>, pinned: Option<SocketAddr>) {
		self.session_id.store(s.map(|s| Arc::new(s.to_string())));
		if let Some(pinned) = pinned {
			self.http_client.pin_backend(ResolvedDestination(pinned));
		}
	}

	pub fn has_session_id(&self) -> bool {
		self.session_id.load().is_some()
	}

	pub async fn send_request(
		&self,
		req: JsonRpcRequest<ClientRequest>,

		ctx: &IncomingRequestContext,
	) -> Result<StreamableHttpPostResponse, ClientError> {
		let message = ClientJsonRpcMessage::Request(req);
		self.send_message(message, ctx).await
	}
	pub async fn send_notification(
		&self,
		req: ClientNotification,

		ctx: &IncomingRequestContext,
	) -> Result<StreamableHttpPostResponse, ClientError> {
		let message = ClientJsonRpcMessage::notification(req);
		self.send_message(message, ctx).await
	}
	pub(super) async fn send_message(
		&self,
		message: ClientJsonRpcMessage,

		ctx: &IncomingRequestContext,
	) -> Result<StreamableHttpPostResponse, ClientError> {
		let mut req = codec::encode_post(self.uri.clone(), &message)
			.map_err(ClientError::new)?
			.map(crate::http::Body::from);

		self.maybe_insert_session_id(&mut req)?;

		ctx.apply(&mut req).map_err(ClientError::new)?;
		emit_standard_headers(req.headers_mut(), &message);

		let mut resp = self.http_client.call(req).await?;
		crate::mcp::session_security::bound_upstream(&mut resp, ctx)?;

		let kind = match codec::classify_post_response(resp.status(), resp.headers()) {
			Ok(kind) => kind,
			Err(ResponseError::Status(_)) => return Err(ClientError::Status(Box::new(resp))),
			Err(error) => return Err(ClientError::new(error)),
		};
		if kind == ResponseKind::Accepted {
			return Ok(StreamableHttpPostResponse::Accepted);
		}
		let session_id = codec::session_id(resp.headers());
		match kind {
			ResponseKind::Sse => sse_response(resp, session_id),
			ResponseKind::Json => {
				let lim = ctx
					.as_request()
					.extensions()
					.get::<crate::mcp::session_security::SessionAccess>()
					.map_or_else(
						|| crate::http::response_buffer_limit(&resp),
						|a| {
							a.limits
								.max_message_bytes
								.min(crate::http::response_buffer_limit(&resp))
						},
					);
				let content_encoding = resp.headers().typed_get::<headers::ContentEncoding>();
				let body_bytes = crate::http::compression::to_bytes_with_decompression(
					resp.into_body(),
					content_encoding.as_ref(),
					lim,
				)
				.await
				.map_err(ClientError::new)?
				.1;
				match codec::decode_json(&body_bytes).map_err(ClientError::new)? {
					Some(msg) => Ok(StreamableHttpPostResponse::Json(msg, session_id)),
					None => Ok(StreamableHttpPostResponse::Accepted),
				}
			},
			ResponseKind::Accepted => Ok(StreamableHttpPostResponse::Accepted),
		}
	}

	pub async fn send_delete(
		&self,

		ctx: &IncomingRequestContext,
	) -> Result<StreamableHttpPostResponse, ClientError> {
		let mut req = ::http::Request::builder()
			.uri(&self.uri)
			.method(http::Method::DELETE)
			.body(crate::http::Body::empty())
			.map_err(ClientError::new)?;

		self.maybe_insert_session_id(&mut req)?;

		ctx.apply(&mut req).map_err(ClientError::new)?;

		let mut resp = self.http_client.call(req).await?;
		crate::mcp::session_security::bound_upstream(&mut resp, ctx)?;

		if !resp.status().is_success() {
			return Err(ClientError::Status(Box::new(resp)));
		}
		Ok(StreamableHttpPostResponse::Accepted)
	}
	pub async fn get_event_stream(
		&self,
		ctx: &IncomingRequestContext,
	) -> Result<StreamableHttpPostResponse, ClientError> {
		let mut req = ::http::Request::builder()
			.uri(&self.uri)
			.method(http::Method::GET)
			.header(ACCEPT, EVENT_STREAM_MIME_TYPE)
			.body(crate::http::Body::empty())
			.map_err(ClientError::new)?;

		self.maybe_insert_session_id(&mut req)?;

		ctx.apply(&mut req).map_err(ClientError::new)?;

		let mut resp = self.http_client.call(req).await?;
		crate::mcp::session_security::bound_upstream(&mut resp, ctx)?;

		match codec::validate_get_response(resp.status(), resp.headers()) {
			Ok(()) => {},
			Err(ResponseError::Status(_)) => return Err(ClientError::Status(Box::new(resp))),
			Err(error) => return Err(ClientError::new(error)),
		}
		let session_id = codec::session_id(resp.headers());
		sse_response(resp, session_id)
	}

	fn maybe_insert_session_id(&self, req: &mut Request) -> Result<(), ClientError> {
		if let Some(session_id) = self.session_id.load().clone() {
			req.headers_mut().insert(
				HEADER_SESSION_ID,
				session_id.as_ref().parse().map_err(ClientError::new)?,
			);
		}
		Ok(())
	}
}

fn sse_response(
	resp: crate::http::Response,
	session_id: Option<String>,
) -> Result<StreamableHttpPostResponse, ClientError> {
	let content_encoding = resp.headers().typed_get::<headers::ContentEncoding>();
	let (body, _encoding) =
		crate::http::compression::decompress_body(resp.into_body(), content_encoding.as_ref())
			.map_err(ClientError::new)?;
	let event_stream = SseStream::from_bytes_stream(body.into_data_stream()).boxed();
	Ok(StreamableHttpPostResponse::Sse(event_stream, session_id))
}
