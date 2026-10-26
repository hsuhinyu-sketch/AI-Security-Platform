use ::http::Uri;
use ::http::header::{ACCEPT, CONTENT_TYPE};
use anyhow::anyhow;
use futures_core::stream::BoxStream;
use futures_util::{StreamExt, TryFutureExt};
use headers::HeaderMapExt;
use rmcp::model::{
	ClientJsonRpcMessage, ClientNotification, ClientRequest, JsonRpcRequest, ServerJsonRpcMessage,
};
use rmcp::transport::common::http_header::EVENT_STREAM_MIME_TYPE;
use sse_stream::{Sse, SseStream};

use crate::client::ResolvedDestination;
use crate::mcp::ClientError;
use crate::mcp::mergestream::Messages;
use crate::mcp::streamablehttp::StreamableHttpPostResponse;
use crate::mcp::upstream::stdio::Process;
use crate::mcp::upstream::{IncomingRequestContext, UpstreamError};
use crate::*;

type BoxedSseStream = BoxStream<'static, Result<Sse, sse_stream::Error>>;

#[derive(Debug, Clone)]
struct ClientCore {
	http_client: super::McpHttpClient,
	uri: Uri,
}

#[derive(Debug)]
pub struct Client {
	client: ClientCore,

	active_stream: Arc<tokio::sync::Mutex<Option<Arc<super::stdio::Process>>>>,
}

struct SseClient {
	client: ClientCore,

	events: BoxedSseStream,
}

impl crate::mcp::upstream::stdio::MCPTransport for SseClient {
	async fn receive(&mut self) -> Option<ServerJsonRpcMessage> {
		loop {
			let raw = self.events.next().await?.ok()?;
			match gateway_mcp::streamable_http::decode_sse_data(raw.data.as_deref()) {
				Ok(Some(message)) => return Some(message),
				Ok(None) => continue,
				Err(error) => {
					// Preserve legacy transport behavior; the shared decoder does not
					// decide whether a caller skips or terminates on malformed data.
					tracing::warn!("failed to deserialize server message: {error}");
					continue;
				},
			}
		}
	}
	fn send(
		&mut self,
		item: ClientJsonRpcMessage,
		ctx: &IncomingRequestContext,
	) -> impl Future<Output = Result<(), UpstreamError>> + Send + 'static {
		let ctx = ctx.clone();
		let client = self.client.clone();
		Box::pin(async move { client.send_message(item, &ctx).map_err(Into::into).await })
	}
	async fn close(&mut self) -> Result<(), UpstreamError> {
		Ok(())
	}
}

impl ClientCore {
	async fn send_message(
		&self,
		message: ClientJsonRpcMessage,
		ctx: &IncomingRequestContext,
	) -> Result<(), ClientError> {
		let body = serde_json::to_vec(&message).map_err(ClientError::new)?;

		let mut req = ::http::Request::builder()
			.uri(&self.uri)
			.method(http::Method::POST)
			.header(CONTENT_TYPE, "application/json")
			.body(body.into())
			.map_err(ClientError::new)?;

		ctx.apply(&mut req).map_err(ClientError::new)?;

		let resp = self.http_client.call(req).await.map_err(ClientError::new)?;

		if !resp.status().is_success() {
			return Err(ClientError::Status(Box::new(resp)));
		}
		Ok(())
	}
}

impl ClientCore {
	async fn establish_sse(
		&self,
		ctx: &IncomingRequestContext,
	) -> Result<StreamableHttpPostResponse, ClientError> {
		let mut req = ::http::Request::builder()
			.uri(&self.uri)
			.method(http::Method::GET)
			.header(ACCEPT, EVENT_STREAM_MIME_TYPE)
			.body(http::Body::empty())
			.map_err(ClientError::new)?;

		ctx.apply(&mut req).map_err(ClientError::new)?;

		let resp = self.http_client.call(req).await?;

		if resp.status() == http::StatusCode::ACCEPTED {
			return Err(ClientError::new(anyhow!("expected an SSE stream")));
		}

		if !resp.status().is_success() {
			return Err(ClientError::Status(Box::new(resp)));
		}

		let content_type = resp.headers().get(CONTENT_TYPE);

		match content_type {
			Some(ct) if ct.as_bytes().starts_with(EVENT_STREAM_MIME_TYPE.as_bytes()) => {
				let content_encoding = resp.headers().typed_get::<headers::ContentEncoding>();
				let (body, _encoding) =
					crate::http::compression::decompress_body(resp.into_body(), content_encoding.as_ref())
						.map_err(ClientError::new)?;
				let event_stream = SseStream::from_bytes_stream(body.into_data_stream()).boxed();
				Ok(StreamableHttpPostResponse::Sse(event_stream, None))
			},
			_ => Err(ClientError::new(anyhow!(
				"establish sse: unexpected content type: {:?}",
				content_type
			))),
		}
	}
}
impl Client {
	pub fn new(http_client: super::McpHttpClient, path: Strng) -> Self {
		let hp = http_client.backend().hostport();
		let uri = format!("http://{}{}", hp, path);
		let uri = uri.parse().expect("invalid URI");
		Self {
			client: ClientCore { http_client, uri },
			active_stream: Default::default(),
		}
	}

	pub fn get_session_state(&self) -> http::sessionpersistence::MCPSession {
		http::sessionpersistence::MCPSession {
			target_name: Some(self.client.http_client.target_name().to_string()),
			session: None,
			backend: self.client.http_client.pinned_backend(),
		}
	}

	pub fn set_session_id(&self, _: Option<&str>, pinned: Option<SocketAddr>) {
		if let Some(pinned) = pinned {
			self
				.client
				.http_client
				.pin_backend(ResolvedDestination(pinned));
		}
	}

	pub async fn stop(&self) -> Result<(), UpstreamError> {
		let mut stream = self.active_stream.lock().await;
		if let Some(s) = stream.as_ref() {
			s.stop().await?;
		}
		*stream = None;
		Ok(())
	}
	async fn get_stream(&self, ctx: &IncomingRequestContext) -> Result<Arc<Process>, UpstreamError> {
		let mut stream = self.active_stream.lock().await;
		if let Some(s) = stream.clone() {
			return Ok(s);
		}

		let (post_uri, sse) = self.establish_sse(ctx).await?;
		let transport = SseClient {
			client: ClientCore {
				uri: post_uri,
				..self.client.clone()
			},
			events: sse,
		};

		let proc = Arc::new(Process::new(transport));
		*stream = Some(proc.clone());
		Ok(proc)
	}
	async fn establish_sse(
		&self,
		ctx: &IncomingRequestContext,
	) -> Result<(Uri, BoxedSseStream), ClientError> {
		let res = Box::pin(self.client.establish_sse(ctx)).await?;
		let mut s = match res {
			StreamableHttpPostResponse::Sse(s, _) => s,
			_ => return Err(ClientError::new(anyhow!("unexpected return typ"))),
		};
		let parsed = loop {
			let sse = futures_util::StreamExt::next(&mut s)
				.await
				.ok_or_else(|| ClientError::new(anyhow!("unexpected empty stream")))?
				.map_err(ClientError::new)?;
			let Some("endpoint") = sse.event.as_deref() else {
				continue;
			};
			let ep = sse.data.unwrap_or_default();
			let parsed = gateway_mcp::transport::message_endpoint(self.client.uri.clone(), &ep)
				.map_err(ClientError::new)?;
			break parsed;
		};
		Ok((parsed, s))
	}
	pub async fn connect_to_event_stream(
		&self,
		ctx: &IncomingRequestContext,
	) -> Result<Messages, UpstreamError> {
		let stream = self.get_stream(ctx).await?;
		stream.get_event_stream().await
	}
	pub async fn send_message(
		&self,
		req: JsonRpcRequest<ClientRequest>,
		ctx: &IncomingRequestContext,
	) -> Result<ServerJsonRpcMessage, UpstreamError> {
		let stream = self.get_stream(ctx).await?;
		stream.send_message(req, ctx).await
	}

	pub async fn send_notification(
		&self,
		req: ClientNotification,
		ctx: &IncomingRequestContext,
	) -> Result<(), UpstreamError> {
		let stream = self.get_stream(ctx).await?;
		stream.send_notification(req, ctx).await
	}
}
