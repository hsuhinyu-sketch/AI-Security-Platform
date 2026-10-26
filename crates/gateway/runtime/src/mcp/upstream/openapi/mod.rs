//! Host I/O adapter for the component-owned OpenAPI/MCP bridge.
use crate::client::ResolvedDestination;
use crate::http::sessionpersistence;
use crate::mcp::mergestream::Messages;
use crate::mcp::upstream::{IncomingRequestContext, UpstreamError};
use gateway_mcp::openapi::{self as protocol, Adapter, Dispatch, DispatchError, PreparedCall};
pub use gateway_mcp::openapi::{
	ParseError, UpstreamOpenAPICall, get_server_prefix, parse_openapi_schema,
};
use headers::HeaderMapExt;
use rmcp::model::{ClientRequest, JsonRpcRequest, Tool};
use std::net::SocketAddr;

#[derive(Debug)]
pub struct Handler {
	http_client: super::McpHttpClient,
	adapter: Adapter,
}
impl Handler {
	pub fn new(
		http_client: super::McpHttpClient,
		tools: Vec<(Tool, UpstreamOpenAPICall)>,
		prefix: String,
	) -> Self {
		Self {
			http_client,
			adapter: Adapter::new(tools, prefix),
		}
	}
	pub fn get_session_state(&self) -> sessionpersistence::MCPSession {
		sessionpersistence::MCPSession {
			target_name: Some(self.http_client.target_name().to_owned()),
			session: None,
			backend: self.http_client.pinned_backend(),
		}
	}
	pub fn set_session_id(&self, _: Option<&str>, pinned: Option<SocketAddr>) {
		if let Some(pinned) = pinned {
			self.http_client.pin_backend(ResolvedDestination(pinned));
		}
	}
	pub async fn send_message(
		&self,
		request: JsonRpcRequest<ClientRequest>,
		ctx: &IncomingRequestContext,
	) -> Result<Messages, UpstreamError> {
		match self
			.adapter
			.dispatch(request, &self.http_client.backend().hostport())
			.map_err(|error| match error {
				DispatchError::InvalidMethod(method) => UpstreamError::InvalidMethod(method),
				DispatchError::Conversion(error) => UpstreamError::OpenAPIError(error),
			})? {
			Dispatch::Local(Some(message)) => Ok(Messages::from(message)),
			Dispatch::Local(None) => Ok(Messages::empty()),
			Dispatch::Call { id, name, call } => {
				let value = self.execute(&name, call, ctx).await?;
				Ok(Messages::from(protocol::tool_response(id, value).map_err(
					|error| UpstreamError::OpenAPIError(error.into()),
				)?))
			},
		}
	}
	async fn execute(
		&self,
		name: &str,
		call: PreparedCall,
		ctx: &IncomingRequestContext,
	) -> Result<serde_json::Value, UpstreamError> {
		let mut request = call.request.map(crate::http::Body::from);
		ctx.apply(&mut request)?;
		protocol::apply_headers(request.headers_mut(), call.headers);
		let response = self.http_client.call(request).await?;
		let status = response.status();
		let limit = crate::http::response_buffer_limit(&response);
		let bytes = if status.is_server_error() {
			crate::http::read_body_with_limit(response.into_body(), limit)
				.await
				.map_err(|error| UpstreamError::OpenAPIError(error.into()))?
		} else {
			let encoding = response.headers().typed_get::<headers::ContentEncoding>();
			crate::http::compression::to_bytes_with_decompression(
				response.into_body(),
				encoding.as_ref(),
				limit,
			)
			.await
			.map_err(|error| UpstreamError::OpenAPIError(error.into()))?
			.1
		};
		protocol::decode_tool_response(name, status, &bytes).map_err(UpstreamError::OpenAPIError)
	}
}
