//! Host adapter for the protocol-owned aggregation stream.
//!
//! The state machine, terminal fan-in and list projection live in `gateway-mcp`.
//! This module only supplies the Host error type, transport decoding and the
//! request-scoped CEL context used by the trusted admission hooks.
use anyhow::anyhow;
use futures_util::StreamExt;
use rmcp::model::ServerJsonRpcMessage;

use crate::mcp::rbac::CelExecWrapper;
use crate::mcp::streamablehttp::StreamableHttpPostResponse;
use crate::mcp::{ClientError, FailureMode};

pub(crate) use gateway_mcp::merge::MergeFailureMode;

pub(crate) type Messages = gateway_mcp::merge::MessageStream<ClientError>;
pub(crate) type MergeStream = gateway_mcp::merge::MergeStream<ClientError>;
pub(crate) type MergeFn = gateway_mcp::merge::MergeFn<ClientError>;

/// A host-built factory. It receives the request CEL only after the fanout
/// guardrail hook has run, then returns the terminal merge closure.
pub(crate) type MergePlan =
	Box<dyn FnOnce(&CelExecWrapper) -> Box<MergeFn> + Send + Sync + 'static>;

impl From<gateway_mcp::merge::MergeError> for ClientError {
	fn from(error: gateway_mcp::merge::MergeError) -> Self {
		ClientError::new(anyhow!(error))
	}
}

impl From<FailureMode> for MergeFailureMode {
	fn from(value: FailureMode) -> Self {
		match value {
			FailureMode::FailClosed => Self::FailClosed,
			FailureMode::FailOpen => Self::FailOpen,
		}
	}
}

/// Convert a Host SSE receiver into the protocol message stream. The channel is
/// transport ownership; it does not expose an upstream connection.
pub(crate) fn from_receiver(rx: tokio::sync::mpsc::Receiver<ServerJsonRpcMessage>) -> Messages {
	Messages::from_stream(tokio_stream::wrappers::ReceiverStream::new(rx).map(Ok))
}

/// Decode a bounded HTTP response body into protocol messages.
pub(crate) fn from_post_response(
	response: StreamableHttpPostResponse,
) -> Result<Messages, ClientError> {
	match response {
		StreamableHttpPostResponse::Accepted => {
			Err(ClientError::new(anyhow!("unexpected 'accepted' response")))
		},
		StreamableHttpPostResponse::Json(message, _) => Ok(message.into()),
		StreamableHttpPostResponse::Sse(stream, _) => Ok(Messages::from_stream(
			stream
				.filter_map(|item| async {
					item
						.map_err(ClientError::new)
						.and_then(|item| {
							gateway_mcp::streamable_http::decode_sse_data(item.data.as_deref())
								.map_err(ClientError::new)
						})
						.transpose()
				})
				.boxed(),
		)),
	}
}
