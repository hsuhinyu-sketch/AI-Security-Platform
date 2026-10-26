use std::fmt;
use std::fmt::{Debug, Formatter};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use futures_util::TryFutureExt;
use gateway_mcp::transport::{Inbound, PendingResponses};
use platform_core::prelude::*;
use rmcp::model::{
	ClientJsonRpcMessage, ClientNotification, ClientRequest, JsonRpcMessage, JsonRpcRequest,
	ServerJsonRpcMessage,
};
use rmcp::transport::{TokioChildProcess, Transport};
use tokio::sync::mpsc::Sender;
use tokio::sync::{mpsc, oneshot};
use tracing::{error, warn};

use crate::mcp::mergestream::Messages;
use crate::mcp::upstream::{IncomingRequestContext, UpstreamError};

#[cfg(test)]
#[path = "stdio_tests.rs"]
mod tests;

const RESPONSE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(120);

struct PendingCall {
	sender: oneshot::Sender<ServerJsonRpcMessage>,
	deadline: tokio::time::Instant,
}

pub struct Process {
	sender: mpsc::Sender<(ClientJsonRpcMessage, IncomingRequestContext)>,
	shutdown_tx: platform_core::responsechannel::Sender<(), Option<UpstreamError>>,
	event_stream: AtomicOption<mpsc::Sender<ServerJsonRpcMessage>>,
	pending_requests: Arc<Mutex<PendingResponses<PendingCall>>>,
	alive: Arc<AtomicBool>,
}

impl Process {
	pub fn is_alive(&self) -> bool {
		self.alive.load(Ordering::Acquire)
	}

	pub async fn stop(&self) -> Result<(), UpstreamError> {
		if !self.is_alive() {
			return Ok(());
		}
		let res = self
			.shutdown_tx
			.send_and_wait(())
			.await
			.map_err(|_| UpstreamError::Send)?;
		if let Some(err) = res {
			Err(err)
		} else {
			Ok(())
		}
	}
	pub async fn send_message(
		&self,
		req: JsonRpcRequest<ClientRequest>,
		ctx: &IncomingRequestContext,
	) -> Result<ServerJsonRpcMessage, UpstreamError> {
		if !self.is_alive() {
			return Err(UpstreamError::Recv);
		}
		let req_id = req.id.clone();
		let (sender, receiver) = oneshot::channel();

		{
			let mut pending = self.pending_requests.lock().unwrap();
			// Close and admission share this lock: no waiter can appear after final clear.
			if !self.is_alive() {
				return Err(UpstreamError::Recv);
			}
			if !pending.register(
				req_id.clone(),
				PendingCall {
					sender,
					deadline: tokio::time::Instant::now() + RESPONSE_TIMEOUT,
				},
			) {
				return Err(UpstreamError::InvalidRequest(
					"request ID already pending or connection response capacity exhausted".into(),
				));
			}
		}

		if self
			.sender
			.send((JsonRpcMessage::Request(req), ctx.clone()))
			.await
			.is_err()
		{
			self.pending_requests.lock().unwrap().discard(&req_id);
			return Err(UpstreamError::Send);
		}

		let response = receiver.await.map_err(|_| UpstreamError::Recv)?;
		Ok(response)
	}
	pub async fn get_event_stream(&self) -> Result<Messages, UpstreamError> {
		let _admission = self.pending_requests.lock().unwrap();
		if !self.is_alive() {
			return Err(UpstreamError::Recv);
		}
		let (tx, rx) = tokio::sync::mpsc::channel(10);
		// This transport assumes a single active downstream event-stream consumer per
		// upstream session. Replacing the sender is acceptable for current MCP usage,
		// where one session owns one active GET/SSE stream, but it is not a general
		// multi-subscriber broadcast mechanism.
		self.event_stream.store(Some(Arc::new(tx)));
		Ok(crate::mcp::mergestream::from_receiver(rx))
	}
	pub async fn send_notification(
		&self,
		req: ClientNotification,
		ctx: &IncomingRequestContext,
	) -> Result<(), UpstreamError> {
		if !self.is_alive() {
			return Err(UpstreamError::Send);
		}
		self
			.sender
			.send((JsonRpcMessage::notification(req), ctx.clone()))
			.await
			.map_err(|_| UpstreamError::Send)?;
		Ok(())
	}
}

impl Process {
	pub fn new(mut proc: impl MCPTransport) -> Self {
		let (sender_tx, mut sender_rx) =
			mpsc::channel::<(ClientJsonRpcMessage, IncomingRequestContext)>(10);
		let (shutdown_tx, mut shutdown_rx) =
			platform_core::responsechannel::new::<(), Option<UpstreamError>>(10);
		let pending_requests = Arc::new(Mutex::new(PendingResponses::<PendingCall>::default()));
		let pending_requests_clone = pending_requests.clone();
		let event_stream: AtomicOption<Sender<ServerJsonRpcMessage>> = Default::default();
		let event_stream_send: AtomicOption<Sender<ServerJsonRpcMessage>> = event_stream.clone();
		let alive = Arc::new(AtomicBool::new(true));
		let alive_task = alive.clone();

		tokio::spawn(async move {
			let mut terminal_err = None;
			let mut shutdown_resp = None;
			// Expiry closes the connection rather than reusing an ambiguous request ID.
			// This branch remains live while send/event backpressure suspends the I/O loop.
			let expiry = async {
				loop {
					tokio::time::sleep(std::time::Duration::from_secs(1)).await;
					if pending_requests_clone
						.lock()
						.unwrap()
						.any(|call| call.deadline <= tokio::time::Instant::now())
					{
						break;
					}
				}
			};
			tokio::select! {
								_ = expiry => { terminal_err = Some(UpstreamError::Recv); },
								_ = async {
			loop {
				tokio::select! {
					req = sender_rx.recv() => match req {
						Some((msg, ctx)) => {
							if let Err(e) = proc.send(msg, &ctx).await {
								error!("Error sending message to stdio process: {:?}", e);
								terminal_err = Some(e);
								break;
							}
						},
						None => break,
					},
					msg = proc.receive() => {
						match msg {
							Some(message) => {
								let routed = pending_requests_clone.lock().unwrap().route(message);
								match routed {
									Inbound::Reply(pending, message) => { let _ = pending.sender.send(message); },
									Inbound::Event(message) => {
										if let Some(sender) = event_stream_send.load().as_ref() { let _ = sender.send(message).await; }
									},
									Inbound::UnmatchedReply => warn!("unmatched MCP transport response"),
								}
							},
							None => {
								terminal_err = Some(UpstreamError::StdioShutdown);
								break;
							}
						}
					},
					req = shutdown_rx.recv() => match req {
						Some((_, resp)) => {
							shutdown_resp = Some(resp);
							break;
						},
						None => break,
					},
				}
			}
								} => {},
						}

			{
				let mut pending = pending_requests_clone.lock().unwrap();
				alive_task.store(false, Ordering::Release);
				event_stream_send.store(None);
				pending.clear();
			}

			let close_err =
				match tokio::time::timeout(std::time::Duration::from_secs(5), proc.close()).await {
					Ok(result) => result.err(),
					Err(_) => Some(UpstreamError::Recv),
				};
			if let Some(e) = close_err.as_ref() {
				warn!("Error shutting down stdio process: {:?}", e);
			}
			if let Some(resp) = shutdown_resp {
				let _ = resp.send(terminal_err.or(close_err));
			}
		});

		Self {
			sender: sender_tx,
			shutdown_tx,
			event_stream,
			pending_requests,
			alive,
		}
	}
}

impl Debug for Process {
	fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
		f.debug_struct("Process").finish()
	}
}

pub trait MCPTransport: Send + 'static {
	/// Send a message to the transport
	///
	/// Notice that the future returned by this function should be `Send` and `'static`.
	/// It's because the sending message could be executed concurrently.
	fn send(
		&mut self,
		item: ClientJsonRpcMessage,
		user_headers: &IncomingRequestContext,
	) -> impl Future<Output = Result<(), UpstreamError>> + Send + 'static;

	/// Receive a message from the transport, this operation is sequential.
	fn receive(&mut self) -> impl Future<Output = Option<ServerJsonRpcMessage>> + Send;

	/// Close the transport
	fn close(&mut self) -> impl Future<Output = Result<(), UpstreamError>> + Send;
}

impl MCPTransport for TokioChildProcess {
	fn send(
		&mut self,
		item: ClientJsonRpcMessage,
		_: &IncomingRequestContext,
	) -> impl Future<Output = Result<(), UpstreamError>> + Send + 'static {
		Transport::send(self, item).map_err(Into::into)
	}

	fn receive(&mut self) -> impl Future<Output = Option<ServerJsonRpcMessage>> + Send {
		Transport::receive(self)
	}

	fn close(&mut self) -> impl Future<Output = Result<(), UpstreamError>> + Send {
		Transport::close(self).map_err(Into::into)
	}
}
