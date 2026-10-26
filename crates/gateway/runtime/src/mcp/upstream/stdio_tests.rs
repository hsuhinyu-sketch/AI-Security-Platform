use super::*;
use serde_json::json;
use std::time::Duration;

struct Peer {
	incoming: mpsc::Receiver<ServerJsonRpcMessage>,
	outgoing: mpsc::Sender<ClientJsonRpcMessage>,
}

impl MCPTransport for Peer {
	fn send(
		&mut self,
		item: ClientJsonRpcMessage,
		_: &IncomingRequestContext,
	) -> impl Future<Output = Result<(), UpstreamError>> + Send + 'static {
		let outgoing = self.outgoing.clone();
		async move { outgoing.send(item).await.map_err(|_| UpstreamError::Send) }
	}
	async fn receive(&mut self) -> Option<ServerJsonRpcMessage> {
		self.incoming.recv().await
	}
	async fn close(&mut self) -> Result<(), UpstreamError> {
		Ok(())
	}
}

fn connection() -> (
	Arc<Process>,
	mpsc::Sender<ServerJsonRpcMessage>,
	mpsc::Receiver<ClientJsonRpcMessage>,
) {
	let (incoming, receiver) = mpsc::channel(4);
	let (sender, outgoing) = mpsc::channel(4);
	(
		Arc::new(Process::new(Peer {
			incoming: receiver,
			outgoing: sender,
		})),
		incoming,
		outgoing,
	)
}

fn call(
	process: Arc<Process>,
	id: i64,
) -> tokio::task::JoinHandle<Result<ServerJsonRpcMessage, UpstreamError>> {
	tokio::spawn(async move {
		let request = serde_json::from_value(
			json!({"jsonrpc":"2.0","id":id,"method":"tools/call","params":{"name":"echo","arguments":{}}}),
		)
		.unwrap();
		let (parts, _) = crate::http::Request::new(crate::http::Body::empty()).into_parts();
		process
			.send_message(request, &IncomingRequestContext::new(&parts))
			.await
	})
}

#[tokio::test]
async fn peer_error_completes_the_original_call_and_does_not_become_an_event() {
	let (process, incoming, mut outgoing) = connection();
	let mut events = process.get_event_stream().await.unwrap();
	let pending = call(process.clone(), 7);
	tokio::time::timeout(Duration::from_secs(5), outgoing.recv())
		.await
		.unwrap()
		.unwrap();
	incoming
		.send(
			serde_json::from_value(
				json!({"jsonrpc":"2.0","id":7,"error":{"code":-32602,"message":"denied by peer"}}),
			)
			.unwrap(),
		)
		.await
		.unwrap();
	let response = tokio::time::timeout(Duration::from_secs(5), pending)
		.await
		.unwrap()
		.unwrap()
		.unwrap();
	assert!(matches!(response, ServerJsonRpcMessage::Error(error) if error.error.code.0 == -32602));
	process.stop().await.unwrap();
	use futures_util::StreamExt;
	assert!(events.next().await.is_none());
}

#[tokio::test]
async fn duplicate_id_does_not_send_or_replace_the_original_waiter() {
	let (process, incoming, mut outgoing) = connection();
	let first = call(process.clone(), 7);
	tokio::time::timeout(Duration::from_secs(5), outgoing.recv())
		.await
		.unwrap()
		.unwrap();
	let duplicate = tokio::time::timeout(Duration::from_secs(5), call(process.clone(), 7))
		.await
		.unwrap()
		.unwrap();
	assert!(matches!(duplicate, Err(UpstreamError::InvalidRequest(_))));
	assert!(outgoing.try_recv().is_err());
	incoming
		.send(serde_json::from_value(json!({"jsonrpc":"2.0","id":7,"result":{}})).unwrap())
		.await
		.unwrap();
	assert!(matches!(
		tokio::time::timeout(Duration::from_secs(5), first)
			.await
			.unwrap()
			.unwrap()
			.unwrap(),
		ServerJsonRpcMessage::Response(_)
	));
	process.stop().await.unwrap();
}

#[tokio::test]
async fn shutdown_wakes_pending_call_with_failure() {
	let (process, _incoming, mut outgoing) = connection();
	let pending = call(process.clone(), 7);
	tokio::time::timeout(Duration::from_secs(5), outgoing.recv())
		.await
		.unwrap()
		.unwrap();
	process.stop().await.unwrap();
	let result = tokio::time::timeout(Duration::from_secs(5), pending)
		.await
		.unwrap()
		.unwrap();
	assert!(matches!(result, Err(UpstreamError::Recv)));
}

#[tokio::test(start_paused = true)]
async fn cancelled_waiters_keep_id_reserved_until_response_deadline_closes_connection() {
	let (process, _incoming, mut outgoing) = connection();
	let first = call(process.clone(), 7);
	outgoing.recv().await.unwrap();
	first.abort();
	assert!(first.await.unwrap_err().is_cancelled());
	let duplicate = call(process.clone(), 7).await.unwrap();
	assert!(matches!(duplicate, Err(UpstreamError::InvalidRequest(_))));
	assert!(outgoing.try_recv().is_err());
	tokio::time::advance(RESPONSE_TIMEOUT + Duration::from_secs(1)).await;
	tokio::task::yield_now().await;
	assert!(!process.is_alive());
	assert!(!process.pending_requests.lock().unwrap().any(|_| true));
	assert!(matches!(
		call(process.clone(), 7).await.unwrap(),
		Err(UpstreamError::Recv)
	));
}

#[tokio::test(start_paused = true)]
async fn response_capacity_counts_cancelled_requests_and_never_dispatches_overflow() {
	let (process, _incoming, mut outgoing) = connection();
	for id in 0..gateway_mcp::transport::MAX_PENDING_RESPONSES {
		let pending = call(process.clone(), id as i64);
		outgoing.recv().await.unwrap();
		pending.abort();
		let _ = pending.await;
	}
	assert!(matches!(
		call(process.clone(), 999).await.unwrap(),
		Err(UpstreamError::InvalidRequest(_))
	));
	assert!(outgoing.try_recv().is_err());
	process.stop().await.unwrap();
	assert!(!process.pending_requests.lock().unwrap().any(|_| true));
}

#[tokio::test(start_paused = true)]
async fn expiry_wakes_live_waiters_even_when_transport_send_is_backpressured() {
	let (process, _incoming, _outgoing) = connection();
	// Peer outgoing capacity is four: the fifth send suspends the driver's I/O loop.
	let pending = (0..6)
		.map(|id| call(process.clone(), id))
		.collect::<Vec<_>>();
	for _ in 0..8 {
		tokio::task::yield_now().await;
	}
	tokio::time::advance(RESPONSE_TIMEOUT + Duration::from_secs(1)).await;
	for call in pending {
		assert!(matches!(call.await.unwrap(), Err(UpstreamError::Recv)));
	}
	assert!(!process.is_alive());
}

#[tokio::test]
async fn concurrent_shutdown_does_not_admit_waiters_after_final_clear() {
	let (process, _incoming, mut outgoing) = connection();
	let drain = tokio::spawn(async move { while outgoing.recv().await.is_some() {} });
	let requests = (0..128)
		.map(|id| call(process.clone(), id))
		.collect::<Vec<_>>();
	process.stop().await.unwrap();
	for request in requests {
		let result = tokio::time::timeout(Duration::from_secs(5), request)
			.await
			.unwrap()
			.unwrap();
		assert!(result.is_err());
	}
	assert!(!process.pending_requests.lock().unwrap().any(|_| true));
	assert!(process.get_event_stream().await.is_err());
	tokio::time::timeout(Duration::from_secs(5), drain)
		.await
		.unwrap()
		.unwrap();
}
