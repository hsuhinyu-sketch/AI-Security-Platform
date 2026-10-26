use super::*;
use bytes::Bytes;
use http_body::Frame;
use http_body_util::BodyExt;
use std::sync::atomic::{AtomicUsize, Ordering};

fn scope() -> ExecutionScope {
	let config=serde_json::from_value(serde_json::json!({"namespace":uuid::Uuid::new_v4().to_string(),"maxDurationSeconds":30,"maxModelCalls":1,"maxToolCalls":1,"maxAttempts":2,"maxConcurrent":1})).unwrap();
	let identity = security_pipeline::GatewayIdentity {
		user_id: Some("alice".into()),
		tenant_id: Some("tenant-a".into()),
		..Default::default()
	};
	let owner = VerifiedOwner::from_identity(&identity, "https://issuer.example").unwrap();
	let handle = InMemoryExecutionBudgetStore::default()
		.create(&config, owner, "configuration".into())
		.unwrap();
	let action = security_pipeline::model_invoke_for_identity(
		uuid::Uuid::new_v4().to_string(),
		identity,
		"local-model",
	);
	ExecutionScope {
		handle,
		fingerprint: "configuration".into(),
		logical: Default::default(),
		action: Arc::new(action),
	}
}
struct Source {
	mode: &'static str,
	handle: ExecutionHandle,
	polls: Arc<AtomicUsize>,
	drops: Arc<AtomicUsize>,
}
impl Drop for Source {
	fn drop(&mut self) {
		self.drops.fetch_add(1, Ordering::SeqCst);
	}
}
impl http_body::Body for Source {
	type Data = Bytes;
	type Error = std::io::Error;
	fn poll_frame(
		self: Pin<&mut Self>,
		_: &mut Context<'_>,
	) -> Poll<Option<Result<Frame<Bytes>, Self::Error>>> {
		let n = self.polls.fetch_add(1, Ordering::SeqCst);
		match self.mode {
			"error" => Poll::Ready(Some(Err(std::io::Error::other("provider failure")))),
			"pending" => Poll::Pending,
			"cancel-in-poll" | "cancel-trailers" | "cancel-eof" | "cancel-error" | "cancel-pending"
			| "partial-cancel"
				if self.mode != "partial-cancel" || n > 0 =>
			{
				self.handle.cancel().unwrap();
				match self.mode {
					"cancel-eof" => Poll::Ready(None),
					"cancel-pending" => Poll::Pending,
					"cancel-error" => Poll::Ready(Some(Err(std::io::Error::new(
						std::io::ErrorKind::ConnectionReset,
						"provider failure",
					)))),
					"cancel-trailers" => Poll::Ready(Some(Ok(Frame::trailers(trailers())))),
					_ => Poll::Ready(Some(Ok(Frame::data(Bytes::from_static(
						b"must-not-disclose",
					))))),
				}
			},
			"ordered" if n < 3 => Poll::Ready(Some(Ok(Frame::data(Bytes::from_static(
				[b"first".as_slice(), b"", b"last"][n],
			))))),
			"ordered" if n == 3 => Poll::Ready(Some(Ok(Frame::trailers(trailers())))),
			_ if n == 0 => Poll::Ready(Some(Ok(Frame::data(Bytes::from_static(b"allowed"))))),
			_ => Poll::Ready(None),
		}
	}
}
fn response(
	scope: &ExecutionScope,
	mode: &'static str,
) -> (Response, Arc<AtomicUsize>, Arc<AtomicUsize>) {
	wrapped_response(scope, mode, true)
}
fn wrapped_response(
	scope: &ExecutionScope,
	mode: &'static str,
	nested: bool,
) -> (Response, Arc<AtomicUsize>, Arc<AtomicUsize>) {
	let polls = Arc::new(AtomicUsize::new(0));
	let drops = Arc::new(AtomicUsize::new(0));
	let body = http::Body::new(Source {
		mode,
		handle: scope.handle.clone(),
		polls: polls.clone(),
		drops: drops.clone(),
	});
	let lease = scope.reserve(CallKind::Model, &scope.action).unwrap();
	let response = protect_response(
		Response::new(body),
		scope,
		lease,
		scope.action.as_ref().clone(),
	);
	(
		if nested {
			protect_output(response, scope)
		} else {
			response
		},
		polls,
		drops,
	)
}
fn usage(scope: &ExecutionScope, attempts: u64, concurrent: u64) {
	let u = scope.handle.usage().unwrap();
	assert_eq!(
		(u.model_calls, u.attempts, u.concurrent),
		(1, attempts, concurrent)
	);
}

#[tokio::test]
async fn s6_budget_eof_error_and_consumer_drop_release_only_concurrency() {
	for mode in ["normal", "error", "pending"] {
		let scope = scope();
		let (response, polls, drops) = response(&scope, mode);
		let mut body = response.into_body();
		usage(&scope, 1, 1);
		match mode {
			"normal" => {
				assert_eq!(
					body.frame().await.unwrap().unwrap().into_data().unwrap(),
					"allowed"
				);
				usage(&scope, 1, 1);
				assert!(body.frame().await.is_none());
			},
			"error" => {
				assert!(body.frame().await.unwrap().is_err());
				assert!(body.frame().await.is_none());
			},
			_ => {
				assert!(futures_util::poll!(body.frame()).is_pending());
				assert_eq!(polls.load(Ordering::SeqCst), 1);
			},
		}
		drop(body);
		assert_eq!(drops.load(Ordering::SeqCst), 1);
		usage(&scope, 1, 0);
		let retry = scope.reserve(CallKind::Model, &scope.action).unwrap();
		usage(&scope, 2, 1);
		drop(retry);
		usage(&scope, 2, 0);
		assert!(matches!(
			scope.reserve(CallKind::Model, &scope.action),
			Err(ProxyError::ExecutionBudget(BudgetError::Attempts))
		));
	}
}

#[tokio::test]
async fn s6_budget_cancel_blocks_buffered_output_and_wakes_pending_source() {
	for idle in [false, true] {
		let scope = scope();
		let (response, polls, drops) = response(&scope, if idle { "pending" } else { "normal" });
		let mut body = response.into_body();
		if idle {
			assert!(futures_util::poll!(body.frame()).is_pending());
		}
		scope.handle.cancel().unwrap();
		assert!(body.frame().await.unwrap().is_err());
		assert!(body.frame().await.is_none());
		assert_eq!(polls.load(Ordering::SeqCst), usize::from(idle));
		assert_eq!(drops.load(Ordering::SeqCst), 1);
		usage(&scope, 1, 0);
	}
}

#[tokio::test(start_paused = true)]
async fn s6_budget_deadline_releases_idle_source_and_lease() {
	let scope = scope();
	let (response, _, drops) = response(&scope, "pending");
	let mut body = response.into_body();
	assert!(futures_util::poll!(body.frame()).is_pending());
	tokio::time::advance(std::time::Duration::from_secs(31)).await;
	assert!(body.frame().await.unwrap().is_err());
	assert!(body.frame().await.is_none());
	assert_eq!(drops.load(Ordering::SeqCst), 1);
	usage(&scope, 1, 0);
}

#[tokio::test]
async fn s6_budget_cancellation_during_source_poll_must_not_disclose() {
	let scope = scope();
	let (response, _, _) = response(&scope, "cancel-in-poll");
	let mut body = response.into_body();
	let frame = body.frame().await.unwrap();
	assert_eq!(scope.handle.state().unwrap(), ExecutionState::Cancelled);
	assert!(
		frame.is_err(),
		"cancellation committed during source poll, but a data frame escaped both budget wrappers: {frame:?}"
	);
}

fn trailers() -> ::http::HeaderMap {
	let mut trailers = ::http::HeaderMap::new();
	trailers.insert("x-test-end", "sensitive-trailer".parse().unwrap());
	trailers
}

#[tokio::test]
async fn cancellation_during_poll_discards_data_trailers_and_eof_once() {
	use http_body::Body as _;
	for nested in [false, true] {
		for mode in [
			"cancel-in-poll",
			"cancel-trailers",
			"cancel-eof",
			"partial-cancel",
		] {
			let scope = scope();
			#[cfg(feature = "ui")]
			let mut audit = crate::security_events::store().subscribe();
			let (response, polls, drops) = wrapped_response(&scope, mode, nested);
			let mut body = response.into_body();
			let mut disclosed = 0;
			if mode == "partial-cancel" {
				let data = body.frame().await.unwrap().unwrap().into_data().unwrap();
				assert_eq!(data, "allowed");
				disclosed += data.len();
			}
			assert!(
				body.frame().await.unwrap().is_err(),
				"{mode}, nested={nested}"
			);
			assert!(body.is_end_stream());
			for _ in 0..3 {
				assert!(body.frame().await.is_none());
			}
			assert_eq!(
				polls.load(Ordering::SeqCst),
				1 + usize::from(mode == "partial-cancel")
			);
			assert_eq!(disclosed, if mode == "partial-cancel" { 7 } else { 0 });
			assert_eq!(drops.load(Ordering::SeqCst), 1);
			usage(&scope, 1, 0);
			#[cfg(feature = "ui")]
			{
				let mut denies = 0;
				while let Ok(event) = audit.try_recv() {
					if event.request_id == scope.action.request_id
						&& event.decision == Some(security_types::DecisionEffect::Deny)
					{
						assert!(
							event
								.policy_id
								.unwrap()
								.starts_with("execution-budget:cancelled:")
						);
						denies += 1;
					}
				}
				assert_eq!(denies, 1, "{mode}, nested={nested}");
			}
			drop(body);
			assert_eq!(drops.load(Ordering::SeqCst), 1);
			usage(&scope, 1, 0);
		}
	}
}

#[tokio::test]
async fn normal_frames_and_trailers_preserve_order_and_source_error_is_not_masked() {
	for nested in [false, true] {
		let scope = scope();
		let (response, polls, drops) = wrapped_response(&scope, "ordered", nested);
		let mut body = response.into_body();
		for bytes in ["first", "", "last"] {
			assert_eq!(
				body.frame().await.unwrap().unwrap().into_data().unwrap(),
				bytes
			);
		}
		assert_eq!(
			body
				.frame()
				.await
				.unwrap()
				.unwrap()
				.into_trailers()
				.unwrap(),
			trailers()
		);
		assert!(body.frame().await.is_none());
		assert!(body.frame().await.is_none());
		assert_eq!(polls.load(Ordering::SeqCst), 5);
		assert_eq!(drops.load(Ordering::SeqCst), 1);
		usage(&scope, 1, 0);
		let scope = self::scope();
		let (response, polls, drops) = wrapped_response(&scope, "cancel-error", nested);
		let mut body = response.into_body();
		let error = body.frame().await.unwrap().unwrap_err();
		assert!(format!("{error:?}").contains("provider failure"));
		assert!(format!("{error:?}").contains("ConnectionReset"));
		assert_eq!(scope.handle.state().unwrap(), ExecutionState::Cancelled);
		assert!(body.frame().await.is_none());
		assert_eq!(polls.load(Ordering::SeqCst), 1);
		assert_eq!(drops.load(Ordering::SeqCst), 1);
		usage(&scope, 1, 0);
	}
}

#[derive(Default)]
struct WakeCounter(AtomicUsize);
impl std::task::Wake for WakeCounter {
	fn wake(self: Arc<Self>) {
		self.0.fetch_add(1, Ordering::SeqCst);
	}
	fn wake_by_ref(self: &Arc<Self>) {
		self.0.fetch_add(1, Ordering::SeqCst);
	}
}
#[tokio::test]
async fn pending_cancellation_notifies_registered_waker_without_repolling_source() {
	use http_body::Body as _;
	for nested in [false, true] {
		let scope = scope();
		let (response, polls, drops) = wrapped_response(&scope, "pending", nested);
		let mut body = response.into_body();
		let wakes = Arc::new(WakeCounter::default());
		let waker = std::task::Waker::from(wakes.clone());
		let mut cx = Context::from_waker(&waker);
		assert!(Pin::new(&mut body).poll_frame(&mut cx).is_pending());
		assert_eq!(wakes.0.load(Ordering::SeqCst), 0);
		scope.handle.cancel().unwrap();
		assert!(wakes.0.load(Ordering::SeqCst) > 0);
		assert!(matches!(
			Pin::new(&mut body).poll_frame(&mut cx),
			Poll::Ready(Some(Err(_)))
		));
		assert!(matches!(
			Pin::new(&mut body).poll_frame(&mut cx),
			Poll::Ready(None)
		));
		assert_eq!(polls.load(Ordering::SeqCst), 1);
		assert_eq!(drops.load(Ordering::SeqCst), 1);
		usage(&scope, 1, 0);
	}
}

#[tokio::test]
async fn cancellation_before_poll_and_during_pending_never_read_again() {
	use http_body::Body as _;
	for nested in [false, true] {
		for during_poll in [false, true] {
			let scope = scope();
			let (response, polls, drops) = wrapped_response(
				&scope,
				if during_poll {
					"cancel-pending"
				} else {
					"normal"
				},
				nested,
			);
			let mut body = response.into_body();
			let wakes = Arc::new(WakeCounter::default());
			let waker = std::task::Waker::from(wakes.clone());
			let mut cx = Context::from_waker(&waker);
			if during_poll {
				assert!(Pin::new(&mut body).poll_frame(&mut cx).is_pending());
				assert!(wakes.0.load(Ordering::SeqCst) > 0);
			} else {
				scope.handle.cancel().unwrap();
			}
			assert!(matches!(
				Pin::new(&mut body).poll_frame(&mut cx),
				Poll::Ready(Some(Err(_)))
			));
			assert!(matches!(
				Pin::new(&mut body).poll_frame(&mut cx),
				Poll::Ready(None)
			));
			assert_eq!(polls.load(Ordering::SeqCst), usize::from(during_poll));
			assert_eq!(drops.load(Ordering::SeqCst), 1);
			usage(&scope, 1, 0);
		}
	}
}
