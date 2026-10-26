use super::*;
use http_body_util::BodyExt;

#[tokio::test]
async fn buffered_response_is_revoked_before_first_poll_and_stays_terminal() {
	let revision = ConfigRevision::default();
	let mut body = RevocableBody::new(axum::body::Body::from("secret"), revision.lease());
	revision.invalidate();
	assert!(body.frame().await.unwrap().is_err());
	assert!(body.frame().await.is_none());
}

#[tokio::test]
async fn revocation_inside_source_poll_cannot_release_the_returned_frame() {
	struct RevokeOnPoll(Arc<ConfigRevision>);
	impl Body for RevokeOnPoll {
		type Data = bytes::Bytes;
		type Error = std::convert::Infallible;
		fn poll_frame(
			self: Pin<&mut Self>,
			_: &mut Context<'_>,
		) -> Poll<Option<Result<http_body::Frame<Self::Data>, Self::Error>>> {
			self.0.invalidate();
			Poll::Ready(Some(Ok(http_body::Frame::data(bytes::Bytes::from_static(
				b"secret",
			)))))
		}
	}
	let revision = Arc::new(ConfigRevision::default());
	let mut body = RevocableBody::new(
		axum::body::Body::new(RevokeOnPoll(revision.clone())),
		revision.lease(),
	);
	assert!(body.frame().await.unwrap().is_err());
	assert!(body.frame().await.is_none());
}

#[tokio::test]
async fn idle_source_wakes_on_revocation_and_normal_frames_are_unchanged() {
	let revision = ConfigRevision::default();
	let body = RevocableBody::new(axum::body::Body::from("visible"), revision.lease());
	assert_eq!(body.size_hint().exact(), Some(7));
	assert_eq!(body.collect().await.unwrap().to_bytes(), "visible");
	let source = axum::body::Body::from_stream(futures_util::stream::pending::<
		Result<bytes::Bytes, std::io::Error>,
	>());
	let mut body = RevocableBody::new(source, revision.lease());
	// Poll once to register the watch waker while the source supplies no waker of its own.
	let pending = std::future::poll_fn(|cx| {
		assert!(Pin::new(&mut body).poll_frame(cx).is_pending());
		Poll::Ready(())
	});
	pending.await;
	revision.invalidate();
	assert!(
		tokio::time::timeout(std::time::Duration::from_secs(1), body.frame())
			.await
			.unwrap()
			.unwrap()
			.is_err()
	);
}

#[tokio::test]
async fn publication_replaces_all_routes_and_invalidates_only_the_previous_generation() {
	let runtime = Arc::new(Runtime::default());
	let id = ListenerId {
		name: "knowledge".into(),
		address: "127.0.0.1".into(),
		port: 14103,
	};
	let make = |label: &'static str| {
		let revision = ConfigRevision::default();
		let lease = revision.lease();
		let router = Router::new().route("/", axum::routing::get(move || async move { label }));
		(
			Prepared(BTreeMap::from([(
				id.clone(),
				Generation { router, revision },
			)])),
			lease,
		)
	};
	let (previous, old) = make("old");
	runtime.commit(previous);
	let (candidate, next) = make("new");
	assert!(old.is_current() && next.is_current());
	runtime.commit(candidate);
	assert!(!old.is_current() && next.is_current());
	let response = dispatch(
		State((runtime, id)),
		Request::new(axum::body::Body::empty()),
	)
	.await;
	assert_eq!(
		response.into_body().collect().await.unwrap().to_bytes(),
		"new"
	);
}
