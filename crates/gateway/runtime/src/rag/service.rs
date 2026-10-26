//! Static listener ownership with atomically replaceable, revocable request generations.
use axum::{
	Router,
	extract::{Request, State},
	http::StatusCode,
	response::{IntoResponse, Response},
};
use gateway_contracts::{ConfigLease, ConfigRevision};
use http_body::Body;
use platform_core::drain;
use std::{
	collections::BTreeMap,
	future::Future,
	pin::Pin,
	sync::{Arc, RwLock},
	task::{Context, Poll},
};
use tower::ServiceExt;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct ListenerId {
	name: String,
	address: String,
	port: u16,
}
struct Generation {
	router: Router,
	revision: ConfigRevision,
}
pub(crate) struct Prepared(BTreeMap<ListenerId, Generation>);
#[derive(Default)]
pub(crate) struct Runtime {
	active: RwLock<Option<Prepared>>,
}
impl std::fmt::Debug for Runtime {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.debug_struct("RagRuntime")
			.field(
				"listeners",
				&self
					.active
					.read()
					.expect("RAG state")
					.as_ref()
					.map_or(0, |p| p.0.len()),
			)
			.finish()
	}
}
impl Runtime {
	pub(crate) async fn prepare(
		&self,
		config: &crate::Config,
		resources: &crate::resource_manager::ResourceFetcher,
		systems: Vec<crate::types::local::RagSystemConfig>,
	) -> anyhow::Result<Prepared> {
		let systems: BTreeMap<_, _> = systems
			.into_iter()
			.map(|s| {
				(
					ListenerId {
						name: s.name.clone(),
						address: s.gateway.bind_address.clone(),
						port: s.gateway.port,
					},
					s,
				)
			})
			.collect();
		{
			let active = self.active.read().expect("RAG state");
			if let Some(active) = &*active {
				anyhow::ensure!(
					active.0.keys().eq(systems.keys()),
					"RAG listener topology changes require restart"
				);
			}
		}
		let mut next = BTreeMap::new();
		for (id, system) in systems {
			let revision = ConfigRevision::default();
			let router = super::build_router(config, resources, system, revision.lease()).await?;
			next.insert(id, Generation { router, revision });
		}
		Ok(Prepared(next))
	}
	pub(crate) fn commit(&self, next: Prepared) {
		let mut active = self.active.write().expect("RAG state");
		if let Some(previous) = &*active {
			for generation in previous.0.values() {
				generation.revision.invalidate();
			}
		}
		*active = Some(next);
	}
	pub(crate) async fn start(self: Arc<Self>, drain: drain::DrainWatcher) -> anyhow::Result<usize> {
		let ids: Vec<_> = self
			.active
			.read()
			.expect("RAG state")
			.as_ref()
			.map(|s| s.0.keys().cloned().collect())
			.unwrap_or_default();
		// Bind the complete static topology before spawning any listener.
		let mut listeners = Vec::new();
		for id in ids {
			let listener = tokio::net::TcpListener::bind((id.address.as_str(), id.port)).await?;
			listeners.push((id, listener));
		}
		let count = listeners.len();
		for (id, listener) in listeners {
			let router = Router::new()
				.fallback(dispatch)
				.with_state((self.clone(), id.clone()));
			let drain = drain.clone();
			tokio::spawn(async move {
				if let Err(error) = axum::serve(listener, router.into_make_service())
					.with_graceful_shutdown(async move {
						let _blocker = drain.wait_for_drain().await;
					})
					.await
				{
					tracing::warn!(system = %id.name, %error, "RAG listener stopped unexpectedly");
				}
			});
		}
		Ok(count)
	}
}
async fn dispatch(
	State((runtime, id)): State<(Arc<Runtime>, ListenerId)>,
	request: Request,
) -> Response {
	let router = runtime
		.active
		.read()
		.expect("RAG state")
		.as_ref()
		.and_then(|s| s.0.get(&id))
		.map(|g| g.router.clone());
	match router {
		Some(router) => router.oneshot(request).await.expect("Router is infallible"),
		None => StatusCode::SERVICE_UNAVAILABLE.into_response(),
	}
}

// Invalidation can race response construction or a source poll. Check on both sides of poll_frame
// and wake a pending body on revocation so buffered JSON cannot escape a superseded generation.
pub(super) struct RevocableBody {
	inner: axum::body::Body,
	lease: ConfigLease,
	changed: Pin<Box<dyn Future<Output = ()> + Send>>,
	ended: bool,
}
impl RevocableBody {
	pub(super) fn new(inner: axum::body::Body, lease: ConfigLease) -> Self {
		let mut receiver = lease.clone();
		Self {
			inner,
			lease,
			changed: Box::pin(async move { receiver.changed().await }),
			ended: false,
		}
	}
}
impl Body for RevocableBody {
	type Data = bytes::Bytes;
	type Error = std::io::Error;
	fn size_hint(&self) -> http_body::SizeHint {
		if self.ended {
			http_body::SizeHint::with_exact(0)
		} else {
			self.inner.size_hint()
		}
	}
	fn is_end_stream(&self) -> bool {
		self.ended || self.inner.is_end_stream()
	}
	fn poll_frame(
		mut self: Pin<&mut Self>,
		cx: &mut Context<'_>,
	) -> Poll<Option<Result<http_body::Frame<Self::Data>, Self::Error>>> {
		if self.ended {
			return Poll::Ready(None);
		}
		if !self.lease.is_current() || self.changed.as_mut().poll(cx).is_ready() {
			self.ended = true;
			return Poll::Ready(Some(Err(std::io::Error::new(
				std::io::ErrorKind::PermissionDenied,
				"RAG configuration changed",
			))));
		}
		let frame = Pin::new(&mut self.inner).poll_frame(cx);
		if !self.lease.is_current() {
			self.ended = true;
			return Poll::Ready(Some(Err(std::io::Error::new(
				std::io::ErrorKind::PermissionDenied,
				"RAG configuration changed",
			))));
		}
		match frame {
			Poll::Ready(Some(Err(error))) => {
				self.ended = true;
				Poll::Ready(Some(Err(std::io::Error::other(error))))
			},
			Poll::Ready(None) => {
				self.ended = true;
				Poll::Ready(None)
			},
			other => other.map(|frame| frame.map(|result| result.map_err(std::io::Error::other))),
		}
	}
}

#[cfg(test)]
#[path = "service_tests.rs"]
mod tests;
