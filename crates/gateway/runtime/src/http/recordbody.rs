use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use bytes::{Buf, Bytes};
use http_body::{Body, Frame, SizeHint};
use parking_lot::Mutex;

use crate::http::buflist::BufList;

#[derive(Clone, Debug)]
pub struct RecordedBodyHandle {
	inner: Arc<Mutex<RecordedBodyHandleInner>>,
	limit: usize,
}

#[derive(Debug)]
struct RecordedBodyHandleInner {
	state: RecordedBodyState,
	recorded: usize,
}

#[derive(Debug)]
enum RecordedBodyState {
	Recording(BufList),
	Complete(Bytes),
}

impl Default for RecordedBodyState {
	fn default() -> Self {
		Self::Recording(BufList::default())
	}
}

impl RecordedBodyHandle {
	pub fn bytes(&self) -> Bytes {
		let mut inner = self.inner.lock();
		match &mut inner.state {
			RecordedBodyState::Recording(buffer) => {
				// This *should* not happen... but that is a recommended pattern of the caller, not something
				// we enforce.
				let mut buffer = buffer.clone();
				let len = buffer.remaining();
				buffer.copy_to_bytes(len)
			},
			RecordedBodyState::Complete(bytes) => bytes.clone(),
		}
	}

	fn push(&self, bytes: Bytes) {
		let mut inner = self.inner.lock();
		let remaining = self.limit.saturating_sub(inner.recorded);
		if let RecordedBodyState::Recording(buffer) = &mut inner.state {
			let to_record = bytes.len().min(remaining);
			if to_record == 0 {
				return;
			}
			buffer.push(bytes.slice(0..to_record));
			inner.recorded += to_record;
		} else {
			debug_assert!(false, "push() cannot be called on a complete body handle.")
		}
	}

	fn complete(&self) {
		let mut inner = self.inner.lock();
		let RecordedBodyState::Recording(buffer) = &mut inner.state else {
			return;
		};
		let mut buffer = std::mem::take(buffer);
		let len = buffer.remaining();
		inner.state = RecordedBodyState::Complete(buffer.copy_to_bytes(len));
	}
}

/// Wraps an HTTP body and records each polled data frame while passing the
/// bytes through unchanged.
///
/// The recorded data is shared through a [`RecordedBodyHandle`]. This is meant
/// for consumers that inspect the captured bytes after the wrapped body has
/// been fully drained.
#[derive(Debug)]
pub struct RecordedBody<B = crate::http::Body> {
	inner: B,
	handle: RecordedBodyHandle,
}

impl<B> RecordedBody<B> {
	pub fn new(inner: B) -> (Self, RecordedBodyHandle) {
		Self::new_with_limit(inner, usize::MAX)
	}

	pub fn new_with_limit(inner: B, limit: usize) -> (Self, RecordedBodyHandle) {
		let handle = RecordedBodyHandle {
			inner: Arc::new(Mutex::new(RecordedBodyHandleInner {
				state: RecordedBodyState::default(),
				recorded: 0,
			})),
			limit,
		};
		(
			Self {
				inner,
				handle: handle.clone(),
			},
			handle,
		)
	}

	pub fn handle(&self) -> RecordedBodyHandle {
		self.handle.clone()
	}
}

impl<B> Body for RecordedBody<B>
where
	B: Body + Unpin,
	B::Error: Into<axum_core::Error>,
{
	type Data = Bytes;
	type Error = axum_core::Error;

	fn poll_frame(
		self: Pin<&mut Self>,
		cx: &mut Context<'_>,
	) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
		let this = self.get_mut();
		let frame = match futures::ready!(Pin::new(&mut this.inner).poll_frame(cx)) {
			Some(Ok(frame)) => frame,
			Some(Err(error)) => return Poll::Ready(Some(Err(error.into()))),
			None => {
				this.handle.complete();
				return Poll::Ready(None);
			},
		};

		match frame.into_data().map_err(Frame::into_trailers) {
			Ok(mut data) => {
				let len = data.remaining();
				let bytes = data.copy_to_bytes(len);
				if bytes.has_remaining() {
					this.handle.push(bytes.clone());
				}
				Poll::Ready(Some(Ok(Frame::data(bytes))))
			},
			Err(Ok(trailers)) => {
				this.handle.complete();
				Poll::Ready(Some(Ok(Frame::trailers(trailers))))
			},
			Err(Err(_unknown)) => {
				tracing::warn!("An unknown body frame has been recorded");
				Poll::Ready(None)
			},
		}
	}

	fn is_end_stream(&self) -> bool {
		self.inner.is_end_stream()
	}

	fn size_hint(&self) -> SizeHint {
		self.inner.size_hint()
	}
}
