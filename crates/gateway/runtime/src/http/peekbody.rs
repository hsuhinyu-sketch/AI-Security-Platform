use std::cmp;
use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::{Buf, Bytes};
use http::HeaderMap;
use http_body::{Frame, SizeHint};
use http_body_util::BodyExt;
use pin_project_lite::pin_project;

use crate::http::Body;
use crate::http::buflist::BufList;

pin_project! {
	struct PartiallyBufferedBody {
		buffer: BufList,
		trailers: Option<HeaderMap>,
		#[pin]
		inner: Body,
	}
}

impl http_body::Body for PartiallyBufferedBody {
	type Data = Bytes;
	type Error = crate::http::Error;

	fn poll_frame(
		mut self: Pin<&mut Self>,
		cx: &mut Context<'_>,
	) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
		if let Some(br) = self.buffer.pop_front() {
			return Poll::Ready(Some(Ok(Frame::data(br))));
		}
		if let Some(br) = self.trailers.take() {
			return Poll::Ready(Some(Ok(Frame::trailers(br))));
		}
		let this = self.project();
		this.inner.poll_frame(cx)
	}

	fn is_end_stream(&self) -> bool {
		!self.buffer.has_remaining() && self.inner.is_end_stream() && self.trailers.is_none()
	}

	/// Returns the bounds on the remaining length of the stream.
	///
	/// When the **exact** remaining length of the stream is known, the upper bound will be set and
	/// will equal the lower bound.
	fn size_hint(&self) -> SizeHint {
		let rem = self.buffer.remaining();
		let mut rest = self.inner.size_hint();
		if let Some(upper) = rest.upper() {
			rest.set_upper(upper.saturating_add(rem as u64));
		}
		rest.set_lower(rest.lower() + rem as u64);
		rest
	}
}

/// inspect_body inspects up to `limit` bytes from the Body. The original body (should be) unchanged.
/// Warning: you MUST poll the returned future to completion, or the original body will be missing data.
pub async fn inspect_body(body: &mut Body, limit: usize) -> anyhow::Result<Bytes> {
	let mut orig = std::mem::replace(body, Body::empty());
	let mut buffer = BufList::default();
	let mut trailers: Option<HeaderMap> = None;
	let mut want = limit;
	loop {
		match orig.frame().await {
			Some(Ok(frame)) => {
				if let Some(data) = frame.data_ref() {
					let want_this_read = cmp::min(data.len(), want);
					if want_this_read == 0 {
						break;
					}
					buffer.push(data.clone());
					want -= cmp::max(want_this_read, 0);
					if want == 0 {
						break;
					}
				} else {
					trailers = Some(frame.into_trailers().unwrap())
				}
			},
			Some(Err(err)) => {
				return Err(err.into());
			},
			None => break,
		}
	}

	// Despite the name, 'copy_to_bytes' takes the data, not copies it.
	// So we send a clone.
	let mut blc = buffer.clone();
	let ret = blc.copy_to_bytes(cmp::min(buffer.remaining(), limit));
	let nb = PartiallyBufferedBody {
		buffer,
		trailers,
		inner: orig,
	};
	*body = Body::new(nb);
	Ok(ret)
}
