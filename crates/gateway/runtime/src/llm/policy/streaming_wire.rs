//! Validate complete provider frames before permissive compatibility converters.
//! No detached reader or unbounded queue; dropping this body drops the upstream.
use crate::http::Body;
use bytes::Bytes;
#[cfg(feature = "providers-aws")]
use bytes::BytesMut;
use futures_util::{StreamExt, TryStreamExt};
use tokio_util::{codec::FramedRead, io::StreamReader};

pub(crate) fn validated(body: Body, limit: usize, aws_event_stream: bool) -> Body {
	let limit = limit.clamp(1024, 4 * 1024 * 1024);
	let reader = StreamReader::new(body.into_data_stream().map_err(std::io::Error::other));
	if aws_event_stream {
		#[cfg(not(feature = "providers-aws"))]
		{
			Body::from_stream(futures_util::stream::once(async {
				Err::<Bytes, _>(std::io::Error::other(
					"AWS streaming support is not compiled",
				))
			}))
		}
		#[cfg(feature = "providers-aws")]
		{
			let frames = FramedRead::new(
				reader,
				crate::parse::aws_sse::EventStreamCodec::with_max_size(limit),
			);
			Body::from_stream(frames.map(move |message| {
				let message = message.map_err(std::io::Error::other)?;
				let mut bytes = BytesMut::new();
				aws_smithy_eventstream::frame::write_message_to(&message, &mut bytes)
					.map_err(std::io::Error::other)?;
				if bytes.len() > limit {
					return Err(std::io::Error::other("provider frame budget"));
				}
				Ok(bytes.freeze())
			}))
		}
	} else {
		let frames = FramedRead::new(
			reader,
			tokio_sse_codec::SseDecoder::<Bytes>::with_max_size(limit),
		);
		Body::from_stream(frames.map(|frame| {
			let frame = frame.map_err(std::io::Error::other)?;
			let tokio_sse_codec::Frame::Event(event) = frame else {
				return Ok(Bytes::new());
			};
			if event.data.as_ref() != b"[DONE]" {
				let value: serde_json::Value =
					serde_json::from_slice(&event.data).map_err(std::io::Error::other)?;
				if !value.is_object() {
					return Err(std::io::Error::other("provider stream is not an object"));
				}
			}
			Ok(crate::parse::encode_sse_event(
				if event.name == "message" {
					""
				} else {
					&event.name
				},
				event.data,
			))
		}))
	}
}
