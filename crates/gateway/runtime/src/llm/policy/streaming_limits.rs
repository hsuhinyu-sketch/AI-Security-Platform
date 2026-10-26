//! Per-response resource admission, after decompression and before conversion/log accumulation.
use std::num::NonZeroUsize;
#[cfg(feature = "gateway-llm")]
use std::{
	collections::HashMap,
	io,
	pin::Pin,
	task::{Context, Poll},
};

#[cfg(feature = "gateway-llm")]
use bytes::{Bytes, BytesMut};
#[cfg(feature = "gateway-llm")]
use http_body::{Frame, SizeHint};
#[cfg(feature = "gateway-llm")]
use serde_json::Value;
#[cfg(feature = "gateway-llm")]
use tokio_util::codec::Decoder;

#[cfg(feature = "gateway-llm")]
use crate::http::Body;
#[cfg(all(feature = "gateway-llm", feature = "providers-aws"))]
use crate::parse::aws_sse::EventStreamCodec;
use crate::{apply, schema};

fn response_bytes() -> NonZeroUsize {
	NonZeroUsize::new(8 * 1024 * 1024).unwrap()
}
fn argument_bytes() -> NonZeroUsize {
	NonZeroUsize::new(1024 * 1024).unwrap()
}
fn tracked_blocks() -> NonZeroUsize {
	NonZeroUsize::new(128).unwrap()
}

#[apply(schema!)]
#[derive(Copy, PartialEq, Eq)]
pub struct StreamingLimits {
	/// Total upstream data bytes after decompression, including protocol framing.
	#[serde(default = "response_bytes")]
	pub max_response_bytes: NonZeroUsize,
	/// Cumulative UTF-8 argument bytes per tool slot; full snapshots use the larger size.
	#[serde(default = "argument_bytes")]
	pub max_tool_argument_bytes: NonZeroUsize,
	/// Distinct tracked tool/content/output slots over the response lifetime, not just open slots.
	#[serde(default = "tracked_blocks")]
	pub max_tracked_blocks: NonZeroUsize,
}
impl Default for StreamingLimits {
	fn default() -> Self {
		Self {
			max_response_bytes: response_bytes(),
			max_tool_argument_bytes: argument_bytes(),
			max_tracked_blocks: tracked_blocks(),
		}
	}
}
impl StreamingLimits {
	pub(crate) fn stricter(self, other: Self) -> Self {
		Self {
			max_response_bytes: self.max_response_bytes.min(other.max_response_bytes),
			max_tool_argument_bytes: self
				.max_tool_argument_bytes
				.min(other.max_tool_argument_bytes),
			max_tracked_blocks: self.max_tracked_blocks.min(other.max_tracked_blocks),
		}
	}
}

#[cfg(feature = "gateway-llm")]
enum Wire {
	#[cfg(feature = "providers-aws")]
	Aws(EventStreamCodec),
	Sse(tokio_sse_codec::SseDecoder<Bytes>),
}
#[cfg(feature = "gateway-llm")]
impl Wire {
	fn decode(&mut self, buffer: &mut BytesMut) -> io::Result<Option<Bytes>> {
		match self {
			#[cfg(feature = "providers-aws")]
			Self::Aws(codec) => Ok(
				codec
					.decode(buffer)
					.map_err(io::Error::other)?
					.map(|m| m.payload().clone()),
			),
			Self::Sse(codec) => {
				while let Some(frame) = codec.decode(buffer).map_err(io::Error::other)? {
					if let tokio_sse_codec::Frame::Event(event) = frame {
						return Ok(Some(event.data));
					}
				}
				Ok(None)
			},
		}
	}
}

#[cfg(feature = "gateway-llm")]
fn input_size(input: &Value) -> io::Result<usize> {
	if input.is_null() || input.as_object().is_some_and(|m| m.is_empty()) {
		return Ok(0);
	}
	serde_json::to_vec(input)
		.map(|bytes| bytes.len())
		.map_err(io::Error::other)
}

#[cfg(feature = "gateway-llm")]
struct Inspection {
	limits: StreamingLimits,
	remaining: usize,
	frame_limit: usize,
	wire: Wire,
	buffer: BytesMut,
	// Bounded numeric keys; no copied provider identifiers or argument contents.
	blocks: HashMap<(u8, i64, i64), usize>,
}
#[cfg(feature = "gateway-llm")]
impl Inspection {
	fn charge(&mut self, key: (u8, i64, i64), bytes: usize, snapshot: bool) -> io::Result<()> {
		if !self.blocks.contains_key(&key) && self.blocks.len() >= self.limits.max_tracked_blocks.get()
		{
			return Err(io::Error::other("stream tracked block limit exceeded"));
		}
		let previous = self.blocks.get(&key).copied().unwrap_or_default();
		let next = if snapshot {
			Some(previous.max(bytes))
		} else {
			previous.checked_add(bytes)
		};
		let next = next
			.filter(|n| *n <= self.limits.max_tool_argument_bytes.get())
			.ok_or_else(|| io::Error::other("stream tool argument limit exceeded"))?;
		self.blocks.insert(key, next);
		Ok(())
	}
	fn event(&mut self, value: &Value) -> io::Result<()> {
		if let Some(index) = value["contentBlockIndex"].as_i64() {
			self.charge(
				(0, 0, index),
				value
					.pointer("/delta/toolUse/input")
					.and_then(Value::as_str)
					.map_or(0, str::len),
				false,
			)?;
		}
		if let Some(choices) = value["choices"].as_array() {
			for (position, choice) in choices.iter().enumerate() {
				if let Some(tools) = choice
					.pointer("/delta/tool_calls")
					.and_then(Value::as_array)
				{
					for tool in tools {
						if let Some(index) = tool["index"].as_i64() {
							self.charge(
								(
									1,
									choice["index"].as_i64().unwrap_or(position as i64),
									index,
								),
								tool
									.pointer("/function/arguments")
									.and_then(Value::as_str)
									.map_or(0, str::len),
								false,
							)?;
						}
					}
				}
			}
		}
		if matches!(
			value["type"].as_str(),
			Some("content_block_start" | "content_block_delta" | "content_block_stop")
		) && let Some(index) = value["index"].as_i64()
		{
			let bytes = value
				.pointer("/delta/partial_json")
				.and_then(Value::as_str)
				.map_or(0, str::len);
			self.charge((2, 0, index), bytes, false)?;
			if let Some(input) = value.pointer("/content_block/input") {
				self.charge((2, 0, index), input_size(input)?, true)?;
			}
		}
		if let Some(index) = value["output_index"].as_i64() {
			let kind = value["type"].as_str().unwrap_or_default();
			let delta = if kind == "response.function_call_arguments.delta" {
				value["delta"].as_str().map_or(0, str::len)
			} else {
				0
			};
			self.charge((3, 0, index), delta, false)?;
			if let Some(content) = value["content_index"].as_i64() {
				self.charge((4, index, content), 0, false)?;
			}
			if let Some(arguments) = value["arguments"]
				.as_str()
				.or_else(|| value.pointer("/item/arguments").and_then(Value::as_str))
			{
				self.charge((3, 0, index), arguments.len(), true)?;
			}
		}
		if let Some(outputs) = value.pointer("/response/output").and_then(Value::as_array) {
			for (index, output) in outputs.iter().enumerate() {
				self.charge(
					(3, 0, index as i64),
					output["arguments"].as_str().map_or(0, str::len),
					true,
				)?;
				if let Some(parts) = output["content"].as_array() {
					for (content, _) in parts.iter().enumerate() {
						self.charge((4, index as i64, content as i64), 0, false)?;
					}
				}
			}
		}
		if let Some(parts) = value.pointer("/message/content").and_then(Value::as_array) {
			for (index, part) in parts.iter().enumerate() {
				let bytes = input_size(&part["input"])?;
				self.charge((2, 0, index as i64), bytes, true)?;
			}
		}
		Ok(())
	}
	fn inspect(&mut self, mut data: &[u8]) -> io::Result<()> {
		self.remaining = self
			.remaining
			.checked_sub(data.len())
			.ok_or_else(|| io::Error::other("stream response byte limit exceeded"))?;
		while !data.is_empty() {
			let count = self
				.frame_limit
				.saturating_sub(self.buffer.len())
				.min(8192)
				.min(data.len());
			if count == 0 {
				return Err(io::Error::other("stream frame limit exceeded"));
			}
			self.buffer.extend_from_slice(&data[..count]);
			data = &data[count..];
			while let Some(payload) = self.wire.decode(&mut self.buffer)? {
				// Preserve permissive converters' unknown/malformed JSON behavior. They
				// cannot accumulate typed state from invalid JSON; raw bytes remain capped.
				if let Ok(value) = serde_json::from_slice::<Value>(&payload) {
					self.event(&value)?;
				}
			}
		}
		Ok(())
	}
}

#[cfg(feature = "gateway-llm")]
pin_project_lite::pin_project! {
	struct ResourceBody {
		#[pin] body: Option<Body>,
		inspection: Option<Inspection>,
	}
}
#[cfg(feature = "gateway-llm")]
impl http_body::Body for ResourceBody {
	type Data = Bytes;
	type Error = axum_core::Error;
	fn poll_frame(
		self: Pin<&mut Self>,
		cx: &mut Context<'_>,
	) -> Poll<Option<Result<Frame<Bytes>, Self::Error>>> {
		let mut this = self.project();
		let Some(body) = this.body.as_mut().as_pin_mut() else {
			return Poll::Ready(None);
		};
		let result = match body.poll_frame(cx) {
			Poll::Pending => return Poll::Pending,
			Poll::Ready(Some(Ok(frame))) => {
				if let Some(inspection) = this.inspection.as_mut()
					&& let Some(data) = frame.data_ref()
				{
					inspection
						.inspect(data)
						.map(|()| frame)
						.map_err(axum_core::Error::new)
				} else {
					Ok(frame)
				}
			},
			Poll::Ready(Some(Err(error))) => Err(error),
			Poll::Ready(None) => {
				this.body.set(None);
				this.inspection.take();
				return Poll::Ready(None);
			},
		};
		if result.is_err() {
			this.body.set(None);
			this.inspection.take();
		}
		Poll::Ready(Some(result))
	}
	fn is_end_stream(&self) -> bool {
		self.body.as_ref().is_none_or(Body::is_end_stream)
	}
	fn size_hint(&self) -> SizeHint {
		self
			.body
			.as_ref()
			.map_or_else(SizeHint::default, Body::size_hint)
	}
}

#[cfg(feature = "gateway-llm")]
pub(crate) fn limited(body: Body, frame_limit: usize, aws: bool, limits: StreamingLimits) -> Body {
	let frame_limit = frame_limit.min(limits.max_response_bytes.get()).max(1);
	Body::new(ResourceBody {
		body: Some(body),
		inspection: Some(Inspection {
			remaining: limits.max_response_bytes.get(),
			limits,
			frame_limit,
			wire: if aws {
				#[cfg(feature = "providers-aws")]
				{
					Wire::Aws(EventStreamCodec::with_max_size(frame_limit))
				}
				#[cfg(not(feature = "providers-aws"))]
				{
					return Body::from_stream(futures_util::stream::once(async {
						Err::<Bytes, _>(io::Error::other("AWS streaming support is not compiled"))
					}));
				}
			} else {
				// This codec requires at least 8 internally; byte admission above
				// still enforces smaller configured totals before buffering input.
				Wire::Sse(tokio_sse_codec::SseDecoder::with_max_size(
					frame_limit.max(8),
				))
			},
			buffer: BytesMut::new(),
			blocks: HashMap::new(),
		}),
	})
}

/// Release converters and their accounting owner immediately on every error/EOF.
#[cfg(feature = "gateway-llm")]
pub(crate) fn terminal(body: Body) -> Body {
	Body::new(ResourceBody {
		body: Some(body),
		inspection: None,
	})
}

#[cfg(all(test, feature = "gateway-llm"))]
#[path = "streaming_limits_tests.rs"]
mod tests;
