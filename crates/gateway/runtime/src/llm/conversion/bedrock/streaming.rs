//! Host-owned Bedrock decoding and terminal handling shared by the three output formats.
use std::{io, marker::PhantomData};

use bytes::{Bytes, BytesMut};
use futures_util::{StreamExt, stream};
use serde::Serialize;
use tokio_util::codec::{Decoder, Encoder};

use crate::{
	http::Body,
	llm::types::bedrock::{ConverseStreamOutput, deserialize_stream_event},
	parse::{
		self,
		aws_sse::{EventStreamCodec, EventStreamError, Message},
	},
};

struct BedrockDecoder(EventStreamCodec);

fn header<'a>(message: &'a Message, name: &str) -> Result<Option<&'a str>, EventStreamError> {
	let mut headers = message
		.headers()
		.iter()
		.filter(|h| h.name().as_str() == name);
	let value = headers.next().map(|h| h.value().as_string());
	if headers.next().is_some() || value.as_ref().is_some_and(|v| v.is_err()) {
		return Err(io::Error::other("invalid Bedrock stream headers").into());
	}
	Ok(value.map(|v| v.expect("validated string header").as_str()))
}

impl Decoder for BedrockDecoder {
	type Item = ConverseStreamOutput;
	type Error = EventStreamError;

	fn decode(&mut self, buffer: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
		while let Some(message) = self.0.decode(buffer)? {
			match header(&message, ":message-type")? {
				Some("exception" | "error") => {
					// Never expose provider payloads (which may contain request data) in Body errors.
					tracing::warn!("Bedrock upstream reported a streaming failure");
					return Err(io::Error::other("Bedrock upstream streaming failure").into());
				},
				None | Some("event") => {}, // Preserve legacy streams without this header.
				Some(_) => return Err(io::Error::other("invalid Bedrock message type").into()),
			}
			if header(&message, ":event-type")?.is_none_or(str::is_empty) {
				return Err(io::Error::other("invalid Bedrock stream event").into());
			}
			match deserialize_stream_event(message) {
				Ok(Some(event)) => return Ok(Some(event)),
				Ok(None) => {}, // An unknown ordinary event never changes output or grants authority.
				Err(_) => {
					tracing::warn!("Bedrock stream contained an invalid event");
					return Err(io::Error::other("invalid Bedrock stream event").into());
				},
			}
		}
		Ok(None)
	}
}

struct SseEncoder<O>(PhantomData<O>);

impl<O: Serialize> Encoder<Vec<(&'static str, O)>> for SseEncoder<O> {
	type Error = io::Error;
	fn encode(
		&mut self,
		events: Vec<(&'static str, O)>,
		buffer: &mut BytesMut,
	) -> Result<(), Self::Error> {
		for (name, event) in events {
			let json = serde_json::to_vec(&event)
				.map_err(|_| io::Error::other("failed to encode Bedrock stream output"))?;
			buffer.extend_from_slice(&parse::encode_sse_event(name, Bytes::from(json)));
		}
		Ok(())
	}
}

pub(super) fn translate<O: Serialize + Send + 'static>(
	body: Body,
	buffer_limit: usize,
	done: Option<Bytes>,
	mut handler: impl FnMut(ConverseStreamOutput) -> Vec<(&'static str, O)> + Send + 'static,
) -> Body {
	let body = parse::transform::parser(
		body,
		BedrockDecoder(EventStreamCodec::with_max_size(buffer_limit)),
		SseEncoder(PhantomData),
		move |event| [handler(event)],
	);
	// Drop the complete decoder/handler/source (and its accounting logger) before
	// returning an error or successful EOF. An error cannot become a later success.
	Body::from_stream(
		stream::unfold(
			(Some(body.into_data_stream()), done),
			|(source, done)| async move {
				let mut source = source?;
				match source.next().await {
					Some(Ok(chunk)) => Some((Ok(chunk), (Some(source), done))),
					Some(Err(error)) => Some((Err(error), (None, None))),
					None => done.map(|done| (Ok(done), (None, None))),
				}
			},
		)
		.fuse(),
	)
}
