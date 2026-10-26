use crate::http::Body;
use crate::parse::{aws_sse, sse};
use bytes::{Bytes, BytesMut};
use http_body::Frame;
use http_body_util::BodyExt;
use serde_json::{Value, json};
use std::collections::VecDeque;
use std::error::Error;
use std::pin::Pin;
use std::sync::{
	Arc, Mutex,
	atomic::{AtomicUsize, Ordering},
};
use std::task::{Context, Poll};
use tokio_util::codec::Decoder;

fn unhex(s: &str) -> Vec<u8> {
	assert_eq!(s.len() % 2, 0);
	s.as_bytes()
		.chunks_exact(2)
		.map(|b| u8::from_str_radix(std::str::from_utf8(b).unwrap(), 16).unwrap())
		.collect()
}
fn hex(b: &[u8]) -> String {
	b.iter().map(|b| format!("{b:02x}")).collect()
}
fn error_value(e: &(dyn Error + 'static)) -> Value {
	let mut causes = Vec::new();
	let mut kinds = Vec::new();
	let mut current = Some(e);
	while let Some(e) = current {
		causes.push(e.to_string());
		if let Some(e) = e.downcast_ref::<aws_sse::EventStreamError>() {
			kinds.push(
				match e {
					aws_sse::EventStreamError::Protocol(_) => "awsProtocol",
					aws_sse::EventStreamError::Io(_) => "awsIo",
					aws_sse::EventStreamError::FrameTooLarge { .. } => "frameTooLarge",
				}
				.to_string(),
			);
		}
		if let Some(e) = e.downcast_ref::<std::io::Error>() {
			kinds.push(format!("io:{:?}", e.kind()));
		}
		current = e.source();
	}
	json!({"causes":causes,"kinds":kinds,"debug":format!("{e:?}")})
}

struct Source {
	frames: VecDeque<Result<Frame<Bytes>, std::io::Error>>,
	polls: Arc<AtomicUsize>,
	drops: Arc<AtomicUsize>,
	pending: bool,
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
		mut self: Pin<&mut Self>,
		_: &mut Context<'_>,
	) -> Poll<Option<Result<Frame<Bytes>, Self::Error>>> {
		self.polls.fetch_add(1, Ordering::SeqCst);
		match self.frames.pop_front() {
			Some(f) => Poll::Ready(Some(f)),
			None if self.pending => Poll::Pending,
			None => Poll::Ready(None),
		}
	}
}
fn chunks(case: &Value) -> Vec<Bytes> {
	let bytes = unhex(case["inputHex"].as_str().unwrap());
	let mut offset = 0;
	let chunks = case["chunkSizes"]
		.as_array()
		.unwrap()
		.iter()
		.map(|n| {
			let end = offset + n.as_u64().unwrap() as usize;
			let b = Bytes::copy_from_slice(&bytes[offset..end]);
			offset = end;
			b
		})
		.collect();
	assert_eq!(offset, bytes.len());
	chunks
}

fn observe_codec(case: &Value) -> Value {
	let mut codec =
		aws_sse::EventStreamCodec::with_max_size(case["limit"].as_u64().unwrap() as usize);
	let mut buffer = BytesMut::new();
	let mut observations = Vec::new();
	for (i, chunk) in chunks(case).into_iter().enumerate() {
		buffer.extend_from_slice(&chunk);
		loop {
			match codec.decode(&mut buffer) {
				Ok(Some(m)) => observations
					.push(json!({"atChunk":i,"message":format!("{m:?}"),"remaining":buffer.len()})),
				Ok(None) => {
					observations.push(json!({"atChunk":i,"pending":true,"remaining":buffer.len()}));
					break;
				},
				Err(e) => {
					observations.push(json!({"atChunk":i,"error":error_value(&e),"remaining":buffer.len()}));
					return json!(observations);
				},
			}
		}
	}
	loop {
		match codec.decode_eof(&mut buffer) {
			Ok(Some(m)) => {
				observations.push(json!({"eofMessage":format!("{m:?}"),"remaining":buffer.len()}))
			},
			Ok(None) => {
				observations.push(json!({"eof":true,"remaining":buffer.len()}));
				break;
			},
			Err(e) => {
				observations.push(json!({"eofError":error_value(&e),"remaining":buffer.len()}));
				break;
			},
		}
	}
	json!(observations)
}

async fn observe_body(case: &Value) -> Value {
	let polls = Arc::new(AtomicUsize::new(0));
	let drops = Arc::new(AtomicUsize::new(0));
	let mut frames: VecDeque<_> = chunks(case)
		.into_iter()
		.map(|b| Ok(Frame::data(b)))
		.collect();
	if case["trailer"] == true {
		frames.push_back(Ok(Frame::trailers(::http::HeaderMap::from_iter([(
			"x-end".parse().unwrap(),
			"kept".parse().unwrap(),
		)]))));
	}
	if case["sourceError"] == true {
		frames.push_back(Err(std::io::Error::new(
			std::io::ErrorKind::ConnectionReset,
			"fixture source reset",
		)));
	}
	let source = Body::new(Source {
		frames,
		polls: polls.clone(),
		drops: drops.clone(),
		pending: false,
	});
	let seen = Arc::new(Mutex::new(Vec::new()));
	let observations = seen.clone();
	let limit = case["limit"].as_u64().unwrap() as usize;
	let mut output = match case["kind"].as_str().unwrap() {
		"aws-transform" => aws_sse::transform(source, limit, move |message| {
			let event = crate::llm::types::bedrock::deserialize_stream_output(message);
			let event = match event {
				Ok(e) => json!({"decoded":format!("{e:?}")}),
				Err(e) => {
					observations
						.lock()
						.unwrap()
						.push(json!({"error":e.to_string()}));
					return None;
				},
			};
			observations.lock().unwrap().push(event.clone());
			Some(event)
		}),
		"aws-multi" => aws_sse::transform_multi(source, limit, move |m| {
			let v = json!({"payloadHex":hex(m.payload())});
			observations.lock().unwrap().push(v.clone());
			vec![("aws.first", v.clone()), ("aws.second", v)]
		}),
		"aws-inspect" => aws_sse::inspect(source, limit, move |m| {
			observations
				.lock()
				.unwrap()
				.push(json!({"payloadHex":hex(m.payload())}))
		}),
		"validated-aws" => crate::llm::policy::streaming_wire::validated(source, limit, true),
		"validated-sse" => crate::llm::policy::streaming_wire::validated(source, limit, false),
		"sse-transform" => sse::json_transform::<Value, Value>(source, limit, move |v| match v {
			Ok(v) => {
				observations.lock().unwrap().push(v.clone());
				Some(v)
			},
			Err(e) => {
				observations
					.lock()
					.unwrap()
					.push(json!({"error":e.to_string()}));
				None
			},
		}),
		"sse-multi" => sse::json_transform_multi::<Value, Value, _>(source, limit, move |v| {
			let v = match v {
				sse::SseJsonEvent::Done => json!({"done":true}),
				sse::SseJsonEvent::Data(Ok(v)) => v,
				sse::SseJsonEvent::Data(Err(e)) => json!({"error":e.to_string()}),
			};
			observations.lock().unwrap().push(v.clone());
			vec![("mapped.delta", v)]
		}),
		"sse-pass" => sse::json_passthrough::<Value>(source, limit, move |v| {
			observations.lock().unwrap().push(json!(format!("{v:?}")))
		}),
		"sse-permissive" => sse::permissive_json_passthrough::<Value>(source, limit, move |v| {
			observations.lock().unwrap().push(json!(format!("{v:?}")))
		}),
		_ => unreachable!(),
	};
	let mut output_frames = Vec::new();
	for _ in 0..256 {
		match tokio::time::timeout(std::time::Duration::from_secs(2), output.frame())
			.await
			.expect("finite fixture must terminate")
		{
			Some(Ok(f)) => {
				if let Some(data) = f.data_ref() {
					output_frames
						.push(json!({"dataHex":hex(data),"sourcePolls":polls.load(Ordering::SeqCst)}));
				} else {
					output_frames.push(json!({"trailers":format!("{:?}",f.trailers_ref().unwrap()),"sourcePolls":polls.load(Ordering::SeqCst)}));
				}
			},
			Some(Err(e)) => {
				output_frames
					.push(json!({"error":error_value(&e),"sourcePolls":polls.load(Ordering::SeqCst)}));
				break;
			},
			None => {
				output_frames.push(json!({"eof":true,"sourcePolls":polls.load(Ordering::SeqCst)}));
				break;
			},
		}
	}
	assert!(output_frames.len() < 256);
	drop(output);
	assert_eq!(drops.load(Ordering::SeqCst), 1);
	json!({"frames":output_frames,"observations":*seen.lock().unwrap(),"sourceDrops":drops.load(Ordering::SeqCst)})
}

#[tokio::test]
async fn s5_transport_matches_original_golden() {
	let fixture: Value = serde_json::from_str(include_str!(
		"../../../../../tests/protocol/fixtures/streaming-transport-golden.json"
	))
	.unwrap();
	assert_eq!(fixture["cases"].as_array().unwrap().len(), 82);
	for case in fixture["cases"].as_array().unwrap() {
		let actual = if case["kind"] == "codec" {
			observe_codec(case)
		} else {
			observe_body(case).await
		};
		assert_eq!(
			actual, case["expected"],
			"{} {}",
			case["kind"], case["name"]
		);
	}
}

#[tokio::test]
async fn s5_transport_bridges_are_lazy_backpressured_and_drop_the_source() {
	let fixture: Value = serde_json::from_str(include_str!(
		"../../../../../tests/protocol/fixtures/streaming-transport-golden.json"
	))
	.unwrap();
	let aws = chunks(
		fixture["cases"]
			.as_array()
			.unwrap()
			.iter()
			.find(|c| c["kind"] == "codec" && c["name"] == "valid")
			.unwrap(),
	)
	.remove(0);
	for kind in [
		"aws-transform",
		"aws-multi",
		"aws-inspect",
		"validated-aws",
		"validated-sse",
		"sse-transform",
		"sse-pass",
		"sse-permissive",
	] {
		let data = if kind.starts_with("aws") || kind == "validated-aws" {
			aws.clone()
		} else {
			Bytes::from_static(b"data: {\"text\":\"bounded\"}\n\n")
		};
		let polls = Arc::new(AtomicUsize::new(0));
		let drops = Arc::new(AtomicUsize::new(0));
		let source = Body::new(Source {
			frames: (0..128).map(|_| Ok(Frame::data(data.clone()))).collect(),
			polls: polls.clone(),
			drops: drops.clone(),
			pending: true,
		});
		let mut body = match kind {
			"aws-transform" => aws_sse::transform(source, 4096, |m| {
				Some(json!({"payloadHex":hex(m.payload())}))
			}),
			"aws-multi" => {
				aws_sse::transform_multi(source, 4096, |_| vec![("one", json!(1)), ("two", json!(2))])
			},
			"aws-inspect" => aws_sse::inspect(source, 4096, |_| {}),
			"validated-aws" => crate::llm::policy::streaming_wire::validated(source, 4096, true),
			"validated-sse" => crate::llm::policy::streaming_wire::validated(source, 4096, false),
			"sse-transform" => sse::json_transform::<Value, Value>(source, 4096, Result::ok),
			"sse-pass" => sse::json_passthrough::<Value>(source, 4096, |_| {}),
			_ => sse::permissive_json_passthrough::<Value>(source, 4096, |_| {}),
		};
		assert_eq!(polls.load(Ordering::SeqCst), 0, "{kind}");
		assert!(body.frame().await.unwrap().is_ok());
		assert_eq!(polls.load(Ordering::SeqCst), 1, "{kind}");
		for _ in 0..8 {
			tokio::task::yield_now().await;
		}
		assert_eq!(polls.load(Ordering::SeqCst), 1, "slow consumer: {kind}");
		drop(body);
		assert_eq!(drops.load(Ordering::SeqCst), 1, "{kind}");
	}
}
