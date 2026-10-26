//! Bounded, demand-driven SSE projection. Never forward unvalidated bytes.
use bytes::Bytes;
use futures_util::{StreamExt, TryStreamExt};
use tokio::time::{Duration, Instant};
use tokio_sse_codec::{Frame, SseDecoder};
use tokio_util::{codec::FramedRead, io::StreamReader};

use super::*;

impl AuthorizedCall {
	pub(super) fn stream_denial(&self, error: ObjectError) -> ProxyError {
		let mut action = self.action.clone();
		if let Some(id) = &self.permit.task_id {
			action.resource.resource_type = ResourceType::AgentTask;
			action.resource.id = task_resource_id(&self.scope, id);
		}
		deny(&action, error)
	}
	pub(super) fn apply_stream(self: Box<Self>, response: &mut Response) -> Result<(), ProxyError> {
		if !response.status().is_success()
			|| response
				.headers()
				.get(header::CONTENT_TYPE)
				.and_then(|v| v.to_str().ok())
				.and_then(|v| v.split(';').next())
				.map(str::trim)
				!= Some("text/event-stream")
			|| response
				.headers()
				.get(header::CONTENT_ENCODING)
				.is_some_and(|v| v != "identity")
		{
			return Err(self.stream_denial(ObjectError::ResponseBinding));
		}
		self.check_live()?;
		let cfg = self.config.a2a_objects.clone().expect("enabled");
		let body = std::mem::replace(response.body_mut(), Body::empty());
		// StreamReader copies into bounded read buffers, rather than accumulating arbitrary chunks.
		let reader = StreamReader::new(body.into_data_stream().map_err(std::io::Error::other));
		let frames = FramedRead::new(
			reader,
			SseDecoder::<Bytes>::with_max_size(cfg.max_event_bytes),
		);
		for name in [
			"content-length",
			"etag",
			"content-encoding",
			"content-digest",
			"digest",
			"content-md5",
		] {
			response.headers_mut().remove(name);
		}
		response.headers_mut().insert(
			header::CACHE_CONTROL,
			"private, no-store".parse().expect("constant"),
		);

		let idle = Instant::now() + Duration::from_secs(cfg.stream_idle_seconds);
		let end = Instant::now() + Duration::from_secs(cfg.max_stream_seconds);
		let reauthorize = Instant::now() + Duration::from_secs(cfg.reauthorize_seconds);
		let stream = futures_util::stream::try_unfold(
			(self, frames, idle, end, reauthorize, false),
			move |(mut call, mut frames, mut idle, end, mut reauthorize, done)| {
				let cfg = cfg.clone();
				async move {
					if done {
						return Ok(None);
					}
					let mut processed = 0;
					loop {
						if processed == 64 {
							tokio::task::yield_now().await;
							processed = 0;
						}
						processed += 1;
						// Bounded demand-driven processing: no spawned task or unbounded queue.
						let frame = tokio::select! {
								biased;
								_ = call.credential.revision.changed() => {
										return Err(call.stream_denial(ObjectError::ConfigChanged));
								}
								_ = tokio::time::sleep_until(idle.min(end)) => {
										return Err(call.stream_denial(ObjectError::StreamTimeout));
								}
								_ = tokio::time::sleep_until(reauthorize) => {
										call.check_live()?;
										reauthorize = Instant::now() + Duration::from_secs(cfg.reauthorize_seconds);
										continue;
								}
								frame = frames.next() => frame,
						};
						let frame = frame
							.ok_or_else(|| call.stream_denial(ObjectError::StreamTruncated))?
							.map_err(|_| call.stream_denial(ObjectError::ResponseBinding))?;
						let Frame::Event(event) = frame else { continue };
						call.check_live()?;
						if event.id.is_some() || event.name != "message" {
							return Err(call.stream_denial(ObjectError::Unsupported));
						}
						let mut rpc: Value = serde_json::from_slice(&event.data)
							.map_err(|_| call.stream_denial(ObjectError::ResponseBinding))?;
						let (visible, done) = call.process_event(&mut rpc)?;
						let visible = visible && call.project_event(rpc.get_mut("result"))?;
						idle = Instant::now() + Duration::from_secs(cfg.stream_idle_seconds);
						call.check_credential().map_err(|e| call.stream_denial(e))?;
						if Instant::now() >= end {
							return Err(call.stream_denial(ObjectError::StreamTimeout));
						}
						if visible {
							let cursor = tokio::select! {
								biased;
								_ = tokio::time::sleep_until(end) => return Err(call.stream_denial(ObjectError::StreamTimeout)),
								result = call.record_event(&rpc) => result?,
							};
							let data = serde_json::to_vec(&rpc)
								.map_err(|_| call.stream_denial(ObjectError::ResponseBinding))?;
							call.check_credential().map_err(|e| call.stream_denial(e))?;
							call.check_continuation()?;
							if Instant::now() >= end {
								return Err(call.stream_denial(ObjectError::StreamTimeout));
							}
							let encoded = crate::parse::encode_sse_event("", Bytes::from(data));
							let encoded = if let Some(cursor) = cursor {
								let mut event = Vec::with_capacity(encoded.len() + 42);
								event.extend_from_slice(format!("id: {cursor}\n").as_bytes());
								event.extend_from_slice(&encoded);
								Bytes::from(event)
							} else {
								encoded
							};
							return Ok::<_, ProxyError>(Some((
								encoded,
								(call, frames, idle, end, reauthorize, done),
							)));
						}
					}
				}
			},
		);
		*response.body_mut() = Body::from_stream(stream);
		Ok(())
	}

	fn check_live(&self) -> Result<(), ProxyError> {
		self.check_continuation()?;
		if self.config.validate_composition().is_err() {
			return Err(self.stream_denial(ObjectError::Unavailable));
		}
		self.check_credential().map_err(|e| self.stream_denial(e))?;
		self
			.config
			.a2a_task_store
			.validate_stream(
				self.config.a2a_objects.as_ref().expect("enabled"),
				&self.permit,
			)
			.map_err(|e| self.stream_denial(e))?;
		Ok(())
	}

	fn process_event(&mut self, rpc: &mut Value) -> Result<(bool, bool), ProxyError> {
		let context = self.context();
		let id = self.rpc_id.clone();
		gateway_a2a::streaming::process_event(rpc, &id, &context, self)
	}
}
