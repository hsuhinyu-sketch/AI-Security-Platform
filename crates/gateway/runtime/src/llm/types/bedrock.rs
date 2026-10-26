pub use gateway_llm::types::bedrock::*;

// Historical strict decoder used by compatibility fixtures and diagnostic inspection.
#[cfg(all(test, feature = "providers-aws"))]
pub fn deserialize_stream_output(
	m: crate::parse::aws_sse::Message,
) -> anyhow::Result<ConverseStreamOutput> {
	let event_type = m
		.headers()
		.iter()
		.find(|h| h.name().as_str() == ":event-type")
		.and_then(|h| h.value().as_string().ok())
		.map(|s| s.as_str().to_owned());
	deserialize_stream_event(m)?
		.ok_or_else(|| anyhow::anyhow!("unexpected event type: {}", event_type.unwrap_or_default()))
}

/// Unknown ordinary events are ignorable extensions, not provider failures.
#[cfg(feature = "providers-aws")]
pub(crate) fn deserialize_stream_event(
	m: crate::parse::aws_sse::Message,
) -> anyhow::Result<Option<ConverseStreamOutput>> {
	// Helper to extract a string header value by name
	let get_header = |name: &str| -> Option<String> {
		m.headers()
			.iter()
			.find(|h| h.name().as_str() == name)
			.and_then(|h| h.value().as_string().ok())
			.map(|s| s.as_str().to_owned())
	};

	// Check for exception messages first - AWS EventStream uses :message-type header
	// to distinguish between normal events and exceptions
	let message_type = get_header(":message-type");
	if message_type.as_deref() == Some("exception") {
		let exception_type = get_header(":exception-type").unwrap_or_else(|| "unknown".to_owned());
		let error_message = String::from_utf8_lossy(m.payload()).to_string();
		anyhow::bail!("{exception_type}: {error_message}");
	}

	let Some(event_type) = get_header(":event-type") else {
		anyhow::bail!("no event type header")
	};

	let payload = m.payload();
	Ok(Some(match event_type.as_str() {
		"contentBlockDelta" => ConverseStreamOutput::ContentBlockDelta(serde_json::from_slice::<
			ContentBlockDeltaEvent,
		>(payload)?),
		"contentBlockStart" => ConverseStreamOutput::ContentBlockStart(serde_json::from_slice::<
			ContentBlockStartEvent,
		>(payload)?),
		"contentBlockStop" => ConverseStreamOutput::ContentBlockStop(serde_json::from_slice::<
			ContentBlockStopEvent,
		>(payload)?),
		"messageStart" => {
			ConverseStreamOutput::MessageStart(serde_json::from_slice::<MessageStartEvent>(payload)?)
		},
		"messageStop" => {
			ConverseStreamOutput::MessageStop(serde_json::from_slice::<MessageStopEvent>(payload)?)
		},
		"metadata" => ConverseStreamOutput::Metadata(serde_json::from_slice::<
			ConverseStreamMetadataEvent,
		>(payload)?),
		_ => return Ok(None),
	}))
}
