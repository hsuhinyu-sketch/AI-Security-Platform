use gateway_llm::types::bedrock::*;
use serde_json::Value;

// Decode only the protocol payload. AWS Message headers and exception policy are Host-owned.
pub fn decode(event: &Value) -> Option<Result<ConverseStreamOutput, serde_json::Error>> {
	let payload = event["payload"].as_str().unwrap();
	Some(match event["type"].as_str()? {
		"contentBlockDelta" => {
			serde_json::from_str(payload).map(ConverseStreamOutput::ContentBlockDelta)
		},
		"contentBlockStart" => {
			serde_json::from_str(payload).map(ConverseStreamOutput::ContentBlockStart)
		},
		"contentBlockStop" => serde_json::from_str(payload).map(ConverseStreamOutput::ContentBlockStop),
		"messageStart" => serde_json::from_str(payload).map(ConverseStreamOutput::MessageStart),
		"messageStop" => serde_json::from_str(payload).map(ConverseStreamOutput::MessageStop),
		"metadata" => serde_json::from_str(payload).map(ConverseStreamOutput::Metadata),
		_ => return None,
	})
}

pub fn fixture() -> Value {
	serde_json::from_str(include_str!("../fixtures/bedrock-streaming-golden.json")).unwrap()
}
