use std::collections::BTreeMap;

use serde_json::{Value, json};

pub fn fixture() -> Value {
	serde_json::from_str(include_str!("../fixtures/streaming-golden.json")).unwrap()
}

/// Normalize only generated clock fields and generated IDs, preserving raw SSE
/// bytes, JSON field order, event boundaries and the original HTTP data chunks.
pub fn normalize_frames(frames: Vec<String>) -> Vec<String> {
	let mut ids = BTreeMap::<String, String>::new();
	let mut replacements = BTreeMap::<String, String>::new();
	fn visit(v: &Value, ids: &mut BTreeMap<String, String>, out: &mut BTreeMap<String, String>) {
		match v {
			Value::Object(fields) => {
				for (key, value) in fields {
					if matches!(key.as_str(), "created" | "created_at") && value.is_number() {
						out.insert(
							format!("\"{key}\":{value}"),
							format!("\"{key}\":1700000000"),
						);
					} else {
						visit(value, ids, out);
					}
				}
			},
			Value::Array(a) => a.iter().for_each(|v| visit(v, ids, out)),
			Value::String(s) => {
				if let Some((prefix, suffix)) = s.split_once('_')
					&& matches!(prefix, "resp" | "msg" | "call")
					&& suffix.len() == 16
					&& suffix.bytes().all(|c| c.is_ascii_hexdigit())
				{
					let next = ids.len();
					let replacement = ids
						.entry(s.clone())
						.or_insert_with(|| format!("{prefix}_fixture_{next}"));
					out.insert(format!("\"{s}\""), format!("\"{replacement}\""));
				}
			},
			_ => {},
		}
	}
	for frame in &frames {
		for line in frame.lines() {
			if let Some(data) = line.strip_prefix("data: ")
				&& let Ok(value) = serde_json::from_str::<Value>(data)
			{
				visit(&value, &mut ids, &mut replacements);
			}
		}
	}
	frames
		.into_iter()
		.map(|mut frame| {
			for (from, to) in &replacements {
				frame = frame.replace(from, to);
			}
			frame
		})
		.collect()
}

pub fn event_values(frames: &[String]) -> Vec<Value> {
	frames.iter().flat_map(|frame| frame.split("\n\n")).filter_map(|raw| {
		let data = raw.lines().find_map(|line| line.strip_prefix("data: "))?;
		let name = raw.lines().find_map(|line| line.strip_prefix("event: ")).unwrap_or("");
		Some(json!({"event":name,"data":serde_json::from_str::<Value>(data).unwrap_or(Value::String(data.into()))}))
	}).collect()
}
