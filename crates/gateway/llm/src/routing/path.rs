//! Model identifiers embedded in existing Vertex and Bedrock request paths.
use percent_encoding::{AsciiSet, CONTROLS, percent_decode_str, utf8_percent_encode};

pub fn extract_model_from_path(path: &str) -> Option<arcstr::ArcStr> {
	let model = if path.ends_with(":streamRawPredict") || path.ends_with(":rawPredict") {
		path
			.split_once("/publishers/anthropic/models/")
			.and_then(|(_, rest)| rest.split_once(':').map(|(model, _)| model))
	} else if path.ends_with("/invoke-with-response-stream")
		|| path.ends_with("/invoke")
		|| path.ends_with("/converse-stream")
		|| path.ends_with("/converse")
	{
		path
			.split_once("/model/")
			.and_then(|(_, rest)| strip_bedrock_model_suffix(rest))
	} else {
		None
	};
	model.map(|model| arcstr::ArcStr::from(percent_decode_str(model).decode_utf8_lossy()))
}

fn strip_bedrock_model_suffix(rest: &str) -> Option<&str> {
	[
		"/invoke-with-response-stream",
		"/invoke",
		"/converse-stream",
		"/converse",
	]
	.into_iter()
	.find_map(|suffix| rest.strip_suffix(suffix))
}

pub fn rewrite_path_model(path: &str, target: &str) -> Option<String> {
	if path.ends_with(":streamRawPredict") || path.ends_with(":rawPredict") {
		let (prefix, rest) = path.split_once("/publishers/anthropic/models/")?;
		let (_, suffix) = rest.split_once(':')?;
		return Some(format!(
			"{prefix}/publishers/anthropic/models/{}:{suffix}",
			encode_model_path_segment(target)
		));
	}
	for suffix in [
		"/invoke-with-response-stream",
		"/invoke",
		"/converse-stream",
		"/converse",
	] {
		if let Some(before_suffix) = path.strip_suffix(suffix)
			&& let Some((prefix, _)) = before_suffix.split_once("/model/")
		{
			return Some(format!(
				"{prefix}/model/{}{suffix}",
				encode_model_path_segment(target)
			));
		}
	}
	None
}

fn encode_model_path_segment(model: &str) -> String {
	const MODEL_SEGMENT: &AsciiSet = &CONTROLS.add(b'/').add(b'%');
	utf8_percent_encode(model, MODEL_SEGMENT).to_string()
}
