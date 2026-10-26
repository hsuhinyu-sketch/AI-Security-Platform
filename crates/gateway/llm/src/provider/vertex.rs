use super::ProviderFormat;
use crate::WireError;
use arcstr::{self as strng, ArcStr as Strng};
use serde_json::{Map, Value};

const ANTHROPIC_VERSION: &str = "vertex-2023-10-16";
pub const DISCOVERY_ENGINE_HOST: Strng = strng::literal!("discoveryengine.googleapis.com");
/// Values supplied by Host; no project discovery or authentication is performed here.
#[derive(Debug, Clone, Copy)]
pub struct Endpoint<'a> {
	pub model: Option<&'a str>,
	pub region: Option<&'a str>,
	pub project_id: &'a str,
}
impl Endpoint<'_> {
	fn configured_model<'a>(&'a self, request_model: Option<&'a str>) -> Option<&'a str> {
		self.model.as_deref().or(request_model)
	}
	pub fn is_anthropic_model(&self, request_model: Option<&str>) -> bool {
		self.anthropic_model(request_model).is_some()
	}
	pub fn prepare_anthropic_message_body(&self, body: Vec<u8>) -> Result<Vec<u8>, WireError> {
		self.prepare_anthropic_body(body, |b| {
			b.remove("model");
		})
	}
	pub fn prepare_anthropic_count_tokens_body(&self, body: Vec<u8>) -> Result<Vec<u8>, WireError> {
		self.prepare_anthropic_body(body, |b| {
			if let Some(Value::String(model)) = b.get("model") {
				let normalized = self
					.configured_model(Some(model))
					.map(|s| s.to_string())
					.unwrap_or_else(|| model.clone());
				b.insert("model".to_string(), Value::String(normalized));
			}
		})
	}
	/// Parse, inject version, apply model handling, strip unsupported fields and serialize.
	fn prepare_anthropic_body(
		&self,
		body: Vec<u8>,
		apply: impl FnOnce(&mut Map<String, Value>),
	) -> Result<Vec<u8>, WireError> {
		let mut body: Map<String, Value> =
			serde_json::from_slice(&body).map_err(WireError::RequestParsing)?;
		body.insert(
			"anthropic_version".to_string(),
			Value::String(ANTHROPIC_VERSION.to_string()),
		);
		apply(&mut body);
		remove_unsupported_vertex_fields(&mut body);
		serde_json::to_vec(&body).map_err(WireError::RequestMarshal)
	}
	pub fn get_path_for_model(
		&self,
		route: Option<ProviderFormat>,
		request_model: Option<&str>,
		streaming: bool,
	) -> Strng {
		let location = self.region.unwrap_or("global");

		match (route, self.anthropic_model(request_model)) {
			(Some(ProviderFormat::AnthropicTokenCount), _) => {
				strng::format!(
					"/v1/projects/{}/locations/{}/publishers/anthropic/models/count-tokens:rawPredict",
					self.project_id,
					location
				)
			},
			(Some(ProviderFormat::Rerank), _) => {
				strng::format!(
					"/v1/projects/{}/locations/{}/rankingConfigs/default_ranking_config:rank",
					self.project_id,
					location
				)
			},
			(Some(ProviderFormat::Embeddings), _) => {
				let model = self.configured_model(request_model).unwrap_or_default();
				strng::format!(
					"/v1/projects/{}/locations/{}/publishers/google/models/{}:predict",
					self.project_id,
					location,
					model
				)
			},
			(_, Some(model)) => {
				strng::format!(
					"/v1/projects/{}/locations/{}/publishers/anthropic/models/{}:{}",
					self.project_id,
					location,
					model,
					if streaming {
						"streamRawPredict"
					} else {
						"rawPredict"
					}
				)
			},
			_ => {
				strng::format!(
					"/v1/projects/{}/locations/{}/endpoints/openapi/chat/completions",
					self.project_id,
					location
				)
			},
		}
	}
	pub fn get_host(&self, route_type: Option<ProviderFormat>) -> Strng {
		// Rerank is served by the Discovery Engine ranking endpoint, not the aiplatform host. Deciding
		// it here keeps the request authority (Host header) and the TCP/TLS connection target in sync.
		if route_type == Some(ProviderFormat::Rerank) {
			return DISCOVERY_ENGINE_HOST;
		}
		match self.region {
			None => strng::literal!("aiplatform.googleapis.com"),
			Some(region) if region == "global" => strng::literal!("aiplatform.googleapis.com"),
			Some(region) if region == "us" || region == "eu" => {
				strng::format!("aiplatform.{region}.rep.googleapis.com")
			},
			Some(region) => strng::format!("{region}-aiplatform.googleapis.com"),
		}
	}
	fn anthropic_model<'a>(&'a self, request_model: Option<&'a str>) -> Option<Strng> {
		let model = self.configured_model(request_model)?;

		// Strip known prefixes
		let model: &str = model
			.split_once("publishers/anthropic/models/")
			.map(|(_, m)| m)
			.or_else(|| model.strip_prefix("anthropic/"))
			.or_else(|| {
				if model.starts_with("claude-") {
					Some(model)
				} else {
					None
				}
			})?;

		// Replace -YYYYMMDD with @YYYYMMDD
		if model.len() > 8 && model.as_bytes()[model.len() - 9] == b'-' {
			let (base, date) = model.split_at(model.len() - 8);
			if date.chars().all(|c| c.is_ascii_digit()) {
				Some(Strng::from(format!("{}@{}", &base[..base.len() - 1], date)))
			} else {
				Some(Strng::from(model))
			}
		} else {
			Some(Strng::from(model))
		}
	}
}
fn remove_unsupported_vertex_fields(body: &mut Map<String, Value>) {
	// output_format is the deprecated predecessor of output_config.format; strip it.
	// output_config is intentionally preserved: Vertex supports it for structured outputs
	// (format.json_schema) and for adaptive thinking depth control (effort).
	body.remove("output_format");
	// Vertex supports cache_control but not the "scope" child from the prompt-caching-scope beta.
	for value in body.values_mut() {
		remove_nested_field(value, "cache_control", "scope");
	}
}
fn remove_nested_field(value: &mut Value, key: &str, child: &str) {
	match value {
		Value::Object(map) => {
			if let Some(Value::Object(nested)) = map.get_mut(key) {
				nested.remove(child);
			}
			for v in map.values_mut() {
				remove_nested_field(v, key, child);
			}
		},
		Value::Array(arr) => {
			for v in arr {
				remove_nested_field(v, key, child);
			}
		},
		_ => {},
	}
}
