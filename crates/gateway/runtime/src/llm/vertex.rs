use platform_core::strng;
use platform_core::strng::Strng;

use crate::llm::{AIError, RouteType};
use crate::*;

/// Host for the Discovery Engine ranking endpoint used by rerank. Distinct from the `aiplatform`
/// host used for chat/embeddings; defined once so the request authority/Host header and the actual
/// TCP/TLS connection target stay in sync.
pub use gateway_llm::provider::vertex::DISCOVERY_ENGINE_HOST;

#[apply(schema!)]
#[cfg_attr(feature = "schema", schemars(rename = "VertexProvider"))]
pub struct Provider {
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub model: Option<Strng>,
	/// Vertex AI region. Special values: `global` uses the global endpoint, while `us` and `eu`
	/// use restricted multi-region endpoints. Other values are treated as regional locations.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub region: Option<Strng>,
	pub project_id: Strng,
}

impl super::Provider for Provider {
	const NAME: Strng = strng::literal!("gcp.vertex_ai");
}

impl Provider {
	pub fn is_anthropic_model(&self, request_model: Option<&str>) -> bool {
		self.endpoint().is_anthropic_model(request_model)
	}

	pub fn prepare_anthropic_message_body(&self, body: Vec<u8>) -> Result<Vec<u8>, AIError> {
		self
			.endpoint()
			.prepare_anthropic_message_body(body)
			.map_err(Into::into)
	}

	pub fn prepare_anthropic_count_tokens_body(&self, body: Vec<u8>) -> Result<Vec<u8>, AIError> {
		self
			.endpoint()
			.prepare_anthropic_count_tokens_body(body)
			.map_err(Into::into)
	}

	pub fn get_path_for_model(
		&self,
		route: RouteType,
		request_model: Option<&str>,
		streaming: bool,
	) -> Strng {
		self
			.endpoint()
			.get_path_for_model(route.provider_format(), request_model, streaming)
	}

	pub fn get_host(&self, route_type: RouteType) -> Strng {
		self.endpoint().get_host(route_type.provider_format())
	}
}

impl Provider {
	pub(super) fn endpoint(&self) -> gateway_llm::provider::vertex::Endpoint<'_> {
		gateway_llm::provider::vertex::Endpoint {
			model: self.model.as_deref(),
			region: self.region.as_deref(),
			project_id: &self.project_id,
		}
	}
}
