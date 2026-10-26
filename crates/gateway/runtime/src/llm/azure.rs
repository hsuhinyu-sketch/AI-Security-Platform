use platform_core::strng;
use platform_core::strng::Strng;

#[cfg(feature = "providers-azure")]
use crate::http::auth::azure::AzureCredentialCache;
use crate::llm::RouteType;
use crate::*;

pub use gateway_llm::provider::azure::AzureResourceType;

#[apply(schema!)]
#[cfg_attr(feature = "schema", schemars(rename = "AzureProvider"))]
pub struct Provider {
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub model: Option<Strng>,
	/// The Azure resource name used to construct the endpoint host.
	pub resource_name: Strng,
	/// The type of Azure endpoint. Determines the host suffix.
	pub resource_type: AzureResourceType,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub api_version: Option<Strng>,
	/// The Foundry project name, required when `resourceType` is `foundry`.
	/// Used to construct paths: `/api/projects/{projectName}/openai/v1/...`.
	/// This is distinct from `resourceName` which is used for the host.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub project_name: Option<Strng>,
	/// Per-provider credential cache, shared across requests via Arc.
	#[serde(skip)]
	#[cfg_attr(feature = "schema", schemars(skip))]
	#[cfg(feature = "providers-azure")]
	pub cached_cred: AzureCredentialCache,
}

impl super::Provider for Provider {
	const NAME: Strng = strng::literal!("azure");
}

impl Provider {
	/// Returns true if `model` (or the provider's configured default model) is a Claude model.
	/// Used to select between Foundry's Anthropic-native and OpenAI-compatible endpoints.
	pub fn is_anthropic_model(&self, model: Option<&str>) -> bool {
		self.endpoint().is_anthropic_model(model)
	}

	pub fn get_path_for_model(&self, route: RouteType, model: &str) -> Strng {
		self
			.endpoint()
			.get_path_for_model(route.provider_format(), model)
	}

	pub fn get_host(&self) -> Strng {
		self.endpoint().get_host()
	}

	pub(super) fn endpoint(&self) -> gateway_llm::provider::azure::Endpoint<'_> {
		gateway_llm::provider::azure::Endpoint {
			model: self.model.as_deref(),
			resource_name: &self.resource_name,
			resource_type: &self.resource_type,
			api_version: self.api_version.as_deref(),
			project_name: self.project_name.as_deref(),
		}
	}
}
