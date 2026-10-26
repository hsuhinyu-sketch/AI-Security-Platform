use super::ProviderFormat;
use arcstr::{self as strng, ArcStr as Strng};

/// The type of Azure endpoint to connect to.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub enum AzureResourceType {
	/// Azure OpenAI Service endpoint: `{resourceName}.openai.azure.com`
	OpenAI,
	/// Azure AI Foundry (project) endpoint: `{resourceName}.services.ai.azure.com`
	/// Requires `project_name` to construct paths like `/api/projects/{project}/openai/v1/...`
	#[serde(alias = "aiServices")]
	Foundry,
}

/// Borrowed protocol parameters, assembled by Host without its credential cache.
#[derive(Debug, Clone, Copy)]
pub struct Endpoint<'a> {
	pub model: Option<&'a str>,
	pub resource_name: &'a str,
	pub resource_type: &'a AzureResourceType,
	pub api_version: Option<&'a str>,
	pub project_name: Option<&'a str>,
}
impl Endpoint<'_> {
	pub fn is_anthropic_model(&self, model: Option<&str>) -> bool {
		let effective = self.model.as_deref().or(model).unwrap_or_default();
		effective.to_ascii_lowercase().starts_with("claude")
	}
	pub fn get_path_for_model(&self, route: Option<ProviderFormat>, model: &str) -> Strng {
		// Foundry exposes both OpenAI-compatible and Anthropic-native endpoints.
		// Route to the Anthropic-native path only for Claude models; GPT and other
		// models use the project-scoped OpenAI-compatible path.
		if matches!(self.resource_type, AzureResourceType::Foundry) {
			if self.is_anthropic_model(Some(model)) {
				if route == Some(ProviderFormat::Messages) {
					return strng::literal!("/anthropic/v1/messages");
				}
				if route == Some(ProviderFormat::AnthropicTokenCount) {
					return strng::literal!("/anthropic/v1/messages/count_tokens");
				}
			}
			let t = if route == Some(ProviderFormat::Embeddings) {
				strng::literal!("embeddings")
			} else if route == Some(ProviderFormat::Responses) {
				strng::literal!("responses")
			} else {
				strng::literal!("chat/completions")
			};
			let project = self.project_name.as_deref().unwrap_or(self.resource_name);
			return strng::format!("/api/projects/{project}/openai/v1/{t}");
		}

		let t = if route == Some(ProviderFormat::Embeddings) {
			strng::literal!("embeddings")
		} else if route == Some(ProviderFormat::Responses) {
			strng::literal!("responses")
		} else {
			strng::literal!("chat/completions")
		};

		let api_version = self.api_version();
		if api_version == "v1" {
			strng::format!("/openai/v1/{t}")
		} else if api_version == "preview" {
			// v1 preview API
			strng::format!("/openai/v1/{t}?api-version=preview")
		} else {
			let model = self.model.as_deref().unwrap_or(model);
			strng::format!(
				"/openai/deployments/{}/{t}?api-version={}",
				model,
				api_version
			)
		}
	}
	pub fn get_host(&self) -> Strng {
		match &self.resource_type {
			AzureResourceType::OpenAI => {
				strng::format!("{}.openai.azure.com", self.resource_name)
			},
			AzureResourceType::Foundry => {
				strng::format!("{}.services.ai.azure.com", self.resource_name)
			},
		}
	}
	fn api_version(&self) -> &str {
		self.api_version.as_deref().unwrap_or("v1")
	}
}
