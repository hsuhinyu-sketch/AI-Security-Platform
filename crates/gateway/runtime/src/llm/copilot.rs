use platform_core::strng;
use platform_core::strng::Strng;

use crate::llm::RouteType;
use crate::*;

#[apply(schema!)]
#[cfg_attr(feature = "schema", schemars(rename = "CopilotProvider"))]
pub struct Provider {
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub model: Option<Strng>,
}

impl super::Provider for Provider {
	const NAME: Strng = strng::literal!("copilot");
}

pub const DEFAULT_HOST_STR: &str = "api.githubcopilot.com";
pub const DEFAULT_HOST: Strng = strng::literal!(DEFAULT_HOST_STR);

pub fn path_suffix(route: RouteType) -> &'static str {
	if route == RouteType::Models {
		return gateway_llm::provider::copilot::MODELS_PATH;
	}
	gateway_llm::provider::copilot::path_suffix(route.provider_format())
}
