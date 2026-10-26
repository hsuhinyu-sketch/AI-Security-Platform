use platform_core::prelude::Strng;
use platform_core::strng;

use crate::llm::InputFormat;
use crate::*;

#[apply(schema!)]
#[cfg_attr(feature = "schema", schemars(rename = "CustomProvider"))]
pub struct Provider {
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub model: Option<Strng>,
	/// Provider identity for cost-catalog lookup and telemetry. Built-in named providers
	/// (cohere, mistral, ...) set this so their cost resolves under the right catalog key;
	/// a bare custom provider may set it to match a catalog entry. Falls back to "custom".
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub provider_override: Option<Strng>,
	pub formats: Vec<ProviderFormatConfig>,
}

impl Provider {
	pub fn supports(&self, format: ProviderFormat) -> bool {
		gateway_llm::provider::custom::supports(self.formats.iter().map(|f| f.format), format)
	}

	pub fn native_format_for(&self, input_format: InputFormat) -> Option<ProviderFormat> {
		gateway_llm::provider::custom::native_format_for(
			self.formats.iter().map(|f| f.format),
			input_format,
		)
	}

	pub fn path_for(&self, format: ProviderFormat) -> Option<&str> {
		gateway_llm::provider::custom::path_for(
			self.formats.iter().map(|f| (f.format, f.path.as_deref())),
			format,
		)
	}
}

impl super::Provider for Provider {
	const NAME: Strng = strng::literal!("custom");
}

pub use gateway_llm::provider::custom::ProviderFormatConfig;

pub use gateway_llm::provider::ProviderFormat;
