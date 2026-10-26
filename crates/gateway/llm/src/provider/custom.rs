use super::{InputFormat, ProviderFormat};

pub fn supports(formats: impl Iterator<Item = ProviderFormat>, format: ProviderFormat) -> bool {
	formats.into_iter().any(|supported| supported == format)
}
pub fn native_format_for(
	formats: impl Iterator<Item = ProviderFormat> + Clone,
	input: InputFormat,
) -> Option<ProviderFormat> {
	input
		.provider_format_preferences()
		.iter()
		.copied()
		.find(|format| supports(formats.clone(), *format))
}
pub fn path_for<'a>(
	formats: impl Iterator<Item = (ProviderFormat, Option<&'a str>)>,
	format: ProviderFormat,
) -> Option<&'a str> {
	formats
		.into_iter()
		.find(|supported| supported.0 == format)
		.and_then(|supported| supported.1)
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct ProviderFormatConfig {
	#[serde(rename = "type")]
	pub format: ProviderFormat,
	#[cfg_attr(feature = "schema", schemars(with = "Option<String>"))]
	pub path: Option<arcstr::ArcStr>,
}
