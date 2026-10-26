use super::ProviderFormat;

pub fn path_suffix(route: Option<ProviderFormat>) -> &'static str {
	match route {
		Some(ProviderFormat::AnthropicTokenCount) => "/messages/count_tokens",
		_ => "/messages",
	}
}
