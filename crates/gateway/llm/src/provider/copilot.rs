use super::ProviderFormat;

/// Discovery is selected by the Host, separately from generation wire formats.
pub const MODELS_PATH: &str = "/models";

pub fn path_suffix(route: Option<ProviderFormat>) -> &'static str {
	match route {
		Some(ProviderFormat::Responses) => "/responses",
		Some(ProviderFormat::Embeddings) => "/embeddings",
		Some(ProviderFormat::Rerank) => "/rerank",
		_ => "/chat/completions",
	}
}
