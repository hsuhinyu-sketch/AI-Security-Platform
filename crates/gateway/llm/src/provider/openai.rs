use super::ProviderFormat;

pub fn path_suffix(route: Option<ProviderFormat>) -> &'static str {
	match route {
		Some(ProviderFormat::Responses) => "/responses",
		Some(ProviderFormat::Embeddings) => "/embeddings",
		Some(ProviderFormat::Rerank) => "/rerank",
		Some(ProviderFormat::Realtime) => "/realtime",
		// All others get translated down to completions
		_ => "/chat/completions",
	}
}
