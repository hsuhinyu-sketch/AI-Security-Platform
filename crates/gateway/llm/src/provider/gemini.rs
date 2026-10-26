use super::ProviderFormat;

pub fn path(route: Option<ProviderFormat>) -> &'static str {
	match route {
		Some(ProviderFormat::Embeddings) => "/v1beta/openai/embeddings",
		Some(ProviderFormat::Rerank) => "/rerank",
		_ => "/v1beta/openai/chat/completions",
	}
}
