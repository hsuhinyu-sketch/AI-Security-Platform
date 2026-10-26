//! URI projection only. The Host binds and authorizes the actual network destination.
use super::{
	ProviderFormat, RouteType, adapter::Adapter, anthropic, copilot, custom, gemini, openai,
};
use http::uri::PathAndQuery;

#[derive(Debug, Clone, Copy)]
pub struct RequestDetails<'a> {
	pub model: &'a str,
	pub native_format: Option<ProviderFormat>,
	pub streaming: bool,
}

fn append_query(uri: &http::Uri, path: &str) -> Result<PathAndQuery, http::Error> {
	let path = match uri.query() {
		Some(query) => format!(
			"{path}{}{query}",
			if path.contains('?') { "&" } else { "?" }
		),
		None => path.to_owned(),
	};
	PathAndQuery::try_from(path).map_err(Into::into)
}
fn prefix_path(path: &str, prefix: Option<&str>) -> String {
	prefix.map_or_else(
		|| path.to_owned(),
		|prefix| format!("{}{path}", prefix.trim_end_matches('/')),
	)
}

impl Adapter<'_> {
	pub fn host(&self, route: RouteType) -> Option<arcstr::ArcStr> {
		Some(match self {
			Self::OpenAI(_) => arcstr::literal!("api.openai.com"),
			Self::Anthropic(_) => arcstr::literal!("api.anthropic.com"),
			Self::Gemini(_) => arcstr::literal!("generativelanguage.googleapis.com"),
			Self::Copilot(_) => arcstr::literal!("api.githubcopilot.com"),
			Self::Azure(endpoint) => endpoint.get_host(),
			Self::Bedrock(endpoint) => endpoint.get_host(route.provider_format()),
			Self::Vertex(endpoint) => endpoint.get_host(route.provider_format()),
			Self::Custom(_) => return None,
		})
	}
	pub fn request_path(
		&self,
		uri: &http::Uri,
		route: RouteType,
		request: Option<RequestDetails<'_>>,
		prefix: Option<&str>,
		host_override: bool,
	) -> Result<Option<PathAndQuery>, http::Error> {
		if matches!(route, RouteType::Passthrough | RouteType::Detect) {
			return prefix
				.map(|prefix| {
					let current = uri.path();
					let rest = self
						.default_base_path()
						.and_then(|base| {
							current
								.strip_prefix(base)
								.filter(|rest| rest.is_empty() || rest.starts_with('/'))
						})
						.unwrap_or(current);
					append_query(uri, &format!("{}{rest}", prefix.trim_end_matches('/')))
				})
				.transpose();
		}
		if host_override && prefix.is_none() && !matches!(self, Self::Custom(_)) {
			return Ok(None);
		}
		let path = match self {
			Self::OpenAI(_) => format!(
				"{}{}",
				prefix.unwrap_or("/v1").trim_end_matches('/'),
				openai::path_suffix(route.provider_format())
			),
			Self::Copilot(_) => format!(
				"{}{}",
				prefix.unwrap_or("").trim_end_matches('/'),
				if route == RouteType::Models {
					copilot::MODELS_PATH
				} else {
					copilot::path_suffix(route.provider_format())
				}
			),
			Self::Gemini(_) => prefix_path(gemini::path(route.provider_format()), prefix),
			Self::Anthropic(_) => format!(
				"{}{}",
				prefix.unwrap_or("/v1").trim_end_matches('/'),
				anthropic::path_suffix(route.provider_format())
			),
			Self::Vertex(endpoint) => prefix_path(
				&endpoint.get_path_for_model(
					route.provider_format(),
					request.map(|r| r.model),
					request.is_some_and(|r| r.streaming),
				),
				prefix,
			),
			Self::Bedrock(endpoint) => {
				let Some(request) = request else {
					return Ok(None);
				};
				prefix_path(
					&endpoint.get_path_for_route(route.provider_format(), request.streaming, request.model),
					prefix,
				)
			},
			Self::Azure(endpoint) => {
				let Some(request) = request else {
					return Ok(None);
				};
				prefix_path(
					&endpoint.get_path_for_model(route.provider_format(), request.model),
					prefix,
				)
			},
			Self::Custom(provider) => {
				let Some(native) = request.and_then(|r| r.native_format) else {
					return Ok(None);
				};
				if let Some(path) = custom::path_for(
					provider
						.formats
						.iter()
						.map(|format| (format.format, format.path.as_deref())),
					native,
				) {
					path.to_owned()
				} else if matches!(
					native,
					ProviderFormat::Messages | ProviderFormat::AnthropicTokenCount
				) {
					format!(
						"{}{}",
						prefix.unwrap_or("/v1").trim_end_matches('/'),
						anthropic::path_suffix(Some(native))
					)
				} else {
					format!(
						"{}{}",
						prefix.unwrap_or("/v1").trim_end_matches('/'),
						openai::path_suffix(Some(native))
					)
				}
			},
		};
		append_query(uri, &path).map(Some)
	}
}
