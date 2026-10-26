use platform_core::prelude::Strng;
use platform_core::strng;

#[cfg(feature = "providers-aws")]
use crate::http::auth::aws::{AwsAssumeRoleCache, AwsCredentialsCache};
use crate::*;

pub use crate::http::auth::AwsRegion;

#[apply(schema!)]
#[cfg_attr(feature = "schema", schemars(rename = "BedrockProvider"))]
pub struct Provider {
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub model: Option<Strng>, // Optional: model override for Bedrock API path
	pub region: Strng, // Required: AWS region
	#[serde(skip_serializing_if = "Option::is_none")]
	pub guardrail_identifier: Option<Strng>,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub guardrail_version: Option<Strng>,
	/// Per-provider AWS source credential cache, shared across requests via Arc.
	#[serde(skip)]
	#[cfg_attr(feature = "schema", schemars(skip))]
	#[cfg(feature = "providers-aws")]
	pub source_credentials_cache: AwsCredentialsCache,
	/// Per-provider AWS AssumeRole credential cache, shared across requests via Arc.
	#[serde(skip)]
	#[cfg_attr(feature = "schema", schemars(skip))]
	#[cfg(feature = "providers-aws")]
	pub assume_role_cache: AwsAssumeRoleCache,
}

impl super::Provider for Provider {
	const NAME: Strng = strng::literal!("aws.bedrock");
}

impl Provider {
	pub fn is_anthropic_model(&self, request_model: Option<&str>) -> bool {
		self.endpoint().is_anthropic_model(request_model)
	}

	pub fn get_path_for_route(
		&self,
		route_type: super::RouteType,
		streaming: bool,
		model: &str,
	) -> Strng {
		self
			.endpoint()
			.get_path_for_route(route_type.provider_format(), streaming, model)
	}

	pub fn get_host(&self, route_type: super::RouteType) -> Strng {
		self.endpoint().get_host(route_type.provider_format())
	}
}

impl Provider {
	pub(super) fn endpoint(&self) -> gateway_llm::provider::bedrock::Endpoint<'_> {
		gateway_llm::provider::bedrock::Endpoint {
			model: self.model.as_deref(),
			region: &self.region,
		}
	}
}
