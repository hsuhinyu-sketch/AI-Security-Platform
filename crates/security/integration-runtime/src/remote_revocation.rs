use std::path::PathBuf;
use std::sync::{Arc, OnceLock};

use security_pipeline::{DelegationRevocationError, DelegationRevocationProvider};

use crate::trusted_https;

/// Runtime configuration for a shared, authoritative delegation-revocation source. The source is
/// queried for every request that carries a verified `delegationId`; this deliberately has no
/// allow cache, so revocation is visible across gateway instances on the next protected action.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RemoteDelegationRevocationConfig {
	pub endpoint: String,
	#[serde(default = "default_timeout_millis")]
	pub timeout_millis: u64,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub identity_pem_file: Option<PathBuf>,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub root_ca_pem_file: Option<PathBuf>,
	#[serde(skip, default = "default_provider_slot")]
	provider: Arc<OnceLock<Result<HttpDelegationRevocationProvider, String>>>,
}

const fn default_timeout_millis() -> u64 {
	100
}

fn default_provider_slot() -> Arc<OnceLock<Result<HttpDelegationRevocationProvider, String>>> {
	Arc::new(OnceLock::new())
}

impl RemoteDelegationRevocationConfig {
	pub fn provider(&self) -> Result<HttpDelegationRevocationProvider, DelegationRevocationError> {
		match self.provider.get_or_init(|| {
			HttpDelegationRevocationProvider::from_config(self).map_err(|error| error.reason)
		}) {
			Ok(provider) => Ok(provider.clone()),
			Err(reason) => Err(DelegationRevocationError {
				reason: reason.clone(),
			}),
		}
	}
}

#[derive(Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct RemoteDelegationRevocationRequest<'a> {
	protocol_version: &'static str,
	delegation_id: &'a str,
}

#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct RemoteDelegationRevocationResponse {
	delegation_id: String,
	revoked: bool,
}

/// Synchronous external revocation provider for the current gateway hook. The protocol binds the
/// response to its requested delegation identifier, preventing a response from another grant from
/// being reused as an allow.
#[derive(Debug, Clone)]
pub struct HttpDelegationRevocationProvider {
	endpoint: String,
	client: reqwest::blocking::Client,
}

impl HttpDelegationRevocationProvider {
	fn from_config(
		config: &RemoteDelegationRevocationConfig,
	) -> Result<Self, DelegationRevocationError> {
		let (endpoint, client) = trusted_https::build_client(
			&config.endpoint,
			config.timeout_millis,
			config.identity_pem_file.as_deref(),
			config.root_ca_pem_file.as_deref(),
			"delegation revocation source",
		)
		.map_err(|reason| DelegationRevocationError { reason })?;
		Ok(Self { endpoint, client })
	}
}

impl DelegationRevocationProvider for HttpDelegationRevocationProvider {
	fn is_revoked(&self, delegation_id: &str) -> Result<bool, DelegationRevocationError> {
		let response = self
			.client
			.post(&self.endpoint)
			.header(reqwest::header::ACCEPT, "application/json")
			.json(&RemoteDelegationRevocationRequest {
				protocol_version: "v1",
				delegation_id,
			})
			.send()
			.map_err(|error| DelegationRevocationError {
				reason: format!("delegation revocation request failed: {error}"),
			})?
			.error_for_status()
			.map_err(|error| DelegationRevocationError {
				reason: format!("delegation revocation source returned an error status: {error}"),
			})?
			.json::<RemoteDelegationRevocationResponse>()
			.map_err(|error| DelegationRevocationError {
				reason: format!("delegation revocation response is invalid: {error}"),
			})?;
		if response.delegation_id != delegation_id {
			return Err(DelegationRevocationError {
				reason: "delegation revocation response delegationId does not match".into(),
			});
		}
		Ok(response.revoked)
	}
}

#[cfg(test)]
mod tests {
	use super::RemoteDelegationRevocationConfig;

	#[test]
	fn rejects_non_https_revocation_endpoint() {
		let config = RemoteDelegationRevocationConfig {
			endpoint: "http://revocations.internal/v1/check".into(),
			timeout_millis: 100,
			identity_pem_file: None,
			root_ca_pem_file: None,
			provider: super::default_provider_slot(),
		};
		assert!(config.provider().is_err());
	}
}
