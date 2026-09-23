use std::path::PathBuf;
use std::sync::{Arc, OnceLock};

use crate::trusted_https;
use security_pipeline::{DynamicPdpError, RemotePdpRequest, RemotePdpResponse, RemotePdpTransport};

/// Runtime configuration for a trusted remote PDP. The identity PEM is a combined client
/// certificate and private-key PEM used for mTLS; it is deliberately a file reference rather
/// than inline configuration, so private key material cannot enter an AI-system config.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RemotePdpConfig {
	pub endpoint: String,
	#[serde(default = "default_timeout_millis")]
	pub timeout_millis: u64,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub identity_pem_file: Option<PathBuf>,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub root_ca_pem_file: Option<PathBuf>,
	/// A loaded AI-system configuration shares one HTTP client across requests.
	#[serde(skip, default = "default_transport_slot")]
	transport: Arc<OnceLock<Result<HttpRemotePdpTransport, String>>>,
}

const fn default_timeout_millis() -> u64 {
	250
}

fn default_transport_slot() -> Arc<OnceLock<Result<HttpRemotePdpTransport, String>>> {
	Arc::new(OnceLock::new())
}

impl RemotePdpConfig {
	pub fn transport(&self) -> Result<HttpRemotePdpTransport, DynamicPdpError> {
		match self
			.transport
			.get_or_init(|| HttpRemotePdpTransport::from_config(self).map_err(|error| error.reason))
		{
			Ok(transport) => Ok(transport.clone()),
			Err(reason) => Err(DynamicPdpError::unavailable(reason.clone())),
		}
	}
}

/// Blocking transport used by the current synchronous gateway security hook. It has a strict
/// timeout and is held in the loaded configuration; a future async security hook can replace
/// this adapter without changing the remote PDP contract in `gateway-adapter`.
#[derive(Debug, Clone)]
pub struct HttpRemotePdpTransport {
	endpoint: String,
	client: reqwest::blocking::Client,
}

impl HttpRemotePdpTransport {
	fn from_config(config: &RemotePdpConfig) -> Result<Self, DynamicPdpError> {
		let (endpoint, client) = trusted_https::build_client(
			&config.endpoint,
			config.timeout_millis,
			config.identity_pem_file.as_deref(),
			config.root_ca_pem_file.as_deref(),
			"remote PDP",
		)
		.map_err(DynamicPdpError::unavailable)?;
		Ok(Self { endpoint, client })
	}
}

impl RemotePdpTransport for HttpRemotePdpTransport {
	fn decide(&self, request: RemotePdpRequest) -> Result<RemotePdpResponse, DynamicPdpError> {
		let response = self
			.client
			.post(&self.endpoint)
			.header(reqwest::header::ACCEPT, "application/json")
			.json(&request)
			.send()
			.map_err(|error| DynamicPdpError::unavailable(format!("remote PDP request failed: {error}")))?
			.error_for_status()
			.map_err(|error| {
				DynamicPdpError::unavailable(format!("remote PDP returned an error status: {error}"))
			})?;
		response.json::<RemotePdpResponse>().map_err(|error| {
			DynamicPdpError::unavailable(format!("remote PDP response is invalid: {error}"))
		})
	}
}

#[cfg(test)]
mod tests {
	use super::RemotePdpConfig;

	#[test]
	fn rejects_non_https_pdp_endpoint() {
		let config = RemotePdpConfig {
			endpoint: "http://pdp.internal/v1/decisions".into(),
			timeout_millis: 250,
			identity_pem_file: None,
			root_ca_pem_file: None,
			transport: super::default_transport_slot(),
		};
		assert!(config.transport().is_err());
	}
}
