use std::path::PathBuf;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use gateway_adapter::{DynamicPdpError, RemotePdpRequest, RemotePdpResponse, RemotePdpTransport};

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
		let endpoint = reqwest::Url::parse(&config.endpoint).map_err(|error| {
			DynamicPdpError::unavailable(format!("remote PDP endpoint is invalid: {error}"))
		})?;
		if endpoint.scheme() != "https" || endpoint.host_str().is_none() {
			return Err(DynamicPdpError::unavailable(
				"remote PDP endpoint must be an absolute https URL",
			));
		}
		if config.timeout_millis == 0 {
			return Err(DynamicPdpError::unavailable(
				"remote PDP timeoutMillis must be greater than zero",
			));
		}

		let mut builder = reqwest::blocking::Client::builder()
			.use_rustls_tls()
			.timeout(Duration::from_millis(config.timeout_millis));
		if let Some(path) = &config.root_ca_pem_file {
			let pem = std::fs::read(path).map_err(|error| {
				DynamicPdpError::unavailable(format!(
					"unable to read remote PDP root CA PEM '{}': {error}",
					path.display()
				))
			})?;
			let certificate = reqwest::Certificate::from_pem(&pem).map_err(|error| {
				DynamicPdpError::unavailable(format!(
					"remote PDP root CA PEM '{}' is invalid: {error}",
					path.display()
				))
			})?;
			builder = builder.add_root_certificate(certificate);
		}
		if let Some(path) = &config.identity_pem_file {
			let pem = std::fs::read(path).map_err(|error| {
				DynamicPdpError::unavailable(format!(
					"unable to read remote PDP identity PEM '{}': {error}",
					path.display()
				))
			})?;
			let identity = reqwest::Identity::from_pem(&pem).map_err(|error| {
				DynamicPdpError::unavailable(format!(
					"remote PDP identity PEM '{}' is invalid: {error}",
					path.display()
				))
			})?;
			builder = builder.identity(identity);
		}
		let client = builder.build().map_err(|error| {
			DynamicPdpError::unavailable(format!("unable to build remote PDP client: {error}"))
		})?;
		Ok(Self {
			endpoint: endpoint.to_string(),
			client,
		})
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
