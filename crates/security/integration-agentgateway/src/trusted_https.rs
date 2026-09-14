use std::path::Path;
use std::time::Duration;

/// Constructs the shared TLS boundary used by remote security bricks. Callers retain the client
/// in their loaded configuration so certificates and connection pools are not rebuilt per request.
pub(crate) fn build_client(
	endpoint: &str,
	timeout_millis: u64,
	identity_pem_file: Option<&Path>,
	root_ca_pem_file: Option<&Path>,
	service_name: &str,
) -> Result<(String, reqwest::blocking::Client), String> {
	let endpoint = reqwest::Url::parse(endpoint)
		.map_err(|error| format!("{service_name} endpoint is invalid: {error}"))?;
	if endpoint.scheme() != "https" || endpoint.host_str().is_none() {
		return Err(format!(
			"{service_name} endpoint must be an absolute https URL"
		));
	}
	if timeout_millis == 0 {
		return Err(format!(
			"{service_name} timeoutMillis must be greater than zero"
		));
	}

	let mut builder = reqwest::blocking::Client::builder()
		.use_rustls_tls()
		.timeout(Duration::from_millis(timeout_millis));
	if let Some(path) = root_ca_pem_file {
		let pem = std::fs::read(path).map_err(|error| {
			format!(
				"unable to read {service_name} root CA PEM '{}': {error}",
				path.display()
			)
		})?;
		let certificate = reqwest::Certificate::from_pem(&pem).map_err(|error| {
			format!(
				"{service_name} root CA PEM '{}' is invalid: {error}",
				path.display()
			)
		})?;
		builder = builder.add_root_certificate(certificate);
	}
	if let Some(path) = identity_pem_file {
		let pem = std::fs::read(path).map_err(|error| {
			format!(
				"unable to read {service_name} identity PEM '{}': {error}",
				path.display()
			)
		})?;
		let identity = reqwest::Identity::from_pem(&pem).map_err(|error| {
			format!(
				"{service_name} identity PEM '{}' is invalid: {error}",
				path.display()
			)
		})?;
		builder = builder.identity(identity);
	}
	let client = builder
		.build()
		.map_err(|error| format!("unable to build {service_name} client: {error}"))?;
	Ok((endpoint.to_string(), client))
}
