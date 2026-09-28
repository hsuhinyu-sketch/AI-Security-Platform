//! Trusted HTTPS source connector. The caller names a configured source and a relative path;
//! it never controls a complete outbound URL, redirect target, DNS bypass, or proxy.

use std::time::Duration;

use reqwest::{Client, Url};
use sha2::{Digest, Sha256};

use crate::DocumentIngestRequest;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TrustedHttpsSourceConfig {
	pub id: String,
	/// Must be an HTTPS directory URL ending in '/'.
	pub base_url: String,
	/// Optional credential environment-variable name; its value is never serialized in config.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub bearer_token_env_var: Option<String>,
	/// Optional administrator-provided PEM CA certificate for private HTTPS sources.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub ca_cert_pem: Option<String>,
}

struct Source {
	id: String,
	base_url: Url,
	bearer_token: Option<String>,
	client: Client,
}

pub struct TrustedHttpsSourceRegistry {
	sources: Vec<Source>,
	max_bytes: usize,
}

struct FetchedDocument {
	source_id: String,
	source_uri: String,
	version: String,
	content: String,
}

impl TrustedHttpsSourceRegistry {
	pub fn validate_config(sources: &[TrustedHttpsSourceConfig]) -> Result<(), String> {
		let mut ids = std::collections::HashSet::new();
		for source in sources {
			if source.id.is_empty() || !ids.insert(source.id.as_str()) {
				return Err("trusted HTTPS source IDs must be unique and nonempty".into());
			}
			let url = Url::parse(&source.base_url)
				.map_err(|_| "trusted source baseUrl is invalid".to_string())?;
			if url.scheme() != "https"
				|| url.host_str().is_none()
				|| !url.path().ends_with('/')
				|| url.query().is_some()
				|| url.fragment().is_some()
				|| !url.username().is_empty()
				|| url.password().is_some()
			{
				return Err("trusted source baseUrl must be an HTTPS directory URL without credentials, query, or fragment".into());
			}
			if source.bearer_token_env_var.as_ref().is_some_and(|name| {
				name.is_empty() || !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
			}) {
				return Err("trusted source bearerTokenEnvVar must be an environment variable name".into());
			}
			if let Some(pem) = &source.ca_cert_pem {
				reqwest::Certificate::from_pem(pem.as_bytes()).map_err(|_| {
					"trusted source caCertPem must contain a valid PEM certificate".to_string()
				})?;
			}
		}
		Ok(())
	}

	pub fn new(configs: Vec<TrustedHttpsSourceConfig>, max_bytes: usize) -> Result<Self, String> {
		Self::validate_config(&configs)?;
		if max_bytes == 0 {
			return Err("trusted source document budget must be positive".into());
		}
		let sources = configs
			.into_iter()
			.map(|source| {
				let bearer_token = source
					.bearer_token_env_var
					.as_ref()
					.map(|name| {
						std::env::var(name).map_err(|_| {
							format!("trusted source credential environment variable '{name}' is unavailable")
						})
					})
					.transpose()?;
				let mut client = Client::builder()
					.use_rustls_tls()
					.no_proxy()
					.redirect(reqwest::redirect::Policy::none())
					.timeout(Duration::from_secs(10));
				if let Some(pem) = &source.ca_cert_pem {
					let certificate = reqwest::Certificate::from_pem(pem.as_bytes())
						.map_err(|_| "trusted source caCertPem is invalid".to_string())?;
					client = client.add_root_certificate(certificate);
				}
				let client = client
					.build()
					.map_err(|error| format!("unable to build trusted source client: {error}"))?;
				Ok(Source {
					id: source.id,
					base_url: Url::parse(&source.base_url).map_err(|_| "invalid source URL".to_string())?,
					bearer_token,
					client,
				})
			})
			.collect::<Result<Vec<_>, String>>()?;
		Ok(Self { sources, max_bytes })
	}

	/// The only public path that can produce a request marked as a trusted HTTPS import.
	pub async fn import_request(
		&self,
		corpus_id: impl Into<String>,
		document_id: impl Into<String>,
		source_id: &str,
		path: &str,
	) -> Result<DocumentIngestRequest, String> {
		let fetched = self.fetch(source_id, path).await?;
		Ok(DocumentIngestRequest::from_trusted_https(
			corpus_id,
			document_id,
			fetched.source_uri,
			fetched.content,
			fetched.source_id,
			fetched.version,
		))
	}

	async fn fetch(&self, source_id: &str, path: &str) -> Result<FetchedDocument, String> {
		let source = self
			.sources
			.iter()
			.find(|source| source.id == source_id)
			.ok_or_else(|| "unknown trusted source ID".to_string())?;
		if !valid_relative_path(path) {
			return Err("invalid trusted source relative path".into());
		}
		let url = source
			.base_url
			.join(path)
			.map_err(|_| "invalid trusted source path".to_string())?;
		if url.origin() != source.base_url.origin() || !url.path().starts_with(source.base_url.path()) {
			return Err("trusted source path escaped configured base URL".into());
		}
		let mut request = source.client.get(url.clone());
		if let Some(token) = &source.bearer_token {
			request = request.bearer_auth(token);
		}
		let mut response = request
			.send()
			.await
			.map_err(|error| format!("trusted source fetch failed: {error}"))?;
		if !response.status().is_success() {
			return Err(format!(
				"trusted source returned HTTP {}",
				response.status()
			));
		}
		if response
			.content_length()
			.is_some_and(|size| size > self.max_bytes as u64)
		{
			return Err("trusted source document exceeds maximum size".into());
		}
		let mut bytes = Vec::new();
		while let Some(chunk) = response
			.chunk()
			.await
			.map_err(|error| format!("trusted source body failed: {error}"))?
		{
			if bytes.len().saturating_add(chunk.len()) > self.max_bytes {
				return Err("trusted source document exceeds maximum size".into());
			}
			bytes.extend_from_slice(&chunk);
		}
		let version = hex::encode(Sha256::digest(&bytes));
		let content =
			String::from_utf8(bytes).map_err(|_| "trusted source document must be UTF-8".to_string())?;
		Ok(FetchedDocument {
			source_id: source.id.clone(),
			source_uri: url.to_string(),
			version,
			content,
		})
	}
}

fn valid_relative_path(path: &str) -> bool {
	!path.is_empty()
		&& !path.starts_with('/')
		&& path.split('/').all(|component| {
			!component.is_empty()
				&& component != "."
				&& component != ".."
				&& component
					.chars()
					.all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
		})
}

#[cfg(test)]
mod tests {
	use super::*;
	#[tokio::test]
	async fn https_import_enforces_ca_path_redirect_and_size() {
		use wiremock::tls_certs::MockTlsCertificates;
		use wiremock::{
			Mock, MockServer, ResponseTemplate,
			matchers::{method, path},
		};

		let certs = MockTlsCertificates::random();
		let server = MockServer::builder()
			.start_https(certs.get_server_config())
			.await;
		Mock::given(method("GET"))
			.and(path("/docs/guide.md"))
			.respond_with(ResponseTemplate::new(200).set_body_string("trusted bytes"))
			.mount(&server)
			.await;
		Mock::given(method("GET"))
			.and(path("/docs/redirect"))
			.respond_with(ResponseTemplate::new(302).insert_header("location", "/private"))
			.mount(&server)
			.await;
		let config = TrustedHttpsSourceConfig {
			id: "kb".into(),
			base_url: format!("{}/docs/", server.uri()),
			bearer_token_env_var: None,
			ca_cert_pem: Some(certs.get_root_ca_cert().pem()),
		};
		let registry = TrustedHttpsSourceRegistry::new(vec![config.clone()], 128).unwrap();
		let request = registry
			.import_request("support", "guide", "kb", "guide.md")
			.await
			.unwrap();
		assert_eq!(request.content(), "trusted bytes");
		assert_eq!(
			request.source_uri(),
			format!("{}/docs/guide.md", server.uri())
		);
		assert_eq!(
			request.source_origin(),
			&crate::SourceOrigin::TrustedHttps {
				source_id: "kb".into(),
				version: hex::encode(Sha256::digest(b"trusted bytes")),
			}
		);
		assert!(
			registry
				.import_request("support", "guide", "kb", "../private")
				.await
				.is_err()
		);
		assert!(
			registry
				.import_request("support", "guide", "missing", "guide.md")
				.await
				.is_err()
		);
		assert_eq!(server.received_requests().await.unwrap().len(), 1);
		assert!(
			registry
				.import_request("support", "guide", "kb", "redirect")
				.await
				.unwrap_err()
				.contains("HTTP 302")
		);
		assert_eq!(server.received_requests().await.unwrap().len(), 2);
		let small = TrustedHttpsSourceRegistry::new(vec![config.clone()], 5).unwrap();
		assert!(
			small
				.import_request("support", "guide", "kb", "guide.md")
				.await
				.unwrap_err()
				.contains("maximum size")
		);
		let no_private_ca = TrustedHttpsSourceRegistry::new(
			vec![TrustedHttpsSourceConfig {
				ca_cert_pem: None,
				..config
			}],
			128,
		)
		.unwrap();
		assert!(
			no_private_ca
				.import_request("support", "guide", "kb", "guide.md")
				.await
				.is_err()
		);
	}

	#[test]
	fn rejects_url_traversal_and_redirectable_sources() {
		assert!(!valid_relative_path("../private"));
		assert!(!valid_relative_path("%2e%2e/private"));
		assert!(!valid_relative_path("https://evil.example/doc"));
		assert!(valid_relative_path("docs/guide-1.md"));
		assert!(
			TrustedHttpsSourceRegistry::validate_config(&[TrustedHttpsSourceConfig {
				id: "kb".into(),
				base_url: "http://kb.example/docs/".into(),
				bearer_token_env_var: None,
				ca_cert_pem: None,
			}])
			.is_err()
		);
	}
}
