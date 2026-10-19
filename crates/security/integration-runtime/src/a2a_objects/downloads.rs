//! Trusted configuration for bounded artifact retrieval, not caller-provided SSRF exceptions.
use std::{net::IpAddr, path::PathBuf};

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(default, rename_all = "camelCase", deny_unknown_fields)]
pub struct ArtifactDownloadConfig {
	pub sources: Vec<ArtifactSource>,
	pub max_files: usize,
	pub max_file_bytes: usize,
	pub max_total_bytes: usize,
	pub timeout_seconds: u64,
}
impl Default for ArtifactDownloadConfig {
	fn default() -> Self {
		Self {
			sources: vec![],
			max_files: 4,
			max_file_bytes: 65536,
			max_total_bytes: 262144,
			timeout_seconds: 5,
		}
	}
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ArtifactSource {
	/// HTTPS domain origin only. No userinfo, query, fragment or non-root path.
	pub origin: String,
	/// Administrator-pinned addresses; retrieval never falls back to system DNS.
	pub addresses: Vec<IpAddr>,
	pub path_prefix: String,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub root_ca_pem_file: Option<PathBuf>,
}

pub fn safe_path(path: &str) -> bool {
	path.starts_with('/')
		&& path.len() <= 1024
		&& path
			.bytes()
			.all(|b| b.is_ascii_alphanumeric() || b"/-_.".contains(&b))
		&& !path.contains("//")
		&& path.split('/').all(|p| p != "." && p != "..")
}

impl ArtifactSource {
	pub fn url(&self) -> Result<reqwest::Url, String> {
		let url = reqwest::Url::parse(&self.origin).map_err(|_| "invalid artifact origin")?;
		if url.scheme() != "https"
			|| url
				.host_str()
				.is_none_or(|h| h.parse::<IpAddr>().is_ok() || h.starts_with('['))
			|| !url.username().is_empty()
			|| url.password().is_some()
			|| url.query().is_some()
			|| url.fragment().is_some()
			|| url.path() != "/"
			|| url.port_or_known_default().is_none_or(|p| p == 0)
			|| self.origin.len() > 512
		{
			return Err(
				"artifact origin requires an HTTPS domain with no credentials/path/query/fragment".into(),
			);
		}
		Ok(url)
	}
	pub fn matches(&self, url: &reqwest::Url) -> bool {
		self
			.url()
			.is_ok_and(|origin| origin.origin() == url.origin())
			&& url.username().is_empty()
			&& url.password().is_none()
			&& url.query().is_none()
			&& url.fragment().is_none()
			&& safe_path(url.path())
			&& url.path().starts_with(&self.path_prefix)
	}
}

impl ArtifactDownloadConfig {
	pub fn validate(&self) -> Result<(), String> {
		if !(1..=16).contains(&self.sources.len())
			|| !(1..=8).contains(&self.max_files)
			|| !(1..=196608).contains(&self.max_file_bytes)
			|| self.max_total_bytes < self.max_file_bytes
			|| self.max_total_bytes > 1048576
			|| !(1..=30).contains(&self.timeout_seconds)
		{
			return Err("artifactDownloads requires bounded sources/files/bytes/timeout".into());
		}
		for source in &self.sources {
			source.url()?;
			if !(1..=4).contains(&source.addresses.len())
				|| source
					.addresses
					.iter()
					.any(|ip| ip.is_unspecified() || ip.is_multicast())
				|| !safe_path(&source.path_prefix)
				|| !source.path_prefix.ends_with('/')
				|| source
					.root_ca_pem_file
					.as_ref()
					.is_some_and(|p| !p.is_absolute())
			{
				return Err("artifact source requires explicit pinned IPs, a safe directory prefix and absolute optional CA path".into());
			}
		}
		for (i, source) in self.sources.iter().enumerate() {
			for other in &self.sources[..i] {
				if source.url()?.origin() == other.url()?.origin()
					&& (source.path_prefix.starts_with(&other.path_prefix)
						|| other.path_prefix.starts_with(&source.path_prefix))
				{
					return Err("artifact source prefixes must not overlap for the same origin".into());
				}
			}
		}
		Ok(())
	}
}
