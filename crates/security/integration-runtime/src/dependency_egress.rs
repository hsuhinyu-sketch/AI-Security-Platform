//! Infrastructure dependencies are not model/Tool destinations. This optional allowlist is
//! evaluated before disclosing data to security services or knowledge/control-plane backends.
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum DependencyKind {
	Pdp,
	AgentDirectory,
	Approval,
	Revocation,
	CapabilityBroker,
	Qdrant,
	Embedding,
	TrustedSource,
	ExtAuthz,
	ExtProc,
	Guardrail,
	RateLimit,
	Oidc,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DependencyEgressConfig {
	#[serde(default = "require_tls")]
	pub require_tls: bool,
	/// Exact canonical host:port, IPv6 in brackets. Missing/empty categories deny.
	#[serde(default)]
	pub destinations: BTreeMap<DependencyKind, Vec<String>>,
}
fn require_tls() -> bool {
	true
}
impl DependencyEgressConfig {
	pub fn validate(&self) -> Result<(), String> {
		for list in self.destinations.values() {
			if list.len() > 256 {
				return Err("dependencyEgress allows at most 256 destinations per kind".into());
			}
			for target in list {
				let url = reqwest::Url::parse(&format!("https://{target}/"))
					.map_err(|_| "invalid dependencyEgress destination")?;
				if target.contains('*')
					|| target != &authority(&url)?
					|| url.path() != "/"
					|| url.query().is_some()
					|| url.fragment().is_some()
					|| !url.username().is_empty()
					|| url.password().is_some()
				{
					return Err("dependencyEgress destinations must be exact canonical host:port without credentials/path/query".into());
				}
			}
		}
		Ok(())
	}
	pub fn check_target(&self, kind: DependencyKind, target: &str, tls: bool) -> Result<(), String> {
		if (self.require_tls && !tls)
			|| !self
				.destinations
				.get(&kind)
				.is_some_and(|v| v.iter().any(|allowed| allowed == target))
		{
			return Err(format!("dependencyEgress denied {kind:?}"));
		}
		Ok(())
	}
	pub fn check_url(&self, kind: DependencyKind, endpoint: &str) -> Result<(), String> {
		let url = reqwest::Url::parse(endpoint).map_err(|_| "invalid dependency URL")?;
		if !matches!(url.scheme(), "https" | "http")
			|| !url.username().is_empty()
			|| url.password().is_some()
			|| url.fragment().is_some()
		{
			return Err("dependency URL requires http(s), no userinfo or fragment".into());
		}
		self.check_target(kind, &authority(&url)?, url.scheme() == "https")
	}
	/// Both levels remain necessary conditions; a local policy cannot widen deployment limits.
	pub fn intersect(&self, other: &Self) -> Self {
		Self {
			require_tls: self.require_tls || other.require_tls,
			destinations: self
				.destinations
				.iter()
				.map(|(k, values)| {
					(
						*k,
						values
							.iter()
							.filter(|v| other.destinations.get(k).is_some_and(|set| set.contains(v)))
							.cloned()
							.collect(),
					)
				})
				.collect(),
		}
	}
}
fn authority(url: &reqwest::Url) -> Result<String, String> {
	let host = url.host().ok_or("dependency URL has no host")?;
	let port = url
		.port_or_known_default()
		.ok_or("dependency URL has no port")?;
	Ok(format!("{host}:{port}"))
}
