//! Gateway-terminated A2A push ingress. This is not an arbitrary outbound webhook allowlist.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PushConfig {
	pub callback_base_url: String,
	#[serde(default = "channels")]
	pub max_channels: usize,
	#[serde(default = "lifetime")]
	pub max_channel_seconds: u64,
	#[serde(default = "bytes")]
	pub max_payload_bytes: usize,
	#[serde(default = "timeout")]
	pub timeout_seconds: u64,
}

fn channels() -> usize {
	32
}
fn lifetime() -> u64 {
	300
}
fn bytes() -> usize {
	65536
}
fn timeout() -> u64 {
	5
}
impl PushConfig {
	pub fn validate(&self) -> Result<(), String> {
		let url =
			reqwest::Url::parse(&self.callback_base_url).map_err(|_| "invalid Push callbackBaseUrl")?;
		if url.scheme() != "https"
			|| url
				.host_str()
				.is_none_or(|s| s.parse::<std::net::IpAddr>().is_ok() || s.starts_with('['))
			|| !url.username().is_empty()
			|| url.password().is_some()
			|| url.query().is_some()
			|| url.fragment().is_some()
			|| url.path() != "/v1/a2a/push/"
			|| url.as_str() != self.callback_base_url
			|| self.callback_base_url.len() > 1024
			|| !(1..=128).contains(&self.max_channels)
			|| !(1..=3600).contains(&self.max_channel_seconds)
			|| !(1024..=65536).contains(&self.max_payload_bytes)
			|| !(1..=30).contains(&self.timeout_seconds)
		{
			return Err("push requires an HTTPS domain callbackBaseUrl ending /v1/a2a/push/ and bounded channels/lifetime/payload/timeout".into());
		}
		Ok(())
	}
}
