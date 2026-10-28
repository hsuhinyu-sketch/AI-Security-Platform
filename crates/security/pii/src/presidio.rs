use crate::*;
use serde::Deserialize;
use std::{net::IpAddr, time::Duration};

pub struct PresidioDetector {
	client: reqwest::Client,
	endpoint: reqwest::Url,
	entities: Vec<String>,
	max_text: usize,
	max_response: usize,
	max_findings: usize,
}
#[derive(Deserialize)]
struct Finding {
	entity_type: String,
	start: usize,
	end: usize,
	score: f32,
}
impl PresidioDetector {
	pub fn new(config: &PiiConfig) -> Result<Self, PiiError> {
		config.validate()?;
		if !config.custom_rules.is_empty() {
			return Err(PiiError::InvalidConfig);
		}
		let mut endpoint = reqwest::Url::parse(
			config
				.presidio_endpoint
				.as_deref()
				.ok_or(PiiError::InvalidConfig)?,
		)
		.map_err(|_| PiiError::InvalidConfig)?;
		// V0.1 deliberately limits sidecars to literal loopback addresses: no DNS rebinding,
		// proxy environment, redirects, arbitrary URL overrides, userinfo or query tokens.
		if !matches!(endpoint.scheme(), "http" | "https")
			|| !endpoint
				.host_str()
				.and_then(|host| host.trim_matches(['[', ']']).parse::<IpAddr>().ok())
				.is_some_and(|ip| ip.is_loopback())
			|| !endpoint.username().is_empty()
			|| endpoint.password().is_some()
			|| endpoint.query().is_some()
			|| endpoint.fragment().is_some()
			|| !matches!(endpoint.path(), "/" | "/analyze")
		{
			return Err(PiiError::InvalidConfig);
		}
		endpoint.set_path("/analyze");
		let client = reqwest::Client::builder()
			.redirect(reqwest::redirect::Policy::none())
			.no_proxy()
			.timeout(Duration::from_millis(config.timeout_ms))
			.build()
			.map_err(|_| PiiError::InvalidConfig)?;
		Ok(Self {
			client,
			endpoint,
			entities: config.policy.entities.keys().cloned().collect(),
			max_text: config.max_text_bytes,
			max_response: config.max_response_bytes,
			max_findings: config.max_findings,
		})
	}
}
#[async_trait::async_trait]
impl PiiDetector for PresidioDetector {
	async fn detect(&self, text: &str, language: &str) -> Result<Vec<PiiFinding>, PiiError> {
		if text.len() > self.max_text {
			return Err(PiiError::InputLimit);
		}
		let mut response=self.client.post(self.endpoint.clone()).json(&serde_json::json!({"text":text,"language":language,"entities":self.entities,"return_decision_process":false})).send().await.map_err(|e|if e.is_timeout(){PiiError::Timeout}else{PiiError::Unavailable})?;
		if !response.status().is_success() {
			return Err(PiiError::UpstreamStatus);
		}
		if response
			.content_length()
			.is_some_and(|len| len > self.max_response as u64)
		{
			return Err(PiiError::InvalidResponse);
		}
		let mut bytes = Vec::new();
		while let Some(chunk) = response.chunk().await.map_err(|e| {
			if e.is_timeout() {
				PiiError::Timeout
			} else {
				PiiError::Unavailable
			}
		})? {
			if bytes.len().saturating_add(chunk.len()) > self.max_response {
				return Err(PiiError::InvalidResponse);
			}
			bytes.extend_from_slice(&chunk);
		}
		let findings: Vec<Finding> =
			serde_json::from_slice(&bytes).map_err(|_| PiiError::InvalidResponse)?;
		if findings.len() > self.max_findings {
			return Err(PiiError::FindingLimit);
		}
		let mut offsets: Vec<_> = text.char_indices().map(|(index, _)| index).collect();
		offsets.push(text.len());
		findings
			.into_iter()
			.map(|finding| {
				if finding.start >= finding.end {
					return Err(PiiError::InvalidResponse);
				}
				let start = *offsets
					.get(finding.start)
					.ok_or(PiiError::InvalidResponse)?;
				let end = *offsets.get(finding.end).ok_or(PiiError::InvalidResponse)?;
				if !self.entities.contains(&finding.entity_type)
					|| !finding.score.is_finite()
					|| !(0.0..=1.0).contains(&finding.score)
				{
					return Err(PiiError::InvalidResponse);
				}
				Ok(PiiFinding {
					entity_type: finding.entity_type,
					start,
					end,
					confidence: finding.score,
					source: "presidio".into(),
				})
			})
			.collect()
	}
}
