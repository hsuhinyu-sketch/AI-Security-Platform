use crate::*;
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, sync::Arc};

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum DetectorBackend {
	#[default]
	Native,
	Presidio,
}

fn yes() -> bool {
	true
}
fn language() -> String {
	"en".into()
}
fn timeout() -> u64 {
	1000
}
fn max_text() -> usize {
	65_536
}
fn max_output() -> usize {
	131_072
}
fn max_response() -> usize {
	131_072
}
fn max_findings() -> usize {
	256
}
fn policy() -> PiiPolicy {
	PiiPolicy {
		entities: ["EMAIL_ADDRESS", "PHONE_NUMBER", "IP_ADDRESS"]
			.into_iter()
			.map(|e| {
				(
					e.into(),
					PiiAction::Replace {
						value: format!("[{e}]"),
					},
				)
			})
			.collect(),
	}
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PiiConfig {
	#[serde(default = "yes")]
	pub enabled: bool,
	#[serde(default)]
	pub mode: PiiMode,
	#[serde(default)]
	pub backend: DetectorBackend,
	#[serde(default = "language")]
	pub language: String,
	#[serde(default = "timeout")]
	pub timeout_ms: u64,
	#[serde(default = "max_text")]
	pub max_text_bytes: usize,
	#[serde(default = "max_output")]
	pub max_output_bytes: usize,
	#[serde(default = "max_response")]
	pub max_response_bytes: usize,
	#[serde(default = "max_findings")]
	pub max_findings: usize,
	#[serde(default = "policy")]
	pub policy: PiiPolicy,
	#[serde(default)]
	pub custom_rules: BTreeMap<String, String>,
	#[serde(default)]
	pub presidio_endpoint: Option<String>,
}
impl PiiConfig {
	pub fn active(&self) -> bool {
		self.enabled && self.mode != PiiMode::Disabled
	}
	pub fn validate(&self) -> Result<(), PiiError> {
		if self.language.is_empty()
			|| self.language.len() > 16
			|| !self
				.language
				.bytes()
				.all(|b| b.is_ascii_alphabetic() || b == b'-')
			|| !(1..=30_000).contains(&self.timeout_ms)
			|| !(1..=1_048_576).contains(&self.max_text_bytes)
			|| !(1..=2_097_152).contains(&self.max_output_bytes)
			|| !(1..=1_048_576).contains(&self.max_response_bytes)
			|| !(1..=4096).contains(&self.max_findings)
			|| self.policy.entities.is_empty()
			|| self.policy.entities.len() > 64
			|| self.custom_rules.len() > 32
		{
			return Err(PiiError::InvalidConfig);
		}
		for (entity, action) in &self.policy.entities {
			if !valid_id(entity) || matches!(action,PiiAction::Replace{value} if value.len()>256) {
				return Err(PiiError::InvalidConfig);
			}
		}
		for (entity, pattern) in &self.custom_rules {
			if !valid_id(entity) || pattern.is_empty() || pattern.len() > 4096 {
				return Err(PiiError::InvalidConfig);
			}
		}
		Ok(())
	}
	pub fn build(&self) -> Result<Option<Arc<PiiEngine>>, PiiError> {
		self.validate()?;
		if !self.active() {
			return Ok(None);
		}
		let detector: Arc<dyn PiiDetector> = match self.backend {
			DetectorBackend::Native => Arc::new(NativeDetector::new(self)?),
			DetectorBackend::Presidio => {
				#[cfg(feature = "presidio")]
				{
					Arc::new(PresidioDetector::new(self)?)
				}
				#[cfg(not(feature = "presidio"))]
				{
					return Err(PiiError::NotCompiled);
				}
			},
		};
		Ok(Some(Arc::new(PiiEngine::with_detector(
			self.clone(),
			detector,
		)?)))
	}
}
