//! Protocol-independent, bounded text detection and anonymization. No identity or policy engine.
use std::{collections::BTreeMap, sync::Arc, time::Duration};

use serde::{Deserialize, Serialize};

mod native;
pub use native::NativeDetector;
#[cfg(feature = "presidio")]
mod presidio;
#[cfg(feature = "presidio")]
pub use presidio::PresidioDetector;
mod config;
pub use config::{DetectorBackend, PiiConfig};

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum PiiError {
	#[error("invalid PII configuration")]
	InvalidConfig,
	#[error("PII capability was not compiled")]
	NotCompiled,
	#[error("PII input exceeds byte budget")]
	InputLimit,
	#[error("PII output exceeds byte budget")]
	OutputLimit,
	#[error("PII detector timed out")]
	Timeout,
	#[error("PII detector unavailable")]
	Unavailable,
	#[error("PII detector returned an unsuccessful status")]
	UpstreamStatus,
	#[error("invalid PII detector response")]
	InvalidResponse,
	#[error("PII findings exceed budget")]
	FindingLimit,
}

/// UTF-8 byte offsets, half-open [start, end), never raw matched text.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PiiFinding {
	pub entity_type: String,
	pub start: usize,
	pub end: usize,
	pub confidence: f32,
	pub source: String,
}

#[async_trait::async_trait]
pub trait PiiDetector: Send + Sync {
	async fn detect(&self, text: &str, language: &str) -> Result<Vec<PiiFinding>, PiiError>;
}

/// Content-control mode, independent of authorization. None of these grant access.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum PiiMode {
	Disabled,
	Audit,
	Shadow,
	#[default]
	Enforce,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "camelCase", deny_unknown_fields)]
pub enum PiiAction {
	DetectOnly,
	Replace { value: String },
	Mask,
	Redact,
	Block,
}

/// Entity-specific actions selected by trusted deployment configuration, not by detected text.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PiiPolicy {
	pub entities: BTreeMap<String, PiiAction>,
}

pub(crate) fn valid_id(value: &str) -> bool {
	!value.is_empty()
		&& value.len() <= 64
		&& value
			.bytes()
			.all(|v| v.is_ascii_uppercase() || v.is_ascii_digit() || v == b'_')
}

/// Python/Presidio Unicode scalar offsets to UTF-8 byte offsets; UTF-16 offsets are not accepted.
pub fn character_range(text: &str, start: usize, end: usize) -> Result<(usize, usize), PiiError> {
	if start >= end {
		return Err(PiiError::InvalidResponse);
	}
	let mut boundaries: Vec<_> = text.char_indices().map(|(index, _)| index).collect();
	boundaries.push(text.len());
	Ok((
		*boundaries.get(start).ok_or(PiiError::InvalidResponse)?,
		*boundaries.get(end).ok_or(PiiError::InvalidResponse)?,
	))
}

/// No Debug implementation: the output contains sensitive text in observation modes.
pub struct PiiOutcome {
	pub text: String,
	pub findings: Vec<PiiFinding>,
	pub modified: bool,
	pub blocked: bool,
	/// Only Audit/Shadow can observe failures without blocking. No silent fallback.
	pub detector_error: Option<PiiError>,
}

pub struct PiiEngine {
	detector: Arc<dyn PiiDetector>,
	config: PiiConfig,
}

impl PiiEngine {
	/// Extension point for alternative detectors; indices and budgets remain checked by the engine.
	pub fn with_detector(
		config: PiiConfig,
		detector: Arc<dyn PiiDetector>,
	) -> Result<Self, PiiError> {
		config.validate()?;
		Ok(Self { detector, config })
	}
	pub fn mode(&self) -> PiiMode {
		self.config.mode
	}
	pub fn finding_limit(&self) -> usize {
		self.config.max_findings
	}
	pub async fn check_ready(&self) -> Result<(), PiiError> {
		let text = "gateway PII readiness check";
		let findings = self.detect(text).await?;
		self.normalize(text, findings)?;
		Ok(())
	}
	async fn detect(&self, text: &str) -> Result<Vec<PiiFinding>, PiiError> {
		if text.len() > self.config.max_text_bytes {
			return Err(PiiError::InputLimit);
		}
		tokio::time::timeout(
			Duration::from_millis(self.config.timeout_ms),
			self.detector.detect(text, &self.config.language),
		)
		.await
		.map_err(|_| PiiError::Timeout)?
	}
	fn normalize(
		&self,
		text: &str,
		mut findings: Vec<PiiFinding>,
	) -> Result<Vec<PiiFinding>, PiiError> {
		if findings.len() > self.config.max_findings {
			return Err(PiiError::FindingLimit);
		}
		for item in &findings {
			if !self.config.policy.entities.contains_key(&item.entity_type)
				|| item.start >= item.end
				|| item.end > text.len()
				|| !text.is_char_boundary(item.start)
				|| !text.is_char_boundary(item.end)
				|| !item.confidence.is_finite()
				|| !(0.0..=1.0).contains(&item.confidence)
				|| item.source.is_empty()
				|| item.source.len() > 64
			{
				return Err(PiiError::InvalidResponse);
			}
		}
		findings.sort_by(|a, b| {
			(a.start, a.end, &a.entity_type)
				.cmp(&(b.start, b.end, &b.entity_type))
				.then_with(|| b.confidence.total_cmp(&a.confidence))
		});
		findings
			.dedup_by(|a, b| a.start == b.start && a.end == b.end && a.entity_type == b.entity_type);
		Ok(findings)
	}
	pub async fn inspect(&self, text: &str) -> Result<PiiOutcome, PiiError> {
		if !self.config.enabled || self.config.mode == PiiMode::Disabled {
			return Ok(PiiOutcome {
				text: text.into(),
				findings: vec![],
				modified: false,
				blocked: false,
				detector_error: None,
			});
		}
		let findings = match self
			.detect(text)
			.await
			.and_then(|v| self.normalize(text, v))
		{
			Ok(findings) => findings,
			Err(error) if self.config.mode != PiiMode::Enforce => {
				return Ok(PiiOutcome {
					text: text.into(),
					findings: vec![],
					modified: false,
					blocked: false,
					detector_error: Some(error),
				});
			},
			Err(error) => return Err(error),
		};
		if self.config.mode != PiiMode::Enforce {
			return Ok(PiiOutcome {
				text: text.into(),
				findings,
				modified: false,
				blocked: false,
				detector_error: None,
			});
		}
		let blocked = findings.iter().any(|f| {
			matches!(
				self.config.policy.entities[&f.entity_type],
				PiiAction::Block
			)
		});
		if blocked {
			return Ok(PiiOutcome {
				text: String::new(),
				findings,
				modified: false,
				blocked: true,
				detector_error: None,
			});
		}
		let output = PiiAnonymizer::apply(
			text,
			&findings,
			&self.config.policy,
			self.config.max_output_bytes,
		)?;
		Ok(PiiOutcome {
			modified: output != text,
			text: output,
			findings,
			blocked: false,
			detector_error: None,
		})
	}
}

/// Intersecting mutations are coalesced, never discarded in favor of a higher-confidence span.
/// Conflicting actions use Redact > Mask > Replace; Block is evaluated before anonymization.
pub struct PiiAnonymizer;
impl PiiAnonymizer {
	pub fn apply(
		text: &str,
		findings: &[PiiFinding],
		policy: &PiiPolicy,
		max_bytes: usize,
	) -> Result<String, PiiError> {
		let mut spans: Vec<(usize, usize, String, u8)> = Vec::new();
		for finding in findings {
			if finding.start >= finding.end
				|| finding.end > text.len()
				|| !text.is_char_boundary(finding.start)
				|| !text.is_char_boundary(finding.end)
			{
				return Err(PiiError::InvalidResponse);
			}
			let action = policy
				.entities
				.get(&finding.entity_type)
				.ok_or(PiiError::InvalidConfig)?;
			let (replacement, rank) = match action {
				PiiAction::DetectOnly => continue,
				PiiAction::Block => return Err(PiiError::InvalidConfig),
				PiiAction::Replace { value } => (value.clone(), 1),
				PiiAction::Mask => ("*".into(), 2),
				PiiAction::Redact => (String::new(), 3),
			};
			spans.push((finding.start, finding.end, replacement, rank));
		}
		spans.sort();
		let mut merged: Vec<(usize, usize, String, u8)> = Vec::new();
		for span in spans {
			if let Some(last) = merged.last_mut()
				&& span.0 < last.1
			{
				last.1 = last.1.max(span.1);
				if span.3 > last.3 || (span.3 == last.3 && span.2 < last.2) {
					last.2 = span.2;
					last.3 = span.3;
				}
			} else {
				merged.push(span);
			}
		}
		let mut output = String::new();
		let mut cursor = 0;
		for (start, end, value, rank) in merged {
			let replacement = if rank == 2 {
				"*".repeat(text[start..end].chars().count())
			} else {
				value
			};
			let length = output
				.len()
				.checked_add(start - cursor)
				.and_then(|n| n.checked_add(replacement.len()))
				.ok_or(PiiError::OutputLimit)?;
			if length > max_bytes {
				return Err(PiiError::OutputLimit);
			}
			output.push_str(&text[cursor..start]);
			output.push_str(&replacement);
			cursor = end;
		}
		if output.len().saturating_add(text.len() - cursor) > max_bytes {
			return Err(PiiError::OutputLimit);
		}
		output.push_str(&text[cursor..]);
		Ok(output)
	}
}
