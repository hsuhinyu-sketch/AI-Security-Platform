use crate::*;
use phonenumber::country;
use regex::Regex;
use std::net::IpAddr;

pub struct NativeDetector {
	rules: Vec<(String, Regex)>,
	max_bytes: usize,
	max_findings: usize,
}
impl NativeDetector {
	pub fn new(config: &PiiConfig) -> Result<Self, PiiError> {
		config.validate()?;
		let mut rules = Vec::new();
		for entity in config.policy.entities.keys() {
			let pattern = match entity.as_str() {
				"EMAIL_ADDRESS" => r"[A-Za-z0-9_.+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,63}",
				"PHONE_NUMBER" => {
					r"\+?[1-9][0-9]{7,14}|\+?[0-9]{1,3}[ -]?\(?[0-9]{2,4}\)?[ -]?[0-9]{3,4}[ -]?[0-9]{3,4}|\(?[0-9]{3}\)?[ -]?[0-9]{3}[ -]?[0-9]{4}"
				},
				"IP_ADDRESS" => r"[0-9A-Fa-f:.]+",
				_ => config
					.custom_rules
					.get(entity)
					.ok_or(PiiError::InvalidConfig)?,
			};
			let regex = regex::RegexBuilder::new(pattern)
				.size_limit(1_048_576)
				.dfa_size_limit(1_048_576)
				.build()
				.map_err(|_| PiiError::InvalidConfig)?;
			if regex.is_match("") {
				return Err(PiiError::InvalidConfig);
			}
			rules.push((entity.clone(), regex));
		}
		Ok(Self {
			rules,
			max_bytes: config.max_text_bytes,
			max_findings: config.max_findings,
		})
	}
}
#[async_trait::async_trait]
impl PiiDetector for NativeDetector {
	async fn detect(&self, text: &str, _language: &str) -> Result<Vec<PiiFinding>, PiiError> {
		if text.len() > self.max_bytes {
			return Err(PiiError::InputLimit);
		}
		let mut output = Vec::new();
		for (entity, regex) in &self.rules {
			for item in regex.find_iter(text) {
				let value = if entity == "IP_ADDRESS" && item.as_str().parse::<IpAddr>().is_err() {
					item.as_str().trim_end_matches('.')
				} else {
					item.as_str()
				};
				let end = item.start() + value.len();
				let bounded = text[..item.start()]
					.chars()
					.next_back()
					.is_none_or(|c| !c.is_ascii_alphanumeric() && c != b'_' as char)
					&& text[end..]
						.chars()
						.next()
						.is_none_or(|c| !c.is_ascii_alphanumeric() && c != '_');
				let valid = match entity.as_str() {
					"EMAIL_ADDRESS" => {
						bounded
							&& !value.starts_with('.')
							&& !value.contains("..")
							&& !value
								.split('@')
								.nth(1)
								.unwrap_or("")
								.split('.')
								.any(|part| part.starts_with('-') || part.ends_with('-'))
					},
					"IP_ADDRESS" => bounded && value.parse::<IpAddr>().is_ok(),
					"PHONE_NUMBER" => {
						let digits = value.bytes().filter(u8::is_ascii_digit).count();
						bounded
							&& (8..=15).contains(&digits)
							&& value.parse::<IpAddr>().is_err()
							&& [
								country::CN,
								country::US,
								country::GB,
								country::DE,
								country::IN,
								country::CA,
								country::BR,
							]
							.into_iter()
							.any(|region| phonenumber::parse(Some(region), value).is_ok_and(|n| n.is_valid()))
					},
					_ => true,
				};
				if !valid {
					continue;
				}
				if output.len() == self.max_findings {
					return Err(PiiError::FindingLimit);
				}
				output.push(PiiFinding {
					entity_type: entity.clone(),
					start: item.start(),
					end,
					confidence: 0.8,
					source: "native".into(),
				});
			}
		}
		Ok(output)
	}
}
