use once_cell::sync::Lazy;
use phonenumber::{country, parse};
use regex::Regex;

use super::{Recognizer, RecognizerResult};

pub struct PhoneRecognizer;

impl Recognizer for PhoneRecognizer {
	fn recognize(&self, text: &str) -> Vec<RecognizerResult> {
		static CANDIDATE_RE: Lazy<Regex> =
			Lazy::new(|| Regex::new(r"(?i)(^|[^0-9])([+()]?[0-9][0-9\s().\-]{6,30})").unwrap());

		let mut results = Vec::new();

		for caps in CANDIDATE_RE.captures_iter(text) {
			let m = caps.get(2).unwrap();
			let candidate = m.as_str();
			let valid = [
				country::US,
				country::GB,
				country::DE,
				country::IL,
				country::IN,
				country::CA,
				country::BR,
			]
			.into_iter()
			.any(|region| parse(Some(region), candidate).is_ok_and(|number| number.is_valid()));
			if valid {
				let digit_count = candidate.chars().filter(|c| c.is_ascii_digit()).count();
				results.push(RecognizerResult {
					entity_type: "PHONE_NUMBER".to_string(),
					matched: candidate.to_string(),
					start: m.start(),
					end: m.end(),
					score: 0.6_f32 + (digit_count.min(15) as f32) / 100.0,
				});
			}
		}

		results.sort_by_key(|r| (r.start, r.end, r.matched.clone()));
		results.dedup_by(|a, b| a.start == b.start && a.end == b.end && a.matched == b.matched);
		results
	}
}
