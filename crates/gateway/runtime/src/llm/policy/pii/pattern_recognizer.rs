use regex::Regex;

use super::{Recognizer, RecognizerResult};

#[derive(Debug)]
struct Pattern {
	regex: Regex,
	score: f32,
}

pub struct PatternRecognizer {
	patterns: Vec<Pattern>,
	entity_type: &'static str,
}

impl PatternRecognizer {
	pub fn new(entity_type: &'static str, patterns: &[(&str, f32)]) -> Self {
		Self {
			patterns: patterns
				.iter()
				.map(|(pattern, score)| Pattern {
					regex: Regex::new(pattern).expect("valid built-in PII pattern"),
					score: *score,
				})
				.collect(),
			entity_type,
		}
	}
}

impl Recognizer for PatternRecognizer {
	fn recognize(&self, text: &str) -> Vec<RecognizerResult> {
		let mut results = Vec::new();
		for pattern in &self.patterns {
			for matched in pattern.regex.find_iter(text) {
				results.push(RecognizerResult {
					entity_type: self.entity_type.to_string(),
					matched: matched.as_str().to_string(),
					start: matched.start(),
					end: matched.end(),
					score: pattern.score,
				});
			}
		}
		results
	}
}
