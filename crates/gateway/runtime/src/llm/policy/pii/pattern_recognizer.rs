use regex::Regex;

use super::recognizer::Recognizer;
use super::recognizer_result::RecognizerResult;

#[derive(Debug)]
pub struct Pattern {
	#[allow(dead_code)]
	pub name: String,
	pub regex: Regex,
	pub score: f32,
}

pub struct PatternRecognizer {
	patterns: Vec<Pattern>,
	#[allow(dead_code)]
	context: Vec<String>,
	entity_type: String,
}

impl PatternRecognizer {
	pub fn new(entity_type: &str, context: Vec<String>) -> Self {
		Self {
			patterns: Vec::new(),
			context,
			entity_type: entity_type.to_string(),
		}
	}

	pub fn add_pattern(&mut self, name: &str, regex: &str, score: f32) {
		let pattern = Pattern {
			name: name.to_string(),
			regex: Regex::new(regex).unwrap(),
			score,
		};
		self.patterns.push(pattern);
	}
}

impl Recognizer for PatternRecognizer {
	fn recognize(&self, text: &str) -> Vec<RecognizerResult> {
		let mut results = Vec::new();
		for pattern in &self.patterns {
			for cap in pattern.regex.captures_iter(text) {
				if let Some(matched) = cap.get(0) {
					let candidate = matched.as_str();
					let score = pattern.score;
					results.push(RecognizerResult {
						entity_type: self.entity_type.clone(),
						matched: candidate.to_string(),
						start: matched.start(),
						end: matched.end(),
						score,
					});
				}
			}
		}
		results
	}
	fn name(&self) -> &str {
		&self.entity_type
	}
}
