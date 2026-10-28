//! Built-in PII recognizers used by prompt and response guards.

use once_cell::sync::Lazy;

use pattern_recognizer::PatternRecognizer;
use phone_recognizer::PhoneRecognizer;

mod pattern_recognizer;
mod phone_recognizer;

#[cfg(test)]
mod tests;

pub trait Recognizer {
	fn recognize(&self, text: &str) -> Vec<RecognizerResult>;
}

#[derive(Debug, Clone, PartialEq)]
pub struct RecognizerResult {
	pub entity_type: String,
	pub matched: String,
	pub start: usize,
	pub end: usize,
	pub score: f32,
}

pub static EMAIL: Lazy<PatternRecognizer> = Lazy::new(|| {
	PatternRecognizer::new(
		"EMAIL_ADDRESS",
		&[(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+", 0.85)],
	)
});

pub static CC: Lazy<PatternRecognizer> = Lazy::new(|| {
	PatternRecognizer::new(
		"CREDIT_CARD",
		&[
			(r"\b4\d{3}[- ]?(\d{3,4})[- ]?(\d{3,4})[- ]?(\d{3,5})\b", 0.3),
			(
				r"\b5[0-5]\d{2}[- ]?(\d{3,4})[- ]?(\d{3,4})[- ]?(\d{3,5})\b",
				0.3,
			),
			(r"\b6\d{3}[- ]?(\d{3,4})[- ]?(\d{3,4})[- ]?(\d{3,5})\b", 0.3),
			(r"\b3\d{3}[- ]?(\d{3,4})[- ]?(\d{3,4})[- ]?(\d{3,5})\b", 0.3),
			(r"\b1\d{3}[- ]?(\d{3,4})[- ]?(\d{3,4})[- ]?(\d{4,5})\b", 0.3),
		],
	)
});

pub static SSN: Lazy<PatternRecognizer> = Lazy::new(|| {
	PatternRecognizer::new(
		"SSN",
		&[
			(r"\b([0-9]{5})-([0-9]{4})\b", 0.05),
			(r"\b([0-9]{3})-([0-9]{6})\b", 0.05),
			(r"\b(([0-9]{3})-([0-9]{2})-([0-9]{4}))\b", 0.05),
			(r"\b[0-9]{9}\b", 0.05),
			(r"\b([0-9]{3})[- .]([0-9]{2})[- .]([0-9]{4})\b", 0.5),
		],
	)
});

pub static CA_SIN: Lazy<PatternRecognizer> = Lazy::new(|| {
	PatternRecognizer::new(
		"CA_SIN",
		&[
			(r"\b([0-9]{3})[- ]([0-9]{3})[- ]([0-9]{3})\b", 0.7),
			(r"\b[0-9]{9}\b", 0.3),
		],
	)
});

pub static PHONE: PhoneRecognizer = PhoneRecognizer;
