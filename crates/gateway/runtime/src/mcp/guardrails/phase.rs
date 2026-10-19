use std::collections::HashMap;

use crate::*;

#[apply(schema_enum!)]
#[derive(Default)]
pub enum Phase {
	#[default]
	Off,
	Request,
	Response,
	Full,
}

impl Phase {
	pub fn runs_request(self) -> bool {
		matches!(self, Phase::Request | Phase::Full)
	}
	pub fn runs_response(self) -> bool {
		matches!(self, Phase::Response | Phase::Full)
	}
}

// Match precedence, most specific first:
//   1. exact match (`tools/call`)
//   2. prefix wildcard (`tools/*`) beats suffix wildcard (`*/list`) -- method
//      names are namespaced left-to-right, so the namespace owner wins
//   3. suffix wildcard beats the `*` catchall
//   4. within the same kind, the longer pattern wins (`notifications/tools/*`
//      over `notifications/*`); the trailing `*` is constant within a kind so
//      it cancels out
//   5. ties broken alphabetically so resolution is deterministic
pub fn resolve(method: &str, methods: &HashMap<String, Phase>) -> Phase {
	if let Some(p) = methods.get(method) {
		return *p;
	}
	methods
		.iter()
		.filter_map(|(pat, phase)| match_kind(pat, method).map(|kind| (kind, pat, *phase)))
		// (kind, len) ascending; alphabetically-first pattern wins the final tie
		.max_by(|a, b| {
			(a.0, a.1.len())
				.cmp(&(b.0, b.1.len()))
				.then_with(|| b.1.cmp(a.1))
		})
		.map(|(_, _, phase)| phase)
		.unwrap_or_default()
}

/// Whether a methods key is a pattern `resolve` can ever match: a non-empty
/// exact name, `*`, or a single leading or trailing `*`.
pub fn pattern_is_matchable(pat: &str) -> bool {
	if pat.is_empty() {
		return false;
	}
	match pat.matches('*').count() {
		0 => true,
		1 => pat.starts_with('*') || pat.ends_with('*'),
		_ => false,
	}
}

// Higher rank = more specific. None if the pattern doesn't match.
fn match_kind(pattern: &str, method: &str) -> Option<u8> {
	if pattern == "*" {
		return Some(1);
	}
	if let Some(prefix) = pattern.strip_suffix('*')
		&& !prefix.contains('*')
		&& method.starts_with(prefix)
	{
		return Some(3);
	}
	if let Some(suffix) = pattern.strip_prefix('*')
		&& !suffix.contains('*')
		&& method.ends_with(suffix)
	{
		return Some(2);
	}
	None
}
