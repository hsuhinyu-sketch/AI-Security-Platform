use std::collections::BTreeMap;
use std::fmt;
use std::str::FromStr;

use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};

use crate::{apply, schema};

#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct Catalog {
	#[serde(default)]
	pub providers: BTreeMap<String, Provider>,
}

impl Catalog {
	pub fn validate(&self) -> anyhow::Result<()> {
		for (pid, p) in &self.providers {
			for (mid, m) in &p.models {
				let mut prev: Option<u64> = None;
				for (i, t) in m.tiers.iter().enumerate() {
					if prev.is_some_and(|p| t.context_over <= p) {
						anyhow::bail!(
							"{pid}/{mid}: tier {i} threshold {} not strictly greater than previous",
							t.context_over
						);
					}
					prev = Some(t.context_over);
				}
			}
		}
		Ok(())
	}

	pub fn override_with(mut self, overlay: Catalog) -> Catalog {
		for (pid, op) in overlay.providers {
			match self.providers.get_mut(&pid) {
				Some(base) => base.models.extend(op.models),
				None => {
					self.providers.insert(pid, op);
				},
			}
		}
		self
	}

	pub fn resolve(&self, provider: &str, model: &str) -> Option<&Model> {
		self.providers.get(provider)?.models.get(model)
	}
}

pub fn from_json(s: &str) -> anyhow::Result<Catalog> {
	let catalog: Catalog = serde_json::from_str(s)?;
	catalog.validate()?;
	Ok(catalog)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct Provider {
	#[serde(default)]
	pub models: BTreeMap<String, Model>,
}

#[apply(schema!)]
#[derive(PartialEq, Eq, Default)]
pub struct Model {
	#[serde(default, skip_serializing_if = "Rates::is_empty")]
	pub rates: Rates,
	#[serde(default, skip_serializing_if = "Vec::is_empty")]
	pub tiers: Vec<Tier>,
}

#[apply(schema!)]
#[derive(PartialEq, Eq, Default)]
pub struct Rates {
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub input: Option<Money>,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub output: Option<Money>,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub cache_read: Option<Money>,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub cache_write: Option<Money>,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub reasoning: Option<Money>,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub input_audio: Option<Money>,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub output_audio: Option<Money>,
}

impl Rates {
	pub fn is_empty(&self) -> bool {
		*self == Rates::default()
	}

	pub fn overlay(&self, delta: &Rates) -> Rates {
		let pick = |base: &Option<Money>, d: &Option<Money>| d.clone().or_else(|| base.clone());
		Rates {
			input: pick(&self.input, &delta.input),
			output: pick(&self.output, &delta.output),
			cache_read: pick(&self.cache_read, &delta.cache_read),
			cache_write: pick(&self.cache_write, &delta.cache_write),
			reasoning: pick(&self.reasoning, &delta.reasoning),
			input_audio: pick(&self.input_audio, &delta.input_audio),
			output_audio: pick(&self.output_audio, &delta.output_audio),
		}
	}
}

#[apply(schema!)]
#[derive(PartialEq, Eq)]
pub struct Tier {
	pub context_over: u64,
	pub rates: Rates,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Money(pub Decimal);

#[cfg(feature = "schema")]
impl schemars::JsonSchema for Money {
	fn schema_name() -> std::borrow::Cow<'static, str> {
		"Money".into()
	}

	fn json_schema(schema_gen: &mut schemars::SchemaGenerator) -> schemars::Schema {
		String::json_schema(schema_gen)
	}
}

impl Money {
	pub fn parse(s: &str) -> Result<Money, String> {
		let d = Decimal::from_str(s).map_err(|e| format!("invalid decimal {s:?}: {e}"))?;
		if d < Decimal::ZERO {
			return Err(format!("negative rate not allowed: {s:?}"));
		}
		if d.scale() > 6 {
			return Err(format!("more than 6 fractional digits: {s:?}"));
		}
		Ok(Money(d))
	}
}

impl fmt::Display for Money {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		write!(f, "{}", self.0)
	}
}

impl TryFrom<String> for Money {
	type Error = String;

	fn try_from(s: String) -> Result<Money, String> {
		Money::parse(&s)
	}
}

impl From<Money> for String {
	fn from(m: Money) -> String {
		m.0.to_string()
	}
}
const TOKENS_PER_UNIT: u64 = 1_000_000;

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct Usage {
	pub input: u64,
	pub cache_read: u64,
	pub cache_write: u64,
	pub output: u64,
	pub reasoning: u64,
	pub input_audio: u64,
	pub output_audio: u64,
}

impl Usage {
	pub fn context_tokens(&self) -> u64 {
		self
			.input
			.saturating_add(self.cache_read)
			.saturating_add(self.cache_write)
			.saturating_add(self.input_audio)
	}
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Breakdown {
	pub input: Decimal,
	pub cache_read: Decimal,
	pub cache_write: Decimal,
	pub output: Decimal,
	pub reasoning: Decimal,
	pub input_audio: Decimal,
	pub output_audio: Decimal,
}

impl Breakdown {
	pub fn total(&self) -> Decimal {
		self.input
			+ self.cache_read
			+ self.cache_write
			+ self.output
			+ self.reasoning
			+ self.input_audio
			+ self.output_audio
	}
}

impl Rates {
	pub fn breakdown(&self, usage: &Usage) -> Breakdown {
		let unit = Decimal::from(TOKENS_PER_UNIT);
		// Audio and reasoning counts are provider-reported subsets of text totals.
		// If no dedicated modality rate exists, bill them at the text rate.
		let reasoning_rate = self.reasoning.as_ref().or(self.output.as_ref());
		let input_audio_rate = self.input_audio.as_ref().or(self.input.as_ref());
		let output_audio_rate = self.output_audio.as_ref().or(self.output.as_ref());
		Breakdown {
			input: line(usage.input, self.input.as_ref()) / unit,
			cache_read: line(usage.cache_read, self.cache_read.as_ref()) / unit,
			cache_write: line(usage.cache_write, self.cache_write.as_ref()) / unit,
			output: line(usage.output, self.output.as_ref()) / unit,
			reasoning: line(usage.reasoning, reasoning_rate) / unit,
			input_audio: line(usage.input_audio, input_audio_rate) / unit,
			output_audio: line(usage.output_audio, output_audio_rate) / unit,
		}
	}
}

impl Model {
	pub(super) fn effective_rates(&self, context_tokens: u64) -> Rates {
		match self
			.tiers
			.iter()
			.filter(|t| context_tokens > t.context_over)
			.max_by_key(|t| t.context_over)
		{
			Some(tier) => self.rates.overlay(&tier.rates),
			None => self.rates.clone(),
		}
	}
}

fn line(tokens: u64, rate: Option<&Money>) -> Decimal {
	match rate {
		Some(Money(r)) => Decimal::from(tokens) * *r,
		None => Decimal::ZERO,
	}
}
