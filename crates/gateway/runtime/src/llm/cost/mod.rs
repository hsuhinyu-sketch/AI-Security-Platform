//! Shared pricing/observation values. LLM Host lifecycle is feature selected.
use crate::{apply, schema};
use catalog::Rates;
pub use catalog::{Catalog, ModelCatalogModels, ModelCatalogProviderModels};
pub use gateway_llm::catalog;
use prometheus_client::encoding::EncodeLabelValue;
use rust_decimal::Decimal;
use rust_decimal::prelude::{FromPrimitive, ToPrimitive};
use serde::{Deserialize, Serialize};
#[cfg(feature = "gateway-llm")]
mod lifecycle;
#[cfg(feature = "gateway-llm")]
pub use lifecycle::{CatalogSnapshot, ModelCatalog};
#[cfg(feature = "gateway-llm")]
pub mod refresh;
#[cfg(feature = "gateway-llm")]
mod service;
#[cfg(feature = "gateway-llm")]
pub use service::{CatalogAdmin, CatalogReader, CatalogService};

/// Host presentation wrapper; all arithmetic remains in the LLM catalog.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Breakdown(catalog::Breakdown);

impl std::ops::Deref for Breakdown {
	type Target = catalog::Breakdown;

	fn deref(&self) -> &Self::Target {
		&self.0
	}
}

#[derive(Debug, Clone)]
pub struct CostProjection {
	pub status: CostLookupStatus,
	pub cost: Option<Breakdown>,
	pub cost_rates: Option<CostRates>,
}

impl CostProjection {
	fn unpriced(status: CostLookupStatus) -> Self {
		CostProjection {
			status,
			cost: None,
			cost_rates: None,
		}
	}
}

#[apply(schema!)]
#[derive(Copy, Default, ::cel::DynamicType)]
pub struct CostRates {
	#[serde(skip_serializing_if = "Option::is_none")]
	pub input: Option<f64>,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub output: Option<f64>,
	#[serde(skip_serializing_if = "Option::is_none")]
	#[dynamic(rename = "cacheRead")]
	pub cache_read: Option<f64>,
	#[serde(skip_serializing_if = "Option::is_none")]
	#[dynamic(rename = "cacheWrite")]
	pub cache_write: Option<f64>,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub reasoning: Option<f64>,
	#[serde(skip_serializing_if = "Option::is_none")]
	#[dynamic(rename = "inputAudio")]
	pub input_audio: Option<f64>,
	#[serde(skip_serializing_if = "Option::is_none")]
	#[dynamic(rename = "outputAudio")]
	pub output_audio: Option<f64>,
}

impl From<&Rates> for CostRates {
	fn from(r: &Rates) -> Self {
		let f = |m: &Option<catalog::Money>| m.as_ref().and_then(|m| m.0.to_f64());
		CostRates {
			input: f(&r.input),
			output: f(&r.output),
			cache_read: f(&r.cache_read),
			cache_write: f(&r.cache_write),
			reasoning: f(&r.reasoning),
			input_audio: f(&r.input_audio),
			output_audio: f(&r.output_audio),
		}
	}
}

fn breakdown_f64(d: Decimal) -> f64 {
	d.to_f64().unwrap_or_default()
}

impl Breakdown {
	// (CEL field name, value) pairs. `total` is computed, the rest are stored.
	fn components(&self) -> [(&'static str, Decimal); 8] {
		[
			("total", self.total()),
			("input", self.0.input),
			("output", self.0.output),
			("cacheRead", self.0.cache_read),
			("cacheWrite", self.0.cache_write),
			("reasoning", self.0.reasoning),
			("inputAudio", self.0.input_audio),
			("outputAudio", self.0.output_audio),
		]
	}
}

#[apply(schema!)]
#[derive(Copy, Default, ::cel::DynamicType)]
pub struct CostBreakdown {
	pub total: f64,
	pub input: f64,
	pub output: f64,
	#[dynamic(rename = "cacheRead")]
	pub cache_read: f64,
	#[dynamic(rename = "cacheWrite")]
	pub cache_write: f64,
	pub reasoning: f64,
	#[dynamic(rename = "inputAudio")]
	pub input_audio: f64,
	#[dynamic(rename = "outputAudio")]
	pub output_audio: f64,
}

impl From<&Breakdown> for CostBreakdown {
	fn from(b: &Breakdown) -> Self {
		CostBreakdown {
			total: breakdown_f64(b.total()),
			input: breakdown_f64(b.0.input),
			output: breakdown_f64(b.0.output),
			cache_read: breakdown_f64(b.0.cache_read),
			cache_write: breakdown_f64(b.0.cache_write),
			reasoning: breakdown_f64(b.0.reasoning),
			input_audio: breakdown_f64(b.0.input_audio),
			output_audio: breakdown_f64(b.0.output_audio),
		}
	}
}

impl From<CostBreakdown> for Breakdown {
	fn from(b: CostBreakdown) -> Self {
		let d = |v| Decimal::from_f64(v).unwrap_or_default();
		Breakdown(catalog::Breakdown {
			input: d(b.input),
			output: d(b.output),
			cache_read: d(b.cache_read),
			cache_write: d(b.cache_write),
			reasoning: d(b.reasoning),
			input_audio: d(b.input_audio),
			output_audio: d(b.output_audio),
		})
	}
}

impl ::cel::types::dynamic::DynamicType for Breakdown {
	fn materialize(&self) -> ::cel::Value<'_> {
		let mut map = vector_map::VecMap::with_capacity(8);
		for (name, value) in self.components() {
			map.insert(
				::cel::objects::KeyRef::from(name),
				::cel::Value::from(breakdown_f64(value)),
			);
		}
		::cel::Value::Map(::cel::objects::MapValue::Borrow(map))
	}

	// Lazy: a field is only converted to f64 when a CEL expression reads it.
	fn field(&self, field: &str) -> Option<::cel::Value<'_>> {
		self
			.components()
			.into_iter()
			.find(|(name, _)| *name == field)
			.map(|(_, value)| ::cel::Value::from(breakdown_f64(value)))
	}
}

impl Serialize for Breakdown {
	fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
		CostBreakdown::from(self).serialize(serializer)
	}
}

impl<'de> Deserialize<'de> for Breakdown {
	fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
		CostBreakdown::deserialize(deserializer).map(Into::into)
	}
}

#[cfg(feature = "schema")]
impl schemars::JsonSchema for Breakdown {
	fn schema_name() -> std::borrow::Cow<'static, str> {
		"CostBreakdown".into()
	}

	fn json_schema(schema_gen: &mut schemars::SchemaGenerator) -> schemars::Schema {
		CostBreakdown::json_schema(schema_gen)
	}
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, EncodeLabelValue)]
pub enum CostLookupStatus {
	Exact,
	Unpriced,
	#[default]
	Missing,
	NoCatalog,
}

#[cfg(test)]
mod value_tests;
