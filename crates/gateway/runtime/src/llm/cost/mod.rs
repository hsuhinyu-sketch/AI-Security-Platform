use std::fmt;
use std::io::ErrorKind;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, bail};
use arc_swap::ArcSwap;
pub use catalog::{Breakdown, Catalog};
use catalog::{Catalog as CatalogData, Rates, Usage};
use prometheus_client::encoding::EncodeLabelValue;
use rust_decimal::Decimal;
use rust_decimal::prelude::{FromPrimitive, ToPrimitive};
use serde::{Deserialize, Serialize};
use tracing::{debug, error, info, warn};

use super::{CacheTokenConvention, LLMInfo, LLMResponse};
use crate::{ModelCatalogSource, apply, schema};

mod catalog;
pub mod refresh;

const TRACE_POLICY_KIND: &str = "llm_cost";

pub struct ModelCatalog {
	snapshot: ArcSwap<CatalogSnapshot>,
}

impl fmt::Debug for ModelCatalog {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.debug_struct("ModelCatalog")
			.field("snapshot", &*self.snapshot.load())
			.finish()
	}
}

impl Default for ModelCatalog {
	fn default() -> Self {
		Self {
			snapshot: ArcSwap::from_pointee(CatalogSnapshot::empty()),
		}
	}
}

impl ModelCatalog {
	pub fn new(sources: Vec<ModelCatalogSource>) -> anyhow::Result<Arc<Self>> {
		let catalog = Arc::new(Self::default());
		if sources.is_empty() {
			return Ok(catalog);
		}
		let file_paths: Vec<PathBuf> = sources
			.iter()
			.filter_map(|s| match s {
				ModelCatalogSource::File { file } => Some(file.clone()),
				ModelCatalogSource::Inline { .. } => None,
				ModelCatalogSource::InlineCatalog { .. } => None,
			})
			.collect();
		tokio::spawn({
			let sources = sources.clone();
			let catalog = catalog.clone();
			async move {
				match load_sources(&sources).await {
					Ok(loaded) => {
						log_loaded_catalog("loaded model catalog", &loaded);
						catalog.snapshot.store(Arc::new(loaded.snapshot));
					},
					Err(e) => {
						warn!("model catalog load failed; will load when the files become valid: {e:#}")
					},
				}
			}
		});
		if !file_paths.is_empty() {
			watch_catalog_files(file_paths, sources, catalog.clone())?;
		}
		Ok(catalog)
	}

	pub fn empty() -> Arc<Self> {
		Arc::new(Self::default())
	}

	pub fn snapshot(&self) -> Arc<CatalogSnapshot> {
		self.snapshot.load_full()
	}

	pub fn list_models(&self) -> ModelCatalogModels {
		self.snapshot.load().list_models()
	}

	pub fn replace(&self, snapshot: CatalogSnapshot) {
		self.snapshot.store(Arc::new(snapshot));
	}

	pub fn project(&self, info: &LLMInfo) -> CostProjection {
		let provider = info.request.provider.as_str();
		let snapshot = self.snapshot.load();
		if let Some(provider_model) = &info.response.provider_model {
			let projection = snapshot.project_with_missing_trace(
				provider,
				provider_model.as_str(),
				&info.response,
				info.request.cache_convention,
				false,
			);
			if projection.status != CostLookupStatus::Missing {
				return projection;
			}
		}
		snapshot.project(
			provider,
			info.request.request_model.as_str(),
			&info.response,
			info.request.cache_convention,
		)
	}
}

pub struct CatalogSnapshot {
	catalog: Option<CatalogData>,
}

impl fmt::Debug for CatalogSnapshot {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.debug_struct("CatalogSnapshot")
			.field("loaded", &self.catalog.is_some())
			.finish()
	}
}

impl CatalogSnapshot {
	fn from_catalogs(catalogs: impl IntoIterator<Item = CatalogData>) -> Self {
		let merged = catalogs
			.into_iter()
			.fold(CatalogData::default(), CatalogData::override_with);
		CatalogSnapshot {
			catalog: Some(merged),
		}
	}

	fn empty() -> Self {
		CatalogSnapshot { catalog: None }
	}

	fn list_models(&self) -> ModelCatalogModels {
		let Some(catalog) = &self.catalog else {
			return ModelCatalogModels {
				loaded: false,
				providers: Vec::new(),
			};
		};
		ModelCatalogModels {
			loaded: true,
			providers: catalog
				.providers
				.iter()
				.map(|(provider, data)| ModelCatalogProviderModels {
					provider: provider.clone(),
					models: data.models.keys().cloned().collect(),
				})
				.collect(),
		}
	}

	fn project(
		&self,
		provider: &str,
		model: &str,
		resp: &LLMResponse,
		convention: CacheTokenConvention,
	) -> CostProjection {
		self.project_with_missing_trace(provider, model, resp, convention, true)
	}

	fn project_with_missing_trace(
		&self,
		provider: &str,
		model: &str,
		resp: &LLMResponse,
		convention: CacheTokenConvention,
		trace_missing: bool,
	) -> CostProjection {
		let Some(catalog) = self.catalog.as_ref() else {
			crate::proxy::dtrace::pol_event!(
				TRACE_POLICY_KIND,
				crate::proxy::dtrace::Severity::Warn,
				details = serde_json::json!({
					"provider": provider,
					"model": model,
					"status": status_name(CostLookupStatus::NoCatalog),
					"reason": "no model catalog",
				}),
			);
			return CostProjection::unpriced(CostLookupStatus::NoCatalog);
		};
		let entry = catalog.resolve(provider, model);
		let Some(entry) = entry else {
			if trace_missing {
				crate::proxy::dtrace::pol_event!(
					TRACE_POLICY_KIND,
					crate::proxy::dtrace::Severity::Warn,
					details = serde_json::json!({
						"provider": provider,
						"model": model,
						"status": status_name(CostLookupStatus::Missing),
						"reason": "no catalog entry for provider/model",
					}),
				);
			}
			return CostProjection::unpriced(CostLookupStatus::Missing);
		};

		let provisional_usage = usage_for(convention, resp, true);
		// Tier selection must be invariant to cache-read repricing below: the
		// cache tokens may move between input/cache_read, but their sum is stable.
		let context_tokens = provisional_usage.context_tokens();
		let rates = entry.effective_rates(context_tokens);
		if rates.is_empty() {
			crate::proxy::dtrace::pol_event!(
				TRACE_POLICY_KIND,
				crate::proxy::dtrace::Severity::Warn,
				details = serde_json::json!({
					"provider": provider,
					"model": model,
					"status": status_name(CostLookupStatus::Unpriced),
					"reason": "catalog entry has no effective rates",
					"cacheTokenConvention": cache_convention_name(convention),
					"contextTokens": context_tokens,
					"usage": &provisional_usage,
				}),
			);
			return CostProjection::unpriced(CostLookupStatus::Unpriced);
		}

		let prices_cache_read = rates.cache_read.is_some();
		let usage = if prices_cache_read {
			provisional_usage
		} else {
			usage_for(convention, resp, false)
		};
		let breakdown = rates.breakdown(&usage);
		let cost = CostBreakdown::from(&breakdown);
		let cost_rates = CostRates::from(&rates);
		crate::proxy::dtrace::pol_event!(
			TRACE_POLICY_KIND,
			crate::proxy::dtrace::Severity::Info,
			details = serde_json::json!({
				"provider": provider,
				"model": model,
				"status": status_name(CostLookupStatus::Exact),
				"cacheTokenConvention": cache_convention_name(convention),
				"contextTokens": context_tokens,
				"pricesCacheRead": prices_cache_read,
				"usage": &usage,
				"rates": cost_rates,
				"cost": cost,
			}),
		);
		CostProjection {
			status: CostLookupStatus::Exact,
			cost: Some(breakdown),
			cost_rates: Some(cost_rates),
		}
	}
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ModelCatalogModels {
	pub loaded: bool,
	pub providers: Vec<ModelCatalogProviderModels>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ModelCatalogProviderModels {
	pub provider: String,
	pub models: Vec<String>,
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
			("input", self.input),
			("output", self.output),
			("cacheRead", self.cache_read),
			("cacheWrite", self.cache_write),
			("reasoning", self.reasoning),
			("inputAudio", self.input_audio),
			("outputAudio", self.output_audio),
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
			input: breakdown_f64(b.input),
			output: breakdown_f64(b.output),
			cache_read: breakdown_f64(b.cache_read),
			cache_write: breakdown_f64(b.cache_write),
			reasoning: breakdown_f64(b.reasoning),
			input_audio: breakdown_f64(b.input_audio),
			output_audio: breakdown_f64(b.output_audio),
		}
	}
}

impl From<CostBreakdown> for Breakdown {
	fn from(b: CostBreakdown) -> Self {
		let d = |v| Decimal::from_f64(v).unwrap_or_default();
		Breakdown {
			input: d(b.input),
			output: d(b.output),
			cache_read: d(b.cache_read),
			cache_write: d(b.cache_write),
			reasoning: d(b.reasoning),
			input_audio: d(b.input_audio),
			output_audio: d(b.output_audio),
		}
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

#[derive(Debug)]
struct LoadedCatalog {
	snapshot: CatalogSnapshot,
	missing: Vec<PathBuf>,
}

async fn load_sources(sources: &[ModelCatalogSource]) -> anyhow::Result<LoadedCatalog> {
	if sources.is_empty() {
		bail!("no model catalog sources supplied");
	}

	let mut catalogs = Vec::with_capacity(sources.len());
	let mut missing = Vec::new();
	for source in sources {
		match source {
			ModelCatalogSource::File { file } => {
				let json = match fs_err::tokio::read_to_string(file).await {
					Ok(json) => json,
					Err(e) if e.kind() == ErrorKind::NotFound => {
						missing.push(file.clone());
						continue;
					},
					Err(e) => {
						return Err(e).context("reading model catalog");
					},
				};
				let catalog = catalog::from_json(&json)
					.with_context(|| format!("invalid model catalog at {}", file.display()))?;
				catalogs.push(catalog);
			},
			ModelCatalogSource::Inline { inline } => {
				let catalog = catalog::from_json(inline).context("invalid inline model catalog")?;
				catalogs.push(catalog);
			},
			ModelCatalogSource::InlineCatalog { inline } => {
				inline.validate().context("invalid inline model catalog")?;
				catalogs.push(inline.clone());
			},
		}
	}
	if catalogs.is_empty() {
		bail!(
			"no configured model catalog sources are currently readable; missing files: {}",
			missing
				.iter()
				.map(|p| p.display().to_string())
				.collect::<Vec<_>>()
				.join(", ")
		);
	}
	Ok(LoadedCatalog {
		snapshot: CatalogSnapshot::from_catalogs(catalogs),
		missing,
	})
}

fn log_loaded_catalog(message: &'static str, loaded: &LoadedCatalog) {
	let catalog = loaded.snapshot.catalog.as_ref();
	let providers = catalog.map_or(0, |catalog| catalog.providers.len());
	let models = catalog.map_or(0, |catalog| {
		catalog.providers.values().map(|p| p.models.len()).sum()
	});
	info!(providers, models, "{}", message);
	if !loaded.missing.is_empty() {
		debug!(files = ?loaded.missing, "{} configured but missing", message);
	}
}

fn watch_catalog_files(
	file_paths: Vec<PathBuf>,
	all_sources: Vec<ModelCatalogSource>,
	catalog: Arc<ModelCatalog>,
) -> anyhow::Result<()> {
	let mut watched = crate::util::watch_files_with_options(
		file_paths,
		crate::util::WatchFilesOptions::default().reload_on_disappearance(true),
	)?;
	info!(
		count = watched.paths().len(),
		"watching model catalog files"
	);
	tokio::task::spawn(async move {
		while watched.changed().await {
			match load_sources(&all_sources).await {
				Ok(loaded) => {
					log_loaded_catalog("model catalog reloaded", &loaded);
					catalog.snapshot.store(Arc::new(loaded.snapshot));
				},
				Err(e) => {
					error!("failed to reload model catalog; keeping last valid catalog: {e:#}")
				},
			}
		}
	});
	Ok(())
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, EncodeLabelValue)]
pub enum CostLookupStatus {
	Exact,
	Unpriced,
	#[default]
	Missing,
	NoCatalog,
}

fn status_name(status: CostLookupStatus) -> &'static str {
	match status {
		CostLookupStatus::Exact => "exact",
		CostLookupStatus::Unpriced => "unpriced",
		CostLookupStatus::Missing => "missing",
		CostLookupStatus::NoCatalog => "noCatalog",
	}
}

fn cache_convention_name(convention: CacheTokenConvention) -> &'static str {
	match convention {
		CacheTokenConvention::InputIncludesCache => "inputIncludesCache",
		CacheTokenConvention::InputExcludesCache => "inputExcludesCache",
	}
}

fn usage_for(
	convention: CacheTokenConvention,
	resp: &LLMResponse,
	prices_cache_read: bool,
) -> Usage {
	let mut cache_read = resp.cached_input_tokens.unwrap_or(0);
	let cache_write = resp.cache_creation_input_tokens.unwrap_or(0);
	let input_audio = resp.input_audio_tokens.unwrap_or(0);
	let output_audio = resp.output_audio_tokens.unwrap_or(0);
	let reasoning = resp.reasoning_tokens.unwrap_or(0);

	let mut input = resp.input_tokens.unwrap_or(0).saturating_sub(input_audio);
	match (convention, prices_cache_read) {
		(CacheTokenConvention::InputIncludesCache, true) => {
			input = input.saturating_sub(cache_read);
		},
		(CacheTokenConvention::InputIncludesCache, false) => {
			// Cached tokens are already included in input_tokens; zero the separate
			// bucket so they aren't double-counted or left unrated.
			cache_read = 0;
		},
		(CacheTokenConvention::InputExcludesCache, true) => {
			// cache_read is already separate from input; keep as-is.
		},
		(CacheTokenConvention::InputExcludesCache, false) => {
			// No cache_read rate in the catalog: fold cached tokens into input so
			// they're billed at the input rate rather than going unrated ($0).
			input = input.saturating_add(cache_read);
			cache_read = 0;
		},
	}
	let output = resp
		.output_tokens
		.unwrap_or(0)
		.saturating_sub(reasoning)
		.saturating_sub(output_audio);

	Usage {
		input,
		cache_read,
		cache_write,
		output,
		reasoning,
		input_audio,
		output_audio,
	}
}
