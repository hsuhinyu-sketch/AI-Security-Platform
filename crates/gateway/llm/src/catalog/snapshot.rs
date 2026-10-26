use super::{Breakdown, Catalog, Rates, Usage};
use crate::{CacheTokenConvention, LLMResponse};
use serde::Serialize;
use std::fmt;

/// A loaded (possibly empty) catalog is distinct from a catalog not yet available.
pub struct CatalogSnapshot {
	catalog: Option<Catalog>,
}

impl fmt::Debug for CatalogSnapshot {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.debug_struct("CatalogSnapshot")
			.field("loaded", &self.catalog.is_some())
			.finish()
	}
}

impl CatalogSnapshot {
	pub fn empty() -> Self {
		Self { catalog: None }
	}

	/// Sources are applied in order; later sources replace complete model entries.
	pub fn from_catalogs(catalogs: impl IntoIterator<Item = Catalog>) -> Self {
		Self {
			catalog: Some(
				catalogs
					.into_iter()
					.fold(Catalog::default(), Catalog::override_with),
			),
		}
	}

	pub fn list_models(&self) -> ModelCatalogModels {
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

	pub fn project(
		&self,
		provider: &str,
		model: &str,
		response: &LLMResponse,
		convention: CacheTokenConvention,
	) -> CostProjection {
		let Some(catalog) = &self.catalog else {
			return CostProjection::NoCatalog;
		};
		let Some(entry) = catalog.resolve(provider, model) else {
			return CostProjection::Missing;
		};
		// Keep tier selection invariant when unpriced cache reads are folded into input.
		let provisional_usage = usage_for(convention, response, true);
		let context_tokens = provisional_usage.context_tokens();
		let rates = entry.effective_rates(context_tokens);
		if rates.is_empty() {
			return CostProjection::Unpriced {
				usage: provisional_usage,
			};
		}
		let usage = if rates.cache_read.is_some() {
			provisional_usage
		} else {
			usage_for(convention, response, false)
		};
		let cost = rates.breakdown(&usage);
		CostProjection::Exact {
			cost,
			rates,
			usage,
			context_tokens,
		}
	}
}

/// An unpriced result cannot be mistaken for a successful zero-cost calculation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CostProjection {
	NoCatalog,
	Missing,
	Unpriced {
		usage: Usage,
	},
	Exact {
		cost: Breakdown,
		rates: Rates,
		usage: Usage,
		context_tokens: u64,
	},
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
