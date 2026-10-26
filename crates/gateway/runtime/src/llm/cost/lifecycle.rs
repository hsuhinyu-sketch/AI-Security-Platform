//! Host catalog publication, file tracking and shutdown; selected with LLM.
use super::*;
use crate::ModelCatalogSource;
use crate::llm::{CacheTokenConvention, LLMInfo, LLMResponse};
use anyhow::{Context, bail};
use arc_swap::ArcSwap;
use catalog::Catalog as CatalogData;
use std::fmt;
use std::io::ErrorKind;
use std::path::PathBuf;
use std::sync::Arc;
use tracing::{debug, error, info, warn};
const TRACE_POLICY_KIND: &str = "llm_cost";

pub struct ModelCatalog {
	snapshot: ArcSwap<CatalogSnapshot>,
	pub(super) tasks: std::sync::Mutex<Vec<tokio::task::AbortHandle>>,
	pub(super) closed: std::sync::atomic::AtomicBool,
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
			tasks: Default::default(),
			closed: Default::default(),
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
		let initial_load = tokio::spawn({
			let sources = sources.clone();
			let catalog = Arc::downgrade(&catalog);
			async move {
				match load_sources(&sources).await {
					Ok(loaded) => {
						log_loaded_catalog("loaded model catalog", &loaded);
						if let Some(catalog) = catalog.upgrade() {
							catalog.publish_if_running(loaded.snapshot);
						}
					},
					Err(e) => {
						warn!("model catalog load failed; will load when the files become valid: {e:#}")
					},
				}
			}
		});
		catalog
			.tasks
			.lock()
			.expect("catalog tasks")
			.push(initial_load.abort_handle());
		if !file_paths.is_empty() {
			match watch_catalog_files(file_paths, sources, Arc::downgrade(&catalog)) {
				Ok(task) => catalog.tasks.lock().expect("catalog tasks").push(task),
				Err(error) => {
					catalog.shutdown();
					return Err(error);
				},
			}
		}
		Ok(catalog)
	}

	pub(super) fn shutdown(&self) {
		let mut tasks = self.tasks.lock().expect("catalog tasks");
		self
			.closed
			.store(true, std::sync::atomic::Ordering::Release);
		for task in tasks.drain(..) {
			task.abort();
		}
	}

	// Serialize background publication with Host shutdown. Readers keep the last snapshot.
	fn publish_if_running(&self, snapshot: CatalogSnapshot) -> bool {
		let _tasks = self.tasks.lock().expect("catalog tasks");
		if self.closed.load(std::sync::atomic::Ordering::Acquire) {
			return false;
		}
		self.snapshot.store(Arc::new(snapshot));
		true
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

	pub fn replace(&self, snapshot: CatalogSnapshot) -> anyhow::Result<()> {
		if !self.publish_if_running(snapshot) {
			bail!("model catalog service is closed");
		}
		Ok(())
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

/// Host diagnostics and compatibility projection around the immutable LLM catalog.
pub struct CatalogSnapshot(catalog::CatalogSnapshot);

impl fmt::Debug for CatalogSnapshot {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		fmt::Debug::fmt(&self.0, f)
	}
}

impl CatalogSnapshot {
	pub(super) fn from_catalogs(catalogs: impl IntoIterator<Item = CatalogData>) -> Self {
		Self(catalog::CatalogSnapshot::from_catalogs(catalogs))
	}

	fn empty() -> Self {
		Self(catalog::CatalogSnapshot::empty())
	}

	fn list_models(&self) -> ModelCatalogModels {
		self.0.list_models()
	}

	pub(super) fn project(
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
		match self.0.project(provider, model, resp, convention) {
			catalog::CostProjection::NoCatalog => {
				crate::proxy::dtrace::pol_event!(
					TRACE_POLICY_KIND,
					crate::proxy::dtrace::Severity::Warn,
					details = serde_json::json!({
							"provider": provider, "model": model,
							"status": status_name(CostLookupStatus::NoCatalog),
							"reason": "no model catalog",
					}),
				);
				CostProjection::unpriced(CostLookupStatus::NoCatalog)
			},
			catalog::CostProjection::Missing => {
				if trace_missing {
					crate::proxy::dtrace::pol_event!(
						TRACE_POLICY_KIND,
						crate::proxy::dtrace::Severity::Warn,
						details = serde_json::json!({
								"provider": provider, "model": model,
								"status": status_name(CostLookupStatus::Missing),
								"reason": "no catalog entry for provider/model",
						}),
					);
				}
				CostProjection::unpriced(CostLookupStatus::Missing)
			},
			catalog::CostProjection::Unpriced { usage } => {
				crate::proxy::dtrace::pol_event!(
					TRACE_POLICY_KIND,
					crate::proxy::dtrace::Severity::Warn,
					details = serde_json::json!({
							"provider": provider, "model": model,
							"status": status_name(CostLookupStatus::Unpriced),
							"reason": "catalog entry has no effective rates",
							"cacheTokenConvention": cache_convention_name(convention),
							"contextTokens": usage.context_tokens(), "usage": &usage,
					}),
				);
				CostProjection::unpriced(CostLookupStatus::Unpriced)
			},
			catalog::CostProjection::Exact {
				cost,
				rates,
				usage,
				context_tokens,
			} => {
				let breakdown = Breakdown(cost);
				let cost_rates = CostRates::from(&rates);
				crate::proxy::dtrace::pol_event!(
					TRACE_POLICY_KIND,
					crate::proxy::dtrace::Severity::Info,
					details = serde_json::json!({
							"provider": provider, "model": model,
							"status": status_name(CostLookupStatus::Exact),
							"cacheTokenConvention": cache_convention_name(convention),
							"contextTokens": context_tokens,
							"pricesCacheRead": rates.cache_read.is_some(),
							"usage": &usage, "rates": cost_rates,
							"cost": CostBreakdown::from(&breakdown),
					}),
				);
				CostProjection {
					status: CostLookupStatus::Exact,
					cost: Some(breakdown),
					cost_rates: Some(cost_rates),
				}
			},
		}
	}
}

#[derive(Debug)]
pub(super) struct LoadedCatalog {
	snapshot: CatalogSnapshot,
	missing: Vec<PathBuf>,
}

pub(super) async fn load_sources(sources: &[ModelCatalogSource]) -> anyhow::Result<LoadedCatalog> {
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
	let listing = loaded.snapshot.list_models();
	let providers = listing.providers.len();
	let models: usize = listing.providers.iter().map(|p| p.models.len()).sum();
	info!(providers, models, "{}", message);
	if !loaded.missing.is_empty() {
		debug!(files = ?loaded.missing, "{} configured but missing", message);
	}
}

fn watch_catalog_files(
	file_paths: Vec<PathBuf>,
	all_sources: Vec<ModelCatalogSource>,
	catalog: std::sync::Weak<ModelCatalog>,
) -> anyhow::Result<tokio::task::AbortHandle> {
	let mut watched = crate::util::watch_files_with_options(
		file_paths,
		crate::util::WatchFilesOptions::default().reload_on_disappearance(true),
	)?;
	info!(
		count = watched.paths().len(),
		"watching model catalog files"
	);
	let task = tokio::task::spawn(async move {
		while watched.changed().await {
			match load_sources(&all_sources).await {
				Ok(loaded) => {
					log_loaded_catalog("model catalog reloaded", &loaded);
					let Some(catalog) = catalog.upgrade() else {
						break;
					};
					if !catalog.publish_if_running(loaded.snapshot) {
						break;
					}
				},
				Err(e) => {
					error!("failed to reload model catalog; keeping last valid catalog: {e:#}")
				},
			}
		}
	});
	Ok(task.abort_handle())
}

impl Drop for ModelCatalog {
	fn drop(&mut self) {
		self.shutdown();
	}
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
