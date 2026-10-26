//! LLM-owned catalog lifecycle. Request readers never own the file-watching service.
use super::{CatalogSnapshot, CostProjection, ModelCatalog, ModelCatalogModels};
use crate::{ModelCatalogSource, llm::LLMInfo};
use std::{
	path::Path,
	sync::{Arc, Weak, atomic::Ordering},
};

#[derive(Debug)]
pub struct CatalogService {
	catalog: Arc<ModelCatalog>,
}

impl CatalogService {
	pub fn new(sources: Vec<ModelCatalogSource>) -> anyhow::Result<Self> {
		Ok(Self::from_catalog(ModelCatalog::new(sources)?))
	}

	pub fn from_catalog(catalog: Arc<ModelCatalog>) -> Self {
		Self { catalog }
	}

	pub fn reader(&self) -> CatalogReader {
		CatalogReader(self.catalog.clone())
	}

	pub fn admin(&self) -> CatalogAdmin {
		CatalogAdmin {
			catalog: Arc::downgrade(&self.catalog),
			_legacy_owner: None,
		}
	}
}

impl Drop for CatalogService {
	fn drop(&mut self) {
		self.catalog.shutdown();
	}
}

/// Read-only data access; retained by in-flight logs after the service has stopped.
#[derive(Debug, Clone)]
pub struct CatalogReader(Arc<ModelCatalog>);

impl From<Arc<ModelCatalog>> for CatalogReader {
	fn from(catalog: Arc<ModelCatalog>) -> Self {
		Self(catalog)
	}
}

impl CatalogReader {
	pub fn snapshot(&self) -> Arc<CatalogSnapshot> {
		self.0.snapshot()
	}
	pub fn list_models(&self) -> ModelCatalogModels {
		self.0.list_models()
	}
	pub fn project(&self, info: &LLMInfo) -> CostProjection {
		self.0.project(info)
	}
}

/// Management access is explicit and stops being usable when its Host owner closes.
#[derive(Debug, Clone)]
pub struct CatalogAdmin {
	catalog: Weak<ModelCatalog>,
	// Preserve the old management constructor that accepts an owning Arc directly.
	_legacy_owner: Option<Arc<ModelCatalog>>,
}

impl From<Arc<ModelCatalog>> for CatalogAdmin {
	fn from(catalog: Arc<ModelCatalog>) -> Self {
		Self {
			catalog: Arc::downgrade(&catalog),
			_legacy_owner: Some(catalog),
		}
	}
}

impl CatalogAdmin {
	fn active(&self) -> anyhow::Result<Arc<ModelCatalog>> {
		self
			.catalog
			.upgrade()
			.filter(|catalog| !catalog.closed.load(Ordering::Acquire))
			.ok_or_else(|| anyhow::anyhow!("model catalog service is closed"))
	}
	pub fn list_models(&self) -> anyhow::Result<ModelCatalogModels> {
		Ok(self.active()?.list_models())
	}
	pub async fn refresh_base(
		&self,
		file: &Path,
	) -> anyhow::Result<super::refresh::RefreshBaseCatalogResponse> {
		let catalog = self.active()?;
		super::refresh::refresh_models_dev_base_catalog(file, &catalog).await
	}
}

#[cfg(test)]
#[path = "service_tests.rs"]
mod tests;
