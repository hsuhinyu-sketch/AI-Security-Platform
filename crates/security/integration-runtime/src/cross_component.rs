//! Administrator-owned cross-component data-flow contract. Context IDs are not credentials.
use crate::{DataClassification, DataEgressConfig};

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CrossComponentConfig {
	/// A deployment-unique AI-system trust domain, shared by its RAG/LLM/Agent/MCP routes.
	pub namespace: String,
	#[serde(default = "ttl")]
	pub ttl_seconds: u64,
	#[serde(default = "capacity")]
	pub max_contexts: usize,
	/// Exactly one policy per class. Sensitive classes intersect all lower-class policies.
	pub destinations: Vec<DataEgressConfig>,
	/// Optional private single-writer journal; absent preserves process-local behavior.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub storage: Option<security_audit::StateJournalConfig>,
	#[serde(skip)]
	pub store: crate::context_store::ContextStoreSlot,
}
fn ttl() -> u64 {
	900
}
fn capacity() -> usize {
	1024
}
impl CrossComponentConfig {
	pub fn validate(&self) -> Result<(), String> {
		if let Some(storage) = &self.storage {
			storage.validate()?;
		}
		if self.namespace.is_empty()
			|| self.namespace.trim() != self.namespace
			|| self.namespace.len() > 128
			|| !(1..=86400).contains(&self.ttl_seconds)
			|| !(1..=16384).contains(&self.max_contexts)
		{
			return Err("crossComponent requires a namespace and bounded lifetime/capacity".into());
		}
		for class in [
			DataClassification::Public,
			DataClassification::Internal,
			DataClassification::Restricted,
		] {
			if self
				.destinations
				.iter()
				.filter(|p| p.classification == class)
				.count()
				!= 1
			{
				return Err(
					"crossComponent.destinations requires exactly one policy for each classification".into(),
				);
			}
		}
		if self.destinations.len() != 3 {
			return Err("invalid crossComponent.destinations".into());
		}
		for policy in &self.destinations {
			policy.validate()?;
		}
		Ok(())
	}
}
