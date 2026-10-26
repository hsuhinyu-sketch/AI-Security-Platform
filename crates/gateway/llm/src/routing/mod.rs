//! Immutable model selection data. A selection carries no execution authority.
pub mod path;

use rand::seq::IndexedRandom;
use serde::Serialize;

#[derive(
	Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, serde::Deserialize,
)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub enum ModelVisibility {
	#[default]
	Public,
	Internal,
}
impl ModelVisibility {
	pub fn is_public(&self) -> bool {
		matches!(self, Self::Public)
	}
}

#[derive(Debug, Clone)]
pub struct ModelRoute {
	pub name: String,
	pub visibility: ModelVisibility,
}
#[derive(Debug, Clone)]
pub struct VirtualModelRoute {
	pub name: String,
	pub routing: VirtualModelRouting,
}
#[derive(Debug, Clone)]
pub enum VirtualModelRouting {
	Weighted(Vec<WeightedTarget>),
	Conditional(Vec<ConditionalTarget>),
	/// Provider groups and per-attempt failover remain the Host's responsibility.
	Failover,
}
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WeightedTarget {
	pub model: String,
	pub weight: usize,
}
#[derive(Debug, Clone)]
pub struct ConditionalTarget {
	pub model: String,
	pub has_condition: bool,
}

#[derive(Debug, Clone)]
pub struct RoutingTable {
	models: Vec<ModelRoute>,
	virtual_models: Vec<VirtualModelRoute>,
}

// Borrowed IDs cannot outlive their table. Index lookup also rejects another snapshot,
// including a clone of a table with identical model names and numeric positions.
#[derive(Clone, Copy)]
pub struct ModelId<'a> {
	table: &'a RoutingTable,
	index: usize,
}
#[derive(Clone, Copy)]
pub struct VirtualModelId<'a> {
	table: &'a RoutingTable,
	index: usize,
}

#[derive(Debug, PartialEq, Eq)]
pub enum VirtualTarget<'a> {
	Model(&'a str),
	Failover,
}
#[derive(Debug, thiserror::Error)]
pub enum SelectionError {
	#[error("virtual model belongs to another routing snapshot")]
	ForeignSnapshot,
	#[error("failed to select weighted virtual model target: {0}")]
	InvalidWeights(#[from] rand::distr::weighted::Error),
	#[error("no conditional target matched")]
	NoMatchingTarget,
}

impl RoutingTable {
	/// Input ordering is significant and is preserved without sorting or deduplication.
	pub fn new(models: Vec<ModelRoute>, virtual_models: Vec<VirtualModelRoute>) -> Self {
		Self {
			models,
			virtual_models,
		}
	}
	pub fn models(&self) -> impl ExactSizeIterator<Item = (ModelId<'_>, &ModelRoute)> {
		self
			.models
			.iter()
			.enumerate()
			.map(|(index, model)| (ModelId { table: self, index }, model))
	}
	pub fn virtual_models(
		&self,
	) -> impl ExactSizeIterator<Item = (VirtualModelId<'_>, &VirtualModelRoute)> {
		self
			.virtual_models
			.iter()
			.enumerate()
			.map(|(index, model)| (VirtualModelId { table: self, index }, model))
	}
	pub fn model_index(&self, id: ModelId<'_>) -> Option<usize> {
		std::ptr::eq(self, id.table).then_some(id.index)
	}
	pub fn virtual_model_index(&self, id: VirtualModelId<'_>) -> Option<usize> {
		std::ptr::eq(self, id.table).then_some(id.index)
	}
	pub fn virtual_model(&self, name: &str) -> Option<VirtualModelId<'_>> {
		self
			.virtual_models()
			.find(|(_, model)| model.name == name)
			.map(|(id, _)| id)
	}
	pub fn resolve_concrete(
		&self,
		name: &str,
		allow_internal: bool,
		mut matches: impl FnMut(ModelId<'_>) -> bool,
	) -> Option<ModelId<'_>> {
		self
			.models()
			.find(|(id, model)| {
				(allow_internal || model.visibility.is_public())
					&& model_name_matches(&model.name, name)
					&& matches(*id)
			})
			.map(|(id, _)| id)
	}
	/// Lists declared public aliases as before; target authorization still runs on invocation.
	pub fn listed_models(&self, mut visible: impl FnMut(ModelId<'_>) -> bool) -> Vec<&str> {
		self
			.models()
			.filter(|(id, model)| model.visibility.is_public() && visible(*id))
			.map(|(_, model)| model.name.as_str())
			.chain(self.virtual_models.iter().map(|model| model.name.as_str()))
			.collect()
	}
	/// Conditions and randomness are requested lazily. No network, request, policy or
	/// authorized flag is accepted; the result must still pass Host execution checks.
	pub fn select_virtual<R: rand::Rng>(
		&self,
		id: VirtualModelId<'_>,
		mut condition: impl FnMut(usize) -> bool,
		rng: impl FnOnce() -> R,
	) -> Result<VirtualTarget<'_>, SelectionError> {
		let index = self
			.virtual_model_index(id)
			.ok_or(SelectionError::ForeignSnapshot)?;
		match &self.virtual_models[index].routing {
			VirtualModelRouting::Weighted(targets) => {
				let target = targets.choose_weighted(&mut rng(), |target| target.weight)?;
				Ok(VirtualTarget::Model(&target.model))
			},
			VirtualModelRouting::Conditional(targets) => targets
				.iter()
				.enumerate()
				.find(|(i, target)| !target.has_condition || condition(*i))
				.map(|(_, target)| VirtualTarget::Model(target.model.as_str()))
				.ok_or(SelectionError::NoMatchingTarget),
			VirtualModelRouting::Failover => Ok(VirtualTarget::Failover),
		}
	}
}

pub fn model_name_matches(pattern: &str, model: &str) -> bool {
	if pattern == "*" {
		return true;
	}
	if let Some(prefix) = pattern.strip_suffix('*') {
		return model.starts_with(prefix);
	}
	if let Some(suffix) = pattern.strip_prefix('*') {
		return model.ends_with(suffix);
	}
	pattern == model
}

#[derive(Debug, thiserror::Error)]
pub enum PatternError {
	#[error("model name wildcard may only appear once: '{0}'")]
	MultipleWildcards(String),
	#[error("model name wildcard must be either at the beginning or the end: '{0}'")]
	InteriorWildcard(String),
}
pub fn validate_model_pattern(pattern: &str) -> Result<(), PatternError> {
	let count = pattern.chars().filter(|c| *c == '*').count();
	if count > 1 {
		return Err(PatternError::MultipleWildcards(pattern.into()));
	}
	if count == 1 && pattern != "*" && !pattern.starts_with('*') && !pattern.ends_with('*') {
		return Err(PatternError::InteriorWildcard(pattern.into()));
	}
	Ok(())
}
/// Configuration ordering: specificity first, declaration order for ties.
pub fn ordered_model_indices<'a>(names: impl IntoIterator<Item = &'a str>) -> Vec<usize> {
	let mut names: Vec<_> = names.into_iter().enumerate().collect();
	names.sort_by_key(|(index, name)| {
		(
			std::cmp::Reverse(name.chars().filter(|c| *c != '*').count()),
			*index,
		)
	});
	names.into_iter().map(|(index, _)| index).collect()
}

#[cfg(test)]
mod tests;
