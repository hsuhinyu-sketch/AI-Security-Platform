use std::time::Duration;

use super::action::CircuitAction;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct CircuitConfig {
	pub enabled: bool,
	pub key: String,
	pub cooldown: Duration,
	pub half_open: HalfOpenConfig,
	pub triggers: Vec<CircuitTriggerConfig>,
	pub actions: Vec<CircuitAction>,
}

impl Default for CircuitConfig {
	fn default() -> Self {
		Self {
			enabled: true,
			key: String::new(),
			cooldown: Duration::from_secs(30),
			half_open: HalfOpenConfig::default(),
			triggers: Vec::new(),
			actions: Vec::new(),
		}
	}
}

#[derive(Debug, Clone, Copy, serde::Serialize, serde::Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct HalfOpenConfig {
	pub max_probes: usize,
	pub success_rate: f64,
	pub max_concurrent_probes: usize,
}

impl Default for HalfOpenConfig {
	fn default() -> Self {
		Self {
			max_probes: 5,
			success_rate: 0.8,
			max_concurrent_probes: 2,
		}
	}
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct CircuitTriggerConfig {
	pub name: String,
	pub kind: TriggerKind,
	pub window: Duration,
	pub threshold: f64,
}

#[derive(Debug, Clone, Copy, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum TriggerKind {
	ConsecutiveFailures,
	ErrorRate,
	TimeoutRate,
}
