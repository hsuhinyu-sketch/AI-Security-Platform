use std::collections::HashMap;
use std::sync::Arc;

use parking_lot::RwLock;

use super::breaker::CircuitBreaker;
use super::config::CircuitConfig;

#[derive(Debug)]
pub struct CircuitBreakerRegistry {
	breakers: RwLock<HashMap<String, Arc<CircuitBreaker>>>,
	default_config: CircuitConfig,
}

impl CircuitBreakerRegistry {
	pub fn new(default_config: CircuitConfig) -> Self {
		Self {
			breakers: RwLock::new(HashMap::new()),
			default_config,
		}
	}

	pub fn get(&self, key: &str) -> Option<Arc<CircuitBreaker>> {
		self.breakers.read().get(key).cloned()
	}

	pub fn get_or_create(&self, key: &str) -> Arc<CircuitBreaker> {
		if let Some(breaker) = self.get(key) {
			return breaker;
		}
		let mut breakers = self.breakers.write();
		if let Some(breaker) = breakers.get(key) {
			return breaker.clone();
		}
		let mut config = self.default_config.clone();
		config.key = key.to_string();
		let breaker = CircuitBreaker::new(key, config);
		breakers.insert(key.to_string(), breaker.clone());
		breaker
	}

	pub fn remove(&self, key: &str) -> Option<Arc<CircuitBreaker>> {
		self.breakers.write().remove(key)
	}

	pub fn snapshot(&self) -> Vec<(String, super::state::CircuitState)> {
		self
			.breakers
			.read()
			.iter()
			.map(|(key, breaker)| (key.clone(), breaker.state()))
			.collect()
	}
}

impl Default for CircuitBreakerRegistry {
	fn default() -> Self {
		Self::new(CircuitConfig::default())
	}
}
