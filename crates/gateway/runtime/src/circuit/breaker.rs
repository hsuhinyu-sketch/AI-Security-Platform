use std::sync::Arc;
use std::time::SystemTime;

use parking_lot::RwLock;

use super::action::CircuitAction;
use super::config::{CircuitConfig, CircuitTriggerConfig, TriggerKind};
use super::state::{CircuitOpenError, CircuitState, OpenReason};
use super::window::{SlidingWindow, WindowEvent};

#[derive(Debug)]
pub struct CircuitBreaker {
	pub key: String,
	config: CircuitConfig,
	state: RwLock<CircuitState>,
	triggers: Vec<ActiveTrigger>,
}

#[derive(Debug)]
struct ActiveTrigger {
	config: CircuitTriggerConfig,
	window: RwLock<SlidingWindow>,
	consecutive_failures: RwLock<u64>,
}

impl CircuitBreaker {
	pub fn new(key: impl Into<String>, config: CircuitConfig) -> Arc<Self> {
		let triggers = config
			.triggers
			.iter()
			.map(|cfg| ActiveTrigger {
				config: cfg.clone(),
				window: RwLock::new(SlidingWindow::new(cfg.window)),
				consecutive_failures: RwLock::new(0),
			})
			.collect();
		Arc::new(Self {
			key: key.into(),
			config,
			state: RwLock::new(CircuitState::Closed),
			triggers,
		})
	}

	pub fn state(&self) -> CircuitState {
		self.state.read().clone()
	}

	pub fn config(&self) -> &CircuitConfig {
		&self.config
	}

	pub fn actions(&self) -> &[CircuitAction] {
		&self.config.actions
	}

	pub fn allow(&self) -> Result<(), CircuitOpenError> {
		let mut state = self.state.write();
		match &*state {
			CircuitState::Closed => Ok(()),
			CircuitState::Open {
				reason,
				trigger,
				cooldown_until,
				..
			} => {
				if SystemTime::now() < *cooldown_until {
					return Err(CircuitOpenError {
						key: self.key.clone(),
						reason: *reason,
						trigger: trigger.clone(),
					});
				}
				*state = CircuitState::HalfOpen {
					entered_at: SystemTime::now(),
					max_probes: self.config.half_open.max_probes,
					in_flight_probes: 0,
					completed_probes: 0,
					succeeded_probes: 0,
				};
				drop(state);
				self.allow()
			},
			CircuitState::HalfOpen { .. } => {
				let CircuitState::HalfOpen {
					in_flight_probes, ..
				} = state.clone()
				else {
					unreachable!()
				};
				let max_concurrent_probes = self.config.half_open.max_concurrent_probes;
				if in_flight_probes >= max_concurrent_probes {
					let (reason, trigger) = self
						.last_open_reason()
						.unwrap_or((OpenReason::HalfOpenFailed, "halfOpen".to_string()));
					return Err(CircuitOpenError {
						key: self.key.clone(),
						reason,
						trigger,
					});
				}
				if let CircuitState::HalfOpen {
					in_flight_probes, ..
				} = &mut *state
				{
					*in_flight_probes += 1;
				}
				Ok(())
			},
		}
	}

	pub fn on_success(&self) {
		let mut state = self.state.write();
		if let CircuitState::HalfOpen {
			completed_probes,
			succeeded_probes,
			in_flight_probes,
			..
		} = &mut *state
		{
			*in_flight_probes = in_flight_probes.saturating_sub(1);
			*completed_probes += 1;
			*succeeded_probes += 1;
			if *completed_probes >= self.config.half_open.max_probes {
				let rate = *succeeded_probes as f64 / *completed_probes as f64;
				if rate >= self.config.half_open.success_rate {
					*state = CircuitState::Closed;
				} else {
					*state = self.open_state(OpenReason::HalfOpenFailed, "halfOpen");
				}
				return;
			}
		}
		drop(state);
		for trigger in &self.triggers {
			if trigger.config.kind == TriggerKind::ConsecutiveFailures {
				*trigger.consecutive_failures.write() = 0;
			}
			trigger.window.write().record(WindowEvent::Success);
		}
	}

	pub fn on_failure(&self) {
		let mut state = self.state.write();
		if let CircuitState::HalfOpen {
			completed_probes,
			succeeded_probes,
			in_flight_probes,
			..
		} = &mut *state
		{
			*in_flight_probes = in_flight_probes.saturating_sub(1);
			*completed_probes += 1;
			if *completed_probes >= self.config.half_open.max_probes {
				let rate = *succeeded_probes as f64 / *completed_probes as f64;
				if rate >= self.config.half_open.success_rate {
					*state = CircuitState::Closed;
				} else {
					*state = self.open_state(OpenReason::HalfOpenFailed, "halfOpen");
				}
				return;
			}
			drop(state);
			return;
		}
		drop(state);
		for trigger in &self.triggers {
			if trigger.config.kind == TriggerKind::ConsecutiveFailures {
				let mut failures = trigger.consecutive_failures.write();
				*failures += 1;
				if *failures as f64 >= trigger.config.threshold {
					drop(failures);
					self.open(OpenReason::ConsecutiveFailures, &trigger.config.name);
					return;
				}
			} else {
				trigger.window.write().record(WindowEvent::Failure);
			}
		}
		self.evaluate_passive_triggers();
	}

	pub fn on_timeout(&self) {
		for trigger in &self.triggers {
			trigger.window.write().record(WindowEvent::Timeout);
		}
		self.evaluate_passive_triggers();
	}

	fn evaluate_passive_triggers(&self) {
		for trigger in &self.triggers {
			let totals = trigger.window.write().totals();
			let open_reason = match trigger.config.kind {
				TriggerKind::ErrorRate if totals.requests > 0 => {
					let rate = totals.failures as f64 / totals.requests as f64;
					(rate >= trigger.config.threshold).then_some(OpenReason::ErrorRate)
				},
				TriggerKind::TimeoutRate if totals.requests > 0 => {
					let rate = totals.timeouts as f64 / totals.requests as f64;
					(rate >= trigger.config.threshold).then_some(OpenReason::TimeoutRate)
				},
				_ => None,
			};
			if let Some(reason) = open_reason {
				self.open(reason, &trigger.config.name);
				return;
			}
		}
	}

	fn open(&self, reason: OpenReason, trigger: &str) {
		let mut state = self.state.write();
		*state = self.open_state(reason, trigger);
	}

	fn open_state(&self, reason: OpenReason, trigger: &str) -> CircuitState {
		CircuitState::Open {
			opened_at: SystemTime::now(),
			reason,
			trigger: trigger.to_string(),
			cooldown_until: SystemTime::now() + self.config.cooldown,
		}
	}

	fn last_open_reason(&self) -> Option<(OpenReason, String)> {
		match self.state.read().clone() {
			CircuitState::Open {
				reason, trigger, ..
			} => Some((reason, trigger)),
			_ => None,
		}
	}
}
