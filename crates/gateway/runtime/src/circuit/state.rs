use std::fmt;
use std::time::SystemTime;

#[derive(Debug, Clone, Copy, serde::Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum OpenReason {
	ConsecutiveFailures,
	ErrorRate,
	TimeoutRate,
	HalfOpenFailed,
}

impl fmt::Display for OpenReason {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		write!(f, "{self:?}")
	}
}

#[derive(Debug, Clone, serde::Serialize, PartialEq)]
#[serde(tag = "state", rename_all = "camelCase")]
pub enum CircuitState {
	Closed,
	Open {
		opened_at: SystemTime,
		reason: OpenReason,
		trigger: String,
		cooldown_until: SystemTime,
	},
	HalfOpen {
		entered_at: SystemTime,
		max_probes: usize,
		in_flight_probes: usize,
		completed_probes: usize,
		succeeded_probes: usize,
	},
}

impl Default for CircuitState {
	fn default() -> Self {
		Self::Closed
	}
}

#[derive(Debug, Clone, thiserror::Error)]
#[error(
"circuit breaker is open: key={key}, reason={reason}, trigger={trigger}",
key = .key,
reason = .reason,
trigger = .trigger
)]
pub struct CircuitOpenError {
	pub key: String,
	pub reason: OpenReason,
	pub trigger: String,
}
