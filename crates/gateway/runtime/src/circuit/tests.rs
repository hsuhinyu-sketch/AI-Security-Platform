use std::time::Duration;

use super::breaker::CircuitBreaker;
use super::config::{CircuitConfig, CircuitTriggerConfig, HalfOpenConfig, TriggerKind};
use super::state::{CircuitState, OpenReason};

fn failover_config() -> CircuitConfig {
	CircuitConfig {
		cooldown: Duration::from_secs(30),
		half_open: HalfOpenConfig {
			max_probes: 2,
			success_rate: 0.5,
			max_concurrent_probes: 1,
		},
		triggers: vec![CircuitTriggerConfig {
			name: "consecutiveFailures".into(),
			kind: TriggerKind::ConsecutiveFailures,
			window: Duration::from_secs(60),
			threshold: 2.0,
		}],
		..Default::default()
	}
}

#[test]
fn breaker_starts_closed() {
	let breaker = CircuitBreaker::new("model:test", failover_config());
	assert_eq!(breaker.state(), CircuitState::Closed);
	assert!(breaker.allow().is_ok());
}

#[test]
fn consecutive_failures_open_breaker() {
	let breaker = CircuitBreaker::new("model:test", failover_config());
	assert!(breaker.allow().is_ok());
	breaker.on_success();
	breaker.on_failure();
	breaker.on_failure();
	assert!(matches!(
		breaker.state(),
		CircuitState::Open {
			reason: OpenReason::ConsecutiveFailures,
			..
		}
	));
	assert!(breaker.allow().is_err());
}

#[test]
fn half_open_recovery() {
	let config = CircuitConfig {
		cooldown: Duration::from_millis(1),
		half_open: HalfOpenConfig {
			max_probes: 2,
			success_rate: 0.5,
			max_concurrent_probes: 1,
		},
		triggers: vec![CircuitTriggerConfig {
			name: "consecutiveFailures".into(),
			kind: TriggerKind::ConsecutiveFailures,
			window: Duration::from_secs(60),
			threshold: 1.0,
		}],
		..Default::default()
	};
	let breaker = CircuitBreaker::new("model:test", config);
	breaker.on_failure();
	assert!(matches!(breaker.state(), CircuitState::Open { .. }));
	// Wait out the cooldown.
	std::thread::sleep(Duration::from_millis(10));
	assert!(breaker.allow().is_ok());
	assert!(matches!(breaker.state(), CircuitState::HalfOpen { .. }));
	breaker.on_success();
	breaker.on_success();
	assert_eq!(breaker.state(), CircuitState::Closed);
}

#[test]
fn error_rate_trigger_opens() {
	let config = CircuitConfig {
		triggers: vec![CircuitTriggerConfig {
			name: "errorRate".into(),
			kind: TriggerKind::ErrorRate,
			window: Duration::from_secs(60),
			threshold: 0.5,
		}],
		..Default::default()
	};
	let breaker = CircuitBreaker::new("model:test", config);
	breaker.on_failure();
	breaker.on_failure();
	breaker.on_failure();
	breaker.on_success();
	assert!(matches!(
		breaker.state(),
		CircuitState::Open {
			reason: OpenReason::ErrorRate,
			..
		}
	));
}
