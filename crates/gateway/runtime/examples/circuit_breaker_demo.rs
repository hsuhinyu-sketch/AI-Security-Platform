use std::time::Duration;

use ai_security_platform_runtime::circuit::{
	CircuitAction, CircuitBreaker, CircuitConfig, CircuitState, CircuitTriggerConfig, HalfOpenConfig,
	TriggerKind,
};

fn print_state(name: &str, breaker: &CircuitBreaker) {
	println!("[{name}] state = {:?}", breaker.state());
}

fn main() {
	println!("=== AgentGateway Circuit Breaker Demo ===\n");

	// Cloud unavailable: consecutive failures open the breaker, then recover via half-open probes.
	println!("--- 1. cloud unavailable: consecutive failures -> open -> half-open -> closed ---");
	let config = CircuitConfig {
		key: "model:cloud-llm".into(),
		cooldown: Duration::from_millis(100),
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
		actions: vec![CircuitAction::Fallback {
			target: "edge-llm".into(),
		}],
		..Default::default()
	};
	let breaker = CircuitBreaker::new("model:cloud-llm", config);
	print_state("initial", &breaker);
	assert!(breaker.allow().is_ok());
	breaker.on_failure();
	print_state("after 1 failure", &breaker);
	breaker.on_failure();
	print_state("after 2 failures", &breaker);
	assert!(breaker.allow().is_err());
	println!(
		"allow() when open -> Err, action would be: {:?}\n",
		breaker.actions()
	);

	std::thread::sleep(Duration::from_millis(200));
	assert!(breaker.allow().is_ok());
	print_state("after cooldown + first probe", &breaker);
	breaker.on_success();
	print_state("probe 1 success", &breaker);
	breaker.on_success();
	print_state("probe 2 success", &breaker);
	assert_eq!(breaker.state(), CircuitState::Closed);
	println!("\nDemo completed successfully.");
}
