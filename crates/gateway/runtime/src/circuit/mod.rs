pub mod action;
pub mod config;
pub mod registry;
pub mod state;
pub mod window;

mod breaker;

pub use action::CircuitAction;
pub use breaker::CircuitBreaker;
pub use config::{CircuitConfig, CircuitTriggerConfig, HalfOpenConfig, TriggerKind};
pub use registry::CircuitBreakerRegistry;
pub use state::{CircuitOpenError, CircuitState, OpenReason};
pub use window::{MetricSample, SlidingWindow};

#[cfg(test)]
mod tests;
