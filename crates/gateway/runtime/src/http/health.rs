//! Configurable backend health / eviction (outlier detection) policy.
//!
//! When a response is considered unhealthy (by CEL or default 5xx), the backend can be
//! evicted for a configurable duration. If no health policy is configured, no eviction
//! is applied. Optional health/failure thresholds and recovery health support multi-request
//! and recovery behavior.

use std::sync::Arc;
use std::time::Duration;

use crate::cel::{ContextBuilder, Expression};
use crate::{serde_dur_option, *};

/// Eviction sub-policy: how long to remove a backend from the active set after an unhealthy response.
#[apply(schema_ser!)]
#[derive(Default)]
pub struct Eviction {
	/// Base ejection time. When absent, falls back to `Retry-After` header (e.g. 429)
	/// or retry policy backoff, then a default (e.g. 3s).
	#[serde(
		default,
		skip_serializing_if = "Option::is_none",
		with = "serde_dur_option"
	)]
	pub duration: Option<Duration>,

	/// Health score to restore when a backend returns from eviction (e.g. 0.2 for gradual recovery).
	/// When absent, health is left unchanged on recovery.
	#[serde(skip_serializing_if = "Option::is_none")]
	pub restore_health: Option<f64>,

	/// Number of consecutive unhealthy responses required before evicting the backend.
	/// When both this and `health_threshold` are set, eviction triggers when either condition is met.
	/// When neither is set, a single unhealthy response can trigger eviction.
	#[serde(skip_serializing_if = "Option::is_none")]
	pub consecutive_failures: Option<i32>,

	/// Evict only when endpoint health (EWMA) is below this threshold (0.0–1.0).
	/// When both this and `consecutive_failures` are set, eviction triggers when either condition is met.
	/// When neither is set, a single unhealthy response triggers eviction.
	#[serde(skip_serializing_if = "Option::is_none")]
	pub health_threshold: Option<f64>,
}

/// Health policy: determines when a backend is unhealthy and how to evict it.
///
/// Maps to the proto `Health` message containing an `unhealthy_condition` CEL expression
/// and an optional `Eviction` sub-message with eviction settings.
#[derive(Default)]
#[apply(schema_ser!)]
pub struct Policy {
	/// CEL expression evaluated per response; `true` means this response is unhealthy (evict).
	/// When absent, any 5xx response, non-zero gRPC status, or a connection failure is treated as unhealthy.
	/// This default lowers the backend's health score but does not trigger eviction on its own.
	#[serde(skip_serializing_if = "Option::is_none")]
	pub unhealthy_expression: Option<Arc<Expression>>,

	/// Eviction settings. When absent, falls back to defaults.
	#[serde(skip_serializing_if = "Option::is_none")]
	pub eviction: Option<Eviction>,
}

const DEFAULT_EVICTION_SECS: u64 = 3;

impl Policy {
	pub fn register_expressions(&self, ctx: &mut ContextBuilder) {
		if let Some(expr) = self.unhealthy_expression.as_ref() {
			ctx.register_expression(expr.as_ref());
		}
	}

	/// Returns the configured base eviction duration, if any.
	pub fn eviction_duration(&self) -> Option<Duration> {
		self.eviction.as_ref().and_then(|e| e.duration)
	}

	/// Computes the eviction decision for a single request.
	///
	/// `current_health` and `consecutive_failure_count` reflect state **before** this request
	/// is recorded. `fallback_duration` is used when no explicit eviction duration is configured
	/// (e.g. from `Retry-After` headers or retry backoff).
	///
	/// Returns `(is_healthy, eviction_duration, restore_health)`.
	pub(crate) fn eviction_decision(
		&self,
		current_health: f64,
		consecutive_failure_count: u64,
		times_ejected: u64,
		unhealthy: bool,
		fallback_duration: Option<Duration>,
	) -> (bool, Option<Duration>, Option<f64>) {
		let health = !unhealthy;
		let ev = self.eviction.as_ref();
		let eviction_duration = if unhealthy {
			let base_duration =
				self
					.eviction_duration()
					.or(fallback_duration)
					.or(if self.eviction.is_some() {
						// If we have eviction, but no duration set, use the default
						Some(Duration::from_secs(DEFAULT_EVICTION_SECS))
					} else {
						// Else there is no eviction
						None
					});
			let health_threshold = ev.and_then(|e| e.health_threshold);
			let consecutive_failures = ev.and_then(|e| e.consecutive_failures);
			// +1 because the current failure hasn't been recorded yet.
			let failures_including_current = consecutive_failure_count + 1;
			let health_below = health_threshold.is_some_and(|t| current_health < t);
			let consecutive_exceeded = consecutive_failures
				.is_some_and(|count| count > 0 && failures_including_current >= count as u64);
			let below_threshold = if health_threshold.is_some() || consecutive_failures.is_some() {
				health_below || consecutive_exceeded
			} else {
				true
			};
			if below_threshold {
				// Multiplicative backoff: base_duration * (times_ejected + 1).
				// No cap -- if all endpoints are evicted the loadbalancer falls back
				// to returning evicted endpoints, which is better than an arbitrary
				// max that unevenly distributes load across equally-degraded backends.
				let multiplier = times_ejected.saturating_add(1);
				base_duration.map(|d| d.saturating_mul(multiplier as u32))
			} else {
				None
			}
		} else {
			None
		};
		(health, eviction_duration, ev.and_then(|e| e.restore_health))
	}
}

/// Local/config eviction sub-policy with duration as string; mirrors `Eviction`.
#[derive(Default)]
#[apply(schema_de!)]
pub struct LocalEviction {
	/// How long to evict an unhealthy backend.
	#[serde(
		default,
		skip_serializing_if = "Option::is_none",
		with = "serde_dur_option"
	)]
	#[cfg_attr(feature = "schema", schemars(with = "Option<String>"))]
	pub duration: Option<Duration>,

	/// Health score to restore when the backend returns from eviction.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub restore_health: Option<f64>,

	/// Consecutive unhealthy responses required before eviction.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub consecutive_failures: Option<i32>,

	/// Health score threshold below which an unhealthy response can evict the backend.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub health_threshold: Option<f64>,
}

/// Local/config health policy with CEL as string; converted to Policy by compiling the expression.
/// Mirrors the proto `Health` message structure.
#[derive(Default)]
#[apply(schema_de!)]
pub struct LocalHealthPolicy {
	/// CEL expression where `true` marks the backend response as unhealthy.
	/// When unset, any 5xx response or connection failure is treated as unhealthy.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub unhealthy_expression: Option<String>,
	/// Settings for temporarily removing unhealthy backends.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub eviction: Option<LocalEviction>,
}

impl TryFrom<LocalHealthPolicy> for Policy {
	type Error = crate::cel::Error;
	fn try_from(local: LocalHealthPolicy) -> Result<Self, Self::Error> {
		let eviction = match local.eviction {
			Some(e) => {
				let validate_score = |field: &str, value: Option<f64>| -> Result<(), crate::cel::Error> {
					if let Some(v) = value
						&& !(0.0..=1.0).contains(&v)
					{
						return Err(crate::cel::Error::Variable(format!(
							"health.eviction.{field} must be between 0.0 and 1.0"
						)));
					}
					Ok(())
				};
				validate_score("healthThreshold", e.health_threshold)?;
				validate_score("restoreHealth", e.restore_health)?;
				Some(Eviction {
					duration: e.duration,
					restore_health: e.restore_health,
					consecutive_failures: e.consecutive_failures,
					health_threshold: e.health_threshold,
				})
			},
			None => None,
		};

		let unhealthy_expression = match local.unhealthy_expression {
			Some(s) if !s.trim().is_empty() => Some(Arc::new(Expression::new_strict(&s)?)),
			_ => None,
		};
		Ok(Policy {
			unhealthy_expression,
			eviction,
		})
	}
}
