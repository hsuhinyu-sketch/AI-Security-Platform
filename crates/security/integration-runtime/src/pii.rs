//! Optional content configuration, separate from authorization. No protocol dependency.
#[cfg(feature = "pii")]
pub type PiiConfiguration = security_pii::PiiConfig;
#[cfg(not(feature = "pii"))]
pub type PiiConfiguration = serde_json::Value;

pub fn active(config: Option<&PiiConfiguration>) -> bool {
	#[cfg(feature = "pii")]
	return config.is_some_and(|c| c.active());
	#[cfg(not(feature = "pii"))]
	return config.is_some_and(|c| {
		c.get("enabled") != Some(&serde_json::json!(false))
			&& c.get("mode") != Some(&serde_json::json!("disabled"))
	});
}
pub fn validate(config: Option<&PiiConfiguration>) -> Result<(), String> {
	#[cfg(feature = "pii")]
	if let Some(config) = config {
		config.build().map_err(|e| e.to_string())?;
	}
	#[cfg(not(feature = "pii"))]
	if active(config) {
		return Err("PII support is not compiled; enable security-pii".into());
	}
	Ok(())
}

#[cfg(feature = "pii")]
struct ValidatedPii {
	config: PiiConfiguration,
	engine: Option<std::sync::Arc<security_pii::PiiEngine>>,
	ready: tokio::sync::OnceCell<()>,
}

/// Clones share an unchanged engine/readiness, but retain independent declaration slots.
#[cfg(feature = "pii")]
#[derive(Default)]
pub struct PreparedPii(std::sync::Mutex<Option<std::sync::Arc<ValidatedPii>>>);
#[cfg(feature = "pii")]
impl Clone for PreparedPii {
	fn clone(&self) -> Self {
		// A poisoned preparation state must not turn into a ready engine.
		Self(std::sync::Mutex::new(
			self.0.lock().ok().and_then(|entry| entry.clone()),
		))
	}
}
#[cfg(feature = "pii")]
impl std::fmt::Debug for PreparedPii {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.write_str("PreparedPii")
	}
}
#[cfg(feature = "pii")]
impl PreparedPii {
	fn validated(&self, config: &PiiConfiguration) -> Result<std::sync::Arc<ValidatedPii>, String> {
		let mut entry = self
			.0
			.lock()
			.map_err(|_| "PII preparation state is unavailable")?;
		if let Some(existing) = &*entry
			&& existing.config == *config
		{
			return Ok(existing.clone());
		}
		let engine = config.build().map_err(|error| error.to_string())?;
		let validated = std::sync::Arc::new(ValidatedPii {
			config: config.clone(),
			engine,
			ready: tokio::sync::OnceCell::new(),
		});
		*entry = Some(validated.clone());
		Ok(validated)
	}

	pub(super) fn validate(&self, config: Option<&PiiConfiguration>) -> Result<(), String> {
		if let Some(config) = config {
			self.validated(config)?;
		}
		Ok(())
	}

	pub async fn prepare(&self, config: &PiiConfiguration) -> Result<(), String> {
		let validated = self.validated(config)?;
		if let Some(engine) = &validated.engine {
			validated
				.ready
				.get_or_try_init(|| async {
					engine
						.check_ready()
						.await
						.map_err(|error| error.to_string())
				})
				.await?;
		}
		Ok(())
	}

	pub fn get(&self, config: &PiiConfiguration) -> Option<std::sync::Arc<security_pii::PiiEngine>> {
		let entry = self.0.lock().ok()?;
		let entry = entry.as_ref().filter(|entry| entry.config == *config)?;
		if entry.ready.get().is_none() {
			return None;
		}
		entry.engine.clone()
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use serde_json::json;
	#[test]
	fn security_configuration_keeps_pii_in_the_fingerprint_and_rejects_runtime_handles() {
		let config: crate::SecurityConfig =
			serde_json::from_value(json!({"pii":{"enabled":false}})).unwrap();
		let wire = serde_json::to_value(&config).unwrap();
		assert_eq!(wire["pii"]["enabled"], false);
		assert!(wire.get("piiRuntime").is_none());
		assert!(serde_json::from_value::<crate::SecurityConfig>(json!({"piiRuntime":{}})).is_err());
		assert!(config.validate_composition().is_ok());
	}
	#[cfg(not(feature = "pii"))]
	#[test]
	fn omitted_component_rejects_active_configuration() {
		assert!(
			validate(Some(&json!({})))
				.unwrap_err()
				.contains("not compiled")
		);
		assert!(validate(Some(&json!({"mode":"disabled"}))).is_ok());
	}
	#[cfg(feature = "pii")]
	#[tokio::test]
	async fn static_validation_and_concurrent_preparation_reuse_the_same_engine() {
		let config: PiiConfiguration = serde_json::from_value(json!({})).unwrap();
		let handle = std::sync::Arc::new(PreparedPii::default());
		handle.validate(Some(&config)).unwrap();
		let validated = handle.validated(&config).unwrap();
		let engine = validated.engine.as_ref().unwrap().clone();
		assert!(handle.get(&config).is_none());
		let mut tasks = tokio::task::JoinSet::new();
		for _ in 0..8 {
			let handle = handle.clone();
			let config = config.clone();
			tasks.spawn(async move {
				handle.prepare(&config).await.unwrap();
			});
		}
		while let Some(result) = tasks.join_next().await {
			result.unwrap();
		}
		assert!(std::sync::Arc::ptr_eq(
			&validated,
			&handle.validated(&config).unwrap()
		));
		assert!(std::sync::Arc::ptr_eq(
			&engine,
			&handle.get(&config).unwrap()
		));
	}

	#[cfg(feature = "pii")]
	#[tokio::test]
	async fn prepared_detector_is_shared_and_never_reused_for_a_different_policy() {
		let config: PiiConfiguration = serde_json::from_value(json!({})).unwrap();
		let handle = PreparedPii::default();
		handle.prepare(&config).await.unwrap();
		let cloned = handle.clone();
		assert!(std::sync::Arc::ptr_eq(
			&handle.get(&config).unwrap(),
			&cloned.get(&config).unwrap()
		));
		let mut changed = config.clone();
		changed.mode = security_pii::PiiMode::Shadow;
		assert!(handle.get(&changed).is_none());
		cloned.prepare(&changed).await.unwrap();
		assert!(handle.get(&config).is_some());
		assert!(cloned.get(&config).is_none());
		assert!(!std::sync::Arc::ptr_eq(
			&handle.get(&config).unwrap(),
			&cloned.get(&changed).unwrap()
		));
	}
}
