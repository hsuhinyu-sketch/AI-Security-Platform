use super::*;
use std::path::PathBuf;
use std::time::Duration;

struct Directory(PathBuf);
impl Directory {
	fn new() -> Self {
		let path = std::env::temp_dir().join(format!("aisp-watcher-{}", uuid::Uuid::new_v4()));
		std::fs::create_dir(&path).unwrap();
		Self(path)
	}
}
impl Drop for Directory {
	fn drop(&mut self) {
		let _ = std::fs::remove_dir_all(&self.0);
	}
}

fn inputs(source: ConfigSource) -> (Arc<crate::Config>, Client, Arc<Metrics>) {
	let mut config = crate::config::parse_config("{}".into(), None).unwrap();
	config.local_config = Some(source);
	let mut registry = prometheus_client::registry::Registry::default();
	let metrics = Arc::new(Metrics::new(&mut registry, Default::default()));
	let client = Client::new(
		&config.dns,
		None,
		config.backend.clone(),
		Some(metrics.clone()),
	);
	(Arc::new(config), client, metrics)
}

fn count(metrics: &Metrics, result: &'static str) -> u64 {
	metrics
		.config_reloads
		.get_or_create(&[("result", result)])
		.get()
}

async fn wait_for(mut predicate: impl FnMut() -> bool) {
	tokio::time::timeout(Duration::from_secs(8), async {
		while !predicate() {
			tokio::time::sleep(Duration::from_millis(10)).await;
		}
	})
	.await
	.unwrap();
}

#[tokio::test]
async fn failed_rewatch_recovers_and_reads_changes_from_the_gap() {
	let directory = Directory::new();
	let live = directory.0.join("live");
	let parked = directory.0.join("parked");
	std::fs::create_dir(&live).unwrap();
	let file = live.join("gateway.yaml");
	std::fs::write(&file, "{}").unwrap();
	let (config, client, metrics) = inputs(ConfigSource::File(file.clone()));
	let manager = StateManager::new(config, client, metrics.clone())
		.await
		.unwrap();
	assert_eq!(count(&metrics, "success"), 1);
	std::fs::rename(&live, &parked).unwrap();
	std::fs::remove_file(parked.join("gateway.yaml")).unwrap();
	wait_for(|| metrics.config_watch_failures.get() > 0).await;
	assert_eq!(metrics.config_watch_active.get(), 0);
	// Restore an invalid candidate before re-registration. Recovery must read it
	// even though no OS watch existed when it was written.
	let before = count(&metrics, "failure");
	std::fs::create_dir(&live).unwrap();
	std::fs::write(&file, "aiSystems: [").unwrap();
	wait_for(|| metrics.config_watch_active.get() == 1 && count(&metrics, "failure") > before).await;
	assert_eq!(metrics.config_reload_last_successful.get(), 0);
	let before = count(&metrics, "success");
	std::fs::write(&file, "{}").unwrap();
	wait_for(|| count(&metrics, "success") > before).await;
	assert_eq!(metrics.config_reload_last_successful.get(), 1);
	drop(manager);
}

#[tokio::test]
async fn dropping_host_stops_retry_and_releases_the_watcher_task() {
	let directory = Directory::new();
	let live = directory.0.join("live");
	std::fs::create_dir(&live).unwrap();
	let file = live.join("gateway.yaml");
	std::fs::write(&file, "{}").unwrap();
	let (config, client, metrics) = inputs(ConfigSource::File(file.clone()));
	let manager = StateManager::new(config, client, metrics.clone())
		.await
		.unwrap();
	let watcher = manager.watcher.as_ref().unwrap().abort_handle();
	std::fs::remove_file(&file).unwrap();
	std::fs::remove_dir(&live).unwrap();
	wait_for(|| metrics.config_watch_failures.get() > 0).await;
	drop(manager);
	wait_for(|| watcher.is_finished()).await;
	assert_eq!(metrics.config_watch_active.get(), 0);
	let before = (
		count(&metrics, "success"),
		count(&metrics, "failure"),
		metrics.config_watch_failures.get(),
	);
	std::fs::create_dir(&live).unwrap();
	std::fs::write(file, "{}").unwrap();
	tokio::time::sleep(Duration::from_millis(1200)).await;
	assert_eq!(
		before,
		(
			count(&metrics, "success"),
			count(&metrics, "failure"),
			metrics.config_watch_failures.get()
		)
	);
}

#[tokio::test]
async fn atomic_replace_can_be_followed_by_another_in_place_change() {
	let directory = Directory::new();
	let file = directory.0.join("gateway.yaml");
	std::fs::write(&file, "{}").unwrap();
	let (config, client, metrics) = inputs(ConfigSource::File(file.clone()));
	let manager = StateManager::new(config, client, metrics.clone())
		.await
		.unwrap();
	let candidate = directory.0.join("next.yaml");
	std::fs::write(&candidate, "aiSystems: [").unwrap();
	std::fs::rename(candidate, &file).unwrap();
	wait_for(|| count(&metrics, "failure") > 0 && metrics.config_watch_active.get() == 1).await;
	let before = count(&metrics, "success");
	std::fs::write(&file, "{}").unwrap();
	wait_for(|| count(&metrics, "success") > before).await;
	drop(manager);
}

#[tokio::test]
async fn static_configuration_counts_startup_without_a_file_watch() {
	let (config, client, metrics) = inputs(ConfigSource::Static("{}".into()));
	let manager = StateManager::new(config, client, metrics.clone())
		.await
		.unwrap();
	assert_eq!(count(&metrics, "success"), 1);
	assert_eq!(metrics.config_reload_last_successful.get(), 1);
	assert_eq!(metrics.config_watch_active.get(), 0);
	let watcher = manager.watcher.as_ref().unwrap().abort_handle();
	drop(manager);
	wait_for(|| watcher.is_finished()).await;
}

#[tokio::test]
async fn invalid_initial_configuration_fails_without_publishing_a_watcher() {
	let directory = Directory::new();
	let file = directory.0.join("gateway.yaml");
	std::fs::write(&file, "aiSystems: [").unwrap();
	let (config, client, metrics) = inputs(ConfigSource::File(file));
	assert!(
		StateManager::new(config, client, metrics.clone())
			.await
			.is_err()
	);
	assert_eq!(count(&metrics, "success"), 0);
	assert_eq!(count(&metrics, "failure"), 1);
	assert_eq!(metrics.config_watch_active.get(), 0);
}

#[tokio::test]
async fn initial_watch_registration_failure_is_counted_and_returned() {
	let directory = Directory::new();
	let file = directory.0.join("absent").join("gateway.yaml");
	let (config, client, metrics) = inputs(ConfigSource::File(file));
	assert!(
		StateManager::new(config, client, metrics.clone())
			.await
			.is_err()
	);
	assert_eq!(metrics.config_watch_failures.get(), 1);
	assert_eq!(count(&metrics, "success"), 0);
	assert_eq!(metrics.config_watch_active.get(), 0);
}

#[tokio::test]
async fn stopping_host_waits_for_reload_task_before_returning() {
	let directory = Directory::new();
	let file = directory.0.join("gateway.yaml");
	std::fs::write(&file, "{}").unwrap();
	let (config, client, metrics) = inputs(ConfigSource::File(file.clone()));
	let mut manager = StateManager::new(config, client, metrics.clone())
		.await
		.unwrap();
	let watcher = manager.watcher.as_ref().unwrap().abort_handle();
	manager.stop().await;
	assert!(watcher.is_finished());
	assert_eq!(metrics.config_watch_active.get(), 0);
	let before = count(&metrics, "failure");
	std::fs::write(file, "aiSystems: [").unwrap();
	tokio::time::sleep(Duration::from_millis(400)).await;
	assert_eq!(count(&metrics, "failure"), before);
}
