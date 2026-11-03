use crate::telemetry::metrics::Metrics;
use platform_core::prelude::*;
use platform_core::readiness;
use std::path::Path;
use std::time::Duration;
use tokio::task::JoinHandle;

#[cfg(test)]
#[path = "state_manager_tests.rs"]
mod tests;

use crate::client::Client;
use crate::store::Stores;
use crate::types::agent::ListenerTarget;
use crate::types::discovery::SelfIdentitySource;
use crate::{ConfigSource, client, store};

#[derive(serde::Serialize)]
pub struct StateManager {
	#[serde(skip_serializing)]
	watcher: Option<JoinHandle<()>>,
	#[serde(flatten)]
	stores: Stores,

	#[serde(skip_serializing)]
	resource_manager: crate::resource_manager::ResourceManager,
	#[cfg(feature = "gateway-rag")]
	#[serde(skip_serializing)]
	rag: Arc<crate::rag::Runtime>,
}

impl StateManager {
	pub async fn new(
		config: Arc<crate::Config>,
		client: client::Client,
		metrics: Arc<Metrics>,
	) -> anyhow::Result<Self> {
		let stores = Stores::new_with_dynamic_ca_cert_cache(
			config.ipv6_enabled,
			config.threading_mode,
			config.dynamic_ca_cert_cache.clone(),
		);
		let resource_manager = crate::resource_manager::ResourceManager::new(client.clone())?;
		#[cfg(feature = "gateway-rag")]
		let rag = Arc::new(crate::rag::Runtime::default());
		let watcher = if let Some(cfg) = &config.local_config {
			let local_client = LocalClient {
				metrics: metrics.clone(),
				config: config.clone(),
				stores: stores.clone(),
				cfg: cfg.clone(),
				client,
				resource_manager: resource_manager.clone(),
				gateway: config.gateway(),
				#[cfg(feature = "gateway-rag")]
				rag: rag.clone(),
			};
			Some(Box::pin(local_client.run()).await?)
		} else {
			None
		};
		Ok(Self {
			watcher,
			stores,
			resource_manager,
			#[cfg(feature = "gateway-rag")]
			rag,
		})
	}

	pub(crate) async fn stop(&mut self) {
		if let Some(watcher) = self.watcher.take() {
			watcher.abort();
			if let Err(error) = watcher.await
				&& !error.is_cancelled()
			{
				warn!(code="CONFIG_WATCH_TASK_FAILED", %error, "configuration reload task failed");
			}
		}
	}

	#[cfg(feature = "gateway-rag")]
	pub(crate) fn rag(&self) -> Arc<crate::rag::Runtime> {
		self.rag.clone()
	}

	pub fn stores(&self) -> Stores {
		self.stores.clone()
	}

	pub fn resource_manager(&self) -> crate::resource_manager::ResourceManager {
		self.resource_manager.clone()
	}
}

impl Drop for StateManager {
	fn drop(&mut self) {
		if let Some(watcher) = self.watcher.take() {
			watcher.abort();
		}
	}
}

// Keep the gauge tied to the task lifetime, including abort before its first poll.
struct ConfigWatchActive(prometheus_client::metrics::gauge::Gauge);
impl Drop for ConfigWatchActive {
	fn drop(&mut self) {
		self.0.set(0);
	}
}

/// LocalClient loads and watches the standalone configuration file.
#[derive(Debug, Clone)]
pub struct LocalClient {
	metrics: Arc<Metrics>,
	config: Arc<crate::Config>,
	pub cfg: ConfigSource,
	pub stores: Stores,
	pub client: Client,
	pub resource_manager: crate::resource_manager::ResourceManager,
	pub gateway: ListenerTarget,
	#[cfg(feature = "gateway-rag")]
	rag: Arc<crate::rag::Runtime>,
}

impl LocalClient {
	pub async fn run(self) -> anyhow::Result<JoinHandle<()>> {
		// Subscribe before reading so a change during the initial load stays queued.
		let watched = if let ConfigSource::File(path) = &self.cfg {
			Some(
				crate::util::watch_files_with_options(
					vec![path.clone()],
					crate::util::WatchFilesOptions::default().close_on_removal(true),
				)
				.map_err(|error| {
					self.metrics.config_watch_failures.inc();
					error!(code="CONFIG_WATCH_START_FAILED", %error, "failed to start config watcher");
					error
				})?,
			)
		} else {
			None
		};
		let next_state = self.reload_config(PreviousState::default()).await?;
		if let (ConfigSource::File(path), Some(watched)) = (&self.cfg, watched) {
			Ok(self.watch_config_file(path, watched, next_state))
		} else {
			Ok(self.watch_resource_changes(next_state))
		}
	}

	fn watch_config_file(
		&self,
		path: &Path,
		watched: crate::util::WatchedFiles,
		mut next_state: PreviousState,
	) -> JoinHandle<()> {
		info!("Watching config file: {}", path.display());
		self.metrics.config_watch_active.set(1);
		let active = ConfigWatchActive(self.metrics.config_watch_active.clone());
		let lc = self.clone();
		let path = path.to_path_buf();
		let mut resource_changes = lc.resource_manager.subscribe_changes();
		tokio::task::spawn(async move {
			let _active = active;
			let watch_options = crate::util::WatchFilesOptions::default().close_on_removal(true);
			let mut watched = Some(watched);
			let mut retry = tokio::time::interval(Duration::from_secs(1));
			retry.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
			let mut resources_open = true;
			loop {
				tokio::select! {
					changed = async { watched.as_mut().unwrap().changed_invalidated().await }, if watched.is_some() => {
						if changed.is_none() || changed == Some(true) {
							watched = None;
							lc.metrics.config_watch_active.set(0);
							if changed.is_none() {
								lc.metrics.config_watch_failures.inc();
								warn!(code="CONFIG_WATCH_LOST", "config watch channel closed; re-registering");
							}
						}
						if changed == Some(false) {
							next_state = Box::pin(lc.reload_config_after_change(next_state)).await;
						}
					}
					_ = retry.tick(), if watched.is_none() => {
						match crate::util::watch_files_with_options(vec![path.clone()], watch_options) {
							Ok(new_watched) => {
								watched = Some(new_watched);
								lc.metrics.config_watch_active.set(1);
								info!(code="CONFIG_WATCH_RESTORED", "config watcher registered");
								// Capture updates that happened while there was no active watch.
								next_state = Box::pin(lc.reload_config_after_change(next_state)).await;
							}
							Err(error) => {
								lc.metrics.config_watch_failures.inc();
								warn!(code="CONFIG_WATCH_RETRY_FAILED", %error, "failed to re-watch config file; retrying");
							}
						}
					}
					changed = resource_changes.changed(), if resources_open => {
						if changed.is_err() {
							resources_open = false;
							warn!(code="CONFIG_RESOURCE_WATCH_CLOSED", "resource change channel closed; file watcher remains active");
						} else {
							let resource = resource_changes.borrow().resource.clone();
							info!(resource, "resource changed, reloading");
							next_state = Box::pin(lc.reload_config_after_change(next_state)).await;
						}
					}
				}
			}
		})
	}

	fn watch_resource_changes(&self, mut next_state: PreviousState) -> JoinHandle<()> {
		let lc = self.clone();
		let mut resource_changes = self.resource_manager.subscribe_changes();
		tokio::task::spawn(async move {
			while resource_changes.changed().await.is_ok() {
				let resource = resource_changes.borrow().resource.clone();
				info!(resource, "resource changed, reloading");
				next_state = Box::pin(lc.reload_config_after_change(next_state)).await;
			}
			warn!(
				code = "CONFIG_RESOURCE_WATCH_CLOSED",
				"resource change channel closed"
			);
		})
	}

	async fn reload_config(&self, prev: PreviousState) -> anyhow::Result<PreviousState> {
		let result = async {
			let config_content = self.cfg.read_to_string().await?;
			let resources =
				crate::resource_manager::ResourceFetcher::managed(self.resource_manager.clone());
			let resource_scope = resources.scope_full_computation();
			let config = crate::types::local::NormalizedLocalConfig::compute(
				&self.config,
				&resources,
				self.gateway.clone(),
				config_content.as_str(),
			)
			.await?;
			info!("loaded config from {:?}", self.cfg);

			#[cfg(feature = "gateway-rag")]
			let rag = self
				.rag
				.prepare(&self.config, &resources, config.rag_systems)
				.await?;

			// Discovery validates the whole candidate before mutation. Finish this last fallible
			// step before publishing listener changes, so a rejected candidate keeps the old binds.
			let next_discovery =
				self
					.stores
					.discovery
					.sync_local(config.services, config.workloads, prev.discovery)?;
			let next_binds = self.stores.binds.sync_local(
				config.binds,
				config.listener_routes,
				config.listener_tcp_routes,
				config.policies,
				config.backends,
				config.route_groups,
				prev.binds,
			);
			#[cfg(feature = "gateway-rag")]
			self.rag.commit(rag);
			resource_scope.finish(true);

			Ok(PreviousState {
				binds: next_binds,
				discovery: next_discovery,
			})
		}
		.await;
		let successful = result.is_ok();
		self
			.metrics
			.config_reloads
			.get_or_create(&[("result", if successful { "success" } else { "failure" })])
			.inc();
		self
			.metrics
			.config_reload_last_successful
			.set(i64::from(successful));
		result
	}

	async fn reload_config_after_change(&self, prev: PreviousState) -> PreviousState {
		debug!("Config dependency changed, reloading...");
		match self.reload_config(prev.clone()).await {
			Ok(nxt) => {
				debug!("Config reloaded successfully");
				nxt
			},
			Err(e) => {
				error!(
					code = "CONFIG_RELOAD_FAILED",
					"Failed to reload config: {}", e
				);
				prev
			},
		}
	}
}

#[derive(Clone, Debug, Default)]
pub struct PreviousState {
	pub binds: store::BindPreviousState,
	pub discovery: store::DiscoveryPreviousState,
}

/// Populates the discovery store's self_workload according to `config.self_identity`.
pub fn start_self_workload_resolution(
	config: &crate::Config,
	stores: Stores,
	_ready: &readiness::Ready,
) {
	match &config.self_identity {
		Some(SelfIdentitySource::Static(w)) => {
			let store = stores.discovery.read();
			store.self_workload.set((**w).clone());
			store.rebucket_all();
		},
		None => {},
	}
}
