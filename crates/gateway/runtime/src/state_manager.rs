use platform_core::prelude::*;
use platform_core::readiness;
use std::path::Path;

use crate::client::Client;
use crate::store::Stores;
use crate::types::agent::ListenerTarget;
use crate::types::discovery::SelfIdentitySource;
use crate::{ConfigSource, client, store};

#[derive(serde::Serialize)]
pub struct StateManager {
	#[serde(flatten)]
	stores: Stores,

	#[serde(skip_serializing)]
	resource_manager: crate::resource_manager::ResourceManager,
}

impl StateManager {
	pub async fn new(config: Arc<crate::Config>, client: client::Client) -> anyhow::Result<Self> {
		let stores = Stores::new_with_dynamic_ca_cert_cache(
			config.ipv6_enabled,
			config.threading_mode,
			config.dynamic_ca_cert_cache.clone(),
		);
		let resource_manager = crate::resource_manager::ResourceManager::new(client.clone())?;
		if let Some(cfg) = &config.local_config {
			let local_client = LocalClient {
				config: config.clone(),
				stores: stores.clone(),
				cfg: cfg.clone(),
				client,
				resource_manager: resource_manager.clone(),
				gateway: config.gateway(),
			};
			Box::pin(local_client.run()).await?;
		}
		Ok(Self {
			stores,
			resource_manager,
		})
	}

	pub fn stores(&self) -> Stores {
		self.stores.clone()
	}

	pub fn resource_manager(&self) -> crate::resource_manager::ResourceManager {
		self.resource_manager.clone()
	}
}

/// LocalClient loads and watches the standalone configuration file.
#[derive(Debug, Clone)]
pub struct LocalClient {
	config: Arc<crate::Config>,
	pub cfg: ConfigSource,
	pub stores: Stores,
	pub client: Client,
	pub resource_manager: crate::resource_manager::ResourceManager,
	pub gateway: ListenerTarget,
}

impl LocalClient {
	pub async fn run(self) -> Result<(), anyhow::Error> {
		let next_state = self.reload_config(PreviousState::default()).await?;
		if let ConfigSource::File(path) = &self.cfg {
			self.watch_config_file(path, next_state).await?;
		} else {
			self.watch_resource_changes(next_state);
		}

		Ok(())
	}

	async fn watch_config_file(
		&self,
		path: &Path,
		mut next_state: PreviousState,
	) -> anyhow::Result<()> {
		let watch_options = crate::util::WatchFilesOptions::default().close_on_removal(true);
		let mut watched =
			crate::util::watch_files_with_options(vec![path.to_path_buf()], watch_options)?;
		info!("Watching config file: {}", path.display());

		let lc: LocalClient = self.to_owned();
		let path = path.to_path_buf();
		let mut resource_changes = lc.resource_manager.subscribe_changes();
		tokio::task::spawn(async move {
			loop {
				tokio::select! {
					changed = watched.changed_invalidated() => {
						let Some(invalidated) = changed else {
							break;
						};
						next_state = lc.reload_config_after_change(next_state).await;
						if invalidated {
							match crate::util::watch_files_with_options(vec![path.clone()], watch_options) {
								Ok(new_watched) => watched = new_watched,
								Err(e) => {
									warn!("failed to re-watch config file {}: {e}", path.display());
									break;
								},
							}
						}
					}
					changed = resource_changes.changed() => {
						if changed.is_err() {
							break;
						}
						let resource = resource_changes.borrow().resource.clone();
						info!(resource, "resource changed, reloading");
						next_state = lc.reload_config_after_change(next_state).await;
					}
				}
			}
		});

		Ok(())
	}

	fn watch_resource_changes(&self, mut next_state: PreviousState) {
		let lc = self.clone();
		let mut resource_changes = self.resource_manager.subscribe_changes();
		tokio::task::spawn(async move {
			while resource_changes.changed().await.is_ok() {
				let resource = resource_changes.borrow().resource.clone();
				info!(resource, "resource changed, reloading");
				next_state = lc.reload_config_after_change(next_state).await;
			}
		});
	}

	async fn reload_config(&self, prev: PreviousState) -> anyhow::Result<PreviousState> {
		let config_content = self.cfg.read_to_string().await?;
		let resources =
			crate::resource_manager::ResourceFetcher::managed(self.resource_manager.clone());
		let config = crate::types::local::NormalizedLocalConfig::from(
			&self.config,
			&resources,
			self.gateway.clone(),
			config_content.as_str(),
		)
		.await?;
		info!("loaded config from {:?}", self.cfg);

		// Sync the state
		let next_binds = self.stores.binds.sync_local(
			config.binds,
			config.listener_routes,
			config.listener_tcp_routes,
			config.policies,
			config.backends,
			config.route_groups,
			prev.binds,
		);
		let next_discovery =
			self
				.stores
				.discovery
				.sync_local(config.services, config.workloads, prev.discovery)?;

		Ok(PreviousState {
			binds: next_binds,
			discovery: next_discovery,
		})
	}

	async fn reload_config_after_change(&self, prev: PreviousState) -> PreviousState {
		debug!("Config dependency changed, reloading...");
		match self.reload_config(prev.clone()).await {
			Ok(nxt) => {
				debug!("Config reloaded successfully");
				nxt
			},
			Err(e) => {
				error!("Failed to reload config: {}", e);
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

#[cfg(test)]
mod tests {
	use std::sync::Arc;

	use super::*;
	use crate::ConfigSource;
	use crate::store::Stores;

	fn test_config() -> crate::Config {
		crate::config::parse_config("{}".to_string(), None).expect("parse default config")
	}

	fn test_stores() -> Stores {
		Stores::new(false, crate::ThreadingMode::Multithreaded)
	}

	fn test_client() -> Client {
		Client::new(
			&client::Config {
				resolver_cfg: hickory_resolver::config::ResolverConfig::default(),
				resolver_opts: hickory_resolver::config::ResolverOpts::default(),
			},
			None,
			crate::BackendConfig::default(),
			None,
		)
	}

	fn local_config(remove_field: &str) -> String {
		format!(
			r#"
frontendPolicies:
  accessLog:
    remove:
    - {remove_field}
"#
		)
	}

	async fn replace_config(path: &Path, remove_field: &str) {
		let replacement = path.with_extension(format!("{remove_field}.tmp"));
		fs_err::tokio::write(&replacement, local_config(remove_field))
			.await
			.unwrap();
		fs_err::rename(&replacement, path).unwrap();
	}

	async fn wait_for_access_log_remove(config: &crate::Config, stores: &Stores, remove_field: &str) {
		tokio::time::timeout(Duration::from_secs(5), async {
			loop {
				let frontend = stores.binds.read().frontend_policies(config.gateway_ref());
				if frontend
					.access_log
					.as_ref()
					.is_some_and(|access_log| access_log.remove.contains(remove_field))
				{
					return;
				}
				tokio::time::sleep(Duration::from_millis(10)).await;
			}
		})
		.await
		.unwrap_or_else(|_| panic!("timed out waiting for access log remove {remove_field}"));
	}

	#[tokio::test]
	async fn file_config_reloads_after_repeated_rename_replacement() {
		let dir = tempfile::tempdir().unwrap();
		let path = dir.path().join("config.yaml");
		fs_err::tokio::write(&path, local_config("first"))
			.await
			.unwrap();

		let mut config = test_config();
		config.local_config = Some(ConfigSource::File(path.clone()));
		let config = Arc::new(config);
		let stores = test_stores();
		let client = test_client();
		let resource_manager = crate::resource_manager::ResourceManager::new(client.clone()).unwrap();
		let local_client = LocalClient {
			config: config.clone(),
			cfg: ConfigSource::File(path.clone()),
			stores: stores.clone(),
			client,
			resource_manager,
			gateway: config.gateway(),
		};

		local_client.run().await.unwrap();
		wait_for_access_log_remove(&config, &stores, "first").await;

		fs_err::tokio::write(&path, local_config("ready"))
			.await
			.unwrap();
		wait_for_access_log_remove(&config, &stores, "ready").await;

		replace_config(&path, "second").await;
		wait_for_access_log_remove(&config, &stores, "second").await;

		fs_err::tokio::write(&path, local_config("ready-again"))
			.await
			.unwrap();
		wait_for_access_log_remove(&config, &stores, "ready-again").await;

		replace_config(&path, "third").await;
		wait_for_access_log_remove(&config, &stores, "third").await;
	}
}
