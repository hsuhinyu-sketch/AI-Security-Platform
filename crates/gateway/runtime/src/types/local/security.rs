//! Only typed policy declarations participate in security preparation. Business JSON is opaque here.
use super::*;
use security_integration_runtime::{SecurityConfig, dependency_egress::DependencyEgressConfig};

impl NormalizedLocalConfig {
	pub(super) async fn prepare_security(
		&self,
		parent: Option<&DependencyEgressConfig>,
	) -> anyhow::Result<()> {
		let configs = self.security_configs();
		// Check every declared dependency before readiness can send even a non-sensitive probe.
		if let Some(parent) = parent {
			for config in &configs {
				config
					.check_dependency_endpoints(parent)
					.map_err(anyhow::Error::msg)?;
			}
		}
		for config in configs {
			config.validate_composition().map_err(anyhow::Error::msg)?;
			#[cfg(feature = "security-pii")]
			if let Some(pii) = &config.pii {
				config
					.pii_runtime
					.prepare(pii)
					.await
					.map_err(anyhow::Error::msg)?;
			}
			config.configuration_digest().map_err(anyhow::Error::msg)?;
			config.prepare_execution().map_err(anyhow::Error::msg)?;
		}
		Ok(())
	}

	fn security_configs(&self) -> Vec<Arc<SecurityConfig>> {
		let mut configs = Vec::new();
		let mut seen = HashSet::new();
		let mut add = |policy: &BackendTrafficPolicy| {
			let config = match policy {
				BackendTrafficPolicy::SecurityAudit(config) => config,
				BackendTrafficPolicy::SecurityPipeline(config) => config.configuration(),
				_ => return,
			};
			if seen.insert(Arc::as_ptr(config)) {
				configs.push(config.clone());
			}
		};
		for policy in &self.policies {
			match &policy.policy {
				PolicyType::Backend(policy) => add(policy),
				PolicyType::Frontend(FrontendPolicy::Tracing(tracing)) => {
					for policy in &tracing.config.policies {
						add(policy);
					}
				},
				_ => {},
			}
		}
		for backend in &self.backends {
			for policy in &backend.inline_policies {
				add(policy);
			}
			#[cfg(feature = "gateway-llm")]
			match &backend.backend {
				Backend::AI(_, ai) => {
					for provider in ai.providers.all_endpoints() {
						for policy in &provider.inline_policies {
							add(policy);
						}
					}
				},
				Backend::LLMRouter(_, router) => {
					for policy in router.backend_policies() {
						add(policy);
					}
				},
				_ => {},
			}
		}
		for (_, routes) in self.listener_routes.iter().chain(self.route_groups.iter()) {
			for route in routes {
				for backend in &route.backends {
					for policy in &backend.inline_policies {
						add(policy);
					}
				}
			}
		}
		for (_, routes) in &self.listener_tcp_routes {
			for route in routes {
				for backend in &route.backends {
					for policy in &backend.inline_policies {
						add(policy);
					}
				}
			}
		}
		configs
	}
}

#[cfg(test)]
#[path = "security/tests.rs"]
mod tests;
