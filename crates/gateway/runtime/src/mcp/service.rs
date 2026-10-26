//! Host-owned MCP service and non-owning request entry point.
use std::sync::{Arc, Weak};

use super::{App, Error};
use crate::{
	RuntimeContext,
	http::{Request, Response},
	proxy::{ProxyError, httpproxy::MustSnapshot},
	store::BackendPolicies,
	telemetry::log::RequestLog,
	types::agent::{McpBackend, ResourceName, SimpleBackendReference},
};

#[derive(Debug)]
pub struct Service {
	app: Arc<App>,
}

impl Service {
	pub fn new(
		stores: crate::store::Stores,
		encoder: crate::http::sessionpersistence::Encoder,
	) -> Self {
		Self::from_app(App::new(stores, encoder))
	}

	pub fn from_app(app: App) -> Self {
		Self { app: Arc::new(app) }
	}

	pub fn handle(&self) -> ServiceHandle {
		ServiceHandle(Arc::downgrade(&self.app))
	}
}

impl Drop for Service {
	fn drop(&mut self) {
		self.app.shutdown();
	}
}

/// A request cannot extend the Host lifetime or access the mutable session registry.
#[derive(Debug, Clone)]
pub struct ServiceHandle(Weak<App>);

impl ServiceHandle {
	fn app(&self) -> Result<Arc<App>, ProxyError> {
		self
			.0
			.upgrade()
			.filter(|app| !app.closed.is_cancelled())
			.ok_or_else(|| ProxyError::MCP(Error::UnknownSession))
	}

	pub(crate) fn should_passthrough(
		&self,
		policies: &BackendPolicies,
		backend: &McpBackend,
		request: &Request,
	) -> Result<Option<SimpleBackendReference>, ProxyError> {
		Ok(self.app()?.should_passthrough(policies, backend, request))
	}

	#[allow(clippy::too_many_arguments)]
	pub(crate) async fn serve(
		&self,
		inputs: Arc<RuntimeContext>,
		name: ResourceName,
		backend: McpBackend,
		policies: BackendPolicies,
		request: MustSnapshot<'_>,
		log: &mut RequestLog,
	) -> Result<Response, ProxyError> {
		let app = self.app()?;
		tokio::select! {
			biased;
			_ = app.closed.cancelled() => Err(ProxyError::MCP(Error::UnknownSession)),
			result = Box::pin(app.serve(inputs, name, backend, policies, request, log)) => result,
		}
	}
}

#[cfg(test)]
#[path = "service_tests.rs"]
mod tests;
