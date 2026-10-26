//! Runtime Host composition; shared network contexts never contain these owners.
#[cfg(feature = "gateway-llm")]
use crate::llm::cost::CatalogReader;
#[cfg(feature = "gateway-llm")]
use crate::llm::cost::{CatalogAdmin, CatalogService};

#[derive(Debug)]
pub struct ProtocolServices {
	#[cfg(feature = "gateway-mcp")]
	mcp: crate::mcp::Service,
	#[cfg(feature = "gateway-llm")]
	catalog: CatalogService,
}

impl ProtocolServices {
	pub fn new(
		#[cfg(feature = "gateway-mcp")] mcp: crate::mcp::Service,
		#[cfg(feature = "gateway-llm")] catalog: CatalogService,
	) -> Self {
		Self {
			#[cfg(feature = "gateway-mcp")]
			mcp,
			#[cfg(feature = "gateway-llm")]
			catalog,
		}
	}
	#[cfg(feature = "gateway-llm")]
	pub fn catalog_admin(&self) -> CatalogAdmin {
		self.catalog.admin()
	}
	pub(crate) fn handles(&self) -> ServiceHandles {
		ServiceHandles {
			#[cfg(feature = "gateway-mcp")]
			mcp: self.mcp.handle(),
			#[cfg(feature = "gateway-llm")]
			catalog: self.catalog.reader(),
		}
	}
}

/// Fixed capabilities installed by the Host at accept, preserved by transport wrappers.
/// Cloning these does not clone the protocol service owners or their lifecycle tasks.
#[derive(Clone, Debug)]
pub(crate) struct ServiceHandles {
	#[cfg(feature = "gateway-mcp")]
	pub(crate) mcp: crate::mcp::ServiceHandle,
	#[cfg(feature = "gateway-llm")]
	pub(crate) catalog: CatalogReader,
}

#[cfg(test)]
#[path = "runtime_services_tests.rs"]
#[cfg(feature = "gateway-mcp")]
mod tests;
