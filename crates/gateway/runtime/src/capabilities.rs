//! Runtime access to the Cargo-selected gateway capability profile.

pub use gateway_composition::{GatewayCapability, GatewayProfile, GatewayProfileProvider};

/// The profile compiled into this `agentgateway` build.
pub fn compiled_profile() -> GatewayProfile {
	gateway_composition::CompiledGatewayProfile::gateway_profile()
}
