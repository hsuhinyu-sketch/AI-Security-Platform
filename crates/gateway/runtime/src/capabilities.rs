//! Runtime access to the Cargo-selected gateway capability profile.

pub use gateway_composition::{GatewayCapability, GatewayProfile, GatewayProfileProvider};

/// The profile compiled into this `agentgateway` build.
pub fn compiled_profile() -> GatewayProfile {
	gateway_composition::CompiledGatewayProfile::gateway_profile()
}

/// Security configuration can also arrive through an embedder/control plane.
/// Reject unavailable execution capabilities before admission, not only in YAML.
pub(crate) fn validate_security(
	config: &security_integration_runtime::SecurityConfig,
	profile: GatewayProfile,
) -> Result<(), String> {
	if !profile.supports(GatewayCapability::Llm)
		&& config.mcp_sessions.as_ref().is_some_and(|sessions| {
			sessions
				.reverse
				.as_ref()
				.is_some_and(|reverse| !reverse.sampling_models.is_empty())
				|| sessions
					.tasks
					.as_ref()
					.is_some_and(|tasks| tasks.sampling.is_some())
		}) {
		return Err("MCP sampling requires LLM support; enable gateway-llm".into());
	}
	Ok(())
}
