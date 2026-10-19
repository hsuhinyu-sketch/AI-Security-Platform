//! Compile-time gateway capability profiles.
//!
//! This crate intentionally contains no protocol implementation. It is the stable boundary
//! between application build profiles and the gateway runtime while LLM, A2A, MCP, and routing
//! continue their gradual extraction into standalone protocol crates.

/// An independently selectable gateway or common security capability.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GatewayCapability {
	Llm,
	A2a,
	Mcp,
	InferenceRouting,
	SecurityS1,
	Rag,
}

impl GatewayCapability {
	pub const fn display_name(self) -> &'static str {
		match self {
			Self::Llm => "LLM Gateway",
			Self::A2a => "A2A Gateway",
			Self::Mcp => "MCP Gateway",
			Self::InferenceRouting => "Inference Routing",
			Self::SecurityS1 => "S1 common security controls",
			Self::Rag => "RAG Gateway",
		}
	}
}

/// Capabilities compiled into one gateway binary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GatewayProfile {
	llm: bool,
	a2a: bool,
	mcp: bool,
	inference_routing: bool,
	security_s1: bool,
	rag: bool,
}

impl GatewayProfile {
	/// Builds a profile explicitly. This is useful for embedders and configuration validation tests.
	pub const fn new(
		llm: bool,
		a2a: bool,
		mcp: bool,
		inference_routing: bool,
		security_s1: bool,
		rag: bool,
	) -> Self {
		Self {
			llm,
			a2a,
			mcp,
			inference_routing,
			security_s1,
			rag,
		}
	}

	pub const fn supports(self, capability: GatewayCapability) -> bool {
		match capability {
			GatewayCapability::Llm => self.llm,
			GatewayCapability::A2a => self.a2a,
			GatewayCapability::Mcp => self.mcp,
			GatewayCapability::InferenceRouting => self.inference_routing,
			GatewayCapability::SecurityS1 => self.security_s1,
			GatewayCapability::Rag => self.rag,
		}
	}
}

/// Implemented by an application or runtime that exposes a compile-time gateway profile.
pub trait GatewayProfileProvider {
	fn gateway_profile() -> GatewayProfile;
}

/// Provider for the capabilities selected by this crate's Cargo features.
pub struct CompiledGatewayProfile;

impl GatewayProfileProvider for CompiledGatewayProfile {
	fn gateway_profile() -> GatewayProfile {
		GatewayProfile::new(
			cfg!(feature = "gateway-llm"),
			cfg!(feature = "gateway-a2a"),
			cfg!(feature = "gateway-mcp"),
			cfg!(feature = "inference-routing"),
			cfg!(feature = "security-s1"),
			cfg!(feature = "gateway-rag"),
		)
	}
}
