// MCP method names shared by configuration validation and the adapter.
#[cfg(feature = "gateway-mcp")]
pub const TOOLS_CALL: &str = "tools/call";
#[cfg(feature = "gateway-mcp")]
pub const PROMPTS_GET: &str = "prompts/get";
#[cfg(feature = "gateway-mcp")]
pub const RESOURCES_READ: &str = "resources/read";
pub const REQUEST_PHASE_UNSUPPORTED: &[&str] = &[
	"resources/subscribe",
	"resources/unsubscribe",
	"completion/complete",
];
