//! Host compatibility path; decoding is owned by the independent MCP protocol crate.
pub(super) use gateway_mcp::wire::decode_server;

#[cfg(test)]
#[path = "wire_tests.rs"]
mod tests;
