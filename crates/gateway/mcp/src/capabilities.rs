//! Projection of the existing protected MCP capability surface.
//! The Host decides whether this restriction applies and admits optional tasks separately.
use rmcp::model::ServerCapabilities;

pub fn restrict_session_capabilities(capabilities: &mut ServerCapabilities, stateful: bool) {
	if let Some(c) = &mut capabilities.resources {
		if !stateful {
			c.subscribe = None;
		}
		c.list_changed = None;
	}
	if let Some(c) = &mut capabilities.tools {
		c.list_changed = None;
	}
	if let Some(c) = &mut capabilities.prompts {
		c.list_changed = None;
	}
	capabilities.tasks = None;
	capabilities.experimental = None;
	capabilities.extensions = None;
	capabilities.logging = None;
	capabilities.completions = None;
}

#[cfg(test)]
mod tests;
