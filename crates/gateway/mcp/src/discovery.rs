//! Pure aggregation of successful upstream negotiation results.
//!
//! The caller selects authorized upstreams and handles transport failures. Runtime
//! identity, cache policy and session-specific capability admission stay with it.
use rmcp::model::{
	DiscoverResult, Implementation, PromptsCapability, ProtocolVersion, ResourcesCapability,
	ServerCapabilities, ServerInfo, ServerResult, ToolsCapability,
};

pub fn merge_initialize<S: AsRef<str>>(
	results: impl IntoIterator<Item = (S, ServerResult)>,
	requested_version: ProtocolVersion,
	multiplexing: bool,
	resource_subscribe: bool,
	server_info: Implementation,
) -> ServerInfo {
	let mut results = results.into_iter();
	if !multiplexing {
		if let Some((_, ServerResult::InitializeResult(info))) = results.next() {
			return info;
		}
		return gateway_info(
			requested_version,
			resource_subscribe,
			Vec::new(),
			server_info,
		);
	}
	let mut lowest_version = requested_version;
	let mut instructions = Vec::new();
	for (server, result) in results {
		if let ServerResult::InitializeResult(info) = result {
			if info.protocol_version.to_string() < lowest_version.to_string() {
				lowest_version = info.protocol_version;
			}
			if let Some(text) = info.instructions
				&& !text.is_empty()
			{
				instructions.push((server.as_ref().to_string(), text));
			}
		}
	}
	gateway_info(
		lowest_version,
		resource_subscribe,
		instructions,
		server_info,
	)
}

pub fn merge_discover<S: AsRef<str>>(
	results: impl IntoIterator<Item = (S, ServerResult)>,
	multiplexing: bool,
	resource_subscribe: bool,
	server_info: Implementation,
) -> DiscoverResult {
	let mut results = results.into_iter();
	if !multiplexing {
		if let Some((_, ServerResult::DiscoverResult(mut discovery))) = results.next() {
			discovery
				.supported_versions
				.retain(|v| crate::protocol::SUPPORTED_VERSIONS.contains(v));
			return discovery;
		}
		return gateway_discovery(resource_subscribe, Vec::new(), server_info);
	}
	let mut instructions = Vec::new();
	let mut supported_versions = crate::protocol::SUPPORTED_VERSIONS.to_vec();
	for (server, result) in results {
		if let ServerResult::DiscoverResult(discovery) = result {
			supported_versions.retain(|v| discovery.supported_versions.contains(v));
			if let Some(text) = discovery.instructions
				&& !text.is_empty()
			{
				instructions.push((server.as_ref().to_string(), text));
			}
		}
	}
	let mut discovery = gateway_discovery(resource_subscribe, instructions, server_info);
	discovery.supported_versions = supported_versions;
	discovery
}

fn gateway_info(
	version: ProtocolVersion,
	resource_subscribe: bool,
	upstream_instructions: Vec<(String, String)>,
	server_info: Implementation,
) -> ServerInfo {
	// The SDK builder requires its server feature. Build the data directly so this
	// crate remains independent of the SDK's server runtime and transports.
	let mut tools = ToolsCapability::default();
	tools.list_changed = Some(true);
	let mut prompts = PromptsCapability::default();
	prompts.list_changed = Some(true);
	let mut resources = ResourcesCapability::default();
	resources.list_changed = Some(true);
	resources.subscribe = resource_subscribe.then_some(true);
	let mut capabilities = ServerCapabilities::default();
	capabilities.tools = Some(tools);
	capabilities.prompts = Some(prompts);
	capabilities.resources = Some(resources);
	let mut instructions = String::from(
		"This server is a gateway to a set of mcp servers. It is responsible for routing requests to the correct server and aggregating the results.",
	);
	for (server, text) in upstream_instructions {
		instructions.push_str(&format!("\n\n[{server}]\n{text}"));
	}
	ServerInfo::new(capabilities)
		.with_protocol_version(version)
		.with_server_info(server_info)
		.with_instructions(instructions)
}

fn gateway_discovery(
	resource_subscribe: bool,
	instructions: Vec<(String, String)>,
	server_info: Implementation,
) -> DiscoverResult {
	let info = gateway_info(
		ProtocolVersion::default(),
		resource_subscribe,
		instructions,
		server_info,
	);
	DiscoverResult::new(
		crate::protocol::SUPPORTED_VERSIONS.to_vec(),
		info.capabilities,
	)
	.with_server_info(info.server_info)
	.with_instructions(info.instructions.unwrap_or_default())
}

#[cfg(test)]
mod tests;
