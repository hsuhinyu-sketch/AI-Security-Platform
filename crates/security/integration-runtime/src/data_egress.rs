use security_audit::{AuditSink, event_from_decision};
use security_pipeline::GatewayError;
use security_types::{ActionRequest, ActionType, DataClassification, Decision, DecisionEffect};

/// Administrator-owned labels and exact destinations. HTTP values are the actual outbound
/// `host:port` or `unix:path`; Tool values are `server-id/tool-name`; other MCP values
/// are logical server IDs bound to backend endpoints by trusted gateway configuration.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DataEgressConfig {
	pub classification: DataClassification,
	#[serde(default)]
	pub model_destinations: Vec<String>,
	#[serde(default)]
	pub inference_destinations: Vec<String>,
	#[serde(default)]
	pub agent_destinations: Vec<String>,
	#[serde(default)]
	pub tool_destinations: Vec<String>,
	/// Exact MCP server IDs for Resource/Prompt operations, checked per actual upstream.
	#[serde(default)]
	pub mcp_destinations: Vec<String>,
	/// Exact HTTPS host:port for external A2A Artifact retrieval; not Agent call permission.
	#[serde(default, skip_serializing_if = "Vec::is_empty")]
	pub artifact_destinations: Vec<String>,
}

impl DataEgressConfig {
	/// Protocol setup is permitted only for a server with an explicitly approved business exit.
	pub fn permits_mcp_transport(&self, server: &str) -> bool {
		self.mcp_destinations.iter().any(|value| value == server)
			|| self
				.tool_destinations
				.iter()
				.any(|value| value.starts_with(&format!("{server}/")))
	}
	pub fn validate(&self) -> Result<(), String> {
		for destination in self
			.model_destinations
			.iter()
			.chain(&self.inference_destinations)
			.chain(&self.agent_destinations)
			.chain(&self.tool_destinations)
			.chain(&self.mcp_destinations)
			.chain(&self.artifact_destinations)
		{
			if destination.is_empty() || destination.trim() != destination {
				return Err("dataEgress destinations must be nonempty exact identifiers without surrounding whitespace".into());
			}
		}
		Ok(())
	}

	/// Side-effect-free candidate eligibility; this is not an execution authorization.
	pub fn permits(&self, action: &ActionRequest, destination: &str) -> bool {
		if action.action.action_type == ActionType::McpOperation
			&& matches!(
				action.action.name.as_str(),
				"initialize"
					| "ping"
					| "tools/list"
					| "transport/get"
					| "transport/delete"
					| "notifications/initialized"
			) {
			return self.permits_mcp_transport(destination);
		}
		let list = match action.action.action_type {
			ActionType::ModelInvoke => &self.model_destinations,
			ActionType::InferenceRoute => &self.inference_destinations,
			ActionType::AgentInvoke => &self.agent_destinations,
			ActionType::ToolInvoke => &self.tool_destinations,
			ActionType::McpOperation => &self.mcp_destinations,
			ActionType::McpTaskOperation => &self.mcp_destinations,
			ActionType::AgentArtifactDownload => &self.artifact_destinations,
			_ => return false,
		};
		list.iter().any(|entry| entry == destination)
	}
}

/// Audits the chosen destination without recording request content or Tool arguments.
pub fn check_data_egress(
	config: &DataEgressConfig,
	action: &ActionRequest,
	destination: &str,
	audit: &dyn AuditSink,
) -> Result<(), GatewayError> {
	let allowed = config.permits(action, destination);
	let decision = Decision {
		request_id: action.request_id.clone(),
		effect: if allowed {
			DecisionEffect::Allow
		} else {
			DecisionEffect::Deny
		},
		policy_id: Some(format!("data-egress:{:?}", config.classification).to_ascii_lowercase()),
		policy_version: None,
		expires_at: None,
	};
	let mut audit_action = action.clone();
	audit_action.resource.id = destination.to_owned();
	audit.record(event_from_decision(
		format!(
			"{}:egress:{:?}:{}",
			action.request_id, action.action.action_type, destination
		),
		&audit_action,
		&decision,
	));
	if allowed {
		Ok(())
	} else {
		Err(GatewayError::Denied(decision))
	}
}
