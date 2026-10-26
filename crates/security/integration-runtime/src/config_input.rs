//! Strict input for the existing flattened security configuration; no runtime state is accepted.
use super::{SecurityConfig, SecurityPipelineConfig};
use serde::de::{Error, MapAccess, Visitor};
use std::collections::BTreeSet;

impl<'de> serde::Deserialize<'de> for SecurityConfig {
	fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
		struct Input;
		impl<'de> Visitor<'de> for Input {
			type Value = SecurityConfig;
			fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
				formatter.write_str("a security configuration object")
			}
			fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
				let mut config = SecurityConfig::default();
				let mut pipeline = serde_json::Map::new();
				let mut seen = BTreeSet::new();
				while let Some(key) = map.next_key::<String>()? {
					if !seen.insert(key.clone()) {
						return Err(A::Error::custom(format!(
							"duplicate security field `{key}`"
						)));
					}
					match key.as_str() {
						"requiredAudit" => config.required_audit = map.next_value()?,
						"dependencyEgress" => config.dependency_egress = map.next_value()?,
						"executionBudget" => config.execution_budget = map.next_value()?,
						"crossComponent" => config.cross_component = map.next_value()?,
						"mcpSessions" => config.mcp_sessions = map.next_value()?,
						"a2aObjects" => config.a2a_objects = map.next_value()?,
						"mode" => config.mode = map.next_value()?,
						"remotePdp" => config.remote_pdp = map.next_value()?,
						"delegationRevocation" => config.delegation_revocation = map.next_value()?,
						"approval" => config.approval = map.next_value()?,
						"capabilityBroker" => config.capability_broker = map.next_value()?,
						"agentIdentity" => config.agent_identity = map.next_value()?,
						"remoteAgentIdentity" => config.remote_agent_identity = map.next_value()?,
						"dataEgress" => config.data_egress = map.next_value()?,
						_ => {
							pipeline.insert(key, map.next_value()?);
						},
					}
				}
				config.pipeline = serde_json_path_to_error::from_value::<SecurityPipelineConfig>(
					serde_json::Value::Object(pipeline),
				)
				.map_err(A::Error::custom)?;
				Ok(config)
			}
		}
		deserializer.deserialize_map(Input)
	}
}

#[cfg(test)]
#[path = "config_input_tests.rs"]
mod tests;
