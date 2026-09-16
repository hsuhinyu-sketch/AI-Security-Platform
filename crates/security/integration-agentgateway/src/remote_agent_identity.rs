use std::path::PathBuf;
use std::sync::{Arc, OnceLock};

use chrono::{DateTime, Utc};
use gateway_adapter::{AgentIdentityError, AgentIdentityProvider};
use security_contracts::ActionRequest;

use crate::trusted_https;

/// Authoritative Agent Directory configuration. The gateway queries it for every request carrying
/// an Agent claim, without an allow cache, so disablement and lifecycle changes apply immediately.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RemoteAgentIdentityConfig {
	pub endpoint: String,
	/// Deny requests without an Agent claim instead of allowing a human-only request through.
	#[serde(default)]
	pub required: bool,
	#[serde(default = "default_timeout_millis")]
	pub timeout_millis: u64,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub identity_pem_file: Option<PathBuf>,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub root_ca_pem_file: Option<PathBuf>,
	#[serde(skip, default = "default_provider_slot")]
	provider: Arc<OnceLock<Result<HttpAgentIdentityProvider, String>>>,
}

const fn default_timeout_millis() -> u64 {
	100
}

fn default_provider_slot() -> Arc<OnceLock<Result<HttpAgentIdentityProvider, String>>> {
	Arc::new(OnceLock::new())
}

impl RemoteAgentIdentityConfig {
	pub fn provider(&self) -> Result<HttpAgentIdentityProvider, AgentIdentityError> {
		match self
			.provider
			.get_or_init(|| HttpAgentIdentityProvider::from_config(self).map_err(|error| error.reason))
		{
			Ok(provider) => Ok(provider.clone()),
			Err(reason) => Err(AgentIdentityError::unavailable(reason.clone())),
		}
	}
}

#[derive(Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct RemoteAgentIdentityRequest<'a> {
	protocol_version: &'static str,
	request: &'a ActionRequest,
}

#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct RemoteAgentIdentityResponse {
	agent_id: String,
	tenant_id: String,
	client_id: String,
	active: bool,
	expires_at: Option<DateTime<Utc>>,
}

/// mTLS transport for an Agent Directory. The response is strictly bound to the Agent, tenant,
/// and OAuth client already extracted from validated JWT claims.
#[derive(Debug, Clone)]
pub struct HttpAgentIdentityProvider {
	endpoint: String,
	client: reqwest::blocking::Client,
}

impl HttpAgentIdentityProvider {
	fn from_config(config: &RemoteAgentIdentityConfig) -> Result<Self, AgentIdentityError> {
		let (endpoint, client) = trusted_https::build_client(
			&config.endpoint,
			config.timeout_millis,
			config.identity_pem_file.as_deref(),
			config.root_ca_pem_file.as_deref(),
			"Agent identity directory",
		)
		.map_err(AgentIdentityError::unavailable)?;
		Ok(Self { endpoint, client })
	}
}

impl AgentIdentityProvider for HttpAgentIdentityProvider {
	fn verify(&self, request: &ActionRequest) -> Result<(), AgentIdentityError> {
		let agent_id = request
			.subject
			.agent_id
			.as_deref()
			.ok_or_else(|| AgentIdentityError::unavailable("Agent identity is missing"))?;
		let tenant_id = request
			.subject
			.tenant_id
			.as_deref()
			.ok_or_else(|| AgentIdentityError::unavailable("Agent tenant identity is missing"))?;
		let client_id = request
			.authorization_context
			.client_id
			.as_deref()
			.ok_or_else(|| AgentIdentityError::unavailable("Agent client identity is missing"))?;
		let response = self
			.client
			.post(&self.endpoint)
			.header(reqwest::header::ACCEPT, "application/json")
			.json(&RemoteAgentIdentityRequest {
				protocol_version: "v1",
				request,
			})
			.send()
			.map_err(|error| {
				AgentIdentityError::unavailable(format!("Agent identity request failed: {error}"))
			})?
			.error_for_status()
			.map_err(|error| {
				AgentIdentityError::unavailable(format!(
					"Agent identity directory returned an error status: {error}"
				))
			})?
			.json::<RemoteAgentIdentityResponse>()
			.map_err(|error| {
				AgentIdentityError::unavailable(format!("Agent identity response is invalid: {error}"))
			})?;
		validate_response(&response, agent_id, tenant_id, client_id)
	}
}

fn validate_response(
	response: &RemoteAgentIdentityResponse,
	agent_id: &str,
	tenant_id: &str,
	client_id: &str,
) -> Result<(), AgentIdentityError> {
	if response.agent_id != agent_id
		|| response.tenant_id != tenant_id
		|| response.client_id != client_id
	{
		return Err(AgentIdentityError::unavailable(
			"Agent identity response does not match the verified request identity",
		));
	}
	if !response.active {
		return Err(AgentIdentityError::unavailable(
			"Agent identity is not active",
		));
	}
	if response
		.expires_at
		.is_some_and(|expires_at| expires_at <= Utc::now())
	{
		return Err(AgentIdentityError::unavailable(
			"Agent identity response has expired",
		));
	}
	Ok(())
}

#[cfg(test)]
mod tests {
	use chrono::{Duration, Utc};

	use super::{RemoteAgentIdentityConfig, RemoteAgentIdentityResponse, validate_response};

	#[test]
	fn rejects_non_https_agent_directory_endpoint() {
		let config = RemoteAgentIdentityConfig {
			endpoint: "http://agents.internal/v1/identities/check".into(),
			required: true,
			timeout_millis: 100,
			identity_pem_file: None,
			root_ca_pem_file: None,
			provider: super::default_provider_slot(),
		};
		assert!(config.provider().is_err());
	}

	#[test]
	fn directory_response_must_bind_verified_identity_and_remain_active() {
		let response = RemoteAgentIdentityResponse {
			agent_id: "support-agent".into(),
			tenant_id: "tenant-a".into(),
			client_id: "support-agent-workload".into(),
			active: true,
			expires_at: Some(Utc::now() + Duration::seconds(30)),
		};
		assert!(
			validate_response(
				&response,
				"support-agent",
				"tenant-a",
				"support-agent-workload"
			)
			.is_ok()
		);
		assert!(
			validate_response(
				&response,
				"other-agent",
				"tenant-a",
				"support-agent-workload"
			)
			.is_err()
		);
		let inactive = RemoteAgentIdentityResponse {
			active: false,
			..response
		};
		assert!(
			validate_response(
				&inactive,
				"support-agent",
				"tenant-a",
				"support-agent-workload"
			)
			.is_err()
		);
	}
}
