use std::path::PathBuf;
use std::sync::Arc;

use crate::blocking_client_cache::BlockingClientCache;
use chrono::{DateTime, Duration, Utc};
use security_pipeline::arguments_hash;
use security_types::ActionRequest;

use crate::trusted_https;

/// A shared capability broker issues opaque, single-use grants after the gateway has completed
/// authorization and approval. The protected Tool/API consumes the token directly with this
/// broker; the gateway never accepts a capability supplied by the original caller.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RemoteCapabilityBrokerConfig {
	pub issue_endpoint: String,
	#[serde(default = "default_timeout_millis")]
	pub timeout_millis: u64,
	#[serde(default = "default_ttl_seconds")]
	pub ttl_seconds: u64,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub identity_pem_file: Option<PathBuf>,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub root_ca_pem_file: Option<PathBuf>,
	#[serde(skip, default = "default_issuer_slot")]
	issuer: Arc<BlockingClientCache<HttpCapabilityIssuer>>,
}

const fn default_timeout_millis() -> u64 {
	250
}

const fn default_ttl_seconds() -> u64 {
	30
}

fn default_issuer_slot() -> Arc<BlockingClientCache<HttpCapabilityIssuer>> {
	Arc::new(BlockingClientCache::default())
}

impl RemoteCapabilityBrokerConfig {
	pub fn issuer(&self) -> Result<HttpCapabilityIssuer, CapabilityIssuerError> {
		match self
			.issuer
			.get_or_init(|| HttpCapabilityIssuer::from_config(self).map_err(|error| error.reason))
		{
			Ok(issuer) => Ok(issuer.clone()),
			Err(reason) => Err(CapabilityIssuerError::unavailable(reason.clone())),
		}
	}
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapabilityGrant {
	pub token: String,
	pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapabilityIssuerError {
	pub reason: String,
}

impl CapabilityIssuerError {
	fn unavailable(reason: impl Into<String>) -> Self {
		Self {
			reason: reason.into(),
		}
	}
}

#[derive(Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct CapabilityIssueRequest<'a> {
	protocol_version: &'static str,
	request: &'a ActionRequest,
	arguments_hash: String,
	ttl_seconds: u64,
}

#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct CapabilityIssueResponse {
	token: String,
	request_id: String,
	arguments_hash: String,
	expires_at: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub struct HttpCapabilityIssuer {
	issue_endpoint: String,
	client: reqwest::blocking::Client,
	ttl: Duration,
}

impl HttpCapabilityIssuer {
	fn from_config(config: &RemoteCapabilityBrokerConfig) -> Result<Self, CapabilityIssuerError> {
		if config.ttl_seconds == 0 {
			return Err(CapabilityIssuerError::unavailable(
				"capability broker ttlSeconds must be greater than zero",
			));
		}
		let (issue_endpoint, client) = trusted_https::build_client(
			&config.issue_endpoint,
			config.timeout_millis,
			config.identity_pem_file.as_deref(),
			config.root_ca_pem_file.as_deref(),
			"capability broker",
		)
		.map_err(CapabilityIssuerError::unavailable)?;
		Ok(Self {
			issue_endpoint,
			client,
			ttl: Duration::seconds(config.ttl_seconds.try_into().unwrap_or(i64::MAX)),
		})
	}

	pub fn issue(
		&self,
		request: &ActionRequest,
		arguments: &serde_json::Value,
	) -> Result<CapabilityGrant, CapabilityIssuerError> {
		let expected_arguments_hash = arguments_hash(arguments);
		let response = self
			.client
			.post(&self.issue_endpoint)
			.header(reqwest::header::ACCEPT, "application/json")
			.json(&CapabilityIssueRequest {
				protocol_version: "v1",
				request,
				arguments_hash: expected_arguments_hash.clone(),
				ttl_seconds: self.ttl.num_seconds().try_into().unwrap_or(u64::MAX),
			})
			.send()
			.map_err(|error| {
				CapabilityIssuerError::unavailable(format!("capability issue request failed: {error}"))
			})?
			.error_for_status()
			.map_err(|error| {
				CapabilityIssuerError::unavailable(format!(
					"capability broker returned an error status: {error}"
				))
			})?
			.json::<CapabilityIssueResponse>()
			.map_err(|error| {
				CapabilityIssuerError::unavailable(format!("capability response is invalid: {error}"))
			})?;
		validate_issue_response(&response, request, &expected_arguments_hash, self.ttl)
	}
}

fn validate_issue_response(
	response: &CapabilityIssueResponse,
	request: &ActionRequest,
	expected_arguments_hash: &str,
	max_ttl: Duration,
) -> Result<CapabilityGrant, CapabilityIssuerError> {
	if response.token.is_empty() {
		return Err(CapabilityIssuerError::unavailable(
			"capability response token is empty",
		));
	}
	if response.request_id != request.request_id {
		return Err(CapabilityIssuerError::unavailable(
			"capability response requestId does not match",
		));
	}
	if response.arguments_hash != expected_arguments_hash {
		return Err(CapabilityIssuerError::unavailable(
			"capability response argumentsHash does not match",
		));
	}
	let now = Utc::now();
	if response.expires_at <= now || response.expires_at > now + max_ttl {
		return Err(CapabilityIssuerError::unavailable(
			"capability response expiresAt is outside the requested TTL",
		));
	}
	Ok(CapabilityGrant {
		token: response.token.clone(),
		expires_at: response.expires_at,
	})
}

#[cfg(test)]
mod tests {
	use chrono::{Duration, Utc};
	use security_pipeline::{GatewayIdentity, arguments_hash, tool_invoke_for_identity};

	use super::{
		CapabilityIssueResponse, RemoteCapabilityBrokerConfig, default_issuer_slot,
		validate_issue_response,
	};

	#[test]
	fn rejects_non_https_capability_broker_endpoint() {
		let config = RemoteCapabilityBrokerConfig {
			issue_endpoint: "http://capability.internal/v1/issue".into(),
			timeout_millis: 250,
			ttl_seconds: 30,
			identity_pem_file: None,
			root_ca_pem_file: None,
			issuer: default_issuer_slot(),
		};
		assert!(config.issuer().is_err());
	}

	#[test]
	fn capability_response_must_bind_request_arguments_and_ttl() {
		let request =
			tool_invoke_for_identity("request-1", GatewayIdentity::default(), "records.delete");
		let hash = arguments_hash(&serde_json::json!({ "recordId": "42" }));
		let response = CapabilityIssueResponse {
			token: "capability-1".into(),
			request_id: request.request_id.clone(),
			arguments_hash: hash.clone(),
			expires_at: Utc::now() + Duration::seconds(20),
		};
		assert!(validate_issue_response(&response, &request, &hash, Duration::seconds(30)).is_ok());
		assert!(validate_issue_response(&response, &request, "wrong", Duration::seconds(30)).is_err());
	}
}
