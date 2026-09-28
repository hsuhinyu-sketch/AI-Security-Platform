use std::path::PathBuf;
use std::sync::Arc;

use crate::blocking_client_cache::BlockingClientCache;
use chrono::{DateTime, Utc};
use security_pipeline::{ApprovalError, ApprovalProvider, arguments_hash};
use security_types::ActionRequest;

use crate::trusted_https;

/// Trusted approval authority for high-risk Tool calls. It receives normalized request context and
/// a hash of arguments, never a caller-provided approval header or raw Tool arguments.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RemoteApprovalConfig {
	pub endpoint: String,
	#[serde(default = "default_timeout_millis")]
	pub timeout_millis: u64,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub identity_pem_file: Option<PathBuf>,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub root_ca_pem_file: Option<PathBuf>,
	#[serde(skip, default = "default_provider_slot")]
	provider: Arc<BlockingClientCache<HttpApprovalProvider>>,
}

const fn default_timeout_millis() -> u64 {
	250
}

fn default_provider_slot() -> Arc<BlockingClientCache<HttpApprovalProvider>> {
	Arc::new(BlockingClientCache::default())
}

impl RemoteApprovalConfig {
	pub fn provider(&self) -> Result<HttpApprovalProvider, ApprovalError> {
		match self
			.provider
			.get_or_init(|| HttpApprovalProvider::from_config(self).map_err(|error| error.reason))
		{
			Ok(provider) => Ok(provider.clone()),
			Err(reason) => Err(ApprovalError::unavailable(reason.clone())),
		}
	}
}

#[derive(Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct RemoteApprovalRequest<'a> {
	protocol_version: &'static str,
	request: &'a ActionRequest,
	arguments_hash: String,
}

#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct RemoteApprovalResponse {
	approval_id: String,
	request_id: String,
	arguments_hash: String,
	approved: bool,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	expires_at: Option<DateTime<Utc>>,
}

/// Blocking transport for the current synchronous security hook. Responses are bound to both the
/// normalized request and the exact argument hash before an approval can be accepted.
#[derive(Debug, Clone)]
pub struct HttpApprovalProvider {
	endpoint: String,
	client: reqwest::blocking::Client,
}

impl HttpApprovalProvider {
	fn from_config(config: &RemoteApprovalConfig) -> Result<Self, ApprovalError> {
		let (endpoint, client) = trusted_https::build_client(
			&config.endpoint,
			config.timeout_millis,
			config.identity_pem_file.as_deref(),
			config.root_ca_pem_file.as_deref(),
			"approval authority",
		)
		.map_err(ApprovalError::unavailable)?;
		Ok(Self { endpoint, client })
	}
}

impl ApprovalProvider for HttpApprovalProvider {
	fn approved(
		&self,
		request: &ActionRequest,
		arguments: &serde_json::Value,
	) -> Result<bool, ApprovalError> {
		let expected_arguments_hash = arguments_hash(arguments);
		let response = self
			.client
			.post(&self.endpoint)
			.header(reqwest::header::ACCEPT, "application/json")
			.json(&RemoteApprovalRequest {
				protocol_version: "v1",
				request,
				arguments_hash: expected_arguments_hash.clone(),
			})
			.send()
			.map_err(|error| ApprovalError::unavailable(format!("approval request failed: {error}")))?
			.error_for_status()
			.map_err(|error| {
				ApprovalError::unavailable(format!(
					"approval authority returned an error status: {error}"
				))
			})?
			.json::<RemoteApprovalResponse>()
			.map_err(|error| {
				ApprovalError::unavailable(format!("approval response is invalid: {error}"))
			})?;
		validate_response(&response, request, &expected_arguments_hash)
	}
}

fn validate_response(
	response: &RemoteApprovalResponse,
	request: &ActionRequest,
	expected_arguments_hash: &str,
) -> Result<bool, ApprovalError> {
	if response.approval_id.is_empty() {
		return Err(ApprovalError::unavailable(
			"approval response approvalId is empty",
		));
	}
	if response.request_id != request.request_id {
		return Err(ApprovalError::unavailable(
			"approval response requestId does not match",
		));
	}
	if response.arguments_hash != expected_arguments_hash {
		return Err(ApprovalError::unavailable(
			"approval response argumentsHash does not match",
		));
	}
	if response.approved
		&& response
			.expires_at
			.is_none_or(|expires_at| expires_at <= Utc::now())
	{
		return Err(ApprovalError::unavailable(
			"approval response is missing a future expiresAt",
		));
	}
	Ok(response.approved)
}

#[cfg(test)]
mod tests {
	use chrono::{Duration, Utc};
	use security_pipeline::{GatewayIdentity, arguments_hash, tool_invoke_for_identity};

	use super::{RemoteApprovalConfig, RemoteApprovalResponse, validate_response};

	#[test]
	fn rejects_non_https_approval_endpoint() {
		let config = RemoteApprovalConfig {
			endpoint: "http://approval.internal/v1/check".into(),
			timeout_millis: 250,
			identity_pem_file: None,
			root_ca_pem_file: None,
			provider: super::default_provider_slot(),
		};
		assert!(config.provider().is_err());
	}

	#[test]
	fn approval_response_must_bind_request_arguments_and_expiry() {
		let request =
			tool_invoke_for_identity("request-1", GatewayIdentity::default(), "records.delete");
		let hash = arguments_hash(&serde_json::json!({ "recordId": "42" }));
		let response = RemoteApprovalResponse {
			approval_id: "approval-1".into(),
			request_id: request.request_id.clone(),
			arguments_hash: hash.clone(),
			approved: true,
			expires_at: Some(Utc::now() + Duration::seconds(30)),
		};
		assert_eq!(validate_response(&response, &request, &hash), Ok(true));

		let wrong_request = RemoteApprovalResponse {
			request_id: "another-request".into(),
			..response
		};
		assert!(validate_response(&wrong_request, &request, &hash).is_err());
	}
}
