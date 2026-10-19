use std::path::PathBuf;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use axum::http::HeaderMap;
use base64::Engine;
use chrono::Utc;
use security_types::ActionRequest;
use sha2::{Digest, Sha256};

use crate::{
	CAPABILITY_CONTEXT_HEADER, CAPABILITY_HEADER, CAPABILITY_PROTOCOL_VERSION,
	ConsumeCapabilityRequest, ConsumeCapabilityResponse,
};

/// mTLS client configuration for a protected Tool/API to consume one forwarded capability.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RemoteCapabilityConsumerConfig {
	pub consume_endpoint: String,
	#[serde(default = "default_timeout_millis")]
	pub timeout_millis: u64,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub identity_pem_file: Option<PathBuf>,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub root_ca_pem_file: Option<PathBuf>,
	#[serde(skip, default = "default_consumer_slot")]
	consumer: Arc<OnceLock<Result<HttpCapabilityConsumer, String>>>,
}

const fn default_timeout_millis() -> u64 {
	250
}

fn default_consumer_slot() -> Arc<OnceLock<Result<HttpCapabilityConsumer, String>>> {
	Arc::new(OnceLock::new())
}

impl RemoteCapabilityConsumerConfig {
	pub fn consumer(&self) -> Result<HttpCapabilityConsumer, CapabilityConsumerError> {
		match self
			.consumer
			.get_or_init(|| HttpCapabilityConsumer::from_config(self).map_err(|error| error.reason))
		{
			Ok(consumer) => Ok(consumer.clone()),
			Err(reason) => Err(CapabilityConsumerError::unavailable(reason.clone())),
		}
	}
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapabilityConsumerError {
	pub reason: String,
}

impl CapabilityConsumerError {
	fn unavailable(reason: impl Into<String>) -> Self {
		Self {
			reason: reason.into(),
		}
	}
}

/// Blocking client suitable for the current Tool/API request hooks. It never trusts a decoded
/// context alone: the broker's consumed response must bind exactly to both that context and the
/// hash computed from the parameters the backend is about to execute.
#[derive(Debug, Clone)]
pub struct HttpCapabilityConsumer {
	consume_endpoint: String,
	client: reqwest::blocking::Client,
}

impl HttpCapabilityConsumer {
	/// Call only behind authenticated gateway-to-Tool transport. The local Tool name must be
	/// supplied by the handler, not copied from an untrusted URL/header. Consumption still occurs
	/// on every request, even when the operation ledger already contains a receipt.
	pub fn authorize_operation(
		&self,
		headers: &HeaderMap,
		arguments: &serde_json::Value,
		local_tool: &str,
	) -> Result<crate::operation::AuthorizedToolOperation, CapabilityConsumerError> {
		authorize_operation_with(
			headers,
			arguments,
			local_tool,
			|token, request, arguments| self.consume(token, request, arguments),
		)
	}
	fn from_config(config: &RemoteCapabilityConsumerConfig) -> Result<Self, CapabilityConsumerError> {
		let endpoint = reqwest::Url::parse(&config.consume_endpoint).map_err(|error| {
			CapabilityConsumerError::unavailable(format!(
				"capability consume endpoint is invalid: {error}"
			))
		})?;
		if endpoint.scheme() != "https" || endpoint.host_str().is_none() {
			return Err(CapabilityConsumerError::unavailable(
				"capability consume endpoint must be an absolute https URL",
			));
		}
		if config.timeout_millis == 0 {
			return Err(CapabilityConsumerError::unavailable(
				"capability consume timeoutMillis must be greater than zero",
			));
		}
		let mut builder = reqwest::blocking::Client::builder()
			.use_rustls_tls()
			.redirect(reqwest::redirect::Policy::none())
			.no_proxy()
			.timeout(Duration::from_millis(config.timeout_millis));
		if let Some(path) = &config.root_ca_pem_file {
			let pem = std::fs::read(path).map_err(|error| {
				CapabilityConsumerError::unavailable(format!(
					"unable to read capability consume root CA PEM '{}': {error}",
					path.display()
				))
			})?;
			let certificate = reqwest::Certificate::from_pem(&pem).map_err(|error| {
				CapabilityConsumerError::unavailable(format!(
					"capability consume root CA PEM '{}' is invalid: {error}",
					path.display()
				))
			})?;
			builder = builder.add_root_certificate(certificate);
		}
		if let Some(path) = &config.identity_pem_file {
			let pem = std::fs::read(path).map_err(|error| {
				CapabilityConsumerError::unavailable(format!(
					"unable to read capability consumer identity PEM '{}': {error}",
					path.display()
				))
			})?;
			let identity = reqwest::Identity::from_pem(&pem).map_err(|error| {
				CapabilityConsumerError::unavailable(format!(
					"capability consumer identity PEM '{}' is invalid: {error}",
					path.display()
				))
			})?;
			builder = builder.identity(identity);
		}
		let client = builder.build().map_err(|error| {
			CapabilityConsumerError::unavailable(format!(
				"unable to build capability consumer client: {error}"
			))
		})?;
		Ok(Self {
			consume_endpoint: endpoint.to_string(),
			client,
		})
	}

	/// Extract the two gateway-controlled headers, hash the actual Tool arguments, and atomically
	/// consume the grant. Missing, malformed, expired, mismatched, or unavailable capabilities all
	/// return an error for the backend to fail closed.
	pub fn consume_forwarded(
		&self,
		headers: &HeaderMap,
		arguments: &serde_json::Value,
	) -> Result<ConsumeCapabilityResponse, CapabilityConsumerError> {
		let token = required_header(headers, CAPABILITY_HEADER)?;
		let request = decode_action_request(required_header(headers, CAPABILITY_CONTEXT_HEADER)?)?;
		self.consume(token, request, arguments)
	}

	pub fn consume(
		&self,
		token: &str,
		request: ActionRequest,
		arguments: &serde_json::Value,
	) -> Result<ConsumeCapabilityResponse, CapabilityConsumerError> {
		if token.is_empty() {
			return Err(CapabilityConsumerError::unavailable(
				"forwarded capability token is empty",
			));
		}
		let arguments_hash = arguments_hash(arguments);
		let response = self
			.client
			.post(&self.consume_endpoint)
			.header(reqwest::header::ACCEPT, "application/json")
			.json(&ConsumeCapabilityRequest {
				protocol_version: CAPABILITY_PROTOCOL_VERSION.into(),
				token: token.into(),
				request: request.clone(),
				arguments_hash: arguments_hash.clone(),
			})
			.send()
			.map_err(|error| {
				CapabilityConsumerError::unavailable(format!("capability consume request failed: {error}"))
			})?
			.error_for_status()
			.map_err(|error| {
				CapabilityConsumerError::unavailable(format!(
					"capability broker rejected consume request: {error}"
				))
			})?;
		// A compromised/misconfigured broker must not grow a blocking worker's
		// response buffer without bound before the binding checks run.
		if response.content_length().is_some_and(|n| n > 16384) {
			return Err(CapabilityConsumerError::unavailable(
				"capability response exceeds budget",
			));
		}
		let mut bytes = Vec::new();
		std::io::Read::read_to_end(&mut std::io::Read::take(response, 16385), &mut bytes)
			.map_err(|_| CapabilityConsumerError::unavailable("capability response unavailable"))?;
		if bytes.len() > 16384 {
			return Err(CapabilityConsumerError::unavailable(
				"capability response exceeds budget",
			));
		}
		let response: ConsumeCapabilityResponse = serde_json::from_slice(&bytes)
			.map_err(|_| CapabilityConsumerError::unavailable("capability response is invalid"))?;
		validate_consume_response(&response, &request, &arguments_hash)?;
		Ok(response)
	}
}

/// Base64url form used in the internal context header. This carries only gateway-normalized
/// security context and is stripped/replaced by the gateway before every HTTP upstream request.
pub fn encode_action_request(request: &ActionRequest) -> Result<String, CapabilityConsumerError> {
	let bytes = serde_json::to_vec(request).map_err(|error| {
		CapabilityConsumerError::unavailable(format!("unable to encode capability context: {error}"))
	})?;
	Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes))
}

pub fn arguments_hash(arguments: &serde_json::Value) -> String {
	Sha256::digest(serde_json::to_vec(arguments).expect("JSON values serialize"))
		.iter()
		.map(|byte| format!("{byte:02x}"))
		.collect()
}

pub(crate) fn authorize_operation_with(
	headers: &HeaderMap,
	arguments: &serde_json::Value,
	local_tool: &str,
	consume: impl FnOnce(
		&str,
		ActionRequest,
		&serde_json::Value,
	) -> Result<ConsumeCapabilityResponse, CapabilityConsumerError>,
) -> Result<crate::operation::AuthorizedToolOperation, CapabilityConsumerError> {
	let key = required_header(headers, crate::OPERATION_HEADER)?;
	if key.len() != 64 || !key.bytes().all(|b| b.is_ascii_hexdigit()) {
		return Err(CapabilityConsumerError::unavailable(
			"invalid operation key",
		));
	}
	let request = decode_action_request(required_header(headers, CAPABILITY_CONTEXT_HEADER)?)?;
	let consumed = consume(
		required_header(headers, CAPABILITY_HEADER)?,
		request.clone(),
		arguments,
	)?;
	validate_consume_response(&consumed, &request, &arguments_hash(arguments))?;
	if consumed.request.action.action_type != security_types::ActionType::ToolInvoke
		|| consumed.request.action.name != local_tool
		|| consumed.request.resource.resource_type != security_types::ResourceType::Tool
		|| consumed.request.resource.id != local_tool
	{
		return Err(CapabilityConsumerError::unavailable(
			"capability does not authorize this Tool",
		));
	}
	let mut request = consumed.request;
	request.request_id.clear();
	let binding =
		arguments_hash(&serde_json::json!({"request":request,"argumentsHash":consumed.arguments_hash}));
	Ok(crate::operation::AuthorizedToolOperation::new(
		key.to_owned(),
		binding,
	))
}

fn required_header<'a>(
	headers: &'a HeaderMap,
	name: &str,
) -> Result<&'a str, CapabilityConsumerError> {
	if headers.get_all(name).iter().take(2).count() != 1 {
		return Err(CapabilityConsumerError::unavailable(format!(
			"missing/duplicate {name} header"
		)));
	}
	headers
		.get(name)
		.and_then(|value| value.to_str().ok())
		.filter(|value| !value.is_empty())
		.ok_or_else(|| CapabilityConsumerError::unavailable(format!("missing required {name} header")))
}

fn decode_action_request(encoded: &str) -> Result<ActionRequest, CapabilityConsumerError> {
	if encoded.len() > 16384 {
		return Err(CapabilityConsumerError::unavailable(
			"capability context exceeds budget",
		));
	}
	let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
		.decode(encoded)
		.map_err(|error| {
			CapabilityConsumerError::unavailable(format!(
				"capability context header is not valid base64url: {error}"
			))
		})?;
	serde_json::from_slice(&bytes).map_err(|error| {
		CapabilityConsumerError::unavailable(format!(
			"capability context header is not a valid action request: {error}"
		))
	})
}

fn validate_consume_response(
	response: &ConsumeCapabilityResponse,
	expected_request: &ActionRequest,
	expected_arguments_hash: &str,
) -> Result<(), CapabilityConsumerError> {
	if response.request != *expected_request {
		return Err(CapabilityConsumerError::unavailable(
			"capability consume response request binding does not match",
		));
	}
	if response.arguments_hash != expected_arguments_hash {
		return Err(CapabilityConsumerError::unavailable(
			"capability consume response argumentsHash does not match",
		));
	}
	if response.expires_at <= Utc::now() {
		return Err(CapabilityConsumerError::unavailable(
			"capability consume response has expired",
		));
	}
	Ok(())
}
