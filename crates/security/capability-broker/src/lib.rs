//! Shared, one-time capability issuance and consumption for protected Tool/API backends.
//!
//! The broker is intentionally separate from gateway process memory. Its HTTP router must sit
//! behind an mTLS-aware host which injects [`BrokerPrincipal`] for each authenticated peer.
//! The default store is only suitable for a single-process PoC; production deployments provide a
//! durable [`CapabilityStore`] implementation with an atomic consume operation.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use axum::extract::{Extension, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Json, Router};
use chrono::{DateTime, Duration, Utc};
use security_types::ActionRequest;
use thiserror::Error;
use uuid::Uuid;

pub const CAPABILITY_PROTOCOL_VERSION: &str = "v1";
/// Forwarded only by the gateway after it receives a broker-issued grant.
pub const CAPABILITY_HEADER: &str = "x-ai-security-capability";
/// Base64url JSON encoding of the gateway-normalized [`ActionRequest`]. Like the capability
/// header, a caller-provided value must be stripped before an upstream Tool/API request.
pub const CAPABILITY_CONTEXT_HEADER: &str = "x-ai-security-capability-context";
/// Gateway-generated stable invocation correlation; never sufficient authorization by itself.
pub const OPERATION_HEADER: &str = "x-aisp-operation-key";

#[cfg(feature = "client")]
pub mod operation;
#[cfg(feature = "client")]
pub mod ticket_backend;

#[cfg(feature = "client")]
mod consumer;
#[cfg(feature = "client")]
pub use consumer::{
	CapabilityConsumerError, HttpCapabilityConsumer, RemoteCapabilityConsumerConfig,
	encode_action_request,
};

/// Identity established by the mTLS listener or trusted service-mesh proxy.
///
/// It is intentionally an HTTP request extension rather than a user-controlled header. The host
/// is responsible for mapping verified client certificates to this value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BrokerPrincipal {
	pub id: String,
	pub can_issue: bool,
	pub can_consume: bool,
}

impl BrokerPrincipal {
	pub fn gateway(id: impl Into<String>) -> Self {
		Self {
			id: id.into(),
			can_issue: true,
			can_consume: false,
		}
	}

	pub fn protected_backend(id: impl Into<String>) -> Self {
		Self {
			id: id.into(),
			can_issue: false,
			can_consume: true,
		}
	}
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IssueCapabilityRequest {
	pub protocol_version: String,
	pub request: ActionRequest,
	pub arguments_hash: String,
	pub ttl_seconds: u64,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct IssueCapabilityResponse {
	pub token: String,
	pub request_id: String,
	pub arguments_hash: String,
	pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConsumeCapabilityRequest {
	pub protocol_version: String,
	pub token: String,
	pub request: ActionRequest,
	pub arguments_hash: String,
}

/// The protected backend receives the normalized binding after a successful atomic consume. It
/// may compare the action/resource with its local operation before executing the Tool request.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ConsumeCapabilityResponse {
	pub request: ActionRequest,
	pub arguments_hash: String,
	pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredCapability {
	pub token: String,
	pub request: ActionRequest,
	pub arguments_hash: String,
	pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum CapabilityStoreError {
	#[error("capability was not found or was already consumed")]
	NotFound,
	#[error("capability has expired")]
	Expired,
	#[error("capability request binding does not match")]
	RequestMismatch,
	#[error("capability arguments hash does not match")]
	ArgumentsMismatch,
	#[error("capability token collision")]
	TokenCollision,
	#[error("capability store is unavailable: {0}")]
	Unavailable(String),
}

/// Backing store boundary. `consume` must remove a token atomically before performing binding
/// checks, so a bad replay attempt also burns the credential.
pub trait CapabilityStore: Send + Sync + 'static {
	fn issue(&self, capability: StoredCapability) -> Result<(), CapabilityStoreError>;

	fn consume(
		&self,
		token: &str,
		request: &ActionRequest,
		arguments_hash: &str,
		now: DateTime<Utc>,
	) -> Result<StoredCapability, CapabilityStoreError>;
}

/// Single-process PoC store. Use a database-backed implementation of [`CapabilityStore`] to
/// share state across broker replicas and survive restarts.
#[derive(Default)]
pub struct InMemoryCapabilityStore {
	capabilities: Mutex<HashMap<String, StoredCapability>>,
}

impl CapabilityStore for InMemoryCapabilityStore {
	fn issue(&self, capability: StoredCapability) -> Result<(), CapabilityStoreError> {
		let mut capabilities = self
			.capabilities
			.lock()
			.map_err(|_| CapabilityStoreError::Unavailable("memory store lock poisoned".into()))?;
		if capabilities.contains_key(&capability.token) {
			return Err(CapabilityStoreError::TokenCollision);
		}
		capabilities.retain(|_, stored| stored.expires_at > Utc::now());
		capabilities.insert(capability.token.clone(), capability);
		Ok(())
	}

	fn consume(
		&self,
		token: &str,
		request: &ActionRequest,
		arguments_hash: &str,
		now: DateTime<Utc>,
	) -> Result<StoredCapability, CapabilityStoreError> {
		let capability = self
			.capabilities
			.lock()
			.map_err(|_| CapabilityStoreError::Unavailable("memory store lock poisoned".into()))?
			.remove(token)
			.ok_or(CapabilityStoreError::NotFound)?;
		if capability.expires_at <= now {
			return Err(CapabilityStoreError::Expired);
		}
		if capability.request != *request {
			return Err(CapabilityStoreError::RequestMismatch);
		}
		if capability.arguments_hash != arguments_hash {
			return Err(CapabilityStoreError::ArgumentsMismatch);
		}
		Ok(capability)
	}
}

#[derive(Clone)]
pub struct CapabilityBroker {
	store: Arc<dyn CapabilityStore>,
	max_ttl: Duration,
}

impl CapabilityBroker {
	pub fn new(store: Arc<dyn CapabilityStore>, max_ttl: Duration) -> Result<Self, BrokerError> {
		if max_ttl <= Duration::zero() {
			return Err(BrokerError::InvalidTtl);
		}
		Ok(Self { store, max_ttl })
	}

	pub fn issue(
		&self,
		request: IssueCapabilityRequest,
	) -> Result<IssueCapabilityResponse, BrokerError> {
		validate_protocol(&request.protocol_version)?;
		if request.arguments_hash.is_empty() {
			return Err(BrokerError::InvalidArgumentsHash);
		}
		let ttl = Duration::seconds(
			request
				.ttl_seconds
				.try_into()
				.map_err(|_| BrokerError::InvalidTtl)?,
		);
		if ttl <= Duration::zero() || ttl > self.max_ttl {
			return Err(BrokerError::InvalidTtl);
		}
		let expires_at = Utc::now() + ttl;
		for _ in 0..3 {
			let capability = StoredCapability {
				token: Uuid::new_v4().to_string(),
				request: request.request.clone(),
				arguments_hash: request.arguments_hash.clone(),
				expires_at,
			};
			match self.store.issue(capability.clone()) {
				Ok(()) => {
					return Ok(IssueCapabilityResponse {
						token: capability.token,
						request_id: request.request.request_id,
						arguments_hash: request.arguments_hash,
						expires_at,
					});
				},
				Err(CapabilityStoreError::TokenCollision) => continue,
				Err(error) => return Err(BrokerError::Store(error)),
			}
		}
		Err(BrokerError::Store(CapabilityStoreError::TokenCollision))
	}

	pub fn consume(
		&self,
		request: ConsumeCapabilityRequest,
	) -> Result<ConsumeCapabilityResponse, BrokerError> {
		validate_protocol(&request.protocol_version)?;
		if request.token.is_empty() {
			return Err(BrokerError::InvalidToken);
		}
		if request.arguments_hash.is_empty() {
			return Err(BrokerError::InvalidArgumentsHash);
		}
		let capability = self
			.store
			.consume(
				&request.token,
				&request.request,
				&request.arguments_hash,
				Utc::now(),
			)
			.map_err(BrokerError::Store)?;
		Ok(ConsumeCapabilityResponse {
			request: capability.request,
			arguments_hash: capability.arguments_hash,
			expires_at: capability.expires_at,
		})
	}

	/// Router endpoints for an mTLS-authenticated host:
	///
	/// - `POST /v1/capabilities/issue` accepts only a `BrokerPrincipal` allowed to issue.
	/// - `POST /v1/capabilities/consume` accepts only a `BrokerPrincipal` allowed to consume.
	pub fn router(self) -> Router {
		Router::new()
			.route("/v1/capabilities/issue", post(issue_handler))
			.route("/v1/capabilities/consume", post(consume_handler))
			.with_state(self)
	}
}

#[derive(Debug, Error)]
pub enum BrokerError {
	#[error("unsupported capability protocol version")]
	UnsupportedProtocol,
	#[error("capability TTL must be greater than zero and no greater than broker maximum")]
	InvalidTtl,
	#[error("capability arguments hash must not be empty")]
	InvalidArgumentsHash,
	#[error("capability token must not be empty")]
	InvalidToken,
	#[error(transparent)]
	Store(#[from] CapabilityStoreError),
}

fn validate_protocol(version: &str) -> Result<(), BrokerError> {
	if version == CAPABILITY_PROTOCOL_VERSION {
		Ok(())
	} else {
		Err(BrokerError::UnsupportedProtocol)
	}
}

async fn issue_handler(
	State(broker): State<CapabilityBroker>,
	principal: Option<Extension<BrokerPrincipal>>,
	Json(request): Json<IssueCapabilityRequest>,
) -> Result<Json<IssueCapabilityResponse>, BrokerHttpError> {
	if !principal.is_some_and(|Extension(principal)| principal.can_issue) {
		return Err(BrokerHttpError::Forbidden);
	}
	broker
		.issue(request)
		.map(Json)
		.map_err(BrokerHttpError::from)
}

async fn consume_handler(
	State(broker): State<CapabilityBroker>,
	principal: Option<Extension<BrokerPrincipal>>,
	Json(request): Json<ConsumeCapabilityRequest>,
) -> Result<Json<ConsumeCapabilityResponse>, BrokerHttpError> {
	if !principal.is_some_and(|Extension(principal)| principal.can_consume) {
		return Err(BrokerHttpError::Forbidden);
	}
	broker
		.consume(request)
		.map(Json)
		.map_err(BrokerHttpError::from)
}

enum BrokerHttpError {
	Forbidden,
	BadRequest(BrokerError),
	Conflict,
	Unavailable,
}

impl From<BrokerError> for BrokerHttpError {
	fn from(error: BrokerError) -> Self {
		match error {
			BrokerError::UnsupportedProtocol
			| BrokerError::InvalidTtl
			| BrokerError::InvalidArgumentsHash
			| BrokerError::InvalidToken
			| BrokerError::Store(CapabilityStoreError::RequestMismatch)
			| BrokerError::Store(CapabilityStoreError::ArgumentsMismatch) => Self::BadRequest(error),
			BrokerError::Store(CapabilityStoreError::NotFound)
			| BrokerError::Store(CapabilityStoreError::Expired) => Self::Conflict,
			BrokerError::Store(CapabilityStoreError::TokenCollision)
			| BrokerError::Store(CapabilityStoreError::Unavailable(_)) => Self::Unavailable,
		}
	}
}

impl IntoResponse for BrokerHttpError {
	fn into_response(self) -> Response {
		let (status, code) = match self {
			Self::Forbidden => (StatusCode::FORBIDDEN, "untrusted-broker-principal"),
			Self::BadRequest(error) => {
				tracing::warn!(error = %error, "capability broker rejected an invalid request");
				(StatusCode::BAD_REQUEST, "invalid-capability-request")
			},
			Self::Conflict => (StatusCode::CONFLICT, "capability-unavailable"),
			Self::Unavailable => (
				StatusCode::SERVICE_UNAVAILABLE,
				"capability-store-unavailable",
			),
		};
		(status, Json(serde_json::json!({ "code": code }))).into_response()
	}
}
