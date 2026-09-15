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
use security_contracts::ActionRequest;
use thiserror::Error;
use uuid::Uuid;

pub const CAPABILITY_PROTOCOL_VERSION: &str = "v1";
/// Forwarded only by the gateway after it receives a broker-issued grant.
pub const CAPABILITY_HEADER: &str = "x-ai-security-capability";
/// Base64url JSON encoding of the gateway-normalized [`ActionRequest`]. Like the capability
/// header, a caller-provided value must be stripped before an upstream Tool/API request.
pub const CAPABILITY_CONTEXT_HEADER: &str = "x-ai-security-capability-context";

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

#[cfg(test)]
mod tests {
	use std::sync::Arc;

	use axum::body::Body;
	use axum::http::{Request, StatusCode};
	use chrono::{Duration, Utc};
	use security_contracts::{
		Action, ActionRequest, ActionType, AuthorizationContext, Resource, ResourceType, Subject,
	};

	use super::{
		BrokerError, BrokerPrincipal, CAPABILITY_PROTOCOL_VERSION, CapabilityBroker, CapabilityStore,
		CapabilityStoreError, ConsumeCapabilityRequest, InMemoryCapabilityStore,
		IssueCapabilityRequest, StoredCapability,
	};
	use tower::ServiceExt;

	fn request() -> ActionRequest {
		ActionRequest {
			request_id: "request-1".into(),
			subject: Subject {
				user_id: Some("alice".into()),
				agent_id: Some("support-agent".into()),
				tenant_id: Some("tenant-a".into()),
				delegation_id: None,
			},
			action: Action {
				action_type: ActionType::ToolInvoke,
				name: "records.delete".into(),
			},
			resource: Resource {
				id: "records.delete".into(),
				resource_type: ResourceType::Tool,
			},
			authorization_context: AuthorizationContext::default(),
		}
	}

	fn broker() -> CapabilityBroker {
		CapabilityBroker::new(
			Arc::new(InMemoryCapabilityStore::default()),
			Duration::seconds(30),
		)
		.unwrap()
	}

	fn issue_request() -> IssueCapabilityRequest {
		IssueCapabilityRequest {
			protocol_version: CAPABILITY_PROTOCOL_VERSION.into(),
			request: request(),
			arguments_hash: "a".repeat(64),
			ttl_seconds: 20,
		}
	}

	#[test]
	fn issue_then_consume_is_bound_and_one_time() {
		let broker = broker();
		let issued = broker.issue(issue_request()).unwrap();
		let consumed = broker
			.consume(ConsumeCapabilityRequest {
				protocol_version: CAPABILITY_PROTOCOL_VERSION.into(),
				token: issued.token.clone(),
				request: request(),
				arguments_hash: "a".repeat(64),
			})
			.unwrap();
		assert_eq!(consumed.request.request_id, "request-1");
		assert!(matches!(
			broker.consume(ConsumeCapabilityRequest {
				protocol_version: CAPABILITY_PROTOCOL_VERSION.into(),
				token: issued.token,
				request: request(),
				arguments_hash: "a".repeat(64),
			}),
			Err(BrokerError::Store(CapabilityStoreError::NotFound))
		));
	}

	#[test]
	fn mismatch_burns_the_capability_before_replay() {
		let broker = broker();
		let issued = broker.issue(issue_request()).unwrap();
		assert!(matches!(
			broker.consume(ConsumeCapabilityRequest {
				protocol_version: CAPABILITY_PROTOCOL_VERSION.into(),
				token: issued.token.clone(),
				request: request(),
				arguments_hash: "b".repeat(64),
			}),
			Err(BrokerError::Store(CapabilityStoreError::ArgumentsMismatch))
		));
		assert!(matches!(
			broker.consume(ConsumeCapabilityRequest {
				protocol_version: CAPABILITY_PROTOCOL_VERSION.into(),
				token: issued.token,
				request: request(),
				arguments_hash: "a".repeat(64),
			}),
			Err(BrokerError::Store(CapabilityStoreError::NotFound))
		));
	}

	#[test]
	fn expired_capability_is_rejected() {
		let store = InMemoryCapabilityStore::default();
		let request = request();
		store
			.issue(StoredCapability {
				token: "expired".into(),
				request: request.clone(),
				arguments_hash: "hash".into(),
				expires_at: Utc::now() - Duration::seconds(1),
			})
			.unwrap();
		assert_eq!(
			store.consume("expired", &request, "hash", Utc::now()),
			Err(CapabilityStoreError::Expired)
		);
	}

	#[test]
	fn issue_rejects_an_excessive_ttl() {
		let mut request = issue_request();
		request.ttl_seconds = 31;
		assert!(matches!(
			broker().issue(request),
			Err(BrokerError::InvalidTtl)
		));
	}

	#[tokio::test]
	async fn issue_endpoint_requires_a_trusted_gateway_principal() {
		let body = serde_json::to_vec(&issue_request()).unwrap();
		let request = Request::builder()
			.method("POST")
			.uri("/v1/capabilities/issue")
			.header("content-type", "application/json")
			.body(Body::from(body.clone()))
			.unwrap();
		let response = broker().router().oneshot(request).await.unwrap();
		assert_eq!(response.status(), StatusCode::FORBIDDEN);

		let mut request = Request::builder()
			.method("POST")
			.uri("/v1/capabilities/issue")
			.header("content-type", "application/json")
			.body(Body::from(body))
			.unwrap();
		request
			.extensions_mut()
			.insert(BrokerPrincipal::gateway("gateway-a"));
		let response = broker().router().oneshot(request).await.unwrap();
		assert_eq!(response.status(), StatusCode::OK);
	}
}
