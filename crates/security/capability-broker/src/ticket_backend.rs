//! A concrete side-effecting MCP Tool: durable ticket creation. The host must
//! authenticate the gateway transport and inject VerifiedToolGateway, never copy
//! it from a caller header. Capability consume and operation admission occur
//! before the business journal commit; receipts are a separate commit.
use crate::operation::{
	AuthorizedToolOperation, JournalOperationStore, OperationAdmission, OperationOutcome,
};
use crate::{CapabilityBroker, CapabilityConsumerError, HttpCapabilityConsumer};
use axum::{
	Extension, Json, Router,
	extract::{DefaultBodyLimit, State},
	http::{HeaderMap, StatusCode},
	response::{IntoResponse, Response},
	routing::post,
};
use security_audit::{StateJournal, StateJournalConfig};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
	collections::HashSet,
	path::Path,
	sync::{Arc, Mutex},
};

pub const TOOL_NAME: &str = "tickets/create";
/// Set by an authenticated listener/middleware after verifying the peer identity.
#[derive(Clone)]
pub struct VerifiedToolGateway(pub String);

pub trait ToolOperationAuthorizer: Send + Sync + 'static {
	fn authorize(
		&self,
		headers: &HeaderMap,
		args: &Value,
	) -> Result<AuthorizedToolOperation, CapabilityConsumerError>;
}
impl ToolOperationAuthorizer for HttpCapabilityConsumer {
	fn authorize(
		&self,
		headers: &HeaderMap,
		args: &Value,
	) -> Result<AuthorizedToolOperation, CapabilityConsumerError> {
		self.authorize_operation(headers, args, TOOL_NAME)
	}
}
/// Co-located broker adapter. Same atomic consume/binding checks as the HTTPS consumer.
impl ToolOperationAuthorizer for CapabilityBroker {
	fn authorize(
		&self,
		headers: &HeaderMap,
		args: &Value,
	) -> Result<AuthorizedToolOperation, CapabilityConsumerError> {
		crate::consumer::authorize_operation_with(headers, args, TOOL_NAME, |token, request, args| {
			self
				.consume(crate::ConsumeCapabilityRequest {
					protocol_version: crate::CAPABILITY_PROTOCOL_VERSION.into(),
					token: token.into(),
					request,
					arguments_hash: crate::consumer::arguments_hash(args),
				})
				.map_err(|_| CapabilityConsumerError {
					reason: "capability consume refused".into(),
				})
		})
	}
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TicketArguments {
	pub title: String,
	pub description: String,
}
impl TicketArguments {
	fn valid(&self) -> bool {
		!self.title.trim().is_empty() && self.title.len() <= 256 && self.description.len() <= 4096
	}
}
#[derive(Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "camelCase", deny_unknown_fields)]
enum BusinessEvent {
	Header {
		version: u32,
		capacity: usize,
	},
	Created {
		sequence: usize,
		operation_key: String,
		ticket_id: String,
		arguments: TicketArguments,
	},
}
struct BusinessStore {
	journal: StateJournal,
	count: usize,
	keys: HashSet<String>,
	capacity: usize,
}
impl BusinessStore {
	fn open(config: &StateJournalConfig, capacity: usize) -> Result<Self, String> {
		let mut count = 0;
		let mut header = false;
		let mut keys = HashSet::new();
		let mut journal = StateJournal::open(config, |event: BusinessEvent| {
			match event {
				BusinessEvent::Header {
					version: 1,
					capacity: declared,
				} if !header && declared == capacity => {
					header = true;
				},
				BusinessEvent::Created {
					sequence,
					operation_key,
					ticket_id,
					arguments,
				} if header
					&& count < capacity
					&& sequence == count + 1
					&& operation_key.len() == 64
					&& operation_key.bytes().all(|b| b.is_ascii_hexdigit())
					&& uuid::Uuid::parse_str(&ticket_id).is_ok()
					&& arguments.valid() =>
				{
					if !keys.insert(operation_key) {
						return Err(std::io::Error::other("duplicate business operation"));
					}
					count += 1;
				},
				_ => return Err(std::io::Error::other("invalid business journal")),
			}
			Ok(())
		})
		.map_err(|_| "business journal unavailable")?;
		if !header {
			journal
				.append(&BusinessEvent::Header {
					version: 1,
					capacity,
				})
				.map_err(|_| "business journal unavailable")?;
		}
		Ok(Self {
			journal,
			count,
			keys,
			capacity,
		})
	}
	fn create(&mut self, key: &str, arguments: TicketArguments) -> Result<Value, ()> {
		if self.count >= self.capacity || self.keys.contains(key) || !arguments.valid() {
			return Err(());
		}
		let id = uuid::Uuid::new_v4().to_string();
		self
			.journal
			.append(&BusinessEvent::Created {
				sequence: self.count + 1,
				operation_key: key.into(),
				ticket_id: id.clone(),
				arguments,
			})
			.map_err(|_| ())?;
		self.count += 1;
		self.keys.insert(key.into());
		Ok(json!({"ticketId":id}))
	}
}

pub struct DurableTicketTool {
	operations: JournalOperationStore,
	business: Mutex<BusinessStore>,
	authorizer: Arc<dyn ToolOperationAuthorizer>,
	gateway_id: String,
	slots: Arc<tokio::sync::Semaphore>,
}
impl DurableTicketTool {
	/// Separate pre-provisioned private journal directory. No automatic repair/reset.
	pub fn open(
		operation_path: &Path,
		business: &StateJournalConfig,
		capacity: usize,
		gateway_id: String,
		authorizer: Arc<dyn ToolOperationAuthorizer>,
	) -> Result<Arc<Self>, String> {
		if !(1..=4096).contains(&capacity) || gateway_id.is_empty() || gateway_id.len() > 256 {
			return Err("invalid ticket backend limits or gateway identity".into());
		}
		let business_store = BusinessStore::open(business, capacity)?;
		let operations = JournalOperationStore::open(operation_path, capacity)
			.map_err(|_| "operation journal unavailable")?;
		Ok(Arc::new(Self {
			operations,
			business: Mutex::new(business_store),
			authorizer,
			gateway_id,
			slots: Arc::new(tokio::sync::Semaphore::new(16)),
		}))
	}
	pub fn router(self: Arc<Self>) -> Router {
		Router::new()
			.route("/mcp", post(handle))
			.layer(DefaultBodyLimit::max(16384))
			.with_state(self)
	}
	fn execute(
		&self,
		headers: HeaderMap,
		arguments: TicketArguments,
		wire_arguments: Value,
	) -> (StatusCode, Value) {
		// The capability binds the original JSON value, including its serialized
		// property order. Validate a clone, but never reserialize the typed struct
		// before authorization: its field order need not match the caller's.
		let Ok(operation) = self.authorizer.authorize(&headers, &wire_arguments) else {
			return (StatusCode::FORBIDDEN, json!({"state":"unauthorized"}));
		};
		match self.operations.begin(&operation) {
			Ok(OperationAdmission::New(permit)) => {
				// The concrete side effect is synced before the separate receipt. Never
				// hold the admission mutex over business IO, or rerun an unknown result.
				let result = self
					.business
					.lock()
					.map_err(|_| ())
					.and_then(|mut s| s.create(operation.key(), arguments));
				let Ok(result) = result else {
					return (StatusCode::CONFLICT, json!({"state":"unknown"}));
				};

				if permit.complete(&result).is_err() {
					return (StatusCode::CONFLICT, json!({"state":"unknown"}));
				}
				(
					StatusCode::OK,
					json!({"content":[{"type":"text","text":result.to_string()}],"structuredContent":result,"isError":false}),
				)
			},
			Ok(OperationAdmission::Existing(OperationOutcome::Completed { result_hash })) => (
				StatusCode::OK,
				json!({"content":[],"structuredContent":{"state":"completed","resultHash":result_hash},"isError":false}),
			),
			Ok(OperationAdmission::Existing(OperationOutcome::InFlight)) => {
				(StatusCode::CONFLICT, json!({"state":"inFlight"}))
			},
			Ok(OperationAdmission::Existing(OperationOutcome::Unknown)) => {
				(StatusCode::CONFLICT, json!({"state":"unknown"}))
			},
			Err(_) => (
				StatusCode::SERVICE_UNAVAILABLE,
				json!({"state":"unavailable"}),
			),
		}
	}
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Rpc {
	jsonrpc: String,
	#[serde(default)]
	id: Option<Value>,
	method: String,
	#[serde(default)]
	params: Value,
}
async fn handle(
	State(backend): State<Arc<DurableTicketTool>>,
	principal: Option<Extension<VerifiedToolGateway>>,
	headers: HeaderMap,
	Json(rpc): Json<Rpc>,
) -> Response {
	if !principal.is_some_and(|Extension(p)| p.0 == backend.gateway_id) {
		return StatusCode::FORBIDDEN.into_response();
	}
	if rpc.jsonrpc != "2.0"
		|| rpc
			.id
			.as_ref()
			.is_some_and(|id| !(id.is_string() || id.is_i64() || id.is_u64()))
	{
		return StatusCode::BAD_REQUEST.into_response();
	}
	if rpc.method == "notifications/initialized" && rpc.id.is_none() {
		return StatusCode::ACCEPTED.into_response();
	}
	let Some(id) = rpc.id else {
		return StatusCode::BAD_REQUEST.into_response();
	};
	let result = match rpc.method.as_str() {
		"initialize" => {
			let version = rpc.params["protocolVersion"]
				.as_str()
				.filter(|v| matches!(*v, "2025-06-18" | "2025-11-25"));
			let Some(version) = version else {
				return StatusCode::BAD_REQUEST.into_response();
			};
			json!({"protocolVersion":version,"capabilities":{"tools":{}},"serverInfo":{"name":"aisp-durable-ticket-tool","version":"1"}})
		},
		"tools/list" => {
			json!({"tools":[{"name":TOOL_NAME,"description":"Durably create a local ticket","inputSchema":{"type":"object","properties":{"title":{"type":"string","maxLength":256},"description":{"type":"string","maxLength":4096}},"required":["title","description"],"additionalProperties":false}}]})
		},
		"tools/call" => {
			if rpc.params["name"] != TOOL_NAME
				|| !rpc
					.params
					.as_object()
					.is_some_and(|p| p.keys().all(|k| matches!(k.as_str(), "name" | "arguments")))
			{
				return StatusCode::BAD_REQUEST.into_response();
			}
			let wire_arguments = rpc.params["arguments"].clone();
			let Ok(arguments) = serde_json::from_value::<TicketArguments>(wire_arguments.clone()) else {
				return StatusCode::BAD_REQUEST.into_response();
			};
			if !arguments.valid() {
				return StatusCode::BAD_REQUEST.into_response();
			}
			let Ok(slot) = backend.slots.clone().try_acquire_owned() else {
				return StatusCode::TOO_MANY_REQUESTS.into_response();
			};
			let work = backend.clone();
			let Ok((status, result)) = tokio::task::spawn_blocking(move || {
				let _slot = slot;
				work.execute(headers, arguments, wire_arguments)
			})
			.await
			else {
				return StatusCode::SERVICE_UNAVAILABLE.into_response();
			};
			let rpc = if status == StatusCode::OK {
				json!({"jsonrpc":"2.0","id":id,"result":result})
			} else {
				json!({"jsonrpc":"2.0","id":id,"error":{"code":-32001,"message":"Tool execution not confirmed; do not automatically retry","data":result}})
			};
			return (status, [("cache-control", "private, no-store")], Json(rpc)).into_response();
		},
		_ => return StatusCode::FORBIDDEN.into_response(),
	};
	(
		[("cache-control", "private, no-store")],
		Json(json!({"jsonrpc":"2.0","id":id,"result":result})),
	)
		.into_response()
}
