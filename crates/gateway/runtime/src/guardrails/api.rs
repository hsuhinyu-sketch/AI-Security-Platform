use std::time::SystemTime;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq)]
pub struct RequestContext {
	pub prompt: String,
	pub user: Option<String>,
	pub model: Option<String>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq)]
pub struct ToolCallContext {
	pub name: String,
	pub arguments: serde_json::Value,
}

/// Build a guardrails request context from an incoming HTTP request.
/// Used by the core proxy pipeline before backend dispatch.
pub fn request_context_from_http_request(req: &crate::http::Request) -> (RequestContext, String) {
	let prompt = req
		.uri()
		.path_and_query()
		.map(|pq| pq.as_str().to_owned())
		.unwrap_or_default();
	let model = req.uri().query().map(|q| q.to_owned());
	let key = req
		.uri()
		.path()
		.trim_start_matches('/')
		.split('/')
		.next()
		.unwrap_or("request")
		.to_owned();
	(
		RequestContext {
			prompt,
			user: None,
			model,
		},
		key,
	)
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq)]
pub struct ResponseContext {
	pub content: String,
	pub model: String,
}

#[derive(Debug, Clone, Copy, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum SafetyLevel {
	L0,
	L1,
	L2,
	L3,
	L4,
}

#[derive(Debug, Clone, Copy, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum SafetyCategory {
	Content,
	Privacy,
	Authorization,
	ToolCall,
	ModelQuality,
	RemoteCommand,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub enum SafetyAction {
	Block,
	Mask { field: String },
	Defer,
	Degrade { model: String },
	Fallback { target: String },
	Reroute { target: String },
	Queue { queue: String },
	RequireApproval,
	FailSafe,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub enum GuardrailDecision {
	Allow,
	Reject {
		reason: String,
		action: SafetyAction,
	},
	Mask {
		field: String,
		reason: String,
	},
	Defer {
		reason: String,
	},
	RequireApproval {
		reason: String,
	},
	FailSafe {
		reason: String,
	},
}

impl GuardrailDecision {
	pub fn is_allowed(&self) -> bool {
		matches!(self, Self::Allow)
	}

	/// Convert a non-allow decision into a safety event that can be emitted to
	/// the audit log and fed into the circuit breaker component.
	pub fn to_safety_event(
		&self,
		scope: impl Into<String>,
		key: impl Into<String>,
	) -> Option<SafetyEvent> {
		let (level, category, reason, action) = match self {
			Self::Allow => return None,
			Self::Reject { reason, action } => (
				SafetyLevel::L2,
				SafetyCategory::Authorization,
				reason.clone(),
				action.clone(),
			),
			Self::Mask { field, reason } => (
				SafetyLevel::L1,
				SafetyCategory::Privacy,
				format!("{field}: {reason}"),
				SafetyAction::Mask {
					field: field.clone(),
				},
			),
			Self::Defer { reason } => (
				SafetyLevel::L1,
				SafetyCategory::Content,
				reason.clone(),
				SafetyAction::Defer,
			),
			Self::RequireApproval { reason } => (
				SafetyLevel::L3,
				SafetyCategory::ToolCall,
				reason.clone(),
				SafetyAction::RequireApproval,
			),
			Self::FailSafe { reason } => (
				SafetyLevel::L4,
				SafetyCategory::ToolCall,
				reason.clone(),
				SafetyAction::FailSafe,
			),
		};
		let event = SafetyEvent::new(level, category, reason, action, scope, key);
		tracing::warn!(
			target: "guardrails",
			level = ?event.level,
			category = ?event.category,
			reason = %event.reason,
			scope = %event.scope,
			key = %event.key,
			"guardrails safety event"
		);
		Some(event)
	}

	/// Convert a non-allow decision into an HTTP response. Used by the core
	/// proxy pipeline to reject the current request without forwarding it.
	pub fn to_http_response(&self) -> crate::http::Response {
		let (status, reason) = match self {
			Self::Allow => unreachable!("allow decisions do not produce a rejection response"),
			Self::Reject { reason, .. } | Self::RequireApproval { reason } => {
				(crate::http::StatusCode::FORBIDDEN, reason.clone())
			},
			Self::Defer { reason } => (crate::http::StatusCode::ACCEPTED, reason.clone()),
			Self::Mask { field, reason } => (
				crate::http::StatusCode::FORBIDDEN,
				format!("masked field {field}: {reason}"),
			),
			Self::FailSafe { reason } => (crate::http::StatusCode::SERVICE_UNAVAILABLE, reason.clone()),
		};
		::http::Response::builder()
			.status(status)
			.header(::http::header::CONTENT_TYPE, "application/json")
			.body(crate::http::Body::from(format!(
				"{{\"error\":{{\"message\":\"{}\"}}}}",
				reason
			)))
			.expect("guardrails response is valid")
	}
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq)]
pub struct SafetyEvent {
	pub level: SafetyLevel,
	pub category: SafetyCategory,
	pub reason: String,
	pub action: SafetyAction,
	pub scope: String,
	pub key: String,
	pub occurred_at: SystemTime,
}

impl SafetyEvent {
	pub fn new(
		level: SafetyLevel,
		category: SafetyCategory,
		reason: impl Into<String>,
		action: SafetyAction,
		scope: impl Into<String>,
		key: impl Into<String>,
	) -> Self {
		Self {
			level,
			category,
			reason: reason.into(),
			action,
			scope: scope.into(),
			key: key.into(),
			occurred_at: SystemTime::now(),
		}
	}
}

#[async_trait::async_trait]
pub trait VehicleGuardrails: Send + Sync {
	async fn check_request(
		&self,
		ctx: &RequestContext,
		vehicle: &super::vehicle::VehicleState,
	) -> GuardrailDecision;

	async fn check_tool_call(
		&self,
		ctx: &ToolCallContext,
		vehicle: &super::vehicle::VehicleState,
	) -> GuardrailDecision;

	async fn check_response(
		&self,
		ctx: &ResponseContext,
		vehicle: &super::vehicle::VehicleState,
	) -> GuardrailDecision;
}
