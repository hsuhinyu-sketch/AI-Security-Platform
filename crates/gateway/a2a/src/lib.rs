//! A2A JSON-RPC validation and Agent Card adaptation without runtime dependencies.
use http::Uri;
pub mod downloads;
pub mod execution;
pub mod objects;
pub mod push;
pub mod recovery;
pub mod streaming;

use serde::Deserialize;
use serde_json::Value;

/// Explicit gateway-local event recovery method.
pub const EVENT_READ_METHOD: &str = "aisp.events/read";

#[derive(Deserialize)]
pub struct RequestEnvelope {
	pub jsonrpc: String,
	pub id: Value,
	pub method: String,
	pub params: Value,
	#[serde(flatten)]
	extra: serde_json::Map<String, Value>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
	Send,
	Stream,
	Get,
	Cancel,
	Resubscribe,
	PushSet,
	PushGet,
	PushList,
	PushDelete,
	Recovery,
}
impl Method {
	pub fn parse(method: &str) -> Option<Self> {
		Some(match method {
			"message/send" => Self::Send,
			"message/stream" => Self::Stream,
			"tasks/get" => Self::Get,
			"tasks/cancel" => Self::Cancel,
			"tasks/resubscribe" => Self::Resubscribe,
			"tasks/pushNotificationConfig/set" => Self::PushSet,
			"tasks/pushNotificationConfig/get" => Self::PushGet,
			"tasks/pushNotificationConfig/list" => Self::PushList,
			"tasks/pushNotificationConfig/delete" => Self::PushDelete,
			EVENT_READ_METHOD => Self::Recovery,
			_ => return None,
		})
	}
	pub fn streaming(self) -> bool {
		matches!(self, Self::Stream | Self::Resubscribe)
	}
	pub fn push_operation(self) -> Option<push::Operation> {
		Some(match self {
			Self::PushSet => push::Operation::Set,
			Self::PushGet => push::Operation::Get,
			Self::PushList => push::Operation::List,
			Self::PushDelete => push::Operation::Delete,
			_ => return None,
		})
	}
}
pub fn supported_method(method: &str) -> bool {
	Method::parse(method).is_some()
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpKind {
	AgentCard,
	Rpc,
	Unknown,
}
pub fn classify_http(method: &http::Method, path: &str) -> HttpKind {
	if method == http::Method::GET
		&& (path.ends_with("/.well-known/agent.json") || path.ends_with("/.well-known/agent-card.json"))
	{
		HttpKind::AgentCard
	} else if method == http::Method::POST {
		HttpKind::Rpc
	} else {
		HttpKind::Unknown
	}
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
	Unsupported,
	ResponseBinding,
	EventCursor,
	DownloadSource,
	DownloadIntegrity,
}
impl std::fmt::Display for Error {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		write!(f, "invalid A2A protocol data: {self:?}")
	}
}
impl std::error::Error for Error {}

impl RequestEnvelope {
	pub fn validated_method(self) -> anyhow::Result<String> {
		anyhow::ensure!(
			self.jsonrpc == "2.0"
				&& (self.id.is_string() || self.id.as_i64().is_some() || self.id.as_u64().is_some())
				&& !self.method.is_empty()
				&& self.method.len() <= 256
				&& self.params.is_object()
				&& !self.extra.contains_key("result")
				&& !self.extra.contains_key("error"),
			"invalid A2A request envelope"
		);
		Ok(self.method)
	}
}

pub fn rewrite_card(
	agent_card: &mut Value,
	uri: Uri,
	protected: bool,
	push_enabled: bool,
) -> anyhow::Result<()> {
	let gateway_base = build_agent_path(uri);
	if protected {
		// Do not advertise protocols/callbacks which the protected adapter refuses.
		if agent_card.get("supportedInterfaces").is_some()
			|| agent_card
				.get("protocolVersion")
				.is_some_and(|v| v != "0.3.0")
		{
			anyhow::bail!("protected Agent Card requires the adapted v0.3 JSON-RPC binding");
		}
		if let Some(capabilities) = agent_card
			.get_mut("capabilities")
			.and_then(Value::as_object_mut)
		{
			let push = push_enabled && capabilities.get("pushNotifications") == Some(&Value::Bool(true));
			capabilities.insert("pushNotifications".into(), Value::Bool(push));
			capabilities.insert("stateTransitionHistory".into(), Value::Bool(false));
			capabilities.remove("extensions");
		}
		agent_card
			.as_object_mut()
			.ok_or_else(|| anyhow::anyhow!("invalid card"))?
			.insert(
				"supportsAuthenticatedExtendedCard".into(),
				Value::Bool(false),
			);
	}
	if let Some(interfaces) = agent_card.get_mut("supportedInterfaces") {
		// A2A v1.0: rewrite url inside each AgentInterface entry.
		let arr = interfaces
			.as_array_mut()
			.ok_or_else(|| anyhow::anyhow!("agent card supportedInterfaces is not an array"))?;
		for iface in arr.iter_mut() {
			if let Some(url_val) = iface.get_mut("url")
				&& let Some(s) = url_val.as_str()
				&& let Ok(iface_uri) = s.parse::<Uri>()
			{
				let path_and_query = iface_uri
					.path_and_query()
					.map(|pq| pq.as_str())
					.unwrap_or_else(|| iface_uri.path());
				*url_val = Value::String(format!("{gateway_base}{path_and_query}"));
			}
		}
	} else if let Some(url_field) = agent_card.get_mut("url") {
		// A2A v0.3: rewrite the single top-level url.
		*url_field = Value::String(gateway_base);
	} else {
		anyhow::bail!("agent card missing URL (no 'url' or 'supportedInterfaces' field)");
	}
	Ok(())
}

fn build_agent_path(uri: Uri) -> String {
	// Keep the original URL the found the agent at, but strip the agent card suffix.
	// Note: this won't work in the case they are hosting their agent in other locations.
	let path = uri.path();
	let path = path.strip_suffix("/.well-known/agent.json").unwrap_or(path);
	let path = path
		.strip_suffix("/.well-known/agent-card.json")
		.unwrap_or(path);

	uri.to_string().replace(uri.path(), path)
}

#[cfg(test)]
mod tests;
