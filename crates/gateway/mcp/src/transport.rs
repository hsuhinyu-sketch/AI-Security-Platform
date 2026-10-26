//! Connection-local protocol correlation. The Host owns I/O, scheduling and waiters.
use http::Uri;
use rmcp::model::{RequestId, ServerJsonRpcMessage};
use std::collections::{HashMap, hash_map::Entry};

pub const MAX_PENDING_RESPONSES: usize = 128;

pub struct PendingResponses<T> {
	entries: HashMap<RequestId, T>,
}

impl<T> Default for PendingResponses<T> {
	fn default() -> Self {
		Self {
			entries: HashMap::new(),
		}
	}
}

pub enum Inbound<T> {
	Reply(T, ServerJsonRpcMessage),
	Event(ServerJsonRpcMessage),
	UnmatchedReply,
}

impl<T> PendingResponses<T> {
	/// A live ID cannot replace an existing waiter, including a cancelled waiter
	/// retained until its peer reply. Reuse before that reply would be ambiguous.
	pub fn register(&mut self, id: RequestId, waiter: T) -> bool {
		if self.entries.len() >= MAX_PENDING_RESPONSES {
			return false;
		}
		match self.entries.entry(id) {
			Entry::Vacant(entry) => {
				entry.insert(waiter);
				true
			},
			Entry::Occupied(_) => false,
		}
	}

	pub fn route(&mut self, message: ServerJsonRpcMessage) -> Inbound<T> {
		let id = match &message {
			ServerJsonRpcMessage::Response(response) => &response.id,
			ServerJsonRpcMessage::Error(error) => match error.id.as_ref() {
				Some(id) => id,
				None => return Inbound::Event(message),
			},
			_ => return Inbound::Event(message),
		};
		match self.entries.remove(id) {
			Some(waiter) => Inbound::Reply(waiter, message),
			None => Inbound::UnmatchedReply,
		}
	}

	pub fn any(&self, predicate: impl FnMut(&T) -> bool) -> bool {
		self.entries.values().any(predicate)
	}

	pub fn discard(&mut self, id: &RequestId) {
		self.entries.remove(id);
	}
	pub fn clear(&mut self) {
		self.entries.clear();
	}
}

/// Resolve the legacy SSE endpoint event; the Host still binds and authorizes
/// the actual destination before sending. A parsed URI is not an egress grant.
pub fn message_endpoint(base: Uri, endpoint: &str) -> Result<Uri, http::Error> {
	if endpoint.starts_with("http://") || endpoint.starts_with("https://") {
		return endpoint.parse::<Uri>().map_err(Into::into);
	}
	let mut parts = base.into_parts();
	let path = if endpoint.starts_with('?') {
		format!(
			"{}{}",
			parts
				.path_and_query
				.as_ref()
				.map_or("/", |path| path.path()),
			endpoint
		)
	} else if endpoint.starts_with('/') {
		endpoint.to_owned()
	} else {
		format!("/{endpoint}")
	};
	parts.path_and_query = Some(path.parse()?);
	Uri::from_parts(parts).map_err(Into::into)
}

#[cfg(test)]
#[path = "transport/tests.rs"]
mod tests;
