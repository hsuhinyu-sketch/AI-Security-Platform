//! Transport-neutral execution correlation and check stages. Never deserialize an internal ID.

/// Generated at trusted ingress; cloning preserves one request across retries and fanout.
/// Wire RPC IDs and caller headers remain separate, untrusted correlation values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestContext {
	request_id: String,
}

impl Default for RequestContext {
	fn default() -> Self {
		Self {
			request_id: uuid::Uuid::new_v4().to_string(),
		}
	}
}

impl RequestContext {
	pub fn request_id(&self) -> &str {
		&self.request_id
	}
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CheckStage {
	Candidate,
	Dispatch,
	Continuation,
}

impl CheckStage {
	pub const fn as_str(self) -> &'static str {
		match self {
			Self::Candidate => "candidate",
			Self::Dispatch => "dispatch",
			Self::Continuation => "continuation",
		}
	}
}

/// Stable, redacted transport-facing categories; detailed decisions remain internal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecurityFailureKind {
	Denied,
	CapabilityRejected,
	CapabilityUnavailable,
}

impl SecurityFailureKind {
	pub const fn as_str(self) -> &'static str {
		match self {
			Self::Denied => "security_denied",
			Self::CapabilityRejected => "capability_rejected",
			Self::CapabilityUnavailable => "capability_unavailable",
		}
	}
}
