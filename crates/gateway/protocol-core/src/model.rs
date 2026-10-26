//! Non-streaming text generation through a Host-bound, protected model route.
//!
//! The Host binds the destination, caller, configuration lease and execution budget.
//! Neither input nor output is an authorization receipt. Implementations must check
//! the final request before sending and must not detach work from the returned future.
use crate::execution::ExecutionFuture;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TextRole {
	System,
	User,
	Assistant,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TextMessage {
	pub role: TextRole,
	pub text: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TextRequest {
	pub messages: Vec<TextMessage>,
	pub max_tokens: u64,
	pub stop: Option<Vec<String>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TextStop {
	EndTurn,
	MaxTokens,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TextResponse {
	pub model: String,
	pub text: String,
	pub stop: TextStop,
}

pub trait BoundTextGeneration: Send + Sync {
	type Error;

	/// Dropping this future cancels the local attempt; remote effects cannot be undone.
	fn generate(&self, request: TextRequest) -> ExecutionFuture<'_, TextResponse, Self::Error>;
}
