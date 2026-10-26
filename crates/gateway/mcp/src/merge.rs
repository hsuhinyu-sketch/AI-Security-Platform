//! Protocol result aggregation and the multi-upstream stream state machine.
//!
//! Host policy is injected at the same point where objects are admitted. Filtered
//! objects are never projected into the downstream list, and the component never
//! receives a CEL evaluator or a Runtime connection.
use futures_core::Stream;
use futures_util::{StreamExt, stream::BoxStream};
use rmcp::model::{
	ListPromptsResult, ListResourceTemplatesResult, ListResourcesResult, ListToolsResult, Prompt,
	RequestId, Resource, ResourceTemplate, ServerJsonRpcMessage, ServerResult,
	SubscriptionsListenResult, Tool,
};
use std::pin::Pin;
use std::task::{Context, Poll};

use crate::routing::{resource_name, resource_uri};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MergeFailureMode {
	FailClosed,
	FailOpen,
}

/// An upstream stream ended before its terminal response. The Host maps this
/// into its existing error container without the component owning that type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MergeError {
	UnexpectedEnd,
}

impl std::fmt::Display for MergeError {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.write_str("upstream stream ended unexpectedly")
	}
}

impl std::error::Error for MergeError {}

/// A stream of already-decoded server messages. The Host owns transport decoding.
pub struct MessageStream<E>(BoxStream<'static, Result<ServerJsonRpcMessage, E>>);

impl<E: Send + 'static> MessageStream<E> {
	/// Never yields and never closes.
	pub fn pending() -> Self {
		Self(futures_util::stream::pending().boxed())
	}

	/// Closes immediately.
	pub fn empty() -> Self {
		Self(futures_util::stream::empty().boxed())
	}

	pub fn from_stream<S>(stream: S) -> Self
	where
		S: Stream<Item = Result<ServerJsonRpcMessage, E>> + Send + 'static,
	{
		Self(stream.boxed())
	}

	pub fn from_result<T: Into<ServerResult>>(id: RequestId, result: T) -> Self {
		MessageStream::from(ServerJsonRpcMessage::response(result.into(), id))
	}

	pub fn map_server_messages(
		self,
		mut f: impl FnMut(ServerJsonRpcMessage) -> ServerJsonRpcMessage + Send + 'static,
	) -> Self {
		Self(self.0.map(move |message| message.map(&mut f)).boxed())
	}
}

impl<E: Send + 'static> Stream for MessageStream<E> {
	type Item = Result<ServerJsonRpcMessage, E>;

	fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
		self.get_mut().0.as_mut().poll_next(cx)
	}
}

impl<E> From<ServerJsonRpcMessage> for MessageStream<E>
where
	E: Send + 'static,
{
	fn from(value: ServerJsonRpcMessage) -> Self {
		Self(futures_util::stream::once(async { Ok(value) }).boxed())
	}
}

impl<E> From<Result<ServerJsonRpcMessage, E>> for MessageStream<E>
where
	E: Send + 'static,
{
	fn from(value: Result<ServerJsonRpcMessage, E>) -> Self {
		Self(futures_util::stream::once(async { value }).boxed())
	}
}

/// A terminal merge consumes the successful results in upstream order. The Host
/// builds this closure with its own policy context already captured.
pub type MergeFn<E> =
	dyn FnOnce(Vec<(String, ServerResult)>) -> Result<ServerResult, E> + Send + Sync + 'static;

/// Merges notifications/errors from every upstream and emits one terminal result.
/// The state machine is protocol logic; errors and admission decisions belong to
/// the caller.
pub struct MergeStream<E> {
	streams: Vec<Option<(String, MessageStream<E>)>>,
	terminal_messages: Vec<Option<(String, ServerResult)>>,
	complete: bool,
	req_id: RequestId,
	merge: Option<Box<MergeFn<E>>>,
	failure_mode: MergeFailureMode,
}

impl<E> MergeStream<E>
where
	E: From<MergeError> + Send + 'static,
{
	pub fn new_without_merge(
		streams: Vec<(String, MessageStream<E>)>,
		failure_mode: MergeFailureMode,
	) -> Self {
		Self::new_internal(streams, RequestId::Number(0), None, failure_mode)
	}

	pub fn new(
		streams: Vec<(String, MessageStream<E>)>,
		req_id: RequestId,
		merge: Box<MergeFn<E>>,
		failure_mode: MergeFailureMode,
	) -> Self {
		Self::new_internal(streams, req_id, Some(merge), failure_mode)
	}

	fn new_internal(
		streams: Vec<(String, MessageStream<E>)>,
		req_id: RequestId,
		merge: Option<Box<MergeFn<E>>>,
		failure_mode: MergeFailureMode,
	) -> Self {
		let terminal_messages = streams.iter().map(|_| None).collect();
		Self {
			streams: streams.into_iter().map(Some).collect(),
			terminal_messages,
			req_id,
			complete: false,
			merge,
			failure_mode,
		}
	}

	fn merge_terminal_messages(&mut self) -> Result<ServerJsonRpcMessage, E> {
		let messages = self
			.terminal_messages
			.iter_mut()
			.filter_map(Option::take)
			.collect();
		let merge = self
			.merge
			.take()
			.expect("merge_terminal_messages called twice");
		Ok(ServerJsonRpcMessage::response(
			merge(messages)?,
			self.req_id.clone(),
		))
	}

	fn fail_closed(&mut self, error: E) -> Poll<Option<Result<ServerJsonRpcMessage, E>>> {
		self.complete = true;
		Poll::Ready(Some(Err(error)))
	}
}

impl<E> Stream for MergeStream<E>
where
	E: From<MergeError> + Send + 'static,
{
	type Item = Result<ServerJsonRpcMessage, E>;

	fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
		let this = self.get_mut();
		if this.complete {
			return Poll::Ready(None);
		}

		let mut any_pending = false;
		for i in 0..this.streams.len() {
			let (name, result) = {
				let Some(stream) = this.streams[i].as_mut() else {
					continue;
				};
				let name = stream.0.clone();
				(name, Pin::new(&mut stream.1).poll_next(cx))
			};

			let mut remove = false;
			match result {
				Poll::Ready(Some(Ok(ServerJsonRpcMessage::Response(response)))) => {
					remove = true;
					this.terminal_messages[i] = Some((name, response.result));
				},
				Poll::Ready(Some(Ok(message))) => return Poll::Ready(Some(Ok(message))),
				Poll::Ready(Some(Err(error))) => match this.failure_mode {
					MergeFailureMode::FailOpen => {
						remove = true;
					},
					MergeFailureMode::FailClosed => {
						return this.fail_closed(error);
					},
				},
				Poll::Ready(None) => match this.failure_mode {
					MergeFailureMode::FailOpen => {
						remove = true;
					},
					MergeFailureMode::FailClosed => {
						return this.fail_closed(E::from(MergeError::UnexpectedEnd));
					},
				},
				Poll::Pending => {
					any_pending = true;
				},
			}
			if remove {
				this.streams[i] = None;
			}
		}

		if any_pending {
			return Poll::Pending;
		}

		this.complete = true;
		if this.merge.is_some() {
			Poll::Ready(Some(this.merge_terminal_messages()))
		} else {
			Poll::Ready(None)
		}
	}
}

/// Existing empty-success fallback used by lifecycle methods.
pub fn empty_result() -> ServerResult {
	ServerResult::empty(())
}

/// The downstream subscription correlation ID must not be the upstream one.
pub fn subscription_ack(subscription_id: RequestId) -> ServerResult {
	SubscriptionsListenResult::new(subscription_id).into()
}

/// Admit each tool before applying the multiplexed name. `admit` is the trusted
/// Host hook; returning false drops the object without exposing it downstream.
pub fn merge_tools<S, F>(
	results: impl IntoIterator<Item = (S, ServerResult)>,
	default_target: Option<&str>,
	mut admit: F,
) -> ServerResult
where
	S: AsRef<str>,
	F: FnMut(&str, &Tool) -> bool,
{
	let mut tools = Vec::new();
	for (server, result) in results {
		let ServerResult::ListToolsResult(result) = result else {
			continue;
		};
		let server = server.as_ref();
		for mut tool in result.tools {
			if !admit(server, &tool) {
				continue;
			}
			tool.name = resource_name(default_target, server, &tool.name).into();
			tools.push(tool);
		}
	}
	ListToolsResult {
		tools,
		..Default::default()
	}
	.into()
}

pub fn merge_prompts<S, F>(
	results: impl IntoIterator<Item = (S, ServerResult)>,
	default_target: Option<&str>,
	mut admit: F,
) -> ServerResult
where
	S: AsRef<str>,
	F: FnMut(&str, &Prompt) -> bool,
{
	let mut prompts = Vec::new();
	for (server, result) in results {
		let ServerResult::ListPromptsResult(result) = result else {
			continue;
		};
		let server = server.as_ref();
		for mut prompt in result.prompts {
			if !admit(server, &prompt) {
				continue;
			}
			prompt.name = resource_name(default_target, server, &prompt.name);
			prompts.push(prompt);
		}
	}
	ListPromptsResult {
		prompts,
		..Default::default()
	}
	.into()
}

pub fn merge_resources<S, F>(
	results: impl IntoIterator<Item = (S, ServerResult)>,
	default_target: Option<&str>,
	mut admit: F,
) -> ServerResult
where
	S: AsRef<str>,
	F: FnMut(&str, &Resource) -> bool,
{
	let mut resources = Vec::new();
	for (server, result) in results {
		let ServerResult::ListResourcesResult(result) = result else {
			continue;
		};
		let server = server.as_ref();
		for mut resource in result.resources {
			if !admit(server, &resource) {
				continue;
			}
			resource.uri = resource_uri(default_target, server, &resource.uri);
			resources.push(resource);
		}
	}
	ListResourcesResult {
		resources,
		..Default::default()
	}
	.into()
}

pub fn merge_resource_templates<S, F>(
	results: impl IntoIterator<Item = (S, ServerResult)>,
	default_target: Option<&str>,
	mut admit: F,
) -> ServerResult
where
	S: AsRef<str>,
	F: FnMut(&str, &ResourceTemplate) -> bool,
{
	let mut resource_templates = Vec::new();
	for (server, result) in results {
		let ServerResult::ListResourceTemplatesResult(result) = result else {
			continue;
		};
		let server = server.as_ref();
		for mut template in result.resource_templates {
			if !admit(server, &template) {
				continue;
			}
			template.uri_template = resource_uri(default_target, server, &template.uri_template);
			resource_templates.push(template);
		}
	}
	ListResourceTemplatesResult {
		resource_templates,
		..Default::default()
	}
	.into()
}

#[cfg(test)]
mod tests;
