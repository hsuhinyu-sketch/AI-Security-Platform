//! Protocol-owned request dispatch for the Host-protected MCP execution path.
//!
//! The component decides which MCP operation is being requested, maps the
//! multiplexed target, and merges upstream results. The Host supplies already
//! protected streams, a terminal merge closure and an optional response hook.
//! No connection, policy object, CEL evaluator or Runtime error type crosses
//! this boundary.
use crate::merge::{MergeError, MergeFailureMode, MergeFn, MergeStream, MessageStream};
use crate::routing::{self, ObjectRoute};
use futures_util::StreamExt;
use gateway_protocol_core::execution::ExecutionFuture;
use rmcp::model::{ClientRequest, JsonRpcRequest};

/// Request-scoped routing data. The Host owns the actual target set.
#[derive(Debug, Clone, Copy)]
pub struct RouteContext<'a> {
	pub default_target: Option<&'a str>,
}

/// Streams and terminal behavior prepared by the Host. `merge` may capture CEL
/// and Host policy state; the component only invokes it.
pub struct FanoutPlan<E> {
	pub streams: Vec<(String, MessageStream<E>)>,
	pub merge: Box<MergeFn<E>>,
	pub failure_mode: MergeFailureMode,
}

/// One already-protected single-target stream.
pub struct SinglePlan<E> {
	pub stream: MessageStream<E>,
}

impl<E> FanoutPlan<E>
where
	E: Send + 'static,
{
	/// Map the Host transport error while preserving the same protocol merge.
	pub fn map_error<F>(self, map: fn(E) -> F) -> FanoutPlan<F>
	where
		F: Send + 'static,
	{
		let streams = self
			.streams
			.into_iter()
			.map(|(name, stream)| {
				(
					name,
					MessageStream::from_stream(stream.map(move |message| message.map_err(map))),
				)
			})
			.collect();
		let merge = self.merge;
		let merge: Box<MergeFn<F>> = Box::new(move |messages| merge(messages).map_err(map));
		FanoutPlan {
			streams,
			merge,
			failure_mode: self.failure_mode,
		}
	}
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FanoutMethod {
	Initialize,
	Discover,
	Ping,
	SetLevel,
	SubscriptionsListen,
	Tools,
	Prompts,
	Resources,
	ResourceTemplates,
}

impl FanoutMethod {
	pub fn from_request(request: &ClientRequest) -> Option<Self> {
		match request {
			ClientRequest::InitializeRequest(_) => Some(Self::Initialize),
			ClientRequest::DiscoverRequest(_) => Some(Self::Discover),
			ClientRequest::PingRequest(_) => Some(Self::Ping),
			ClientRequest::SetLevelRequest(_) => Some(Self::SetLevel),
			ClientRequest::SubscriptionsListenRequest(_) => Some(Self::SubscriptionsListen),
			ClientRequest::ListToolsRequest(_) => Some(Self::Tools),
			ClientRequest::ListPromptsRequest(_) => Some(Self::Prompts),
			ClientRequest::ListResourcesRequest(_) => Some(Self::Resources),
			ClientRequest::ListResourceTemplatesRequest(_) => Some(Self::ResourceTemplates),
			_ => None,
		}
	}
}

/// Complete protected operations supplied by the Host. `Context` is intentionally
/// opaque to this component; it may be `IncomingRequestContext` in the Runtime
/// adapter, but no Host fields are named here.
pub trait HostExecution {
	type Context: Send;
	type Error: From<MergeError> + Send + 'static;

	fn fanout<'a>(
		&'a mut self,
		context: Self::Context,
		method: FanoutMethod,
		request: JsonRpcRequest<ClientRequest>,
		target: Option<String>,
	) -> ExecutionFuture<'a, FanoutPlan<Self::Error>, Self::Error>;

	/// Resolve a Task through the Host's owner-bound registry and execute with
	/// its original ticket. A client Task ID is never an execution grant.
	fn task<'a>(
		&'a mut self,
		context: Self::Context,
		request: JsonRpcRequest<ClientRequest>,
	) -> ExecutionFuture<'a, SinglePlan<Self::Error>, Self::Error>;

	fn call<'a>(
		&'a mut self,
		context: Self::Context,
		route: ObjectRoute,
		request: JsonRpcRequest<ClientRequest>,
	) -> ExecutionFuture<'a, SinglePlan<Self::Error>, Self::Error>;

	/// Host response finalization after protocol merge (protected capability
	/// restriction, response guardrails). The Host owns any state it needs.
	fn finish_fanout(&mut self, stream: MessageStream<Self::Error>) -> MessageStream<Self::Error>;
}

pub enum DispatchOutcome<E> {
	Messages(MessageStream<E>),
	/// Not implemented by the gateway. No Host operation has been invoked.
	Unsupported,
}

impl<E> std::fmt::Debug for DispatchOutcome<E> {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		match self {
			Self::Messages(_) => f.write_str("Messages(..)"),
			Self::Unsupported => f.write_str("Unsupported"),
		}
	}
}

pub enum DispatchError<E> {
	Host(E),
	Route(routing::Error),
}

impl<E: std::fmt::Debug> std::fmt::Debug for DispatchError<E> {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		match self {
			Self::Host(error) => f.debug_tuple("Host").field(error).finish(),
			Self::Route(error) => f.debug_tuple("Route").field(error).finish(),
		}
	}
}

/// Dispatch discovery lists and object requests through complete Host operations.
/// The Host must not call this after it has already routed or mutated a request.
pub async fn dispatch<H: HostExecution + Send>(
	mut request: JsonRpcRequest<ClientRequest>,
	route_context: RouteContext<'_>,
	host: &mut H,
	context: H::Context,
) -> Result<DispatchOutcome<H::Error>, DispatchError<H::Error>>
where
	H::Error: From<MergeError> + Send + 'static,
{
	let id = request.id.clone();

	if let Some(method) = FanoutMethod::from_request(&request.request) {
		let target = if let ClientRequest::SubscriptionsListenRequest(listen) = &mut request.request
			&& let Some(resources) = &mut listen.params.notifications.resource_subscriptions
		{
			let (target, mapped) =
				routing::route_subscription_resources(route_context.default_target, resources)
					.map_err(DispatchError::Route)?;
			*resources = mapped;
			target
		} else {
			None
		};
		let plan = host
			.fanout(context, method, request, target)
			.await
			.map_err(DispatchError::Host)?;
		let merged = MessageStream::from_stream(MergeStream::new(
			plan.streams,
			id,
			plan.merge,
			plan.failure_mode,
		));
		return Ok(DispatchOutcome::Messages(host.finish_fanout(merged)));
	}

	if matches!(
		&request.request,
		ClientRequest::GetTaskRequest(_)
			| ClientRequest::GetTaskPayloadRequest(_)
			| ClientRequest::CancelTaskRequest(_)
	) {
		let plan = host
			.task(context, request)
			.await
			.map_err(DispatchError::Host)?;
		return Ok(DispatchOutcome::Messages(plan.stream));
	}

	if matches!(
		&request.request,
		ClientRequest::CallToolRequest(_)
			| ClientRequest::GetPromptRequest(_)
			| ClientRequest::ReadResourceRequest(_)
			| ClientRequest::CompleteRequest(_)
			| ClientRequest::SubscribeRequest(_)
			| ClientRequest::UnsubscribeRequest(_)
	) {
		let route = routing::route_request(route_context.default_target, &mut request.request)
			.map_err(DispatchError::Route)?;
		let Some(route) = route else {
			// Object requests always produce a route; retain a defensive
			// unsupported result without mutating the request twice.
			return Ok(DispatchOutcome::Unsupported);
		};
		let plan = host
			.call(context, route, request)
			.await
			.map_err(DispatchError::Host)?;
		return Ok(DispatchOutcome::Messages(plan.stream));
	}

	Ok(DispatchOutcome::Unsupported)
}

#[cfg(test)]
#[path = "execution_tests.rs"]
mod tests;
