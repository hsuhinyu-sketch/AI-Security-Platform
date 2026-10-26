//! Host adapter for the protocol-owned MCP request dispatcher.
//!
//! The adapter keeps session, connection, policy and telemetry state in the Host.
//! The component receives only opaque request context and already-protected streams.
use futures_util::StreamExt;
use gateway_mcp::execution::{FanoutMethod, FanoutPlan, HostExecution, SinglePlan};
use gateway_mcp::merge::MessageStream;
use gateway_mcp::routing::ObjectRoute;
use gateway_protocol_core::execution::ExecutionFuture;
use rmcp::model::{ClientRequest, JsonRpcRequest};

use crate::mcp::MCPInfo;
use crate::mcp::handler::{FanoutFinish, Relay};
use crate::mcp::mergestream::Messages;
use crate::mcp::rbac::CelExecWrapper;
use crate::mcp::upstream::{IncomingRequestContext, UpstreamError};
use crate::telemetry::log::AsyncLog;

pub(super) struct SessionHost<'a> {
	relay: &'a Relay,
	span: &'a mut crate::telemetry::log::SpanWriteOnDrop,
	log: &'a AsyncLog<MCPInfo>,
	cel: CelExecWrapper,
	finish: Option<FanoutFinish>,
}

impl<'a> SessionHost<'a> {
	pub(super) fn new(
		relay: &'a Relay,
		span: &'a mut crate::telemetry::log::SpanWriteOnDrop,
		log: &'a AsyncLog<MCPInfo>,
		cel: CelExecWrapper,
	) -> Self {
		Self {
			relay,
			span,
			log,
			cel,
			finish: None,
		}
	}
}

impl HostExecution for SessionHost<'_> {
	type Context = IncomingRequestContext;
	type Error = UpstreamError;

	fn fanout<'a>(
		&'a mut self,
		context: Self::Context,
		method: FanoutMethod,
		request: JsonRpcRequest<ClientRequest>,
		target: Option<String>,
	) -> ExecutionFuture<'a, FanoutPlan<Self::Error>, Self::Error> {
		Box::pin(async move {
			if FanoutMethod::from_request(&request.request) != Some(method)
				|| (target.is_some() && method != FanoutMethod::SubscriptionsListen)
			{
				return Err(UpstreamError::InvalidMethod(
					request.request.method().to_string(),
				));
			}
			let request_id = context.security_request_id().to_owned();
			let identity = crate::mcp::security::identity_from_context(&context);
			let merge = match method {
				FanoutMethod::Initialize => {
					let ClientRequest::InitializeRequest(initialize) = &request.request else {
						unreachable!()
					};
					self.relay.merge_initialize(
						initialize.params.protocol_version.clone(),
						self.relay.is_multiplexing(),
					)
				},
				FanoutMethod::Discover => self.relay.merge_discover(self.relay.is_multiplexing()),
				FanoutMethod::Ping | FanoutMethod::SetLevel => self.relay.merge_empty(),
				FanoutMethod::Tools => self.relay.merge_tools(request_id, identity),
				FanoutMethod::Prompts => self.relay.merge_prompts(request_id, identity),
				FanoutMethod::Resources => self.relay.merge_resources(request_id, identity),
				FanoutMethod::ResourceTemplates => {
					self.relay.merge_resource_templates(request_id, identity)
				},
				FanoutMethod::SubscriptionsListen => {
					self.relay.validate_subscription_request(
						&request,
						target.as_deref(),
						self.span,
						self.log,
						&self.cel,
					)?;
					self.relay.merge_subscriptions_listen(request.id.clone())
				},
			};
			let (plan, finish) = self
				.relay
				.prepare_fanout(request, context, merge, target.map(|target| vec![target]))
				.await?;
			self.finish = Some(finish);
			Ok(plan.map_error(UpstreamError::Http))
		})
	}

	fn task<'a>(
		&'a mut self,
		mut context: Self::Context,
		mut request: JsonRpcRequest<ClientRequest>,
	) -> ExecutionFuture<'a, SinglePlan<Self::Error>, Self::Error> {
		Box::pin(async move {
			let target = super::session_security::tasks::route(&mut request, &mut context)?;
			let stream = self.relay.prepare_single(request, context, &target).await?;
			Ok(SinglePlan {
				stream: to_execution_messages(stream),
			})
		})
	}

	fn call<'a>(
		&'a mut self,
		context: Self::Context,
		route: ObjectRoute,
		request: JsonRpcRequest<ClientRequest>,
	) -> ExecutionFuture<'a, SinglePlan<Self::Error>, Self::Error> {
		Box::pin(async move {
			let stream = self
				.relay
				.prepare_routed_object_request(route, request, context, self.span, self.log, &self.cel)
				.await?;
			Ok(SinglePlan {
				stream: to_execution_messages(stream),
			})
		})
	}

	fn finish_fanout(&mut self, stream: MessageStream<Self::Error>) -> MessageStream<Self::Error> {
		match self.finish.take() {
			Some(finish) => finish.finish(stream),
			None => stream,
		}
	}
}

fn to_execution_messages(stream: Messages) -> MessageStream<UpstreamError> {
	MessageStream::from_stream(stream.map(|message| message.map_err(UpstreamError::Http)))
}
