//! Session-local subscriptions. Pending reservations cannot disclose notifications.
use super::*;
use std::collections::hash_map::Entry;

#[cfg(test)]
#[path = "subscription_tests.rs"]
mod tests;

#[derive(Debug)]
pub(super) enum State {
	Pending(uuid::Uuid),
	Active(uuid::Uuid),
}

#[derive(Clone)]
pub(crate) struct Ticket(Arc<Pending>);
struct Pending {
	binding: Arc<SessionBinding>,
	key: (String, String),
	nonce: uuid::Uuid,
}
impl Drop for Pending {
	fn drop(&mut self) {
		if let Ok(mut entries) = self.binding.subscriptions.lock()
			&& matches!(entries.get(&self.key), Some(State::Pending(n)) if *n == self.nonce)
		{
			entries.remove(&self.key);
		}
	}
}
impl Ticket {
	pub(super) fn commit(&self, access: &SessionAccess) -> Result<(), ClientError> {
		access.check().map_err(ClientError::new)?;
		if !access
			.binding
			.as_ref()
			.is_some_and(|binding| Arc::ptr_eq(binding, &self.0.binding))
		{
			return Err(ClientError::new(access.denial("subscription-binding")));
		}
		authorize_resource(access, &self.0.key.0, &self.0.key.1).map_err(ClientError::new)?;
		access.current().map_err(ClientError::new)?;
		let mut entries = self
			.0
			.binding
			.subscriptions
			.lock()
			.map_err(|_| ClientError::new(access.denial("store-unavailable")))?;
		match entries.entry(self.0.key.clone()) {
			Entry::Occupied(mut entry) if matches!(entry.get(), State::Pending(n) if *n == self.0.nonce) =>
			{
				entry.insert(State::Active(self.0.nonce));
				Ok(())
			},
			_ => Err(ClientError::new(access.denial("subscription-cancelled"))),
		}
	}
}

pub(crate) fn prepare_subscription(
	request: &rmcp::model::JsonRpcRequest<rmcp::model::ClientRequest>,
	ctx: &mut super::super::upstream::IncomingRequestContext,
	server: &str,
) -> Result<(), super::super::upstream::UpstreamError> {
	let http = ctx.as_request();
	let Some(access) = http.extensions().get::<SessionAccess>() else {
		return Ok(());
	};
	use rmcp::model::ClientRequest;
	let (uri, subscribe) = match &request.request {
		ClientRequest::SubscribeRequest(r) => (&r.params.uri, true),
		ClientRequest::UnsubscribeRequest(r) => (&r.params.uri, false),
		_ => return Ok(()),
	};
	let result = (|| {
		access.check()?;
		if uri.is_empty() || uri.trim() != uri || uri.len() > 4096 {
			return Err(access.denial("resource-identifier"));
		}
		let binding = access
			.binding
			.clone()
			.ok_or_else(|| access.denial("subscription-requires-session"))?;
		let key = (server.to_string(), uri.clone());
		if subscribe {
			authorize_resource(access, server, uri)?;
		}
		let mut entries = binding
			.subscriptions
			.lock()
			.map_err(|_| access.denial("store-unavailable"))?;
		if !subscribe {
			// Fail closed immediately, even if upstream cancellation fails. A pending ack cannot reopen it.
			entries.remove(&key);
			return Ok(None);
		}
		if entries.contains_key(&key) {
			return Err(access.denial("subscription-exists"));
		}
		if entries.len() >= access.limits.max_subscriptions {
			return Err(access.denial("subscription-limit"));
		}
		let nonce = uuid::Uuid::new_v4();
		entries.insert(key.clone(), State::Pending(nonce));
		drop(entries);
		Ok(Some(Ticket(Arc::new(Pending {
			binding,
			key,
			nonce,
		}))))
	})();
	let ticket =
		result.map_err(|e| super::super::upstream::UpstreamError::InvalidRequest(e.to_string()))?;
	if let Some(ticket) = ticket {
		ctx.extensions_mut().insert(ticket);
	}
	Ok(())
}

fn authorize_resource(access: &SessionAccess, server: &str, uri: &str) -> Result<(), ProxyError> {
	let cel = super::super::rbac::CelExecWrapper::new((*access.authorization_request).clone());
	if !access.policies.validate(
		&super::super::rbac::ResourceType::Resource(super::super::rbac::ResourceId::new(
			server.into(),
			uri.into(),
		)),
		&cel,
	) {
		return Err(access.denial("resource-rbac"));
	}
	for method in ["resources/read", "resources/subscribe"] {
		let action = security_pipeline::mcp_operation_for_identity(
			access.action.request_id.clone(),
			access.identity.clone(),
			method,
			security_types::ResourceType::McpResource,
			security_pipeline::mcp_object_id(server, uri),
		);
		access
			.security()
			.authorize(&action, None)
			.map_err(|_| access.denial("resource-authorization"))?;
		if let Some(egress) = &access.config.data_egress {
			security_integration_runtime::check_data_egress(
				egress,
				&action,
				server,
				&crate::security_events::UiSecurityAuditSink,
			)
			.map_err(|_| access.denial("resource-egress"))?;
		}
		if let Some(flow) = &access.flow {
			flow.check(&action, server)?;
		}
	}
	Ok(())
}

pub(super) fn notification(
	access: &SessionAccess,
	server: &str,
	message: &rmcp::model::ServerJsonRpcMessage,
) -> Result<bool, ProxyError> {
	let rmcp::model::ServerJsonRpcMessage::Notification(n) = message else {
		return Ok(false);
	};
	let rmcp::model::ServerNotification::ResourceUpdatedNotification(n) = &n.notification else {
		return Ok(false);
	};
	let binding = access
		.binding
		.as_ref()
		.ok_or_else(|| access.denial("subscription-requires-session"))?;
	let key = (server.to_string(), n.params.uri.clone());
	access.check()?;
	let generation = {
		let entries = binding
			.subscriptions
			.lock()
			.map_err(|_| access.denial("store-unavailable"))?;
		match entries.get(&key) {
			Some(State::Active(generation)) => *generation,
			_ => return Err(access.denial("unsolicited-resource-update")),
		}
	};
	// Remote authorization must not hold the registry lock. A concurrent unsubscribe or
	// replacement invalidates this notification even if the new subscription has the same URI.
	authorize_resource(access, server, &n.params.uri)?;
	access.current()?;
	if !binding
		.subscriptions
		.lock()
		.map_err(|_| access.denial("store-unavailable"))?
		.get(&key)
		.is_some_and(|s| matches!(s, State::Active(current) if *current == generation))
	{
		return Err(access.denial("subscription-changed"));
	}
	Ok(true)
}
