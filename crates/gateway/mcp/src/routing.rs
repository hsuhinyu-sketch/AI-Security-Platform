//! Name and URI projection for multiplexed MCP servers.
//!
//! Parsing identifies a target; it does not authorize it or establish that it exists.
//! The caller must resolve the target and apply its execution policy before sending.
use rmcp::model::{
	ClientRequest, Meta, Reference, RequestId, ServerJsonRpcMessage, ServerNotification,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
	InvalidResourceName,
	InvalidResourceUri,
	UnsupportedReference,
	MixedSubscriptionTargets,
}

impl std::fmt::Display for Error {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.write_str(match self {
			Self::InvalidResourceName => "invalid resource name",
			Self::InvalidResourceUri => "invalid resource URI",
			Self::UnsupportedReference => "unsupported completion reference",
			Self::MixedSubscriptionTargets => {
				"subscriptions/listen resourceSubscriptions must target one upstream"
			},
		})
	}
}
impl std::error::Error for Error {}

/// Resolve a subscription batch without mutating the caller's list on error.
/// Empty lists retain the existing unrestricted-target selection (None).
/// The caller must validate target existence and authorize every returned URI.
pub fn route_subscription_resources(
	default_target: Option<&str>,
	resources: &[String],
) -> Result<(Option<String>, Vec<String>), Error> {
	let mut target: Option<String> = None;
	let mut mapped = Vec::with_capacity(resources.len());
	for uri in resources {
		let (server, original_uri) = parse_resource_uri(default_target, uri)?;
		if target.as_deref().is_some_and(|target| target != server) {
			return Err(Error::MixedSubscriptionTargets);
		}
		if target.is_none() {
			target = Some(server.to_string());
		}
		mapped.push(original_uri.to_string());
	}
	Ok((target, mapped))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObjectKind {
	Tool,
	Prompt,
	Resource,
}

/// Routing data only: no target admission or authorization grant.
#[derive(Debug, PartialEq, Eq)]
pub struct ObjectRoute {
	pub kind: ObjectKind,
	pub target: String,
	pub requested: String,
	pub object: String,
}

/// Preserve the legacy stateless handshake scope: Tool/Prompt calls initialize
/// only their selected upstream; other messages initialize the admitted fanout.
/// The Host owns connection setup, session persistence and the protected sends.
pub fn legacy_initialization_target(
	default_target: Option<&str>,
	request: Option<&ClientRequest>,
) -> Result<Option<String>, Error> {
	let name = match request {
		Some(ClientRequest::CallToolRequest(call)) => call.params.name.as_ref(),
		Some(ClientRequest::GetPromptRequest(call)) => call.params.name.as_str(),
		_ => return Ok(None),
	};
	parse_resource_name(default_target, name).map(|(target, _)| Some(target.to_owned()))
}

/// Resolve and remove the gateway namespace from a single-object request.
/// Non-object methods are left untouched for their existing lifecycle handlers.
pub fn route_request(
	default_target: Option<&str>,
	request: &mut ClientRequest,
) -> Result<Option<ObjectRoute>, Error> {
	let route = match request {
		ClientRequest::CallToolRequest(call) => {
			let route = name_route(default_target, &call.params.name, ObjectKind::Tool)?;
			call.params.name = route.object.clone().into();
			route
		},
		ClientRequest::GetPromptRequest(call) => {
			let route = name_route(default_target, &call.params.name, ObjectKind::Prompt)?;
			call.params.name = route.object.clone();
			route
		},
		ClientRequest::ReadResourceRequest(call) => {
			let route = uri_route(default_target, &call.params.uri)?;
			call.params.uri = route.object.clone();
			route
		},
		ClientRequest::SubscribeRequest(call) => {
			let route = uri_route(default_target, &call.params.uri)?;
			call.params.uri = route.object.clone();
			route
		},
		ClientRequest::UnsubscribeRequest(call) => {
			let route = uri_route(default_target, &call.params.uri)?;
			call.params.uri = route.object.clone();
			route
		},
		ClientRequest::CompleteRequest(call) => match &call.params.r#ref {
			Reference::Prompt(prompt) => {
				let route = name_route(default_target, &prompt.name, ObjectKind::Prompt)?;
				call.params.r#ref = Reference::for_prompt(route.object.clone());
				route
			},
			Reference::Resource(resource) => {
				let route = uri_route(default_target, &resource.uri)?;
				call.params.r#ref = Reference::for_resource(route.object.clone());
				route
			},
			_ => return Err(Error::UnsupportedReference),
		},
		_ => return Ok(None),
	};
	Ok(Some(route))
}

fn name_route(
	default_target: Option<&str>,
	requested: &str,
	kind: ObjectKind,
) -> Result<ObjectRoute, Error> {
	let (target, object) = parse_resource_name(default_target, requested)?;
	Ok(ObjectRoute {
		kind,
		target: target.to_string(),
		requested: requested.to_string(),
		object: object.to_string(),
	})
}

fn uri_route(default_target: Option<&str>, requested: &str) -> Result<ObjectRoute, Error> {
	let (target, object) = parse_resource_uri(default_target, requested)?;
	Ok(ObjectRoute {
		kind: ObjectKind::Resource,
		target: target.to_string(),
		requested: requested.to_string(),
		object: object.to_string(),
	})
}

pub fn resource_name(default_target: Option<&str>, target: &str, name: &str) -> String {
	if default_target.is_none() {
		format!("{target}_{name}")
	} else {
		name.to_string()
	}
}

pub fn resource_uri(default_target: Option<&str>, target: &str, uri: &str) -> String {
	if default_target.is_none()
		&& let Some(scheme_end) = uri.find("://")
	{
		let (scheme, rest) = uri.split_at(scheme_end);
		format!("{target}+{scheme}{rest}")
	} else {
		// Keep the existing handling of URIs without a scheme; validation is separate.
		uri.to_string()
	}
}

pub fn parse_resource_name<'a, 'b: 'a>(
	default_target: Option<&'a str>,
	name: &'b str,
) -> Result<(&'a str, &'b str), Error> {
	match default_target {
		Some(default) => Ok((default, name)),
		None => name.split_once('_').ok_or(Error::InvalidResourceName),
	}
}

pub fn parse_resource_uri<'a, 'b>(
	default_target: Option<&'a str>,
	uri: &'b str,
) -> Result<(&'a str, &'b str), Error>
where
	'b: 'a,
{
	match default_target {
		Some(default) => Ok((default, uri)),
		None => uri.split_once('+').ok_or(Error::InvalidResourceUri),
	}
}

pub fn rewrite_resource_update_message(
	default_target: Option<&str>,
	target: &str,
	mut message: ServerJsonRpcMessage,
) -> ServerJsonRpcMessage {
	if let ServerJsonRpcMessage::Notification(notification) = &mut message
		&& let ServerNotification::ResourceUpdatedNotification(resource_updated) =
			&mut notification.notification
	{
		resource_updated.params.uri =
			resource_uri(default_target, target, resource_updated.params.uri.as_str());
	}
	message
}

pub fn set_subscription_ack_id(
	mut message: ServerJsonRpcMessage,
	subscription_id: &RequestId,
) -> ServerJsonRpcMessage {
	if let ServerJsonRpcMessage::Notification(notification) = &mut message
		&& let ServerNotification::SubscriptionsAcknowledgedNotification(ack) =
			&mut notification.notification
	{
		let mut meta = ack.params.meta.take().unwrap_or_else(Meta::new);
		// SDK serialization lets extension metadata override params metadata.
		// Consolidate both first so an upstream ID cannot overwrite the downstream ID.
		if let Some(extension_meta) = ack.extensions.remove::<Meta>() {
			meta.extend(extension_meta);
		}
		meta.set_subscription_id(subscription_id.clone());
		ack.params.meta = Some(meta);
	}
	message
}

#[cfg(test)]
mod tests;
