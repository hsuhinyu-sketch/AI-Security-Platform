use std::sync::Arc;

use ::cel::Value;
use ::cel::objects::{KeyRef, MapValue};
use serde::Serialize;
use vector_map::VecMap;

use crate::cel::ContextBuilder;
use crate::http::authorization::{RuleSet, RuleSets};
use crate::*;

#[apply(schema!)]
pub struct McpAuthorization(
	/// CEL authorization rules for MCP tools, prompts, and resources.
	RuleSet,
);

impl McpAuthorization {
	pub fn new(rule_set: RuleSet) -> Self {
		Self(rule_set)
	}

	pub fn into_inner(self) -> RuleSet {
		self.0
	}
}

/// Cheap clone via Arc; this API treats the request as read-only after construction.
#[derive(Clone)]
pub struct CelExecWrapper(Arc<::http::Request<()>>);

impl CelExecWrapper {
	pub fn new(req: ::http::Request<()>) -> CelExecWrapper {
		CelExecWrapper(Arc::new(req))
	}
}
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct McpAuthorizationSet(RuleSets);

impl McpAuthorizationSet {
	pub fn new(rs: RuleSets) -> Self {
		Self(rs)
	}
	pub fn validate(&self, res: &ResourceType, cel: &CelExecWrapper) -> bool {
		if !self.0.has_rules() {
			return true;
		}
		tracing::debug!("Checking RBAC for resource: {:?}", res);
		let mcp = crate::mcp::MCPInfo::from(res);
		let exec = crate::cel::Executor::new_mcp_request(cel.0.as_ref(), &mcp);
		self.0.validate(&exec)
	}

	pub fn register(&self, cel: &mut ContextBuilder) {
		self.0.register(cel);
	}
}

#[apply(schema!)]
#[derive(Eq, PartialEq)]
pub enum ResourceType {
	/// The tool being accessed
	Tool(ResourceId),
	/// The prompt being accessed
	Prompt(ResourceId),
	/// The resource being accessed
	Resource(ResourceId),
}

impl cel::DynamicType for ResourceType {
	fn materialize(&self) -> Value<'_> {
		let (n, t) = match self {
			ResourceType::Tool(t) => ("tool", t),
			ResourceType::Prompt(t) => ("prompt", t),
			ResourceType::Resource(t) => ("resource", t),
		};
		Value::Map(MapValue::Borrow(VecMap::from_iter([(
			KeyRef::String(n.into()),
			t.materialize(),
		)])))
	}

	fn field(&self, field: &str) -> Option<Value<'_>> {
		match (self, field) {
			(ResourceType::Tool(t), "tool") => Some(t.materialize()),
			(ResourceType::Prompt(t), "prompt") => Some(t.materialize()),
			(ResourceType::Resource(t), "resource") => Some(t.materialize()),
			_ => None,
		}
	}
}

#[apply(schema!)]
#[derive(Eq, PartialEq, ::cel::DynamicType)]
pub struct ResourceId {
	#[serde(default)]
	/// The target of the resource
	target: String,
	#[serde(rename = "name", default)]
	/// The name of the resource
	id: String,
}

impl ResourceId {
	pub fn new(target: String, id: String) -> Self {
		Self { target, id }
	}

	pub fn target(&self) -> &str {
		&self.target
	}

	pub fn name(&self) -> &str {
		&self.id
	}
}
