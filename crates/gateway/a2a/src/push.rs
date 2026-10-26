//! Push wire projection only. Channel proofs, secrets, admission and durable commits stay in Host.
use crate::{Error, RequestEnvelope, objects::object};
use serde_json::{Value, json};
pub const PREFIX: &str = "/v1/a2a/push/";
pub fn is_callback_path(path: &str) -> bool {
	path == "/v1/a2a/push" || path.starts_with(PREFIX)
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Operation {
	Set,
	Get,
	List,
	Delete,
}
impl Operation {
	pub fn name(self) -> &'static str {
		match self {
			Self::Set => "set",
			Self::Get => "get",
			Self::List => "list",
			Self::Delete => "delete",
		}
	}
}
pub fn requested_url(rpc: &RequestEnvelope) -> Result<Option<&str>, Error> {
	let cfg = &rpc.params["pushNotificationConfig"];
	object(cfg, &["url"])?;
	Ok(cfg["url"].as_str())
}
pub fn public_config(task: &str, id: &str, url: &str) -> Value {
	json!({"taskId":task,"pushNotificationConfig":{"id":id,"url":url}})
}
pub fn registration_request(
	rpc: &RequestEnvelope,
	task: Option<&str>,
	id: &str,
	url: &str,
	secret: &str,
) -> Value {
	json!({"jsonrpc":"2.0","id":rpc.id,"method":rpc.method,"params":{"taskId":task,"pushNotificationConfig":{"id":id,"url":url,"authentication":{"schemes":["Bearer"],"credentials":secret}}}})
}
pub fn validate_registration(result: &Value, task: &str, id: &str, url: &str) -> Result<(), Error> {
	if result["taskId"] != task
		|| result["pushNotificationConfig"]["id"] != id
		|| result["pushNotificationConfig"]["url"] != url
	{
		Err(Error::ResponseBinding)
	} else {
		Ok(())
	}
}
pub fn valid_delete_result(result: &Value) -> bool {
	result.as_object().is_some_and(|o| o.is_empty())
}
pub fn response(id: &Value, result: Value) -> Value {
	json!({"jsonrpc":"2.0","id":id,"result":result})
}
