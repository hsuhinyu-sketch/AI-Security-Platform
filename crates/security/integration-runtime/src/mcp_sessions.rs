//! Protocol-neutral limits for the opt-in MCP session contract. No messages or credentials.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(default, rename_all = "camelCase", deny_unknown_fields)]
pub struct McpSessionConfig {
	#[serde(skip_serializing_if = "Option::is_none")]
	pub tasks: Option<McpTaskConfig>,
	pub max_sessions: usize,
	pub max_streams: usize,
	/// Pending and active resource subscriptions per protected session.
	pub max_subscriptions: usize,
	pub max_session_seconds: u64,
	pub reauthorize_seconds: u64,
	pub stream_idle_seconds: u64,
	pub max_stream_seconds: u64,
	pub max_message_bytes: usize,
	/// Explicitly adapted 2025-era reverse requests on the originating POST stream.
	pub reverse: Option<McpReverseConfig>,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(default, rename_all = "camelCase", deny_unknown_fields)]
pub struct McpTaskConfig {
	/// Form elicitation on a live tasks/result POST, never an implicit background channel.
	#[serde(skip_serializing_if = "disabled")]
	pub elicitation: bool,
	/// Bounded roots/list on the original Task result stream; not filesystem access.
	#[serde(skip_serializing_if = "disabled")]
	pub roots: bool,
	/// Gateway-managed, non-streaming text sampling through a trusted local LLM route.
	#[serde(skip_serializing_if = "Option::is_none")]
	pub sampling: Option<McpTaskSamplingConfig>,
	pub tools: Vec<String>,
	pub max_tasks: usize,
	pub max_task_seconds: u64,
	pub max_argument_bytes: usize,
}
impl Default for McpTaskConfig {
	fn default() -> Self {
		Self {
			elicitation: false,
			roots: false,
			sampling: None,
			tools: vec![],
			max_tasks: 64,
			max_task_seconds: 300,
			max_argument_bytes: 16384,
		}
	}
}
fn disabled(value: &bool) -> bool {
	!*value
}
impl McpTaskConfig {
	pub fn interactive(&self) -> bool {
		self.elicitation || self.roots || self.sampling.is_some()
	}
	pub fn validate(&self) -> Result<(), String> {
		if let Some(sampling) = &self.sampling {
			sampling.validate()?;
		}
		if !(1..=128).contains(&self.tools.len())
			|| self
				.tools
				.iter()
				.any(|s| s.is_empty() || s.len() > 128 || s.trim() != s)
			|| !(1..=128).contains(&self.max_tasks)
			|| !(1..=3600).contains(&self.max_task_seconds)
			|| !(1024..=16384).contains(&self.max_argument_bytes)
		{
			return Err("mcpSessions.tasks requires an explicit tool allowlist and bounded tasks/lifetime/arguments".into());
		}
		Ok(())
	}
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct McpTaskSamplingConfig {
	pub authority: String,
	pub path: String,
	pub model: String,
}
impl McpTaskSamplingConfig {
	pub fn validate(&self) -> Result<(), String> {
		let (host, port) = self
			.authority
			.split_once(':')
			.map_or((self.authority.as_str(), None), |(h, p)| (h, Some(p)));
		if host.split('.').any(|label| {
			label.is_empty()
				|| !label
					.as_bytes()
					.first()
					.is_some_and(u8::is_ascii_alphanumeric)
				|| !label
					.as_bytes()
					.last()
					.is_some_and(u8::is_ascii_alphanumeric)
		}) || port.is_some_and(|p| p.parse::<u16>().ok().is_none_or(|n| n == 0))
			|| self.authority.is_empty()
			|| self.authority.len() > 253
			|| !self
				.authority
				.bytes()
				.all(|c| c.is_ascii_alphanumeric() || b".-:".contains(&c))
			|| !self.path.starts_with('/')
			|| self.path.len() > 256
			|| !self
				.path
				.bytes()
				.all(|c| c.is_ascii_alphanumeric() || b"/._-".contains(&c))
			|| self.path.split('/').any(|p| matches!(p, "." | ".."))
			|| self.model.is_empty()
			|| self.model.len() > 128
			|| self.model.trim() != self.model
			|| self.model.chars().any(char::is_control)
		{
			return Err("Task sampling requires a fixed local route authority/path and model".into());
		}
		Ok(())
	}
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(default, rename_all = "camelCase", deny_unknown_fields)]
pub struct McpReverseConfig {
	pub sampling_models: Vec<String>,
	pub max_sampling_tokens: u64,
	pub elicitation: bool,
	pub elicitation_fields: Vec<String>,
	pub roots: Vec<String>,
	pub max_pending: usize,
	pub timeout_seconds: u64,
}
impl Default for McpReverseConfig {
	fn default() -> Self {
		Self {
			sampling_models: vec![],
			max_sampling_tokens: 256,
			elicitation: false,
			elicitation_fields: vec![],
			roots: vec![],
			max_pending: 16,
			timeout_seconds: 30,
		}
	}
}
impl McpReverseConfig {
	pub fn validate(&self) -> Result<(), String> {
		if !(1..=64).contains(&self.max_pending)
			|| !(1..=300).contains(&self.timeout_seconds)
			|| !(1..=4096).contains(&self.max_sampling_tokens)
			|| self.sampling_models.len() > 32
			|| self.roots.len() > 32
			|| self.elicitation_fields.len() > 32
			|| self
				.elicitation_fields
				.iter()
				.any(|s| s.is_empty() || s.len() > 128 || s.trim() != s)
			|| self
				.sampling_models
				.iter()
				.chain(&self.roots)
				.any(|s| s.is_empty() || s.len() > 512 || s.trim() != s)
			|| self.roots.iter().any(|s| !valid_root_uri(s))
		{
			return Err("mcpSessions.reverse requires bounded pending/timeout/tokens and explicit model/root allowlists".into());
		}
		Ok(())
	}
}

/// Exact, unambiguous local file URI declarations, never a prefix/path access grant.
/// Deliberately reject escaping/normalization instead of interpreting client filesystem paths.
pub fn valid_root_uri(uri: &str) -> bool {
	uri.strip_prefix("file:///").is_some_and(|path| {
		!path.is_empty()
			&& uri.len() <= 512
			&& !uri.chars().any(|c| c.is_control() || c.is_whitespace())
			&& !path.contains(['%', '?', '#', '\\'])
			&& !path
				.split('/')
				.any(|s| s.is_empty() || matches!(s, "." | ".."))
	})
}
impl Default for McpSessionConfig {
	fn default() -> Self {
		Self {
			tasks: None,
			max_sessions: 1024,
			max_streams: 128,
			max_subscriptions: 128,
			max_session_seconds: 86400,
			reauthorize_seconds: 5,
			stream_idle_seconds: 30,
			max_stream_seconds: 3600,
			max_message_bytes: 262144,
			reverse: None,
		}
	}
}
impl McpSessionConfig {
	pub fn validate(&self) -> Result<(), String> {
		if let Some(tasks) = &self.tasks {
			tasks.validate()?;
			if let Some(sampling) = &tasks.sampling {
				if self
					.reverse
					.as_ref()
					.is_none_or(|r| !r.sampling_models.contains(&sampling.model))
				{
					return Err("Task sampling requires the fixed model in reverse.samplingModels".into());
				}
			}
			if tasks.interactive() && self.max_streams < 2 {
				return Err("Task interactions require at least two session streams".into());
			}
			if tasks.roots && self.reverse.as_ref().is_none_or(|r| r.roots.is_empty()) {
				return Err("Task roots require an explicit reverse.roots URI allowlist".into());
			}
			if tasks.elicitation
				&& (self.max_streams < 2
					|| self
						.reverse
						.as_ref()
						.is_none_or(|r| !r.elicitation || r.elicitation_fields.is_empty()))
			{
				return Err("Task elicitation requires reverse.elicitation, an explicit field allowlist and at least two session streams".into());
			}
		}
		if let Some(reverse) = &self.reverse {
			reverse.validate()?;
		}
		if self.max_sessions == 0
			|| self.max_streams == 0
			|| !(1..=4096).contains(&self.max_subscriptions)
			|| !(1..=2_592_000).contains(&self.max_session_seconds)
			|| !(1..=60).contains(&self.reauthorize_seconds)
			|| !(1..=3600).contains(&self.stream_idle_seconds)
			|| !(1..=86400).contains(&self.max_stream_seconds)
			|| !(1024..=16_777_216).contains(&self.max_message_bytes)
		{
			return Err(
				"mcpSessions requires positive capacity and bounded session/stream/message limits".into(),
			);
		}
		Ok(())
	}
}
