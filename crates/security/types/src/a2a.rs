//! Canonical Task ownership/lifecycle values shared with protocol adapters.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum TaskState {
	Submitted,
	Working,
	InputRequired,
	AuthRequired,
	Completed,
	Canceled,
	Failed,
	Rejected,
	Unknown,
}

impl TaskState {
	pub fn terminal(self) -> bool {
		matches!(
			self,
			Self::Completed | Self::Canceled | Self::Failed | Self::Rejected
		)
	}
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaskOperation {
	Create,
	Read,
	Continue,
	Cancel,
	Subscribe,
}

impl TaskOperation {
	pub fn name(self) -> &'static str {
		match self {
			Self::Create => "create",
			Self::Read => "read",
			Self::Continue => "continue",
			Self::Cancel => "cancel",
			Self::Subscribe => "subscribe",
		}
	}
}

pub fn valid_event_cursor(cursor: &str) -> bool {
	uuid::Uuid::parse_str(cursor)
		.is_ok_and(|id| id.get_version_num() == 4 && id.to_string() == cursor)
}

#[cfg(test)]
mod tests {
	use super::*;
	#[test]
	fn durable_state_values_and_cursor_shape_are_stable() {
		for (wire, state, terminal) in [
			("submitted", TaskState::Submitted, false),
			("working", TaskState::Working, false),
			("input-required", TaskState::InputRequired, false),
			("auth-required", TaskState::AuthRequired, false),
			("completed", TaskState::Completed, true),
			("canceled", TaskState::Canceled, true),
			("failed", TaskState::Failed, true),
			("rejected", TaskState::Rejected, true),
			("unknown", TaskState::Unknown, false),
		] {
			assert_eq!(serde_json::to_value(state).unwrap(), wire);
			assert_eq!(
				serde_json::from_value::<TaskState>(serde_json::json!(wire)).unwrap(),
				state
			);
			assert_eq!(state.terminal(), terminal);
		}
		assert!(valid_event_cursor("01234567-89ab-4def-8123-456789abcdef"));
		for invalid in [
			"01234567-89AB-4DEF-8123-456789ABCDEF",
			"01234567-89ab-1def-8123-456789abcdef",
			"not-a-cursor",
		] {
			assert!(!valid_event_cursor(invalid));
		}
	}
}
