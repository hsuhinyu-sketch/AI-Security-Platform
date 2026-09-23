#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct GuardrailsConfig {
	pub enabled: bool,
	pub request_rules: Vec<RequestRule>,
	pub tool_rules: Vec<ToolRule>,
	pub response_rules: Vec<ResponseRule>,
}

impl Default for GuardrailsConfig {
	fn default() -> Self {
		Self {
			enabled: true,
			request_rules: Vec::new(),
			tool_rules: Vec::new(),
			response_rules: Vec::new(),
		}
	}
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct RequestRule {
	pub name: String,
	pub pattern: String,
	pub level: super::api::SafetyLevel,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ResponseRule {
	pub name: String,
	pub pattern: String,
	pub level: super::api::SafetyLevel,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ToolRule {
	pub name: String,
	pub allowed: bool,
	pub max_speed_kmh: Option<f64>,
	pub level: super::api::SafetyLevel,
}
