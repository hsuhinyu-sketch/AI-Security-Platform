#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum CircuitAction {
	Block { status: u16, body: String },
	Fallback { target: String },
	Degrade { model: String },
	Reroute { target: String },
	Queue { queue: String },
	RequireApproval { reason: String },
}
