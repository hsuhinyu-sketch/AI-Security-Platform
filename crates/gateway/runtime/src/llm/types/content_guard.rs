//! Host projection adapter; pure field ownership and rewrite rules live in gateway-llm.
use crate::llm::{
	InputFormat,
	policy::webhook::{Message, ResponseChoice},
};
use serde::{Serialize, de::DeserializeOwned};

pub fn choices<T: Serialize>(
	response: &T,
	format: InputFormat,
) -> anyhow::Result<Vec<ResponseChoice>> {
	let value = serde_json::to_value(response)?;
	let projection = gateway_llm::content::project(&value, format)?;
	Ok(
		projection
			.texts()
			.map(|text| ResponseChoice {
				message: Message {
					role: "assistant".into(),
					content: text.into(),
				},
			})
			.collect(),
	)
}

pub fn replace<T: Serialize + DeserializeOwned>(
	response: &mut T,
	format: InputFormat,
	choices: Vec<ResponseChoice>,
) -> anyhow::Result<()> {
	let mut value = serde_json::to_value(&*response)?;
	let projection = gateway_llm::content::project(&value, format)?;
	anyhow::ensure!(
		choices
			.iter()
			.all(|choice| choice.message.role == "assistant"),
		"guard cannot change response roles"
	);
	projection.replace(
		&mut value,
		choices
			.into_iter()
			.map(|c| c.message.content.to_string())
			.collect(),
	)?;
	// Commit only a complete, structurally valid response; errors never publish a partial mask.
	*response = serde_json::from_value(value)?;
	Ok(())
}
