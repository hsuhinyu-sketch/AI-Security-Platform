//! Pure protocol data. Provider conversion, authorization and execution belong to the Host.

#[cfg(feature = "protocol")]
pub mod bedrock;
#[cfg(feature = "protocol")]
pub mod completions;
#[cfg(feature = "protocol")]
pub mod count_tokens;
#[cfg(feature = "protocol")]
pub mod embeddings;
#[cfg(feature = "protocol")]
pub mod messages;
mod normalized;
#[cfg(feature = "protocol")]
pub mod rerank;
#[cfg(feature = "protocol")]
pub mod responses;
#[cfg(feature = "protocol")]
pub mod vertex;

pub use normalized::{CacheTokenConvention, LLMResponse};

#[cfg(feature = "protocol")]
fn is_default<T: Default + PartialEq>(t: &T) -> bool {
	*t == T::default()
}

#[cfg(feature = "protocol")]
pub(crate) fn convert<I: serde::Serialize, O: serde::de::DeserializeOwned>(
	input: I,
) -> Result<O, serde_json::Error> {
	let v = serde_json::to_value(input)?;
	let o = serde_json::from_value::<O>(v)?;
	Ok(o)
}
