use crate::llm::types::ResponseType;
use crate::llm::{AIError, logged_response_parsing, types};

pub mod from_rerank {
	use super::*;

	pub fn translate(
		req: &types::rerank::Request,
		_provider: &crate::llm::vertex::Provider,
	) -> Result<Vec<u8>, AIError> {
		gateway_llm::conversion::vertex::from_rerank::translate(req).map_err(Into::into)
	}

	/// Discovery Engine returns synthetic ids + scores in rank order; it does not echo document text.
	pub fn translate_response(bytes: &[u8]) -> Result<Box<dyn ResponseType>, AIError> {
		let resp: types::vertex::RankResponse =
			serde_json::from_slice(bytes).map_err(logged_response_parsing(bytes))?;
		let out = gateway_llm::conversion::vertex::from_rerank::translate_response(resp)
			.map_err(AIError::from)?;
		Ok(Box::new(out))
	}
}

pub mod from_embeddings {
	use super::*;

	pub fn translate(req: &types::embeddings::Request) -> Result<Vec<u8>, AIError> {
		gateway_llm::conversion::vertex::from_embeddings::translate(req).map_err(Into::into)
	}

	pub fn translate_response(bytes: &[u8], model: &str) -> Result<Box<dyn ResponseType>, AIError> {
		let resp: types::vertex::PredictResponse =
			serde_json::from_slice(bytes).map_err(logged_response_parsing(bytes))?;
		let out = gateway_llm::conversion::vertex::from_embeddings::translate_response(resp, model)
			.map_err(AIError::from)?;
		Ok(Box::new(out))
	}
}
