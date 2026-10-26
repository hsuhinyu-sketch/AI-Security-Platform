pub mod bedrock;
pub mod completions;
pub mod gemini;
pub mod messages;
pub mod openai_compat;
pub mod responses;
pub mod vertex;

fn response_error(bytes: &[u8], error: gateway_llm::WireError) -> crate::llm::AIError {
	match error {
		gateway_llm::WireError::ResponseParsing(error) => {
			crate::llm::logged_response_parsing(bytes)(error)
		},
		error => error.into(),
	}
}
