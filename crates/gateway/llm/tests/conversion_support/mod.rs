//! Observations shared by the pre-migration Host capture and post-migration contract tests.
use super::{Error, conversion, error_view, types};
use serde::{Serialize, de::DeserializeOwned};
use serde_json::{Value, json};

pub fn json_error(error: serde_json::Error) -> Value {
	json!({"error":error.to_string(),"category":format!("{:?}",error.classify()),"line":error.line(),"column":error.column(),"stage":"input"})
}

pub fn wire(bytes: Vec<u8>) -> Value {
	let wire = String::from_utf8(bytes).unwrap();
	json!({"json":serde_json::from_str::<Value>(&wire).unwrap(),"wire":wire})
}

pub fn result(result: Result<Vec<u8>, Error>) -> Value {
	match result {
		Ok(bytes) => wire(bytes),
		Err(error) => error_view(&error),
	}
}

pub fn request<T: DeserializeOwned>(
	input: &str,
	f: impl FnOnce(&T) -> Result<Vec<u8>, Error>,
) -> Value {
	match serde_json::from_str::<T>(input) {
		Ok(request) => result(f(&request)),
		Err(error) => json_error(error),
	}
}

pub fn round_trip<T: DeserializeOwned + Serialize>(input: &str) -> Value {
	match serde_json::from_str::<T>(input) {
		Ok(value) => wire(serde_json::to_vec(&value).unwrap()),
		Err(error) => json_error(error),
	}
}

pub fn observe_a(case: &Value) -> Value {
	let input = case["input"].as_str().unwrap();
	match case["kind"].as_str().unwrap() {
		"responses-wire" => round_trip::<types::responses::Request>(input),
		"chat-to-messages" => request(input, conversion::messages::from_completions::translate),
		"messages-to-chat" => request(input, conversion::completions::from_messages::translate),
		"chat-response-to-messages" => super::chat_response(input),
		"openai-compatible" => super::openai_request(input),
		"data-url" => {
			let value: String = serde_json::from_str(input).unwrap();
			json!(gateway_llm::conversion::completions::parse_data_url(&value))
		},
		"system-text" => match serde_json::from_str::<types::completions::typed::RequestMessage>(input)
		{
			Ok(value) => json!(gateway_llm::conversion::completions::extract_system_text(
				&value
			)),
			Err(error) => json_error(error),
		},
		"google-error-type" => {
			let value = serde_json::from_str(input).unwrap();
			json!(gateway_llm::conversion::completions::google_error_type(
				&value
			))
		},
		unknown => panic!("unknown conversion fixture kind: {unknown}"),
	}
}
