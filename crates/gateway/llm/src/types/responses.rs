use serde::{Deserialize, Serialize};

use serde_json::Value;
use typed::OutputItem;
use typed::{InputContent, InputItem, InputMessage, InputRole, InputTextContent};

#[derive(Debug, Deserialize, Clone, Serialize, Default)]
pub struct RequestVendorExtensions {
	#[serde(skip_serializing_if = "Option::is_none")]
	pub thinking_budget_tokens: Option<u64>,

	#[serde(flatten, default)]
	pub rest: serde_json::Value,
}

#[derive(Debug, Deserialize, Clone, Serialize)]
pub struct Response {
	pub id: String,
	pub status: String,
	pub output: Vec<OutputItem>,
	pub model: String,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub service_tier: Option<String>,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub usage: Option<Usage>,
	#[serde(flatten, default)]
	pub rest: serde_json::Value,
}

#[derive(Debug, Deserialize, Clone, Serialize)]
pub struct Usage {
	pub input_tokens: u64,
	pub output_tokens: u64,
	/// Breakdown of tokens used in a completion.
	#[serde(skip_serializing_if = "Option::is_none")]
	pub input_tokens_details: Option<UsageInputDetails>,
	/// Breakdown of tokens used in the prompt.
	#[serde(skip_serializing_if = "Option::is_none")]
	pub output_tokens_details: Option<UsageOutputDetails>,
	#[serde(flatten, default)]
	pub rest: serde_json::Value,
}

#[derive(Debug, Deserialize, Clone, Serialize)]
pub struct UsageOutputDetails {
	pub reasoning_tokens: Option<u64>,
	#[serde(flatten, default)]
	pub rest: serde_json::Value,
}

#[derive(Debug, Deserialize, Clone, Serialize)]
pub struct UsageInputDetails {
	pub cached_tokens: Option<u64>,
	#[serde(flatten, default)]
	pub rest: serde_json::Value,
}

pub mod typed {
	use async_openai::types::responses as openai_responses;
	// Re-export async-openai Responses API types for cleaner usage
	pub use async_openai::types::responses::{
		AssistantRole, CreateResponse, CustomToolCallOutput, CustomToolCallOutputOutput,
		EasyInputContent, EasyInputMessage, ErrorObject, FunctionCallOutput, FunctionToolCall,
		IncompleteDetails, InputContent, InputItem, InputMessage, InputParam, InputRole,
		InputTextContent, InputTokenDetails, Item, MessageItem, OutputContent, OutputItem,
		OutputMessage, OutputMessageContent, OutputStatus, OutputTextContent, OutputTokenDetails,
		ReasoningEffort, Response, ResponseCompletedEvent, ResponseContentPartAddedEvent,
		ResponseContentPartDoneEvent, ResponseCreatedEvent, ResponseErrorEvent, ResponseFailedEvent,
		ResponseFunctionCallArgumentsDeltaEvent, ResponseFunctionCallArgumentsDoneEvent,
		ResponseIncompleteEvent, ResponseOutputItemAddedEvent, ResponseOutputItemDoneEvent,
		ResponseTextDeltaEvent, ResponseTextParam, ResponseUsage, Role, Status,
		TextResponseFormatConfiguration, Tool, ToolChoiceFunction, ToolChoiceOptions, ToolChoiceParam,
	};
	use serde::{Deserialize, Serialize};

	/// Event types for streaming responses from the Responses API (minimal strict subset).
	#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
	#[allow(clippy::enum_variant_names)]
	#[serde(tag = "type")]
	pub enum ResponseStreamEvent {
		/// An event that is emitted when a response is created.
		#[serde(rename = "response.created")]
		ResponseCreated(openai_responses::ResponseCreatedEvent),
		/// Emitted when a new output item is added.
		#[serde(rename = "response.output_item.added")]
		ResponseOutputItemAdded(openai_responses::ResponseOutputItemAddedEvent),
		/// Emitted when a new content part is added.
		#[serde(rename = "response.content_part.added")]
		ResponseContentPartAdded(openai_responses::ResponseContentPartAddedEvent),
		/// Emitted when there is an additional text delta.
		#[serde(rename = "response.output_text.delta")]
		ResponseOutputTextDelta(openai_responses::ResponseTextDeltaEvent),
		/// Emitted when there is a partial function-call arguments delta.
		#[serde(rename = "response.function_call_arguments.delta")]
		ResponseFunctionCallArgumentsDelta(openai_responses::ResponseFunctionCallArgumentsDeltaEvent),
		/// Emitted when function-call arguments are finalized.
		#[serde(rename = "response.function_call_arguments.done")]
		ResponseFunctionCallArgumentsDone(openai_responses::ResponseFunctionCallArgumentsDoneEvent),
		/// Emitted when a content part is done.
		#[serde(rename = "response.content_part.done")]
		ResponseContentPartDone(openai_responses::ResponseContentPartDoneEvent),
		/// Emitted when an output item is marked done.
		#[serde(rename = "response.output_item.done")]
		ResponseOutputItemDone(openai_responses::ResponseOutputItemDoneEvent),
		/// Emitted when the model response is complete.
		#[serde(rename = "response.completed")]
		ResponseCompleted(openai_responses::ResponseCompletedEvent),
		/// An event that is emitted when a response finishes as incomplete.
		#[serde(rename = "response.incomplete")]
		ResponseIncomplete(openai_responses::ResponseIncompleteEvent),
		/// An event that is emitted when a response fails.
		#[serde(rename = "response.failed")]
		ResponseFailed(openai_responses::ResponseFailedEvent),
		/// Emitted when an error occurs.
		#[serde(rename = "error")]
		ResponseError(openai_responses::ResponseErrorEvent),
	}
}

/// Raw Responses API input — preserves the wire format for passthrough fidelity.
/// Typed deserialization would reject unknown item shapes (e.g. assistant history).
#[derive(Debug, Deserialize, Clone, Serialize)]
#[serde(untagged)]
pub enum RequestInput {
	Text(String),
	Items(Vec<RawInputItem>),
}

#[derive(Debug, Deserialize, Clone, Serialize, PartialEq)]
#[serde(transparent)]
pub struct RawInputItem(Value);

impl RawInputItem {
	pub fn from_typed(item: InputItem) -> Self {
		Self(serde_json::to_value(item).expect("responses input item should serialize"))
	}

	pub fn from_user_text(text: String) -> Self {
		Self::from_typed(InputItem::from(InputMessage {
			content: vec![InputContent::InputText(InputTextContent { text })],
			role: InputRole::User,
			status: None,
		}))
	}

	/// Borrow the unchanged raw item for Host prompt projection without imposing an SDK shape.
	pub fn as_value(&self) -> &Value {
		&self.0
	}
}

#[derive(Debug, Deserialize, Clone, Serialize)]
pub struct Request {
	// Required field for prompt enrichment/guards
	pub input: RequestInput,

	// Fields we actually read for routing/telemetry
	#[serde(skip_serializing_if = "Option::is_none")]
	pub model: Option<String>,

	#[serde(skip_serializing_if = "Option::is_none")]
	pub max_output_tokens: Option<u32>,

	#[serde(skip_serializing_if = "Option::is_none")]
	pub temperature: Option<f32>,

	#[serde(skip_serializing_if = "Option::is_none")]
	pub top_p: Option<f32>,

	#[serde(skip_serializing_if = "Option::is_none")]
	pub stream: Option<bool>,

	#[serde(skip_serializing_if = "Option::is_none")]
	pub vendor_extensions: Option<RequestVendorExtensions>,

	// Everything else (tools, reasoning, etc.) - passthrough
	#[serde(flatten, default)]
	pub rest: serde_json::Value,
}
