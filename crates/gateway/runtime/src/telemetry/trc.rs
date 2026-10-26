use crate::{cel, telemetry::log::LoggingFields};
use std::{collections::HashMap, sync::Arc};

pub use traceparent::TraceParent;

#[cfg(feature = "telemetry-otlp")]
mod otlp;
#[cfg(feature = "telemetry-otlp")]
pub use otlp::*;

#[derive(serde::Serialize, serde::Deserialize, Default, Copy, Eq, PartialEq, Clone, Debug)]
#[serde(rename_all = "lowercase", deny_unknown_fields)]
#[cfg_attr(feature = "schema", derive(crate::JsonSchema))]
pub enum Protocol {
	#[default]
	Grpc,
	Http,
}

#[derive(serde::Serialize, Clone, Debug)]
pub struct DeprecatedConfig {
	pub endpoint: Option<String>,
	#[serde(serialize_with = "crate::serdes::ser_sensitive_header_map")]
	pub headers: HashMap<String, String>,
	pub protocol: Protocol,
	pub fields: LoggingFields,
	pub random_sampling: Option<Arc<cel::Expression>>,
	pub client_sampling: Option<Arc<cel::Expression>>,
	pub path: String,
}

mod traceparent {
	use std::fmt;

	use rand::RngExt;

	use crate::http::Request;
	use crate::http::x_headers::TRACEPARENT;

	/// Represents a traceparent, as defined by https://www.w3.org/TR/trace-context/
	#[derive(Clone, Eq, PartialEq)]
	pub struct TraceParent {
		pub version: u8,
		pub trace_id: u128,
		pub span_id: u64,
		pub flags: u8,
	}

	impl Default for TraceParent {
		fn default() -> Self {
			Self::new()
		}
	}

	impl TraceParent {
		pub fn new() -> Self {
			let mut rng = rand::rng();
			Self {
				version: 0,
				trace_id: rng.random(),
				span_id: rng.random(),
				flags: 0,
			}
		}
		pub fn insert_header(&self, req: &mut Request) {
			let hv = hyper::header::HeaderValue::from_bytes(format!("{self:?}").as_bytes()).unwrap();
			req.headers_mut().insert(TRACEPARENT, hv);
		}
		pub fn from_request(req: &Request) -> Option<Self> {
			req
				.headers()
				.get(TRACEPARENT)
				.and_then(|b| b.to_str().ok())
				.and_then(|b| TraceParent::try_from(b).ok())
		}
		pub fn new_span(&self) -> Self {
			let mut rng = rand::rng();
			let mut cpy: TraceParent = self.clone();
			cpy.span_id = rng.random();
			cpy
		}
		pub fn trace_id(&self) -> String {
			format!("{:032x}", self.trace_id)
		}
		pub fn span_id(&self) -> String {
			format!("{:016x}", self.span_id)
		}
		pub fn is_sampled(&self) -> bool {
			(self.flags & 0x01) == 0x01
		}
	}

	impl fmt::Debug for TraceParent {
		fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
			write!(
				f,
				"{:02x}-{:032x}-{:016x}-{:02x}",
				self.version, self.trace_id, self.span_id, self.flags
			)
		}
	}

	impl fmt::Display for TraceParent {
		fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
			write!(f, "{:032x}", self.trace_id,)
		}
	}

	impl TryFrom<&str> for TraceParent {
		type Error = anyhow::Error;

		fn try_from(value: &str) -> Result<Self, Self::Error> {
			if value.len() != 55 {
				anyhow::bail!("traceparent malformed length was {}", value.len())
			}

			let segs: Vec<&str> = value.split('-').collect();

			Ok(Self {
				version: u8::from_str_radix(segs[0], 16)?,
				trace_id: u128::from_str_radix(segs[1], 16)?,
				span_id: u64::from_str_radix(segs[2], 16)?,
				flags: u8::from_str_radix(segs[3], 16)?,
			})
		}
	}
}

/// Validate explicit use rather than silently discarding an unavailable output.
pub fn validate_compiled() -> anyhow::Result<()> {
	anyhow::ensure!(
		cfg!(feature = "telemetry-otlp"),
		"OTLP telemetry is not compiled; enable telemetry-otlp"
	);
	Ok(())
}

pub(crate) fn deserialize_optional<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
	D: serde::Deserializer<'de>,
	T: serde::Deserialize<'de>,
{
	let value = <Option<T> as serde::Deserialize>::deserialize(deserializer)?;
	if value.is_some() {
		validate_compiled().map_err(serde::de::Error::custom)?;
	}
	Ok(value)
}
