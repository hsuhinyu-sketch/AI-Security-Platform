// Originally derived from https://github.com/istio/ztunnel (Apache 2.0 licensed)

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use hyper::Request;
use hyper::body::Incoming;
use platform_core::drain::DrainWatcher;
use prometheus_client::encoding::text::encode;
use prometheus_client::registry::Registry;

use super::hyper_helpers;
use crate::Address;
use crate::http::Response;

pub struct Server {
	s: hyper_helpers::Server<Mutex<Registry>>,
}

impl Server {
	pub async fn new(
		addr: Address,
		drain_rx: DrainWatcher,
		registry: Registry,
	) -> anyhow::Result<Self> {
		hyper_helpers::Server::<Mutex<Registry>>::bind("stats", addr, drain_rx, Mutex::new(registry))
			.await
			.map(|s| Server { s })
	}

	pub fn address(&self) -> Option<SocketAddr> {
		self.s.address()
	}

	pub fn spawn(self) {
		self.s.spawn(|registry, req| async move {
			match req.uri().path() {
				"/metrics" | "/stats/prometheus" => Ok(handle_metrics(registry, req).await),
				_ => Ok(hyper_helpers::empty_response(hyper::StatusCode::NOT_FOUND)),
			}
		})
	}
}

async fn handle_metrics(reg: Arc<Mutex<Registry>>, req: Request<Incoming>) -> Response {
	let mut buf = String::new();
	let reg = reg.lock().expect("mutex");
	if let Err(err) = encode(&mut buf, &reg) {
		return ::http::Response::builder()
			.status(hyper::StatusCode::INTERNAL_SERVER_ERROR)
			.body(err.to_string().into())
			.expect("builder with known status code should not fail");
	}

	let response_content_type = content_type(&req);

	::http::Response::builder()
		.status(hyper::StatusCode::OK)
		.header(hyper::header::CONTENT_TYPE, response_content_type)
		.body(buf.into())
		.expect("builder with known status code should not fail")
}

#[derive(Default)]
enum ContentType {
	#[default]
	PlainText,
	OpenMetrics,
}

impl From<ContentType> for &str {
	fn from(c: ContentType) -> Self {
		match c {
			ContentType::PlainText => "text/plain; charset=utf-8",
			ContentType::OpenMetrics => "application/openmetrics-text;charset=utf-8;version=1.0.0",
		}
	}
}

#[inline(always)]
fn content_type<T>(req: &Request<T>) -> &str {
	req
		.headers()
		.get_all(http::header::ACCEPT)
		.iter()
		.flat_map(|entry| entry.to_str().ok())
		// get_all can return multiple in one line still
		.flat_map(|entry| {
			entry
				.split(",")
				.map(str::trim)
				.map(|entry| entry.to_lowercase())
		})
		.find_map(|v| match v.split(";").collect::<Vec<_>>().first() {
			Some(&"application/openmetrics-text") => Some(ContentType::OpenMetrics),
			_ => None,
		})
		.unwrap_or_default()
		.into()
}
