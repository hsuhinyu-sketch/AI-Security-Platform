//! Local management exposure policy. This is not caller authentication.
use axum::{
	extract::{Request, State},
	middleware::Next,
	response::{IntoResponse, Response},
};
use http::{Method, StatusCode};
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub enum Mode {
	#[default]
	Edge,
	Diagnostic,
	Demo,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default, rename_all = "camelCase", deny_unknown_fields)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct ManagementConfig {
	pub mode: Mode,
	/// Enables profiling, debug, logging changes and shutdown only in demo mode.
	pub unsafe_debug: bool,
}

impl ManagementConfig {
	pub fn validate(&self, address: &crate::Address) -> anyhow::Result<()> {
		anyhow::ensure!(
			!self.unsafe_debug || self.mode == Mode::Demo,
			"config.management.unsafeDebug requires demo mode"
		);
		if let crate::Address::SocketAddr(address) = address {
			anyhow::ensure!(
				address.ip().is_loopback(),
				"management listener must use loopback, a Unix socket or off; remote management is not authenticated"
			);
		}
		Ok(())
	}

	fn permits(&self, method: &Method, path: &str) -> bool {
		if self.mode == Mode::Edge {
			return false;
		}
		let read = method == Method::GET || method == Method::HEAD;
		if read
			&& (matches!(
				path,
				"/"
					| "/ui"
					| "/api/runtime"
					| "/api/costs/models"
					| "/api/security/overview"
					| "/api/security/events"
					| "/api/security/stream"
			) || path.starts_with("/ui/")
				|| path.starts_with("/api/security/events/"))
		{
			return true;
		}
		// These POST endpoints query logs; they do not mutate runtime configuration.
		if method == Method::POST
			&& matches!(
				path,
				"/api/logs/search" | "/api/logs/get" | "/api/logs/tail" | "/api/logs/analytics/summary"
			) {
			return true;
		}
		if self.mode != Mode::Demo {
			return false;
		}
		if read
			&& matches!(
				path,
				"/api/config" | "/api/config/effective" | "/config_dump"
			) {
			return true;
		}
		if method == Method::POST
			&& matches!(
				path,
				"/api/config" | "/api/costs/refresh-base" | "/api/cel" | "/cel"
			) {
			return true;
		}
		self.unsafe_debug
			&& ((read
				&& matches!(
					path,
					"/debug/pprof/profile" | "/debug/pprof/heap" | "/memory" | "/debug/tasks"
				)) || (method == Method::POST
				&& matches!(path, "/quitquitquit" | "/logging" | "/debug/trace")))
	}
}

pub async fn enforce(
	State(config): State<ManagementConfig>,
	request: Request,
	next: Next,
) -> Response {
	// A loopback listener can still receive browser requests after DNS rebinding.
	// Require local HTTP authority names when present; Unix/HTTP 1.0 clients can omit them.
	let local_authority = |value: &str| {
		value
			.parse::<http::uri::Authority>()
			.is_ok_and(|authority| {
				let host = authority
					.host()
					.trim_start_matches('[')
					.trim_end_matches(']');
				host.eq_ignore_ascii_case("localhost")
					|| host
						.parse::<std::net::IpAddr>()
						.is_ok_and(|ip| ip.is_loopback())
			})
	};
	if request
		.headers()
		.get(http::header::HOST)
		.is_some_and(|host| !host.to_str().is_ok_and(local_authority))
		|| request
			.uri()
			.authority()
			.is_some_and(|authority| !local_authority(authority.as_str()))
	{
		return (StatusCode::FORBIDDEN, "local management authority required").into_response();
	}
	let path = request.uri().path();
	if !config.permits(request.method(), path) {
		return (
			StatusCode::FORBIDDEN,
			"management operation disabled by deployment mode",
		)
			.into_response();
	}
	let sensitive = matches!(
		path,
		"/quitquitquit" | "/logging" | "/debug/trace" | "/memory"
	) || path.starts_with("/debug/")
		|| (request.method() == Method::POST
			&& matches!(
				path,
				"/api/config" | "/api/costs/refresh-base" | "/api/cel" | "/cel"
			));
	// Non-simple header prevents cross-origin HTML forms from invoking local mutations.
	// It is not a credential: other local processes can still send it.
	if sensitive
		&& request
			.headers()
			.get("x-requested-with")
			.and_then(|v| v.to_str().ok())
			!= Some("AI-Security-Platform")
	{
		return (
			StatusCode::FORBIDDEN,
			"explicit management request header required",
		)
			.into_response();
	}
	next.run(request).await
}
