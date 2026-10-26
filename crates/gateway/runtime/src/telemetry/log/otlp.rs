use super::*;
use opentelemetry::logs::{AnyValue, LogRecord as _, Logger, LoggerProvider as _, Severity};
use opentelemetry::{Key, KeyValue};
use opentelemetry_otlp::{WithExportConfig, WithHttpConfig};
use opentelemetry_sdk::Resource;
use opentelemetry_sdk::logs::SdkLoggerProvider;
pub struct OtelAccessLogger {
	provider: SdkLoggerProvider,
	logger: opentelemetry_sdk::logs::SdkLogger,
}

impl std::fmt::Debug for OtelAccessLogger {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.debug_struct("OtelAccessLogger").finish()
	}
}

fn to_any_value(v: &ValueBag) -> AnyValue {
	if let Some(b) = v.to_str() {
		AnyValue::String(b.to_string().into())
	} else if let Some(b) = v.to_i64() {
		AnyValue::Int(b)
	} else if let Some(b) = v.to_f64() {
		AnyValue::Double(b)
	} else if let Some(b) = v.to_bool() {
		AnyValue::Boolean(b)
	} else {
		AnyValue::String(v.to_string().into())
	}
}

/// Policy-aware OTLP gRPC log exporter that routes via `GrpcReferenceChannel`, ensuring
/// backend policies are looked up and applied by `PolicyClient::call_reference`.
#[derive(Clone)]
struct PolicyGrpcLogExporter {
	tonic_client:
		opentelemetry_proto::tonic::collector::logs::v1::logs_service_client::LogsServiceClient<
			crate::http::ext_proc::GrpcReferenceChannel,
		>,
	is_shutdown: Arc<bool>,
	resource: Resource,
	runtime: tokio::runtime::Handle,
}

impl std::fmt::Debug for PolicyGrpcLogExporter {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.debug_struct("PolicyGrpcLogExporter").finish()
	}
}

impl PolicyGrpcLogExporter {
	fn new(
		client: crate::proxy::httpproxy::PolicyClient,
		target: Arc<crate::types::agent::SimpleBackendReference>,
		policies: Vec<crate::types::agent::BackendTrafficPolicy>,
		runtime: tokio::runtime::Handle,
	) -> Self {
		use crate::http::ext_proc::GrpcReferenceChannel;
		// The previous exporter rebuilt PolicyClient::new(inputs), clearing caller labels.
		let mut client = client;
		client.outbound = None;
		let channel = GrpcReferenceChannel {
			target,
			policies: Arc::new(policies),
			client,
		};
		let tonic_client =
			opentelemetry_proto::tonic::collector::logs::v1::logs_service_client::LogsServiceClient::new(
				channel,
			);
		Self {
			tonic_client,
			is_shutdown: Arc::new(false),
			resource: Resource::builder().build(),
			runtime,
		}
	}
}

impl opentelemetry_sdk::logs::LogExporter for PolicyGrpcLogExporter {
	fn export(
		&self,
		batch: opentelemetry_sdk::logs::LogBatch<'_>,
	) -> impl std::future::Future<Output = opentelemetry_sdk::error::OTelSdkResult> + Send {
		use opentelemetry_proto::transform::logs::tonic::group_logs_by_resource_and_scope;
		use opentelemetry_sdk::error::{OTelSdkError, OTelSdkResult};

		let is_shutdown = self.is_shutdown.clone();
		let mut client = self.tonic_client.clone();
		let resource: opentelemetry_proto::transform::common::tonic::ResourceAttributesWithSchema =
			(&self.resource).into();
		let resource_logs = group_logs_by_resource_and_scope(&batch, &resource);
		let handle = self.runtime.clone();

		async move {
			if *is_shutdown {
				return Err(OTelSdkError::AlreadyShutdown);
			}
			let req =
				opentelemetry_proto::tonic::collector::logs::v1::ExportLogsServiceRequest { resource_logs };
			// Drop tonic Response inside the spawned task so guard is released on the Tokio runtime, not on
			// the BatchProcessor OS thread which has no Tokio context.
			handle
				.spawn(async move {
					client
						.export(req)
						.await
						.map(|_| ())
						.map_err(|e| e.message().to_string())
				})
				.await
				.map_err(|e| OTelSdkError::InternalFailure(e.to_string()))?
				.map_err(OTelSdkError::InternalFailure) as OTelSdkResult
		}
	}

	fn shutdown(&self) -> opentelemetry_sdk::error::OTelSdkResult {
		Ok(())
	}

	fn set_resource(&mut self, resource: &opentelemetry_sdk::Resource) {
		self.resource = resource.clone();
	}
}

fn build_resource(defaults: Option<&trc::GlobalResourceDefaults>) -> Resource {
	let mut resource_builder = Resource::builder();
	if let Some(d) = defaults {
		for kv in &d.attrs {
			resource_builder = resource_builder.with_attribute(kv.clone());
		}
	}
	resource_builder = resource_builder.with_service_name(
		defaults
			.and_then(|d| d.service_name.clone())
			.unwrap_or_else(|| "agentgateway".to_string()),
	);
	resource_builder = resource_builder.with_attribute(KeyValue::new(
		"service.version",
		platform_core::version::BuildInfo::new().version,
	));
	resource_builder.build()
}

impl OtelAccessLogger {
	pub fn new(
		policy_client: crate::proxy::httpproxy::PolicyClient,
		backend_ref: crate::types::agent::SimpleBackendReference,
		policies: Vec<crate::types::agent::BackendTrafficPolicy>,
		protocol: crate::types::agent::TracingProtocol,
		path: String,
	) -> anyhow::Result<Self> {
		let defaults = trc::global_resource_defaults();
		let resource = build_resource(defaults);

		let exporter_runtime = policy_client.exporter_runtime();

		let provider = if protocol == crate::types::agent::TracingProtocol::Grpc {
			let exporter = PolicyGrpcLogExporter::new(
				policy_client.clone(),
				Arc::new(backend_ref),
				policies,
				exporter_runtime,
			);
			SdkLoggerProvider::builder()
				.with_resource(resource)
				.with_batch_exporter(exporter)
				.build()
		} else {
			let http_client = trc::PolicyOtelHttpClient {
				policy_client,
				backend_ref,
				policies,
				runtime: exporter_runtime,
			};
			let exporter = opentelemetry_otlp::LogExporter::builder()
				.with_http()
				.with_http_client(http_client)
				.with_endpoint(path)
				.build()?;
			SdkLoggerProvider::builder()
				.with_resource(resource)
				.with_batch_exporter(exporter)
				.build()
		};

		let logger = provider.logger("agentgateway.access");

		Ok(Self { provider, logger })
	}

	pub fn shutdown(&self) {
		let _ = self.provider.shutdown();
	}
}

impl OtelLogSink for OtelAccessLogger {
	fn emit<'v>(&self, level: &str, target: &str, kv: &[(&str, Option<ValueBag<'v>>)]) {
		let severity = match level {
			"error" => Severity::Error,
			"warn" => Severity::Warn,
			"info" => Severity::Info,
			"debug" => Severity::Debug,
			"trace" => Severity::Trace,
			_ => Severity::Info,
		};
		let severity_text: &'static str = match level {
			"error" => "ERROR",
			"warn" => "WARN",
			"info" => "INFO",
			"debug" => "DEBUG",
			"trace" => "TRACE",
			_ => "INFO",
		};

		let mut record = self.logger.create_log_record();
		record.set_severity_number(severity);
		record.set_severity_text(severity_text);
		record.set_target(target.to_string());

		let mut trace_id_val: Option<u128> = None;
		let mut span_id_val: Option<u64> = None;

		for &(k, ref v) in kv {
			let Some(v) = v else { continue };

			match k {
				"trace.id" => {
					if let Some(s) = v.to_str()
						&& let Ok(id) = u128::from_str_radix(&s, 16)
					{
						trace_id_val = Some(id);
					}
					record.add_attribute(Key::new(k.to_string()), to_any_value(v));
				},
				"span.id" => {
					if let Some(s) = v.to_str()
						&& let Ok(id) = u64::from_str_radix(&s, 16)
					{
						span_id_val = Some(id);
					}
					record.add_attribute(Key::new(k.to_string()), to_any_value(v));
				},
				_ => {
					record.add_attribute(Key::new(k.to_string()), to_any_value(v));
				},
			}
		}

		if let Some(tid) = trace_id_val {
			record.set_trace_context(
				opentelemetry::trace::TraceId::from(tid),
				span_id_val
					.map(opentelemetry::trace::SpanId::from)
					.unwrap_or(opentelemetry::trace::SpanId::INVALID),
				None,
			);
		}

		self.logger.emit(record);
	}

	fn shutdown(&self) {
		let _ = self.provider.shutdown();
	}
}
