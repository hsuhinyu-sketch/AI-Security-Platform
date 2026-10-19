//! Non-stream Task Artifact hydration. No client-chosen fetch endpoint or forwarded credentials.
use super::*;
use base64::Engine;
use security_integration_runtime::a2a_objects::downloads::{
	ArtifactDownloadConfig, ArtifactSource,
};
use sha2::{Digest, Sha256};
use std::{net::SocketAddr, time::Duration};
use tokio::io::AsyncReadExt;

// Global across AI systems. Try-acquire only: no unbounded transfer/wait queue.
static TRANSFERS: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(8);

pub(super) struct FileReference {
	url: reqwest::Url,
	sha256: [u8; 32],
	size: usize,
}
impl FileReference {
	pub(super) fn parse(part: &Value) -> Result<Self, ObjectError> {
		let uri = part["file"]["uri"]
			.as_str()
			.filter(|s| s.len() <= 2048)
			.ok_or(ObjectError::DownloadSource)?;
		let url = reqwest::Url::parse(uri).map_err(|_| ObjectError::DownloadSource)?;
		if url.as_str() != uri
			|| url.scheme() != "https"
			|| !url.username().is_empty()
			|| url.password().is_some()
			|| url.query().is_some()
			|| url.fragment().is_some()
		{
			return Err(ObjectError::DownloadSource);
		}
		let manifest = &part["metadata"]["aispDownload"];
		object(manifest, &["sha256", "sizeBytes"])?;
		let hash = manifest["sha256"]
			.as_str()
			.filter(|s| {
				s.len() == 64
					&& s
						.bytes()
						.all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
			})
			.ok_or(ObjectError::DownloadIntegrity)?;
		let mut sha256 = [0; 32];
		for (i, byte) in sha256.iter_mut().enumerate() {
			*byte = u8::from_str_radix(&hash[i * 2..i * 2 + 2], 16)
				.map_err(|_| ObjectError::DownloadIntegrity)?;
		}
		let size = manifest["sizeBytes"]
			.as_u64()
			.and_then(|n| usize::try_from(n).ok())
			.ok_or(ObjectError::DownloadIntegrity)?;
		Ok(Self { url, sha256, size })
	}
}
struct Plan {
	artifact: usize,
	part: usize,
	reference: FileReference,
	source: ArtifactSource,
	action: ActionRequest,
	destination: String,
}

impl AuthorizedCall {
	pub(crate) fn set_download_constraints(
		&mut self,
		flow: Option<crate::security_flow::FlowAccess>,
		guards: Option<crate::proxy::RoutingGuards>,
	) {
		self.flow = flow;
		self.download_guards = guards;
	}
	fn download_live(&self, plan: &Plan) -> Result<(), ProxyError> {
		self.check_credential().map_err(|e| deny(&plan.action, e))?;
		self
			.config
			.a2a_task_store
			.validate_permit(
				self.config.a2a_objects.as_ref().expect("enabled"),
				&self.permit,
			)
			.map_err(|e| deny(&plan.action, e))?;
		let task = self
			.permit
			.task_id
			.as_deref()
			.ok_or_else(|| deny(&plan.action, ObjectError::ResponseBinding))?;
		let task_read = agent_object_for_identity(
			&self.action.request_id,
			self.identity.clone(),
			"read",
			ResourceType::AgentTask,
			task_resource_id(&self.scope, task),
		);
		let mut artifact_read = plan.action.clone();
		artifact_read.action.action_type = security_types::ActionType::AgentArtifactRead;
		artifact_read.action.name = "read".into();
		for action in [
			&self.invocation,
			&self.action,
			&task_read,
			&artifact_read,
			&plan.action,
		] {
			crate::security::evaluate(&self.config, action)
				.map_err(|_| ProxyError::AuthorizationFailed)?;
		}
		if let Some(guards) = &self.download_guards {
			guards.authorize_artifact_download(
				&self.config,
				&[
					&self.invocation,
					&self.action,
					&task_read,
					&artifact_read,
					&plan.action,
				],
				&plan.action,
				&plan.destination,
			)?;
		}
		if let Some(policy) = &self.config.data_egress {
			security_integration_runtime::check_data_egress(
				policy,
				&plan.action,
				&plan.destination,
				&UiSecurityAuditSink,
			)
			.map_err(|_| ProxyError::AuthorizationFailed)?;
		}
		if self.config.cross_component.is_some() && self.flow.is_none() {
			return Err(deny(&plan.action, ObjectError::DownloadSource));
		}
		if let Some(flow) = &self.flow {
			flow.check(&plan.action, &plan.destination)?;
		}
		// Dynamic authorization may have waited. Do not extend credential/config lifetimes.
		self.check_credential().map_err(|e| deny(&plan.action, e))?;
		self
			.config
			.a2a_task_store
			.validate_permit(
				self.config.a2a_objects.as_ref().expect("enabled"),
				&self.permit,
			)
			.map_err(|e| deny(&plan.action, e))?;
		Ok(())
	}

	pub(super) async fn hydrate_artifacts(&self, rpc: &mut Value) -> Result<(), ProxyError> {
		let Some(artifacts) = rpc["result"].get("artifacts").and_then(Value::as_array) else {
			return Ok(());
		};
		let Some(cfg) = self
			.config
			.a2a_objects
			.as_ref()
			.and_then(|c| c.artifact_downloads.as_ref())
		else {
			return Ok(());
		};
		cfg
			.validate()
			.map_err(|_| deny(&self.action, ObjectError::DownloadSource))?;
		let deadline = tokio::time::Instant::now() + Duration::from_secs(cfg.timeout_seconds);
		let mut plans = vec![];
		let mut total = 0usize;
		let task = self
			.permit
			.task_id
			.as_deref()
			.ok_or_else(|| deny(&self.action, ObjectError::ResponseBinding))?;
		// Preflight all visible files and grants before the first GET. Hidden artifacts were
		// already projected out by process_result; they never trigger downloads.
		for (i, artifact) in artifacts.iter().enumerate() {
			for (j, part) in artifact["parts"]
				.as_array()
				.expect("validated")
				.iter()
				.enumerate()
			{
				if part["kind"] != "file" || part["file"].get("uri").is_none() {
					continue;
				}
				let mut action = agent_object_for_identity(
					&self.action.request_id,
					self.identity.clone(),
					"download",
					ResourceType::AgentArtifact,
					artifact_resource_id(
						&self.scope,
						task,
						artifact["artifactId"].as_str().expect("validated"),
					),
				);
				action.action.action_type = security_types::ActionType::AgentArtifactDownload;
				let reference = FileReference::parse(part).map_err(|e| deny(&action, e))?;
				total = total
					.checked_add(reference.size)
					.ok_or_else(|| deny(&action, ObjectError::DownloadLimit))?;
				if plans.len() >= cfg.max_files
					|| reference.size > cfg.max_file_bytes
					|| total > cfg.max_total_bytes
				{
					return Err(deny(&action, ObjectError::DownloadLimit));
				}
				let source = cfg
					.sources
					.iter()
					.find(|source| source.matches(&reference.url))
					.ok_or_else(|| deny(&action, ObjectError::DownloadSource))?
					.clone();
				let destination = format!(
					"{}:{}",
					reference.url.host_str().expect("source domain"),
					reference.url.port_or_known_default().expect("HTTPS")
				);
				let plan = Plan {
					artifact: i,
					part: j,
					reference,
					source,
					action,
					destination,
				};
				plans.push(plan);
			}
		}
		if plans.is_empty() {
			return Ok(());
		}
		let _slot = TRANSFERS
			.try_acquire()
			.map_err(|_| deny(&self.action, ObjectError::DownloadLimit))?;
		let mut revision = self.credential.revision.clone();
		let expiry_millis = self
			.credential
			.expires_at
			.saturating_mul(1000)
			.saturating_sub(chrono::Utc::now().timestamp_millis())
			.max(0) as u64;
		let expiry_wait = Duration::from_millis(expiry_millis.min((cfg.timeout_seconds + 1) * 1000));
		let work = async {
			// All grants must pass before any GET. Yield between files so timers and
			// cancellation can run; synchronous PDP calls retain their own IO timeout.
			for plan in &plans {
				self.download_live(plan)?;
				tokio::task::yield_now().await;
			}
			for plan in &plans {
				self.download_live(plan)?;
				if tokio::time::Instant::now() >= deadline {
					return Err(deny(&plan.action, ObjectError::StreamTimeout));
				}
				let _lease = self
					.execution
					.as_ref()
					.map(|scope| {
						scope.reserve(
							security_integration_runtime::execution_budget::CallKind::Transport,
							&plan.action,
						)
					})
					.transpose()?;
				let bytes = self.fetch_file(plan, cfg, deadline).await?;
				self.download_live(plan)?;
				let file = rpc["result"]["artifacts"][plan.artifact]["parts"][plan.part]["file"]
					.as_object_mut()
					.expect("validated");
				file.remove("uri");
				file.insert(
					"bytes".into(),
					Value::String(base64::engine::general_purpose::STANDARD.encode(bytes)),
				);
				audit_object_check(&plan.action, Ok(()), &UiSecurityAuditSink);
			}
			// The first file's permit/context may change while later files are pending.
			for plan in &plans {
				self.download_live(plan)?;
			}
			if tokio::time::Instant::now() >= deadline {
				return Err(deny(&self.action, ObjectError::StreamTimeout));
			}
			Ok(())
		};
		let guarded = async {
			tokio::select! {
				biased;
				_ = revision.changed() => Err(deny(&self.action, ObjectError::ConfigChanged)),
				_ = tokio::time::sleep(expiry_wait) => Err(deny(&self.action, ObjectError::CredentialExpired)),
				result = tokio::time::timeout_at(deadline, work) => result.map_err(|_| deny(&self.action, ObjectError::StreamTimeout))?,
			}
		};
		if let Some(execution) = &self.execution {
			execution.run_for(&self.action, guarded).await?
		} else {
			guarded.await
		}
	}

	async fn fetch_file(
		&self,
		plan: &Plan,
		cfg: &ArtifactDownloadConfig,
		deadline: tokio::time::Instant,
	) -> Result<Vec<u8>, ProxyError> {
		let fail = |e| deny(&plan.action, e);
		let origin = plan
			.source
			.url()
			.map_err(|_| fail(ObjectError::DownloadSource))?;
		let addresses: Vec<_> = plan
			.source
			.addresses
			.iter()
			.map(|ip| SocketAddr::new(*ip, origin.port_or_known_default().expect("HTTPS")))
			.collect();
		let mut builder = reqwest::Client::builder()
			.https_only(true)
			.http1_only()
			.redirect(reqwest::redirect::Policy::none())
			.retry(reqwest::retry::never())
			.no_proxy()
			.no_gzip()
			.no_brotli()
			.no_deflate()
			.no_zstd()
			.pool_max_idle_per_host(0)
			.timeout(Duration::from_secs(cfg.timeout_seconds))
			.resolve_to_addrs(origin.host_str().expect("domain"), &addresses);
		if let Some(path) = &plan.source.root_ca_pem_file {
			let file = tokio::fs::File::open(path)
				.await
				.map_err(|_| fail(ObjectError::DownloadTransport))?;
			let mut pem = Vec::new();
			file
				.take(65537)
				.read_to_end(&mut pem)
				.await
				.map_err(|_| fail(ObjectError::DownloadTransport))?;
			if pem.len() > 65536 {
				return Err(fail(ObjectError::DownloadLimit));
			}
			let cert =
				reqwest::Certificate::from_pem(&pem).map_err(|_| fail(ObjectError::DownloadTransport))?;
			builder = builder.tls_certs_only([cert]);
		}
		let client = builder
			.build()
			.map_err(|_| fail(ObjectError::DownloadTransport))?;
		let receive = async {
			if tokio::time::Instant::now() >= deadline {
				return Err(fail(ObjectError::StreamTimeout));
			}
			// Never copy JWT, Agent/backend auth, cookies, capability or context headers.
			let mut response = client
				.get(plan.reference.url.clone())
				.header("accept-encoding", "identity")
				.send()
				.await
				.map_err(|_| fail(ObjectError::DownloadTransport))?;
			if response.status() != reqwest::StatusCode::OK
				|| response
					.remote_addr()
					.is_none_or(|peer| !addresses.contains(&peer))
				|| response
					.headers()
					.get("content-encoding")
					.is_some_and(|v| v != "identity")
				|| response
					.content_length()
					.is_some_and(|n| n != plan.reference.size as u64)
			{
				return Err(fail(ObjectError::DownloadTransport));
			}
			let mut bytes = Vec::with_capacity(plan.reference.size);
			while let Some(chunk) = response
				.chunk()
				.await
				.map_err(|_| fail(ObjectError::DownloadTransport))?
			{
				self.check_credential().map_err(fail)?;
				if chunk.len() > plan.reference.size.saturating_sub(bytes.len()) {
					return Err(fail(ObjectError::DownloadLimit));
				}
				bytes.extend_from_slice(&chunk);
			}
			if bytes.len() != plan.reference.size
				|| Sha256::digest(&bytes).as_slice() != plan.reference.sha256
			{
				return Err(fail(ObjectError::DownloadIntegrity));
			}
			Ok(bytes)
		};
		tokio::pin!(receive);
		let mut interval = tokio::time::interval(Duration::from_secs(
			self
				.config
				.a2a_objects
				.as_ref()
				.expect("enabled")
				.reauthorize_seconds,
		));
		interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
		loop {
			tokio::select! {
				biased;
				_ = interval.tick() => {
					self.download_live(plan)?;
					if tokio::time::Instant::now() >= deadline { return Err(fail(ObjectError::StreamTimeout)); }
				},
				result = &mut receive => return result,
			}
		}
	}
}
