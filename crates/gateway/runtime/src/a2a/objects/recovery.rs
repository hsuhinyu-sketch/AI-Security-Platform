//! Explicit gateway-local recovery, not A2A tasks/resubscribe or background Agent consumption.
use super::*;
use security_integration_runtime::a2a_objects::events::EventBinding;
use security_types::ActionType;
use std::sync::OnceLock;

pub(crate) const METHOD: &str = gateway_a2a::EVENT_READ_METHOD;

// Disk I/O runs off the Tokio workers, with no unbounded blocking-pool queue or body staging.
pub(super) fn io_slot() -> Result<tokio::sync::OwnedSemaphorePermit, ObjectError> {
	static SLOTS: OnceLock<Arc<tokio::sync::Semaphore>> = OnceLock::new();
	SLOTS
		.get_or_init(|| Arc::new(tokio::sync::Semaphore::new(8)))
		.clone()
		.try_acquire_owned()
		.map_err(|_| ObjectError::Capacity)
}

impl AuthorizedCall {
	pub(super) async fn commit_push_event(self: &Arc<Self>, result: Value) -> Result<(), ProxyError> {
		self.check_continuation()?;
		let objects = self.config.a2a_objects.as_ref().expect("enabled");
		let limits = objects
			.event_recovery
			.as_ref()
			.ok_or_else(|| deny(&self.action, ObjectError::EventStorage))?;
		security_audit::StateJournal::encoded_len(&result, limits.max_event_bytes)
			.map_err(|_| deny(&self.action, ObjectError::EventStorage))?;
		let binding = self.event_binding()?;
		let slot = io_slot().map_err(|e| deny(&self.action, e))?;
		let call = self.clone();
		let commit = tokio::task::spawn_blocking(move || {
			let _slot = slot;
			let objects = call.config.a2a_objects.as_ref().expect("enabled");
			call
				.config
				.a2a_task_store
				.commit_push(objects, &call.permit, binding, result)?;
			call.config.a2a_task_store.drain_push(objects)
		});
		self
			.wait_event_io(async {
				commit
					.await
					.map_err(|_| deny(&self.action, ObjectError::EventStorage))?
					.map_err(|e| deny(&self.action, e))
			})
			.await?;
		self.check_continuation()
	}
	async fn wait_event_io<T>(
		&self,
		future: impl std::future::Future<Output = Result<T, ProxyError>>,
	) -> Result<T, ProxyError> {
		let remaining = self
			.credential
			.expires_at
			.saturating_mul(1000)
			.saturating_sub(chrono::Utc::now().timestamp_millis())
			.max(0) as u64;
		let timeout = std::time::Duration::from_millis(remaining).min(std::time::Duration::from_secs(
			self
				.config
				.a2a_objects
				.as_ref()
				.expect("enabled")
				.stream_idle_seconds,
		));
		let mut revision = self.credential.revision.clone();
		let guarded = async {
			tokio::select! {
				biased;
				_ = revision.changed() => Err(self.stream_denial(ObjectError::ConfigChanged)),
				_ = tokio::time::sleep(timeout) => Err(self.stream_denial(ObjectError::StreamTimeout)),
				result = future => result,
			}
		};
		if let Some(execution) = &self.execution {
			execution.run_for(&self.action, guarded).await?
		} else {
			guarded.await
		}
	}
	pub(super) fn check_continuation(&self) -> Result<(), ProxyError> {
		self.check_credential().map_err(|e| self.stream_denial(e))?;
		self
			.config
			.a2a_task_store
			.validate_permit(
				self.config.a2a_objects.as_ref().expect("enabled"),
				&self.permit,
			)
			.map_err(|e| self.stream_denial(e))?;
		if let Some(execution) = &self.execution {
			execution.failure().map_or(Ok(()), Err)?;
		}
		if self.config.cross_component.is_some() && self.flow.is_none() {
			return Err(deny(&self.action, ObjectError::StreamAuthorization));
		}
		if let Some(flow) = &self.flow {
			flow.current()?;
		}
		let mut actions = vec![&self.invocation, &self.action];
		let read = self.permit.task_id.as_ref().map(|id| {
			agent_object_for_identity(
				&self.action.request_id,
				self.identity.clone(),
				"read",
				ResourceType::AgentTask,
				task_resource_id(&self.scope, id),
			)
		});
		if let Some(read) = &read {
			actions.push(read);
		}
		for action in &actions {
			crate::security::evaluate(&self.config, action)
				.map_err(|_| self.stream_denial(ObjectError::StreamAuthorization))?;
		}
		if let Some(guards) = &self.download_guards {
			guards
				.authorize_a2a_continuation(&self.config, &actions)
				.map_err(|_| deny(&self.action, ObjectError::StreamAuthorization))?;
		}
		self.check_credential().map_err(|e| self.stream_denial(e))?;
		Ok(())
	}
	fn event_binding(&self) -> Result<EventBinding, ProxyError> {
		let flow = self
			.flow
			.as_ref()
			.map(|f| f.recovery_binding())
			.transpose()?;
		let parents = self
			.download_guards
			.as_ref()
			.map(|g| g.a2a_recovery_binding())
			.transpose()?;
		let lineage = serde_json::to_string(&(&self.config, flow, parents))
			.map_err(|_| deny(&self.action, ObjectError::EventStorage))?;
		EventBinding::from_permit(&self.permit, crate::security::digest(&lineage))
			.map_err(|e| deny(&self.action, e))
	}
	pub(super) async fn record_event(&self, rpc: &Value) -> Result<Option<String>, ProxyError> {
		let Some(settings) = self
			.config
			.a2a_objects
			.as_ref()
			.and_then(|o| o.event_recovery.as_ref())
		else {
			return Ok(None);
		};
		let Some(result) = rpc
			.get("result")
			.filter(|result| gateway_a2a::recovery::recoverable(result))
		else {
			return Ok(None);
		};
		self.check_continuation()?;
		let store = settings.store().map_err(|e| deny(&self.action, e))?;
		security_audit::StateJournal::encoded_len(result, settings.max_event_bytes)
			.map_err(|_| deny(&self.action, ObjectError::EventStorage))?;
		let binding = self.event_binding()?;
		let slot = io_slot().map_err(|e| deny(&self.action, e))?;
		let result = result.clone();
		let append = tokio::task::spawn_blocking(move || {
			let _slot = slot;
			store.append(binding, result)
		});
		let cursor = self
			.wait_event_io(async {
				append
					.await
					.map_err(|_| deny(&self.action, ObjectError::EventStorage))?
					.map_err(|e| deny(&self.action, e))
			})
			.await?;
		self.check_continuation()?;
		Ok(Some(cursor))
	}
	fn artifact_visible(&self, id: &str) -> bool {
		let action = agent_object_for_identity(
			&self.action.request_id,
			self.identity.clone(),
			"read",
			ResourceType::AgentArtifact,
			artifact_resource_id(
				&self.scope,
				self.permit.task_id.as_deref().expect("bound"),
				id,
			),
		);
		crate::security::evaluate(&self.config, &action).is_ok()
			&& self.download_guards.as_ref().is_none_or(|g| {
				g.authorize_a2a_continuation(&self.config, &[&action])
					.is_ok()
			})
	}
	pub(super) fn project_event(&self, result: Option<&mut Value>) -> Result<bool, ProxyError> {
		gateway_a2a::recovery::project_event(result, |id| self.artifact_visible(id))
			.map_err(|e| deny(&self.action, object_error(e)))
	}

	/// A bounded local JSON batch. Does NOT finish old snapshots or reopen terminal Tasks.
	pub(crate) async fn recovery_response(&self) -> Result<Option<Response>, ProxyError> {
		let Some((after, limit)) = &self.recovery else {
			return Ok(None);
		};
		self.check_continuation()?;
		let mut recovery = self.action.clone();
		recovery.action.action_type = ActionType::AgentEventRecover;
		recovery.action.name = "read".into();
		crate::security::evaluate(&self.config, &recovery)
			.map_err(|_| deny(&recovery, ObjectError::StreamAuthorization))?;
		if let Some(guards) = &self.download_guards {
			guards.authorize_a2a_continuation(&self.config, &[&recovery])?;
		}
		let objects = self.config.a2a_objects.as_ref().expect("enabled");
		let _read_lease = self
			.config
			.a2a_task_store
			.reserve_stream(objects)
			.map_err(|e| deny(&recovery, e))?;
		self
			.config
			.a2a_task_store
			.validate_permit(objects, &self.permit)
			.map_err(|e| deny(&recovery, e))?;
		let settings = objects
			.event_recovery
			.as_ref()
			.ok_or_else(|| deny(&recovery, ObjectError::Unsupported))?;
		let store = settings.store().map_err(|e| deny(&recovery, e))?;
		let binding = self.event_binding()?;
		let after = after.clone();
		let limit = *limit;
		let staging_slot = Arc::new(io_slot().map_err(|e| deny(&recovery, e))?);
		let slot = staging_slot.clone();
		let read = tokio::task::spawn_blocking(move || {
			let _slot = slot;
			store.read(&binding, &after, limit)
		});
		let batch = self
			.wait_event_io(async {
				read
					.await
					.map_err(|_| deny(&recovery, ObjectError::EventStorage))?
					.map_err(|e| deny(&recovery, e))
			})
			.await?;
		let events = gateway_a2a::recovery::project_batch(
			batch
				.events
				.iter()
				.map(|event| (event.cursor.as_str(), event.result.clone())),
			|id| self.artifact_visible(id),
		)
		.map_err(|e| deny(&self.action, object_error(e)))?;
		self.check_continuation()?;
		self
			.config
			.a2a_task_store
			.validate_permit(objects, &self.permit)
			.map_err(|e| deny(&recovery, e))?;
		crate::security::evaluate(&self.config, &recovery)
			.map_err(|_| deny(&recovery, ObjectError::StreamAuthorization))?;
		if let Some(guards) = &self.download_guards {
			guards.authorize_a2a_continuation(&self.config, &[&recovery])?;
		}
		let body =
			gateway_a2a::recovery::response(&self.rpc_id, events, batch.next_cursor, batch.has_more);
		security_audit::StateJournal::encoded_len(&body, settings.max_batch_bytes + 4096)
			.map_err(|_| deny(&recovery, ObjectError::EventStorage))?;
		audit_object_check(&recovery, Ok(()), &UiSecurityAuditSink);
		let bytes = bytes::Bytes::from(
			serde_json::to_vec(&body).map_err(|_| deny(&recovery, ObjectError::EventStorage))?,
		);
		let body = Body::from_stream(futures_util::stream::once(async move {
			let _leases = (staging_slot, _read_lease);
			Ok::<_, std::io::Error>(bytes)
		}));
		let response = ::http::Response::builder()
			.status(200)
			.header(header::CONTENT_TYPE, "application/json")
			.header(header::CACHE_CONTROL, "private, no-store")
			.body(body)
			.map_err(|_| deny(&recovery, ObjectError::EventStorage))?;
		Ok(Some(response))
	}
}
