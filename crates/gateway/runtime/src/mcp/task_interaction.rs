//! Task-owned form, roots and managed sampling, only on a live tasks/result POST.
//! Metadata handles never extend the response-stream lease or create execution authority.
use super::*;

#[derive(Clone)]
pub(crate) struct Link {
	ticket: Ticket,
}

impl std::fmt::Debug for Link {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.write_str("TaskInteraction")
	}
}
pub(crate) struct Lease {
	record: Arc<Record>,
	released: AtomicBool,
}
impl Lease {
	pub(crate) fn release(&self) {
		if !self.released.swap(true, Ordering::AcqRel) {
			self
				.record
				.interaction_active
				.store(false, Ordering::Release);
		}
	}
}
impl Drop for Lease {
	fn drop(&mut self) {
		self.release();
	}
}
pub(super) fn reserve_result(
	ticket: &mut Ticket,
	access: &SessionAccess,
	ctx: &mut IncomingRequestContext,
) -> Result<(), ProxyError> {
	if ticket.method != "tasks/result"
		|| !access
			.limits
			.tasks
			.as_ref()
			.is_some_and(|t| t.interactive())
	{
		return Ok(());
	}
	if ticket
		.record
		.interaction_active
		.compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
		.is_err()
	{
		return Err(access.denial("task-interaction-result-already-open"));
	}
	let lease = Arc::new(Lease {
		record: ticket.record.clone(),
		released: AtomicBool::new(false),
	});
	ticket.interaction = Arc::downgrade(&lease);
	ctx.extensions_mut().insert(lease);
	Ok(())
}
impl Link {
	pub(crate) fn attach(
		ticket: &Ticket,
		access: &SessionAccess,
		server: &str,
	) -> Result<Option<(Self, Arc<Lease>)>, ProxyError> {
		if ticket.method != "tasks/result"
			|| !access
				.limits
				.tasks
				.as_ref()
				.is_some_and(|t| t.interactive())
		{
			return Ok(None);
		}
		let link = Self {
			ticket: ticket.clone(),
		};
		if server != link.ticket.record.server {
			return Err(access.denial("task-interaction-inactive"));
		}
		link.ticket.check(access)?;
		if !link.answerable() {
			return Ok(None);
		} // Terminal result reads are still ordinary Task reads.
		let lease = ticket
			.interaction
			.upgrade()
			.filter(|l| !l.released.load(Ordering::Acquire))
			.ok_or_else(|| access.denial("task-interaction-result-lease"))?;
		Ok(Some((link, lease)))
	}
	pub(crate) fn live(&self) -> bool {
		let record = &self.ticket.record;
		!record.expired()
			&& !record.cancel.load(Ordering::Acquire)
			&& record.accepted.load(Ordering::Acquire)
	}
	pub(crate) fn answerable(&self) -> bool {
		if !self.live() {
			return false;
		}
		let record = &self.ticket.record;
		let unfinished = record.receipt.lock().is_ok_and(|r| r.is_none());
		unfinished
			&& record.snapshot.lock().is_ok_and(|s| {
				s.as_ref()
					.is_some_and(|s| matches!(s.status, TaskStatus::Working | TaskStatus::InputRequired))
			})
	}
	pub(crate) fn check(
		&self,
		access: &SessionAccess,
		method: &str,
		phase: &str,
	) -> Result<(), ProxyError> {
		let enabled = access.limits.tasks.as_ref().is_some_and(|t| match method {
			"elicitation/create" => t.elicitation,
			"roots/list" => t.roots,
			"sampling/createMessage" => t.sampling.is_some(),
			_ => false,
		}) && access
			.limits
			.reverse
			.as_ref()
			.is_some_and(|r| match method {
				"elicitation/create" => r.elicitation,
				"roots/list" => !r.roots.is_empty(),
				"sampling/createMessage" => !r.sampling_models.is_empty(),
				_ => false,
			});
		if access
			.config
			.pipeline
			.requires_tool_approval(&self.ticket.record.business)
			|| access
				.legacy
				.as_ref()
				.is_some_and(|p| p.requires_tool_approval(&self.ticket.record.business))
		{
			return Err(access.denial("task-interaction-approval-rebinding-unadapted"));
		}
		if !self.answerable() || !enabled {
			return Err(access.denial("task-interaction-inactive"));
		}
		self.ticket.check(access)?;
		let action = operation(
			access,
			&format!("{method}/{phase}"),
			&self.ticket.record.server,
			&self.ticket.record.id,
		);
		crate::security::evaluate(&access.config, &action)
			.map_err(|_| access.denial("task-interaction-authorization"))?;
		if let Some(guards) = &self.ticket.record.guards {
			guards.check_mcp_elicitation_approval(&self.ticket.record.business)?;
			guards.authorize_mcp_task(&access.config, &[&action])?;
		}
		if let Some(flow) = &access.flow {
			flow.check(&action, &self.ticket.record.server)?;
		}
		self.ticket.check(access)?;
		if !self.answerable() {
			return Err(access.denial("task-interaction-inactive"));
		}
		Ok(())
	}
	pub(crate) fn business(&self) -> Arc<(ActionRequest, Option<Value>)> {
		Arc::new((
			self.ticket.record.business.clone(),
			Some(self.ticket.record.arguments.clone()),
		))
	}
	pub(crate) fn model_guards(&self) -> Option<crate::proxy::RoutingGuards> {
		self.ticket.record.guards.clone()
	}
	pub(crate) fn correlate_model(
		&self,
		access: &SessionAccess,
		request_id: String,
	) -> Result<(), ProxyError> {
		let mut action = operation(
			access,
			"sampling/createMessage/request",
			&self.ticket.record.server,
			&self.ticket.record.id,
		);
		action.request_id = request_id;
		crate::security::evaluate(&access.config, &action)
			.map_err(|_| access.denial("task-sampling-model-correlation"))?;
		if let Some(guards) = &self.ticket.record.guards {
			guards.authorize_mcp_task(&access.config, &[&action])?;
		}
		Ok(())
	}
	pub(crate) fn rbac(&self) -> crate::mcp::rbac::ResourceType {
		crate::mcp::rbac::ResourceType::Tool(crate::mcp::rbac::ResourceId::new(
			self.ticket.record.server.clone(),
			self.ticket.record.tool.clone(),
		))
	}
	pub(crate) fn gateway_id(&self) -> &str {
		&self.ticket.record.id
	}
	pub(crate) fn upstream_id(&self) -> Option<&str> {
		self.ticket.record.upstream.get().map(String::as_str)
	}
	pub(crate) fn deadline(&self) -> Instant {
		let record = &self.ticket.record;
		let credential_deadline = Instant::now()
			.checked_add(Duration::from_secs(
				record
					.credential_expires
					.saturating_sub(chrono::Utc::now().timestamp())
					.max(0) as u64,
			))
			.unwrap_or(record.expires);
		record
			.expires
			.min(
				record
					.peer_deadline
					.get()
					.copied()
					.unwrap_or(record.expires),
			)
			.min(credential_deadline)
	}
	pub(crate) fn valid_meta(&self, meta: &Value, upstream: bool) -> bool {
		meta.get(RELATED).is_some_and(|r| {
			r.as_object().is_some_and(|r| r.len() == 1)
				&& r["taskId"].as_str()
					== if upstream {
						self.upstream_id()
					} else {
						Some(self.gateway_id())
					}
		})
	}
	pub(crate) fn claim(&self, access: &SessionAccess, id: &Value) -> Result<(), ProxyError> {
		security_audit::StateJournal::encoded_len(id, 512)
			.map_err(|_| access.denial("task-interaction-id-limit"))?;
		let mut seen = self
			.ticket
			.record
			.interaction_ids
			.lock()
			.map_err(|_| access.denial("task-store"))?;
		let digest = security_pipeline::arguments_hash(id);
		if seen.len() >= 64 || !seen.insert(digest) {
			return Err(access.denial("task-interaction-duplicate-or-limit"));
		}
		Ok(())
	}
}
