//! Immutable, method-bound, single-send outbound proof for a Task interaction answer.
use super::*;

#[derive(Clone)]
pub(crate) struct ResponseTicket {
	parent: Arc<Parent>,
	expires: Instant,
	hash: String,
	method: String,
	sent: Arc<AtomicBool>,
}
impl ResponseTicket {
	pub(super) fn new(parent: Arc<Parent>, expires: Instant, method: &str, rpc: &Value) -> Self {
		Self {
			parent,
			expires,
			hash: security_pipeline::arguments_hash(rpc),
			method: method.to_owned(),
			sent: Arc::new(AtomicBool::new(false)),
		}
	}
	pub(crate) fn check(&self, access: &SessionAccess) -> Result<(), ProxyError> {
		if !self.parent.is_live() || Instant::now() >= self.expires {
			return Err(access.denial("task-elicitation-response-expired"));
		}
		self
			.parent
			.task
			.as_ref()
			.ok_or_else(|| access.denial("task-elicitation-response-binding"))?
			.check(access, &self.method, "respond")?;
		authorize_inner(
			access,
			&self.parent.server,
			&self.method,
			"respond",
			self.method == "sampling/createMessage",
		)?;
		check_business(access, &self.parent)?;
		if !self.parent.is_live() || Instant::now() >= self.expires {
			return Err(access.denial("task-elicitation-response-expired"));
		}
		Ok(())
	}
	pub(crate) async fn verify_dispatch(
		&self,
		request: &mut crate::http::Request,
	) -> Result<(), ProxyError> {
		let access = request
			.extensions()
			.get::<SessionAccess>()
			.cloned()
			.ok_or(ProxyError::AuthorizationFailed)?;
		self.check(&access)?;
		let rpc: Value = crate::json::inspect_body(request)
			.await
			.map_err(|_| access.denial("task-elicitation-response-dispatch"))?;
		if request.method() != http::Method::POST
			|| security_pipeline::arguments_hash(&rpc) != self.hash
		{
			return Err(access.denial("task-elicitation-response-dispatch"));
		}
		self.check(&access)
	}
	pub(crate) fn before_send(&self) -> Result<(), ProxyError> {
		if !self.parent.is_live()
			|| Instant::now() >= self.expires
			|| !self.parent.task.as_ref().is_some_and(|t| t.answerable())
			|| self
				.sent
				.compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
				.is_err()
		{
			return Err(ProxyError::AuthorizationFailed);
		}
		Ok(())
	}
	pub(crate) async fn run<T>(
		&self,
		future: impl std::future::Future<Output = Result<T, super::super::super::upstream::UpstreamError>>,
	) -> Result<T, super::super::super::upstream::UpstreamError> {
		tokio::time::timeout(
			self.expires.saturating_duration_since(Instant::now()),
			future,
		)
		.await
		.map_err(|_| ProxyError::AuthorizationFailed)?
	}
}
