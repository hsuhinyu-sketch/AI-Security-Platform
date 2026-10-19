//! A process-local configuration lease; never accepted from headers or config.
use std::sync::Arc;
use tokio::sync::watch;

#[derive(Debug)]
pub(crate) struct ConfigRevision(watch::Sender<Arc<()>>);
impl Default for ConfigRevision {
	fn default() -> Self {
		Self(watch::channel(Arc::new(())).0)
	}
}
impl ConfigRevision {
	pub(crate) fn lease(&self) -> ConfigLease {
		let receiver = self.0.subscribe();
		let token = receiver.borrow().clone();
		ConfigLease {
			receiver,
			token,
			_keepalive: self.0.clone(),
		}
	}
	pub(crate) fn invalidate(&self) {
		self.0.send_replace(Arc::new(()));
	}
}
#[derive(Debug, Clone)]
pub(crate) struct ConfigLease {
	receiver: watch::Receiver<Arc<()>>,
	token: Arc<()>,
	// A dropped test/embedding store is not a spurious immediate watch-channel EOF.
	_keepalive: watch::Sender<Arc<()>>,
}
impl ConfigLease {
	pub(crate) fn is_current(&self) -> bool {
		Arc::ptr_eq(&self.token, &self.receiver.borrow())
	}
	pub(crate) async fn changed(&mut self) {
		let _ = self.receiver.changed().await;
	}
}
