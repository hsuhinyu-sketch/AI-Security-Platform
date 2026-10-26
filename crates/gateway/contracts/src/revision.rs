//! A process-local configuration lease; never accepted from headers or config.
use std::sync::Arc;
use tokio::sync::watch;

#[derive(Debug)]
pub struct ConfigRevision(watch::Sender<Arc<()>>);
impl Default for ConfigRevision {
	fn default() -> Self {
		Self(watch::channel(Arc::new(())).0)
	}
}
impl ConfigRevision {
	pub fn lease(&self) -> ConfigLease {
		let receiver = self.0.subscribe();
		let token = receiver.borrow().clone();
		ConfigLease {
			receiver,
			token,
			_keepalive: self.0.clone(),
		}
	}
	pub fn invalidate(&self) {
		self.0.send_replace(Arc::new(()));
	}
}
#[derive(Debug, Clone)]
pub struct ConfigLease {
	receiver: watch::Receiver<Arc<()>>,
	token: Arc<()>,
	// Retain the sender for the lease lifetime; invalidation is an explicit owner action.
	_keepalive: watch::Sender<Arc<()>>,
}
impl ConfigLease {
	pub fn is_current(&self) -> bool {
		Arc::ptr_eq(&self.token, &self.receiver.borrow())
	}
	pub async fn changed(&mut self) {
		let _ = self.receiver.changed().await;
	}
}
