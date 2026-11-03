//! Shared admission for synchronous compatibility calls and awaited remote evaluations.
use tokio::sync::{Semaphore, SemaphorePermit};

static REMOTE_DECISIONS: Semaphore = Semaphore::const_new(32);

pub(super) fn reserve() -> Result<SemaphorePermit<'static>, &'static str> {
	REMOTE_DECISIONS
		.try_acquire()
		.map_err(|_| "remote security worker limit reached")
}

pub(super) async fn evaluate<T: Send + 'static>(
	work: impl FnOnce() -> T + Send + 'static,
) -> Result<T, &'static str> {
	// Reserve before queueing: Tokio's blocking pool must not become an unbounded security queue.
	let permit = reserve()?;
	tokio::task::spawn_blocking(move || {
		let _permit = permit;
		work()
	})
	.await
	.map_err(|_| "remote security worker failed")
}

#[cfg(test)]
mod tests {
	use super::*;

	#[tokio::test]
	async fn cancelled_waiter_keeps_capacity_until_work_finishes_and_panic_releases_it() {
		let (started, running) = tokio::sync::oneshot::channel();
		let (release, wait) = std::sync::mpsc::channel();
		let waiter = tokio::spawn(evaluate(move || {
			let _ = started.send(());
			wait.recv().unwrap();
		}));
		running.await.unwrap();
		// Occupy every remaining slot without assuming other parallel tests are idle.
		let mut held = Vec::new();
		while let Ok(permit) = reserve() {
			held.push(permit);
		}
		assert!(held.len() < 32);
		waiter.abort();
		assert!(waiter.await.unwrap_err().is_cancelled());
		assert_eq!(
			evaluate(|| ()).await,
			Err("remote security worker limit reached")
		);
		release.send(()).unwrap();
		let permit = tokio::time::timeout(std::time::Duration::from_secs(2), async {
			loop {
				if let Ok(permit) = reserve() {
					break permit;
				}
				tokio::time::sleep(std::time::Duration::from_millis(1)).await;
			}
		})
		.await
		.unwrap();
		drop(permit);
		assert_eq!(
			evaluate(|| panic!("remote worker failure fixture")).await,
			Err("remote security worker failed")
		);
		assert!(evaluate(|| 42).await.is_ok());
	}
}
