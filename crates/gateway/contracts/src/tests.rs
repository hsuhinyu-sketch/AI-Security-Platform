use super::{ConfigLease, ConfigRevision};
use std::{sync::Arc, time::Duration};
use tokio::{sync::Barrier, time::timeout};

const DEADLINE: Duration = Duration::from_secs(5);

#[test]
fn fresh_leases_and_clones_share_revocation() {
	let revision = ConfigRevision::default();
	let first = revision.lease();
	let clone = first.clone();
	let second = revision.lease();
	assert!(first.is_current() && clone.is_current() && second.is_current());
	revision.invalidate();
	assert!(!first.is_current() && !clone.is_current() && !second.is_current());
}

#[test]
fn later_generations_never_revalidate_old_leases() {
	let revision = ConfigRevision::default();
	let first = revision.lease();
	revision.invalidate();
	let second = revision.lease();
	assert!(!first.is_current() && second.is_current());
	for _ in 0..32 {
		revision.invalidate();
		assert!(!first.is_current() && !second.is_current());
		assert!(revision.lease().is_current());
	}
}

#[tokio::test]
async fn invalidation_before_wait_is_not_lost() {
	let revision = ConfigRevision::default();
	let mut lease = revision.lease();
	revision.invalidate();
	timeout(DEADLINE, lease.changed()).await.unwrap();
	// Advancing the watch cursor never grants the old lease current authority.
	assert!(!lease.is_current());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn concurrent_consumers_all_observe_invalidation() {
	let revision = ConfigRevision::default();
	let barrier = Arc::new(Barrier::new(17));
	let mut consumers = Vec::new();
	for _ in 0..16 {
		let barrier = barrier.clone();
		let mut lease = revision.lease();
		consumers.push(tokio::spawn(async move {
			barrier.wait().await;
			timeout(DEADLINE, lease.changed()).await.unwrap();
			assert!(!lease.is_current());
		}));
	}
	timeout(DEADLINE, barrier.wait()).await.unwrap();
	revision.invalidate();
	for consumer in consumers {
		timeout(DEADLINE, consumer).await.unwrap().unwrap();
	}
}

#[tokio::test]
async fn dropping_owner_keeps_lease_current_without_spurious_notification() {
	let revision = ConfigRevision::default();
	let mut lease = revision.lease();
	drop(revision);
	assert!(lease.is_current());
	assert!(
		timeout(Duration::from_millis(10), lease.changed())
			.await
			.is_err()
	);
	assert!(lease.is_current());
}

#[tokio::test]
async fn cancelled_wait_can_observe_a_later_invalidation() {
	let revision = ConfigRevision::default();
	let mut lease = revision.lease();
	assert!(
		timeout(Duration::from_millis(10), lease.changed())
			.await
			.is_err()
	);
	revision.invalidate();
	timeout(DEADLINE, lease.changed()).await.unwrap();
	assert!(!lease.is_current());
}

#[tokio::test]
async fn cloned_leases_have_independent_notification_cursors() {
	let revision = ConfigRevision::default();
	let mut original = revision.lease();
	let mut cloned: ConfigLease = original.clone();
	revision.invalidate();
	timeout(DEADLINE, original.changed()).await.unwrap();
	timeout(DEADLINE, cloned.changed()).await.unwrap();
	assert!(!original.is_current() && !cloned.is_current());
	let mut fresh = revision.lease();
	assert!(fresh.is_current());
	assert!(
		timeout(Duration::from_millis(10), fresh.changed())
			.await
			.is_err()
	);
	revision.invalidate();
	timeout(DEADLINE, fresh.changed()).await.unwrap();
	assert!(!fresh.is_current());
}

#[tokio::test]
async fn unrelated_revisions_do_not_share_notifications_or_authority() {
	let first = ConfigRevision::default();
	let second = ConfigRevision::default();
	let mut lease = second.lease();
	first.invalidate();
	assert!(lease.is_current());
	assert!(
		timeout(Duration::from_millis(10), lease.changed())
			.await
			.is_err()
	);
	second.invalidate();
	timeout(DEADLINE, lease.changed()).await.unwrap();
	assert!(!lease.is_current());
}
