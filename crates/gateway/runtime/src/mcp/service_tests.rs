use super::*;

fn service() -> Service {
	Service::new(
		crate::store::Stores::default(),
		crate::http::sessionpersistence::Encoder::base64(),
	)
}

#[test]
fn handles_share_one_app_without_owning_it() {
	fn send_sync<T: Send + Sync>() {}
	send_sync::<Service>();
	send_sync::<ServiceHandle>();
	let service = service();
	let first = service.handle();
	let cloned = first.clone();
	assert!(Arc::ptr_eq(&first.app().unwrap(), &cloned.app().unwrap()));
	assert_eq!(Arc::strong_count(&service.app), 1);
	drop(service);
	assert!(first.app().is_err());
	assert!(cloned.app().is_err());
	assert_eq!(first.0.strong_count(), 0);
}

#[tokio::test]
async fn owner_shutdown_revokes_handles_even_with_an_active_call_reference() {
	let service = service();
	let handle = service.handle();
	let active = handle.app().unwrap();
	let closed = active.closed.clone();
	drop(service);
	tokio::time::timeout(std::time::Duration::from_secs(1), closed.cancelled())
		.await
		.unwrap();
	assert!(handle.app().is_err());
	assert!(active.closed.is_cancelled());
	drop(active);
	assert_eq!(handle.0.strong_count(), 0);
}

#[test]
fn new_host_does_not_restore_old_service_handles() {
	let old = service();
	let handle = old.handle();
	drop(old);
	let new = service();
	assert!(handle.app().is_err());
	assert!(new.handle().app().is_ok());
}
