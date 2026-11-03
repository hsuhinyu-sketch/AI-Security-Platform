use super::*;

struct Directory(PathBuf);
impl Directory {
	fn new() -> Self {
		let path = std::env::temp_dir().join(format!("aisp-resource-watch-{}", uuid::Uuid::new_v4()));
		std::fs::create_dir(&path).unwrap();
		Self(path)
	}
}
impl Drop for Directory {
	fn drop(&mut self) {
		let _ = std::fs::remove_dir_all(&self.0);
	}
}

fn manager() -> ResourceManager {
	let config = crate::config::parse_config("{}".into(), None).unwrap();
	ResourceManager::new(Client::new(&config.dns, None, config.backend, None)).unwrap()
}

async fn wait_for(mut predicate: impl FnMut() -> bool) {
	tokio::time::timeout(Duration::from_secs(8), async {
		while !predicate() {
			tokio::time::sleep(Duration::from_millis(10)).await;
		}
	})
	.await
	.unwrap();
}

async fn active_file(manager: &ResourceManager, path: &Path) -> ResourceRef {
	let resource = ResourceRef::File(path.to_path_buf());
	assert_eq!(
		manager.fetch_and_wait(resource.clone()).await.unwrap(),
		"original"
	);
	manager.retain_resources(HashSet::from([resource.clone()]));
	resource
}

#[tokio::test]
async fn missing_parent_keeps_one_task_and_recovers_gap_contents() {
	let directory = Directory::new();
	let live = directory.0.join("live");
	let parked = directory.0.join("parked");
	std::fs::create_dir(&live).unwrap();
	let file = live.join("keys.json");
	std::fs::write(&file, "original").unwrap();
	let manager = manager();
	let resource = active_file(&manager, &file).await;
	let task = manager.inner.watched_files.watches.lock().unwrap()[&file].abort_handle();
	let mut changes = manager.subscribe_changes();
	std::fs::rename(&live, &parked).unwrap();
	std::fs::remove_file(parked.join("keys.json")).unwrap();
	wait_for(|| manager.cached(&resource).is_none()).await;
	tokio::time::sleep(Duration::from_millis(1100)).await;
	assert!(!task.is_finished());
	assert_eq!(manager.inner.watched_files.watches.lock().unwrap().len(), 1);
	changes.borrow_and_update();
	std::fs::create_dir(&live).unwrap();
	std::fs::write(&file, "written in gap").unwrap();
	wait_for(|| manager.cached(&resource).as_deref() == Some(b"written in gap")).await;
	assert!(changes.has_changed().unwrap());
	assert_eq!(
		manager.inner.watched_files.watches.lock().unwrap()[&file].id(),
		task.id()
	);
	std::fs::write(&file, "later write").unwrap();
	wait_for(|| manager.cached(&resource).as_deref() == Some(b"later write")).await;
}

#[tokio::test]
async fn atomic_replacements_preserve_task_and_only_notify_changed_bytes() {
	let directory = Directory::new();
	let file = directory.0.join("keys.json");
	std::fs::write(&file, "original").unwrap();
	let manager = manager();
	let resource = active_file(&manager, &file).await;
	let task_id = manager.inner.watched_files.watches.lock().unwrap()[&file].id();
	for value in ["second", "third"] {
		let next = directory.0.join("next.json");
		std::fs::write(&next, value).unwrap();
		std::fs::rename(next, &file).unwrap();
		wait_for(|| manager.cached(&resource).as_deref() == Some(value.as_bytes())).await;
		assert_eq!(
			manager.inner.watched_files.watches.lock().unwrap()[&file].id(),
			task_id
		);
	}
	let before = manager.inner.change_counter.load(AtomicOrdering::Relaxed);
	manager.refresh_file(file).await;
	assert_eq!(
		manager.inner.change_counter.load(AtomicOrdering::Relaxed),
		before
	);
}

#[tokio::test]
async fn pruning_retrying_dependency_stops_task_and_prevents_resurrection() {
	let directory = Directory::new();
	let live = directory.0.join("live");
	std::fs::create_dir(&live).unwrap();
	let file = live.join("keys.json");
	std::fs::write(&file, "original").unwrap();
	let manager = manager();
	let resource = active_file(&manager, &file).await;
	let task = manager.inner.watched_files.watches.lock().unwrap()[&file].abort_handle();
	std::fs::remove_file(&file).unwrap();
	std::fs::remove_dir(&live).unwrap();
	wait_for(|| manager.cached(&resource).is_none()).await;
	manager.retain_resources(HashSet::new());
	wait_for(|| task.is_finished()).await;
	let before = manager.inner.change_counter.load(AtomicOrdering::Relaxed);
	std::fs::create_dir(&live).unwrap();
	std::fs::write(&file, "must remain inactive").unwrap();
	manager.refresh_file(file).await;
	tokio::time::sleep(Duration::from_millis(1200)).await;
	assert!(manager.cached(&resource).is_none());
	assert_eq!(
		manager.inner.change_counter.load(AtomicOrdering::Relaxed),
		before
	);
	assert!(
		manager
			.inner
			.watched_files
			.watches
			.lock()
			.unwrap()
			.is_empty()
	);
}

#[tokio::test]
async fn retired_task_cannot_remove_a_new_watch_for_the_same_path() {
	let directory = Directory::new();
	let file = directory.0.join("keys.json");
	std::fs::write(&file, "original").unwrap();
	let manager = manager();
	let resource = active_file(&manager, &file).await;
	let old = manager.inner.watched_files.watches.lock().unwrap()[&file].abort_handle();
	manager.retain_resources(HashSet::new());
	manager.fetch_and_wait(resource.clone()).await.unwrap();
	manager.retain_resources(HashSet::from([resource.clone()]));
	wait_for(|| old.is_finished()).await;
	assert_eq!(manager.inner.watched_files.watches.lock().unwrap().len(), 1);
	std::fs::write(file, "new task").unwrap();
	wait_for(|| manager.cached(&resource).as_deref() == Some(b"new task")).await;
}

#[tokio::test]
async fn concurrent_fetches_keep_one_registered_watch() {
	let directory = Directory::new();
	let file = directory.0.join("keys.json");
	std::fs::write(&file, "original").unwrap();
	let manager = manager();
	let resource = ResourceRef::File(file.clone());
	let mut tasks = tokio::task::JoinSet::new();
	for _ in 0..8 {
		let manager = manager.clone();
		let resource = resource.clone();
		tasks.spawn(async move { manager.fetch_and_wait(resource).await.unwrap() });
	}
	while let Some(result) = tasks.join_next().await {
		assert_eq!(result.unwrap(), "original");
	}
	manager.retain_resources(HashSet::from([resource.clone()]));
	assert_eq!(manager.inner.watched_files.watches.lock().unwrap().len(), 1);
	std::fs::write(file, "concurrent update").unwrap();
	wait_for(|| manager.cached(&resource).as_deref() == Some(b"concurrent update")).await;
}

#[tokio::test]
async fn last_owner_drop_releases_scheduler_and_idle_file_watch() {
	let directory = Directory::new();
	let file = directory.0.join("keys.json");
	std::fs::write(&file, "original").unwrap();
	let manager = manager();
	active_file(&manager, &file).await;
	let weak = Arc::downgrade(&manager.inner);
	let task = manager.inner.watched_files.watches.lock().unwrap()[&file].abort_handle();
	tokio::task::yield_now().await;
	drop(manager);
	wait_for(|| weak.upgrade().is_none() && task.is_finished()).await;
}

#[tokio::test]
async fn http_scheduler_refreshes_while_manager_is_owned() {
	use tokio::io::{AsyncReadExt, AsyncWriteExt};
	let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
	let address = listener.local_addr().unwrap();
	let server = tokio::spawn(async move {
		for content in ["original", "refreshed"] {
			let (mut stream, _) = listener.accept().await.unwrap();
			let mut request = Vec::new();
			while !request.windows(4).any(|window| window == b"\r\n\r\n") {
				let mut buffer = [0; 2048];
				let count = stream.read(&mut buffer).await.unwrap();
				assert!(count > 0);
				request.extend_from_slice(&buffer[..count]);
			}
			stream.write_all(format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\nCache-Control: max-age=60\r\nConnection: close\r\n\r\n{content}", content.len()).as_bytes()).await.unwrap();
		}
	});
	let manager = manager();
	let resource = ResourceRef::Http {
		url: format!("http://{address}/keys").parse().unwrap(),
		kind: ResourceKind::Jwks,
	};
	let initial = tokio::time::timeout(
		Duration::from_secs(5),
		manager.fetch_and_wait(resource.clone()),
	)
	.await
	.unwrap()
	.unwrap();
	assert_eq!(initial, "original");
	manager.retain_resources(HashSet::from([resource.clone()]));
	let mut changes = manager.subscribe_changes();
	// Exercise the scheduler's existing due-time path without a minute-long wait.
	manager.store(resource.clone(), initial, Some(Instant::now()));
	wait_for(|| manager.cached(&resource).as_deref() == Some(b"refreshed")).await;
	assert!(changes.has_changed().unwrap());
	changes.borrow_and_update();
	server.await.unwrap();
}

async fn read_http_request(stream: &mut tokio::net::TcpStream) {
	use tokio::io::AsyncReadExt;
	let mut request = Vec::new();
	while !request.windows(4).any(|w| w == b"\r\n\r\n") {
		let mut buffer = [0; 1024];
		let count = stream.read(&mut buffer).await.unwrap();
		assert!(count > 0);
		request.extend_from_slice(&buffer[..count]);
	}
}

fn http_resource(listener: &tokio::net::TcpListener) -> ResourceRef {
	ResourceRef::Http {
		url: format!("http://{}/keys", listener.local_addr().unwrap())
			.parse()
			.unwrap(),
		kind: ResourceKind::Jwks,
	}
}

#[tokio::test]
async fn failed_http_refresh_retries_and_preserves_last_good_bytes() {
	use tokio::io::AsyncWriteExt;
	let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
	let resource = http_resource(&listener);
	let (failed_tx, failed_rx) = tokio::sync::oneshot::channel();
	let server = tokio::spawn(async move {
		let mut failed_tx = Some(failed_tx);
		for (index, (status, body)) in [(200, "old"), (503, "bad"), (200, "new")]
			.into_iter()
			.enumerate()
		{
			let (mut stream, _) = listener.accept().await.unwrap();
			read_http_request(&mut stream).await;
			stream
				.write_all(
					format!(
						"HTTP/1.1 {status} Test\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
						body.len()
					)
					.as_bytes(),
				)
				.await
				.unwrap();
			if index == 1 {
				let _ = failed_tx.take().unwrap().send(());
			}
		}
	});
	let manager = manager();
	let original = manager.fetch_and_wait(resource.clone()).await.unwrap();
	manager.retain_resources(HashSet::from([resource.clone()]));
	manager.store(resource.clone(), original, Some(Instant::now()));
	failed_rx.await.unwrap();
	wait_for(|| {
		manager
			.inner
			.entries
			.lock()
			.unwrap()
			.get(&resource)
			.unwrap()
			.next_refresh
			.is_some_and(|at| at > Instant::now() + Duration::from_secs(5))
	})
	.await;
	assert_eq!(manager.cached(&resource).unwrap(), "old");
	tokio::time::timeout(FAILED_HTTP_REFRESH + Duration::from_secs(5), async {
		while manager.cached(&resource).as_deref() != Some(b"new") {
			tokio::time::sleep(Duration::from_millis(20)).await;
		}
	})
	.await
	.unwrap();
	server.await.unwrap();
}

#[tokio::test]
async fn http_refresh_finishing_after_retirement_does_not_restore_cache() {
	use tokio::io::AsyncWriteExt;
	let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
	let resource = http_resource(&listener);
	let (started_tx, started_rx) = tokio::sync::oneshot::channel();
	let (release_tx, release_rx) = tokio::sync::oneshot::channel();
	let server = tokio::spawn(async move {
		let (mut stream, _) = listener.accept().await.unwrap();
		read_http_request(&mut stream).await;
		started_tx.send(()).unwrap();
		release_rx.await.unwrap();
		stream
			.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\nConnection: close\r\n\r\nnew")
			.await
			.unwrap();
	});
	let manager = manager();
	manager.retain_resources(HashSet::from([resource.clone()]));
	manager.store(resource.clone(), Bytes::from_static(b"old"), None);
	let refreshing = tokio::spawn({
		let manager = manager.clone();
		let resource = resource.clone();
		async move { manager.refetch_and_notify_if_changed(resource).await }
	});
	started_rx.await.unwrap();
	manager.retain_resources(HashSet::new());
	let version = manager.inner.change_counter.load(AtomicOrdering::Relaxed);
	release_tx.send(()).unwrap();
	refreshing.await.unwrap();
	server.await.unwrap();
	assert!(manager.cached(&resource).is_none());
	assert_eq!(
		manager.inner.change_counter.load(AtomicOrdering::Relaxed),
		version
	);
}

#[tokio::test]
async fn stalled_http_body_times_out_and_allows_other_refreshes() {
	use tokio::io::AsyncWriteExt;
	let slow = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
	let fast = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
	let slow_resource = http_resource(&slow);
	let fast_resource = http_resource(&fast);
	let (started_tx, started_rx) = tokio::sync::oneshot::channel();
	let slow_server = tokio::spawn(async move {
		let (mut stream, _) = slow.accept().await.unwrap();
		read_http_request(&mut stream).await;
		stream
			.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\nx")
			.await
			.unwrap();
		started_tx.send(()).unwrap();
		std::future::pending::<()>().await;
	});
	let fast_server = tokio::spawn(async move {
		let (mut stream, _) = fast.accept().await.unwrap();
		read_http_request(&mut stream).await;
		stream
			.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\nConnection: close\r\n\r\nnew")
			.await
			.unwrap();
	});
	let manager = manager();
	manager.retain_resources(HashSet::from([
		slow_resource.clone(),
		fast_resource.clone(),
	]));
	manager.store(
		slow_resource.clone(),
		Bytes::from_static(b"old"),
		Some(Instant::now()),
	);
	started_rx.await.unwrap();
	manager.store(
		fast_resource.clone(),
		Bytes::from_static(b"old"),
		Some(Instant::now()),
	);
	tokio::time::timeout(HTTP_FETCH_TIMEOUT + Duration::from_secs(5), async {
		while manager.cached(&fast_resource).as_deref() != Some(b"new") {
			tokio::time::sleep(Duration::from_millis(20)).await;
		}
	})
	.await
	.unwrap();
	assert_eq!(manager.cached(&slow_resource).unwrap(), "old");
	fast_server.await.unwrap();
	slow_server.abort();
}

#[test]
fn http_resource_diagnostics_exclude_credentials_but_identity_keeps_query() {
	let first = ResourceRef::Http {
		url: "https://example.test/keys?token=secret-one"
			.parse()
			.unwrap(),
		kind: ResourceKind::Jwks,
	};
	let second = ResourceRef::Http {
		url: "https://example.test/keys?token=secret-two"
			.parse()
			.unwrap(),
		kind: ResourceKind::Jwks,
	};
	assert_ne!(resource_key(&first), resource_key(&second));
	assert_eq!(
		safe_resource_key(&first),
		"http:Jwks:https://example.test/keys"
	);
	assert_eq!(safe_resource_key(&first), safe_resource_key(&second));
}
