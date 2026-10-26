use super::*;

#[tokio::test]
async fn dropping_idle_watch_stops_forwarder_without_another_file_event() {
	let file = std::env::temp_dir().join(format!("aisp-idle-watch-{}", uuid::Uuid::new_v4()));
	std::fs::write(&file, "unchanged").unwrap();
	struct File(std::path::PathBuf);
	impl Drop for File {
		fn drop(&mut self) {
			let _ = std::fs::remove_file(&self.0);
		}
	}
	let _file = File(file.clone());
	let watched = watch_files(vec![file]).unwrap();
	let forwarder = watched.forwarder.clone();
	tokio::task::yield_now().await;
	assert!(!forwarder.is_finished());
	drop(watched);
	tokio::time::timeout(Duration::from_secs(5), async {
		while !forwarder.is_finished() {
			tokio::task::yield_now().await;
		}
	})
	.await
	.unwrap();
}
