use std::fmt::Display;
use std::io::{Error, ErrorKind};
use std::path::{Path, PathBuf, absolute};
use std::time::Duration;

use anyhow::{anyhow, bail};
use notify::{EventKind, RecursiveMode};
use tokio::sync::mpsc;
use tracing::warn;

pub trait ErrorContext<T> {
	fn ctx(self, msg: impl Display) -> anyhow::Result<T>;
}

impl<T, E: Display> ErrorContext<T> for Result<T, E> {
	fn ctx(self, msg: impl Display) -> anyhow::Result<T> {
		self.map_err(|err| anyhow!("{msg}: {err}"))
	}
}

impl<T> ErrorContext<T> for Option<T> {
	fn ctx(self, msg: impl Display) -> anyhow::Result<T> {
		self.ok_or_else(|| anyhow!("{msg}"))
	}
}

pub fn is_runtime_shutdown(e: &Error) -> bool {
	if e.kind() == ErrorKind::Other
		&& e.to_string() == "A Tokio 1.x context was found, but it is being shutdown."
	{
		return true;
	}
	false
}

pub struct WatchedFiles {
	paths: Vec<PathBuf>,
	changes: mpsc::Receiver<FileWatchChange>,
	forwarder: tokio::task::AbortHandle,
}

#[cfg(test)]
#[path = "util_watch_tests.rs"]
mod watch_tests;

impl Drop for WatchedFiles {
	fn drop(&mut self) {
		self.forwarder.abort();
	}
}

#[derive(Clone, Copy, Debug, Default)]
pub struct WatchFilesOptions {
	reload_on_disappearance: bool,
	close_on_removal: bool,
}

impl WatchFilesOptions {
	pub fn reload_on_disappearance(mut self, reload: bool) -> Self {
		self.reload_on_disappearance = reload;
		self
	}

	pub fn close_on_removal(mut self, close: bool) -> Self {
		self.close_on_removal = close;
		self
	}
}

struct FileWatchChange {
	invalidated: bool,
}

impl WatchedFiles {
	pub fn paths(&self) -> &[PathBuf] {
		&self.paths
	}
	pub async fn changed(&mut self) -> bool {
		self.changes.recv().await.is_some()
	}

	/// Waits for the next reload-worthy change and reports whether the underlying
	/// watch was invalidated by file removal/replacement.
	pub async fn changed_invalidated(&mut self) -> Option<bool> {
		self.changes.recv().await.map(|change| change.invalidated)
	}
}

pub fn watch_files(paths: Vec<PathBuf>) -> anyhow::Result<WatchedFiles> {
	watch_files_with_options(paths, WatchFilesOptions::default())
}

pub fn watch_files_with_options(
	paths: Vec<PathBuf>,
	options: WatchFilesOptions,
) -> anyhow::Result<WatchedFiles> {
	let (raw_tx, mut raw_rx) = mpsc::channel(1);

	let mut watcher =
		notify_debouncer_full::new_debouncer(Duration::from_millis(250), None, move |res| {
			futures::executor::block_on(async {
				let _ = raw_tx.send(res).await;
			})
		})
		.map_err(|e| anyhow!("failed to create file watcher: {e}"))?;

	let paths = paths
		.iter()
		.map(|path| normalize_watch_path(path))
		.collect::<std::io::Result<Vec<_>>>()?;
	if paths.is_empty() {
		bail!("no files supplied to watch");
	}

	let mut watched_targets: Vec<PathBuf> = Vec::new();
	let mut watch_errors = Vec::new();
	let mut unwatched_paths = Vec::new();
	for p in &paths {
		let mut path_watched = false;
		for target in watch_targets_for_path(p)? {
			if watched_targets.iter().any(|p| p == &target) {
				path_watched = true;
				continue;
			}
			match watcher.watch(&target, RecursiveMode::NonRecursive) {
				Ok(()) => {
					watched_targets.push(target.clone());
					path_watched = true;
				},
				Err(e) => {
					let reason = notify_error_reason(&e);
					watch_errors.push(format!("{}: {}", target.display(), reason));
					warn!("failed to watch path {}: {}", target.display(), reason);
				},
			}
		}
		if !path_watched {
			unwatched_paths.push(p.display().to_string());
		}
	}
	if !unwatched_paths.is_empty() {
		return Err(anyhow::anyhow!(
			"failed to watch configured file paths: {}; watch errors: {}",
			unwatched_paths.join(", "),
			watch_errors.join(", ")
		));
	}

	let (change_tx, change_rx) = mpsc::channel(1);
	let watched_paths = paths.clone();
	let mut targets = resolve_targets(&paths);
	let forwarder = tokio::task::spawn(async move {
		while let Some(events) = raw_rx.recv().await {
			match events {
				Ok(events) => {
					let current = resolve_targets(&paths);
					let invalidated = options.close_on_removal
						&& batch_invalidates_watch(events.iter().map(|e| &**e), &paths, &targets);
					let triggered = batch_triggers_reload(
						events.iter().map(|e| &**e),
						&paths,
						&targets,
						&current,
						options,
					);
					targets = current;
					if (triggered || invalidated)
						&& change_tx
							.send(FileWatchChange { invalidated })
							.await
							.is_err()
					{
						break;
					}
					if invalidated {
						break;
					}
				},
				Err(errors) => warn!("file watch error: {errors:?}"),
			}
		}
		drop(watcher);
	});

	Ok(WatchedFiles {
		paths: watched_paths,
		changes: change_rx,
		forwarder: forwarder.abort_handle(),
	})
}

fn watch_targets_for_path(path: &Path) -> anyhow::Result<Vec<PathBuf>> {
	let mut targets = vec![path.to_path_buf()];
	if should_watch_parent(path)? {
		let parent = path.parent().ok_or_else(|| {
			anyhow!(
				"failed to get the parent of watched file {}",
				path.display()
			)
		})?;
		targets.push(parent.to_path_buf());
	}
	Ok(targets)
}

fn should_watch_parent(path: &Path) -> anyhow::Result<bool> {
	let meta = match fs_err::symlink_metadata(path) {
		Ok(meta) => meta,
		Err(e) if e.kind() == ErrorKind::NotFound => return Ok(true),
		Err(e) => return Err(e.into()),
	};
	Ok(meta.file_type().is_symlink())
}

fn normalize_watch_path(path: &Path) -> std::io::Result<PathBuf> {
	match fs_err::symlink_metadata(path) {
		Ok(meta) if meta.file_type().is_symlink() => absolute(path),
		Ok(_) => fs_err::canonicalize(path),
		Err(e) if e.kind() == ErrorKind::NotFound => {
			let absolute_path = absolute(path)?;
			let Some(parent) = absolute_path.parent() else {
				return Ok(absolute_path);
			};
			let Some(file_name) = absolute_path.file_name() else {
				return Ok(absolute_path);
			};
			match fs_err::canonicalize(parent) {
				Ok(parent) => Ok(parent.join(file_name)),
				Err(_) => Ok(absolute_path),
			}
		},
		Err(e) => Err(e),
	}
}

fn notify_error_reason(e: &notify::Error) -> String {
	match &e.kind {
		notify::ErrorKind::Generic(err) => err.clone(),
		notify::ErrorKind::Io(err) => err.to_string(),
		notify::ErrorKind::PathNotFound => "No path was found.".to_string(),
		notify::ErrorKind::WatchNotFound => "No watch was found.".to_string(),
		notify::ErrorKind::InvalidConfig(config) => format!("Invalid configuration: {config:?}"),
		notify::ErrorKind::MaxFilesWatch => "OS file watch limit reached.".to_string(),
	}
}

fn resolve_targets(paths: &[PathBuf]) -> Vec<Option<PathBuf>> {
	paths
		.iter()
		.map(|p| match fs_err::symlink_metadata(p) {
			Ok(meta) if meta.file_type().is_symlink() => fs_err::canonicalize(p).ok(),
			Ok(_) => Some(p.clone()),
			Err(_) => None,
		})
		.collect()
}

fn batch_triggers_reload<'a>(
	events: impl IntoIterator<Item = &'a notify::Event>,
	abspaths: &[PathBuf],
	previous_targets: &[Option<PathBuf>],
	current_targets: &[Option<PathBuf>],
	options: WatchFilesOptions,
) -> bool {
	// A target appearing or changing means a valid new version is available.
	// Disappearance is opt-in because some callers should keep last-good state.
	let target_rotated =
		previous_targets
			.iter()
			.zip(current_targets.iter())
			.any(|(previous, current)| match (previous, current) {
				(None, Some(_)) => true,
				(Some(previous), Some(current)) => previous != current,
				(Some(_), None) => options.reload_on_disappearance,
				_ => false,
			});
	target_rotated
		|| events
			.into_iter()
			.any(|event| should_reload(event, abspaths, previous_targets, current_targets))
}

fn batch_invalidates_watch<'a>(
	events: impl IntoIterator<Item = &'a notify::Event>,
	abspaths: &[PathBuf],
	previous_targets: &[Option<PathBuf>],
) -> bool {
	// File removal or rename can invalidate an OS file watch even if the replacement
	// exists by debounce time. Callers can use this to close and re-register the watch.
	events.into_iter().any(|event| {
		matches!(
			event.kind,
			EventKind::Remove(_) | EventKind::Modify(notify::event::ModifyKind::Name(_))
		) && event.paths.iter().any(|path| {
			abspaths
				.iter()
				.zip(previous_targets.iter())
				.any(|(abspath, previous)| abspath == path || previous.as_deref() == Some(path.as_path()))
		})
	})
}

fn should_reload(
	event: &notify::Event,
	abspaths: &[PathBuf],
	previous_targets: &[Option<PathBuf>],
	current_targets: &[Option<PathBuf>],
) -> bool {
	if matches!(
		event.kind,
		EventKind::Modify(_)
			| EventKind::Create(_)
			| EventKind::Access(notify::event::AccessKind::Close(
				notify::event::AccessMode::Write
			))
	) {
		return event.paths.iter().any(|path| {
			abspaths.iter().any(|abspath| abspath == path)
				|| current_targets
					.iter()
					.any(|t| t.as_deref() == Some(path.as_path()))
		});
	}
	if matches!(event.kind, EventKind::Remove(_)) {
		return event.paths.iter().any(|path| {
			abspaths
				.iter()
				.zip(previous_targets.iter())
				.zip(current_targets.iter())
				.any(|((abspath, previous), current)| {
					current.is_some() && (abspath == path || previous.as_deref() == Some(path.as_path()))
				})
		});
	}
	false
}
