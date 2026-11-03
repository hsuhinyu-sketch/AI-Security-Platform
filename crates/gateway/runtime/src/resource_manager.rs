use std::cmp::Ordering;
use std::collections::{BinaryHeap, HashMap, HashSet};
use std::future::pending;
use std::path::{Path, PathBuf, absolute};
use std::sync::atomic::{AtomicU64, Ordering as AtomicOrdering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Context, anyhow};
use bytes::Bytes;
use headers::{CacheControl, HeaderMapExt};
use http::header::EXPIRES;
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;
use tokio::time::{Instant, sleep_until};
use tracing::{info, warn};

use crate::client::Client;
use crate::http::Body;

const JWKS_TTL: Duration = Duration::from_mins(15);
const OPENAPI_TTL: Duration = Duration::from_hours(24);
const GENERIC_TTL: Duration = Duration::from_mins(15);
const FAILED_HTTP_REFRESH: Duration = Duration::from_secs(15);
const MIN_HTTP_REFRESH: Duration = Duration::from_secs(60);
const HTTP_FETCH_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub enum ResourceKind {
	Generic,
	Jwks,
	OpenApi,
	OidcDiscovery,
}

impl ResourceKind {
	fn default_ttl(self) -> Duration {
		match self {
			ResourceKind::OpenApi => OPENAPI_TTL,
			ResourceKind::Jwks => JWKS_TTL,
			ResourceKind::Generic | ResourceKind::OidcDiscovery => GENERIC_TTL,
		}
	}
}

#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub enum ResourceRef {
	File(PathBuf),
	Http { url: http::Uri, kind: ResourceKind },
}

#[derive(Clone, Debug, Default)]
pub struct ResourceChange {
	pub version: u64,
	pub resource: String,
}

#[derive(Clone)]
pub struct ResourceManager {
	inner: Arc<Inner>,
}

impl std::fmt::Debug for ResourceManager {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.debug_struct("ResourceManager").finish_non_exhaustive()
	}
}

#[derive(Clone, Debug)]
pub struct ResourceFetcher {
	mode: ResourceFetcherMode,
	// Populated only while a ResourceFetchScope is active for managed fetchers.
	// It records the resources the successful config should retain.
	tracking: Arc<std::sync::Mutex<Option<HashSet<ResourceRef>>>>,
}

pub struct ResourceFetchScope<'a> {
	fetcher: &'a ResourceFetcher,
	active: bool,
}

#[derive(Clone, Debug)]
enum ResourceFetcherMode {
	Managed(ResourceManager),
	CachedOrDirect(ResourceManager),
	Direct(Box<Client>),
	FilesOnly,
}

impl ResourceFetcher {
	/// Uses the manager cache and starts refresh/watch behavior for runtime config dependencies.
	pub fn managed(manager: ResourceManager) -> Self {
		Self {
			mode: ResourceFetcherMode::Managed(manager),
			tracking: Default::default(),
		}
	}

	/// Reads from the manager cache when present, otherwise fetches once without retaining or watching.
	pub fn cached_or_direct(manager: ResourceManager) -> Self {
		Self {
			mode: ResourceFetcherMode::CachedOrDirect(manager),
			tracking: Default::default(),
		}
	}

	/// Fetches resources directly with the client and does not use the manager cache.
	pub fn direct(client: Client) -> Self {
		Self {
			mode: ResourceFetcherMode::Direct(Box::new(client)),
			tracking: Default::default(),
		}
	}

	/// Reads local files directly and rejects HTTP resources.
	pub fn files_only() -> Self {
		Self {
			mode: ResourceFetcherMode::FilesOnly,
			tracking: Default::default(),
		}
	}

	/// Loads a normalized resource according to this fetcher's mode.
	pub async fn fetch(&self, resource: ResourceRef) -> anyhow::Result<Bytes> {
		let normalized = normalize_resource(resource)?;
		match &self.mode {
			ResourceFetcherMode::Managed(manager) => {
				self.track_resource(normalized.clone());
				manager.fetch_and_wait_normalized(normalized).await
			},
			ResourceFetcherMode::CachedOrDirect(manager) => {
				manager.fetch_cached_or_direct_normalized(normalized).await
			},
			ResourceFetcherMode::Direct(client) => fetch_direct(client.as_ref(), &normalized)
				.await
				.map(|r| r.content),
			ResourceFetcherMode::FilesOnly => match normalized {
				ResourceRef::File(path) => fs_err::tokio::read(&path)
					.await
					.with_context(|| format!("read resource file {}", path.display()))
					.map(Bytes::from),
				ResourceRef::Http { url, .. } => Err(anyhow!(
					"resource fetcher cannot fetch HTTP resource {}",
					safe_http_resource(&url)
				)),
			},
		}
	}

	/// Records managed resource lookups during a full config computation.
	/// The returned guard commits fetched resources on success, or restores the
	/// last committed set on failure so failed reloads do not leave stale state.
	pub fn scope_full_computation(&self) -> ResourceFetchScope<'_> {
		if !matches!(self.mode, ResourceFetcherMode::Managed(_)) {
			return ResourceFetchScope {
				fetcher: self,
				active: false,
			};
		}

		let mut tracking = self
			.tracking
			.lock()
			.expect("resource fetcher tracking mutex poisoned");
		*tracking = Some(HashSet::new());
		ResourceFetchScope {
			fetcher: self,
			active: true,
		}
	}

	fn take_tracked_resources(&self) -> Option<HashSet<ResourceRef>> {
		let mut tracking = self
			.tracking
			.lock()
			.expect("resource fetcher tracking mutex poisoned");
		tracking.take()
	}

	fn track_resource(&self, resource: ResourceRef) {
		if let Some(tracking) = self
			.tracking
			.lock()
			.expect("resource fetcher tracking mutex poisoned")
			.as_mut()
		{
			tracking.insert(resource);
		}
	}
}

impl ResourceFetchScope<'_> {
	pub fn finish(mut self, success: bool) {
		if !self.active {
			return;
		}
		self.active = false;
		let fetched = self.fetcher.take_tracked_resources();
		if let (Some(fetched), ResourceFetcherMode::Managed(manager)) = (fetched, &self.fetcher.mode) {
			if success {
				manager.retain_resources(fetched);
			} else {
				manager.retain_active_resources();
			}
		}
	}
}

impl Drop for ResourceFetchScope<'_> {
	fn drop(&mut self) {
		if self.active {
			self.fetcher.take_tracked_resources();
			if let ResourceFetcherMode::Managed(manager) = &self.fetcher.mode {
				manager.retain_active_resources();
			}
		}
	}
}

struct Inner {
	client: Client,
	entries: Mutex<HashMap<ResourceRef, Entry>>,
	// Resources referenced by the last successfully normalized local config.
	// Background refreshes check this before publishing changes.
	active_resources: Mutex<HashSet<ResourceRef>>,
	watched_files: FileWatchRegistry,
	scheduler_tx: mpsc::UnboundedSender<ScheduledRefresh>,
	change_tx: watch::Sender<ResourceChange>,
	change_counter: AtomicU64,
}

struct Entry {
	content: Bytes,
	next_refresh: Option<Instant>,
}

#[derive(Default)]
struct FileWatchRegistry {
	watches: Mutex<HashMap<PathBuf, JoinHandle<()>>>,
}

impl FileWatchRegistry {
	fn contains(&self, path: &Path) -> bool {
		self
			.watches
			.lock()
			.expect("resource file watcher mutex poisoned")
			.contains_key(path)
	}

	fn insert_or_abort(&self, path: PathBuf, task: JoinHandle<()>) {
		let mut watches = self
			.watches
			.lock()
			.expect("resource file watcher mutex poisoned");
		if watches.contains_key(&path) {
			task.abort();
			return;
		}
		watches.insert(path, task);
	}

	fn retain_paths(&self, retained: &HashSet<PathBuf>) {
		self
			.watches
			.lock()
			.expect("resource file watcher mutex poisoned")
			.retain(|path, task| {
				let retain = retained.contains(path);
				if !retain {
					task.abort();
				}
				retain
			});
	}
}

impl Drop for FileWatchRegistry {
	fn drop(&mut self) {
		for (_, task) in self
			.watches
			.get_mut()
			.expect("resource file watcher mutex poisoned")
			.drain()
		{
			task.abort();
		}
	}
}

#[derive(Debug)]
struct ScheduledRefresh {
	at: Instant,
	resource: ResourceRef,
}

#[derive(Debug, PartialEq, Eq)]
struct TimerEntry {
	at: Instant,
	resource: ResourceRef,
}

impl PartialOrd for TimerEntry {
	fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
		Some(self.cmp(other))
	}
}
impl Ord for TimerEntry {
	fn cmp(&self, other: &Self) -> Ordering {
		other
			.at
			.cmp(&self.at)
			.then_with(|| resource_key(&self.resource).cmp(&resource_key(&other.resource)))
	}
}

impl ResourceManager {
	pub fn new(client: Client) -> anyhow::Result<Self> {
		let (scheduler_tx, scheduler_rx) = mpsc::unbounded_channel();
		let (change_tx, _) = watch::channel(ResourceChange::default());
		let manager = Self {
			inner: Arc::new(Inner {
				client,
				entries: Default::default(),
				active_resources: Default::default(),
				watched_files: Default::default(),
				scheduler_tx,
				change_tx,
				change_counter: AtomicU64::new(0),
			}),
		};
		manager.start_http_scheduler(scheduler_rx);
		Ok(manager)
	}

	pub fn subscribe_changes(&self) -> watch::Receiver<ResourceChange> {
		self.inner.change_tx.subscribe()
	}

	pub async fn fetch_and_wait(&self, resource: ResourceRef) -> anyhow::Result<Bytes> {
		let resource = normalize_resource(resource)?;
		self.fetch_and_wait_normalized(resource).await
	}

	async fn fetch_and_wait_normalized(&self, resource: ResourceRef) -> anyhow::Result<Bytes> {
		if let ResourceRef::File(path) = &resource {
			self.watch_file(path)?;
		}
		if let Some(content) = self.cached(&resource) {
			return Ok(content);
		}
		let FetchResult { content, next } = self.fetch(&resource).await?;
		self.store(resource, content.clone(), next);
		Ok(content)
	}

	pub async fn fetch_cached_or_direct(&self, resource: ResourceRef) -> anyhow::Result<Bytes> {
		let resource = normalize_resource(resource)?;
		self.fetch_cached_or_direct_normalized(resource).await
	}

	async fn fetch_cached_or_direct_normalized(
		&self,
		resource: ResourceRef,
	) -> anyhow::Result<Bytes> {
		if let Some(content) = self.cached(&resource) {
			return Ok(content);
		}
		fetch_direct(&self.inner.client, &resource)
			.await
			.map(|r| r.content)
	}

	pub fn retain_resources(&self, retained: HashSet<ResourceRef>) {
		*self
			.inner
			.active_resources
			.lock()
			.expect("resource active set mutex poisoned") = retained.clone();
		self.retain_cached_and_watched_resources(&retained);
	}

	fn retain_active_resources(&self) {
		// Failed reloads may have fetched temporary resources before erroring.
		// Prune back to the last successful dependency set.
		let retained = self
			.inner
			.active_resources
			.lock()
			.expect("resource active set mutex poisoned")
			.clone();
		self.retain_cached_and_watched_resources(&retained);
	}

	fn retain_cached_and_watched_resources(&self, retained: &HashSet<ResourceRef>) {
		self
			.inner
			.entries
			.lock()
			.expect("resource cache mutex poisoned")
			.retain(|resource, _| retained.contains(resource));

		let retained_files = retained
			.iter()
			.filter_map(|resource| match resource {
				ResourceRef::File(path) => Some(path.clone()),
				ResourceRef::Http { .. } => None,
			})
			.collect::<HashSet<_>>();
		self.inner.watched_files.retain_paths(&retained_files);
	}

	fn cached(&self, resource: &ResourceRef) -> Option<Bytes> {
		self
			.inner
			.entries
			.lock()
			.expect("resource cache mutex poisoned")
			.get(resource)
			.map(|e| e.content.clone())
	}

	fn store(&self, resource: ResourceRef, content: Bytes, next: Option<Instant>) {
		self
			.inner
			.entries
			.lock()
			.expect("resource cache mutex poisoned")
			.insert(
				resource.clone(),
				Entry {
					content,
					next_refresh: next,
				},
			);
		if let Some(at) = next {
			tracing::debug!(
				resource = %safe_resource_key(&resource),
				refresh_in = ?at.saturating_duration_since(Instant::now()),
				"scheduled resource refresh"
			);
			let _ = self
				.inner
				.scheduler_tx
				.send(ScheduledRefresh { at, resource });
		}
	}

	async fn refetch_and_notify_if_changed(&self, resource: ResourceRef) {
		// A resource can be forgotten while an HTTP refresh is queued or in flight.
		// Check before and after I/O so stale refreshes cannot resurrect it.
		if !self.is_active(&resource) {
			return;
		}
		let result = self.fetch(&resource).await;
		let FetchResult { content, next } = match result {
			Ok(result) => result,
			Err(e) => {
				warn!(resource = %safe_resource_key(&resource), "failed to refresh resource: {e}");
				let active = self
					.inner
					.active_resources
					.lock()
					.expect("resource active set mutex poisoned");
				if !active.contains(&resource) {
					return;
				}
				let next = Instant::now() + FAILED_HTTP_REFRESH;
				let mut entries = self
					.inner
					.entries
					.lock()
					.expect("resource cache mutex poisoned");
				let Some(entry) = entries.get_mut(&resource) else {
					return;
				};
				entry.next_refresh = Some(next);
				let _ = self
					.inner
					.scheduler_tx
					.send(ScheduledRefresh { at: next, resource });
				return;
			},
		};
		let active = self
			.inner
			.active_resources
			.lock()
			.expect("resource active set mutex poisoned");
		if !active.contains(&resource) {
			return;
		}

		let changed = {
			let mut entries = self
				.inner
				.entries
				.lock()
				.expect("resource cache mutex poisoned");
			let changed = entries
				.get(&resource)
				.is_none_or(|entry| entry.content != content);
			entries.insert(
				resource.clone(),
				Entry {
					content,
					next_refresh: next,
				},
			);
			changed
		};
		if let Some(at) = next {
			tracing::debug!(
				resource = %safe_resource_key(&resource),
				refresh_in = ?at.saturating_duration_since(Instant::now()),
				"scheduled resource refresh"
			);
			let _ = self.inner.scheduler_tx.send(ScheduledRefresh {
				at,
				resource: resource.clone(),
			});
		}
		if changed {
			self.notify_changed(&resource);
		}
	}

	async fn fetch(&self, resource: &ResourceRef) -> anyhow::Result<FetchResult> {
		fetch_direct(&self.inner.client, resource).await
	}

	fn is_active(&self, resource: &ResourceRef) -> bool {
		self
			.inner
			.active_resources
			.lock()
			.expect("resource active set mutex poisoned")
			.contains(resource)
	}

	fn watch_file(&self, path: &Path) -> anyhow::Result<()> {
		let path = absolute(path)?;
		if self.inner.watched_files.contains(&path) {
			return Ok(());
		}
		let options = crate::util::WatchFilesOptions::default()
			.reload_on_disappearance(true)
			.close_on_removal(true);
		let initial = crate::util::watch_files_with_options(vec![path.clone()], options)?;
		let owner = Arc::downgrade(&self.inner);
		let watched_path = path.clone();
		let task = tokio::spawn(async move {
			let path = watched_path;
			let mut watched = Some(initial);
			let mut retry = tokio::time::interval(Duration::from_secs(1));
			retry.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
			loop {
				tokio::select! {
					changed = async { watched.as_mut().unwrap().changed_invalidated().await }, if watched.is_some() => {
						if changed != Some(false) {
							watched = None;
							if changed.is_none() {
								warn!(code="RESOURCE_WATCH_LOST", path=%path.display(), "resource watch channel closed; re-registering");
							}
						}
						let Some(inner) = owner.upgrade() else { return; };
						// Evict missing content and notify the existing reload path promptly.
						Self { inner }.refresh_file(path.clone()).await;
					}
					_ = retry.tick(), if watched.is_none() => {
						match crate::util::watch_files_with_options(vec![path.clone()], options) {
							Ok(new_watched) => {
								watched = Some(new_watched);
								info!(code="RESOURCE_WATCH_RESTORED", path=%path.display(), "resource watcher registered");
								let Some(inner) = owner.upgrade() else { return; };
								// Read after registration to capture changes made during the gap.
								Self { inner }.refresh_file(path.clone()).await;
							}
							Err(error) => warn!(code="RESOURCE_WATCH_RETRY_FAILED", path=%path.display(), %error, "failed to re-watch resource file; retrying"),
						}
					}
				}
			}
		});
		self.inner.watched_files.insert_or_abort(path, task);
		Ok(())
	}

	async fn refresh_file(&self, path: PathBuf) {
		let resource = ResourceRef::File(path.clone());
		if !self.is_active(&resource) {
			return;
		}
		let content = fs_err::tokio::read(&path).await;
		let changed = {
			// Hold the existing active-set lock through the write so pruning cannot
			// finish between the final membership check and cache publication.
			let active = self
				.inner
				.active_resources
				.lock()
				.expect("resource active set mutex poisoned");
			if !active.contains(&resource) {
				return;
			}
			let mut entries = self
				.inner
				.entries
				.lock()
				.expect("resource cache mutex poisoned");
			match content {
				Ok(content) => {
					let content = Bytes::from(content);
					let changed = entries
						.get(&resource)
						.is_none_or(|entry| entry.content != content);
					entries.insert(
						resource.clone(),
						Entry {
							content,
							next_refresh: None,
						},
					);
					changed
				},
				Err(error) => {
					warn!(code="RESOURCE_FILE_READ_FAILED", path=%path.display(), %error, "failed to refresh resource file");
					entries.remove(&resource).is_some()
				},
			}
		};
		if changed {
			self.notify_changed(&resource);
		}
	}

	fn start_http_scheduler(&self, mut scheduler_rx: mpsc::UnboundedReceiver<ScheduledRefresh>) {
		let owner = Arc::downgrade(&self.inner);
		tokio::spawn(async move {
			let mut heap = BinaryHeap::<TimerEntry>::new();
			loop {
				let next = heap.peek().map(|entry| entry.at);
				tokio::select! {
					_ = maybe_sleep_until(next) => {
						let Some(entry) = heap.pop() else {
							continue;
						};
						let Some(inner) = owner.upgrade() else { return; };
						let manager = Self { inner };
						if manager.should_refresh(&entry.resource, entry.at) {
							manager.refetch_and_notify_if_changed(entry.resource).await;
						}
					}
					scheduled = scheduler_rx.recv() => {
						let Some(scheduled) = scheduled else {
							return;
						};
						heap.push(TimerEntry {
							at: scheduled.at,
							resource: scheduled.resource,
						});
					}
				}
			}
		});
	}

	fn should_refresh(&self, resource: &ResourceRef, at: Instant) -> bool {
		if !self.is_active(resource) {
			return false;
		}
		self
			.inner
			.entries
			.lock()
			.expect("resource cache mutex poisoned")
			.get(resource)
			.and_then(|entry| entry.next_refresh)
			.is_some_and(|current| current == at)
	}

	fn notify_changed(&self, resource: &ResourceRef) {
		let next = self
			.inner
			.change_counter
			.fetch_add(1, AtomicOrdering::Relaxed)
			+ 1;
		let _ = self.inner.change_tx.send(ResourceChange {
			version: next,
			resource: safe_resource_key(resource),
		});
	}
}

struct FetchResult {
	content: Bytes,
	next: Option<Instant>,
}

async fn fetch_direct(client: &Client, resource: &ResourceRef) -> anyhow::Result<FetchResult> {
	match resource {
		ResourceRef::File(path) => {
			let content = fs_err::tokio::read(path)
				.await
				.with_context(|| format!("read resource file {}", path.display()))?;
			Ok(FetchResult {
				content: content.into(),
				next: None,
			})
		},
		ResourceRef::Http { url, kind } => {
			let fetch = async {
				let resp = client
					.simple_call(
						::http::Request::builder()
							.uri(url)
							.body(Body::empty())
							.expect("builder should succeed"),
					)
					.await
					.with_context(|| format!("fetch {}", safe_http_resource(url)))?;
				if !resp.status().is_success() {
					return Err(anyhow!("resource server returned HTTP {}", resp.status()));
				}
				let ttl = ttl_from_headers(resp.headers(), kind.default_ttl());
				let body = crate::http::read_resp_body(resp).await?;
				Ok(FetchResult {
					content: body,
					next: Some(Instant::now() + ttl.max(MIN_HTTP_REFRESH)),
				})
			};
			tokio::time::timeout(HTTP_FETCH_TIMEOUT, fetch)
				.await
				.map_err(|_| anyhow!("resource fetch timed out"))?
		},
	}
}

fn ttl_from_headers(headers: &http::HeaderMap, default: Duration) -> Duration {
	if let Some(ttl) = cache_control_max_age(headers) {
		return ttl;
	}
	if let Some(expires) = headers.get(EXPIRES).and_then(|value| value.to_str().ok())
		&& let Ok(expires) = httpdate::parse_http_date(expires)
		&& let Ok(ttl) = expires.duration_since(std::time::SystemTime::now())
	{
		return ttl;
	}
	default
}

fn cache_control_max_age(headers: &http::HeaderMap) -> Option<Duration> {
	let cache_control = headers.typed_get::<CacheControl>()?;
	if cache_control.no_cache() || cache_control.no_store() {
		return None;
	}
	cache_control.max_age()
}

fn resource_key(resource: &ResourceRef) -> String {
	match resource {
		ResourceRef::File(path) => format!("file:{}", path.display()),
		ResourceRef::Http { url, kind } => format!("http:{kind:?}:{url}"),
	}
}

// Resource URLs may contain query credentials or userinfo. Keep the full URI
// for cache identity and ordering, but never emit it as diagnostic metadata.
fn safe_http_resource(url: &http::Uri) -> String {
	let host = url.host().unwrap_or_default();
	let port = url
		.port_u16()
		.map(|port| format!(":{port}"))
		.unwrap_or_default();
	format!(
		"{}://{host}{port}{}",
		url.scheme_str().unwrap_or_default(),
		url.path()
	)
}

fn safe_resource_key(resource: &ResourceRef) -> String {
	match resource {
		ResourceRef::File(path) => format!("file:{}", path.display()),
		ResourceRef::Http { url, kind } => format!("http:{kind:?}:{}", safe_http_resource(url)),
	}
}

fn normalize_resource(resource: ResourceRef) -> anyhow::Result<ResourceRef> {
	Ok(match resource {
		ResourceRef::File(path) => ResourceRef::File(absolute(path)?),
		ResourceRef::Http { url, kind } => ResourceRef::Http { url, kind },
	})
}

async fn maybe_sleep_until(till: Option<Instant>) {
	if let Some(till) = till {
		sleep_until(till).await;
	} else {
		pending::<()>().await;
	}
}

#[cfg(test)]
#[path = "resource_manager_tests.rs"]
mod tests;
