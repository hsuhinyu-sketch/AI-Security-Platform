use std::collections::VecDeque;
use std::collections::hash_map::DefaultHasher;
use std::error::Error as StdError;
use std::fmt::{self, Debug, Formatter};
use std::future::Future;
use std::hash::{Hash, Hasher};
use std::ops::{Deref, DerefMut};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Weak};
use std::task::{self, Poll};
use std::time::{Duration, Instant};

use futures_channel::oneshot;
use futures_core::ready;
use futures_util::future::Either;
use hashbrown::HashMap;
use hashbrown::hash_map::EntryRef;
use http::{Request, Response};
use hyper::rt::{Sleep, Timer as _};
use parking_lot::{MappedMutexGuard, Mutex, MutexGuard};
use tracing::{debug, trace};

use crate::client::RequestBody;
use crate::common::exec;
use crate::common::exec::Exec;
use crate::common::timer::Timer;
use crate::connect::Connected;
use crate::pool;

// per https://datatracker.ietf.org/doc/html/rfc9113#section-6.5.2-2.6.1, servers are expected to
// but not required to set this to at least 100. In practice, a wide range of clients will have failures
// with settings less than this, so it seems a safe default.
pub const DEFAULT_EXPECTED_HTTP2_CAPACITY: usize = 100;

// Fairly arbitrary number; we may want to explore tuning this.
const SHARD_COUNT: usize = 16;

type HostMap<K> = HashMap<K, HostPool<K>>;

/// Shard the host map to avoid one mega-mutex contention.
/// While under extremely high concurrency, this shows ~20% improvement in throughput and is pretty low cost.
/// Note: a key is deterministically in a single shard; this does not increase the number of outbound connections.
#[derive(Debug)]
struct HostShards<K: Key> {
	shards: [Mutex<HostMap<K>>; SHARD_COUNT],
}

impl<K: Key> HostShards<K> {
	fn new() -> Self {
		Self {
			shards: std::array::from_fn(|_| Mutex::new(HashMap::new())),
		}
	}

	fn shard_index(key: &K) -> usize {
		key.shard() % SHARD_COUNT
	}

	fn lock_shard(&self, key: &K) -> MutexGuard<'_, HostMap<K>> {
		self.shards[Self::shard_index(key)].lock()
	}

	fn lock_host(&self, key: &K) -> MappedMutexGuard<'_, HostPool<K>> {
		MutexGuard::map(self.lock_shard(key), |hosts| match hosts.entry_ref(key) {
			EntryRef::Occupied(entry) => entry.into_mut(),
			EntryRef::Vacant(entry) => {
				entry.insert_with_key(key.clone(), HostPool::new(key.expected_capacity()))
			},
		})
	}

	fn clear_expired(&self, settings: &PoolSettings) {
		let now = settings.timer.now();
		for shard in &self.shards {
			let mut hosts = shard.lock();
			Pool::<K>::clear_expired(settings, now, &mut hosts);
		}
	}
}

/// Pool is a connection pool for a set of hosts.
/// Each host shares the same top level settings, and individual per-K entries maintain state for
/// each host under mutex.
#[derive(Clone, Debug)]
pub struct Pool<K: Key> {
	hosts: Arc<HostShards<K>>,
	pub settings: Arc<PoolSettings>,
}

#[derive(Debug)]
pub struct PoolSettings {
	max_idle_per_host: usize,
	idle_interval_spawned: AtomicBool,
	exec: Exec,
	timer: Timer,
	timeout: Option<Duration>,
	pub expected_http2_capacity: usize,
}

impl<K: Key> Pool<K> {
	/// This should *only* be called by the IdleTask
	fn clear_expired(settings: &PoolSettings, now: Instant, hosts: &mut HostMap<K>) {
		let dur = settings.timeout.expect("interval assumes timeout");

		hosts.retain(|key, host| {
			host.idle.retain(|entry| {
				if !entry.value.is_open() {
					trace!("idle interval evicting closed for {:?}", key);
					return false;
				}

				// Avoid `Instant::sub` to avoid issues like rust-lang/rust#86470.
				if now.saturating_duration_since(entry.idle_at) > dur {
					trace!("idle interval evicting expired for {:?}", key);
					return false;
				}

				// Otherwise, keep this value...
				true
			});
			let empty = host.idle.is_empty()
				&& host.active_h2.0.is_empty()
				&& host.connecting == 0
				&& host.waiters.is_empty();
			!empty
		});
	}
	fn lock_hosts<'a>(hosts: &'a HostShards<K>, k: &K) -> MappedMutexGuard<'a, HostPool<K>> {
		hosts.lock_host(k)
	}
	fn host(&self, k: &K) -> MappedMutexGuard<'_, HostPool<K>> {
		Pool::<K>::lock_hosts(self.hosts.as_ref(), k)
	}
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ExpectedCapacity {
	// Always HTTP1: only a single concurrent request is allowed.
	Http1,
	// Always HTTP2: multiple concurrent requests are allowed.
	Http2,
	// HTTP/1 or HTTP/2, depending on the connection (ALPN)
	Auto,
}

pub trait Key: Eq + Hash + Clone + Debug + Unpin + Send + Sync + 'static {
	fn expected_capacity(&self) -> ExpectedCapacity;

	fn shard(&self) -> usize {
		let mut hasher = DefaultHasher::new();
		self.hash(&mut hasher);
		hasher.finish() as usize
	}
}

#[derive(Debug)]
enum CapacityCache {
	// Based on the request properties, what we expect the capacity will be
	Guess(ExpectedCapacity),
	// Based on historical requests, what we expect the capacity will be.
	#[allow(dead_code)]
	Cached(usize),
}

impl CapacityCache {
	fn expected_capacity(&self, expected_http2_capacity: usize) -> usize {
		match self {
			CapacityCache::Guess(ExpectedCapacity::Http1) => 1,
			CapacityCache::Guess(ExpectedCapacity::Http2) => expected_http2_capacity,
			// Assume we are going to get HTTP2; this ensures we don't flood with connections for HTTP/1.1
			// If we don't get it, we will just try again with the new expected value cached.
			CapacityCache::Guess(ExpectedCapacity::Auto) => expected_http2_capacity,
			CapacityCache::Cached(exact) => *exact,
		}
	}
}

#[derive(Default)]
struct H2Pool(VecDeque<ReservedHttp2Connection>);

impl Debug for H2Pool {
	fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
		let active: Vec<_> = self
			.0
			.iter()
			.map(|h| h.load.active_streams.load(Ordering::Acquire))
			.collect();
		write!(f, "H2Pool({active:?})")
	}
}

impl H2Pool {
	pub fn ensure_tracked(&mut self, c: &ReservedHttp2Connection) {
		if !self.0.iter().any(|entry| Arc::ptr_eq(&entry.load, &c.load)) {
			let cpy = ReservedHttp2Connection {
				info: c.info.clone(),
				tx: c.tx.clone(),
				load: c.load.clone(),
			};
			if c.load.remaining_capacity() == 0 {
				self.0.push_back(cpy)
			} else {
				self.0.push_front(cpy)
			}
		}
	}
	/// increment_load attempts to increment the load on a connection if it is HTTP2.
	/// This automatically manages tracking of position
	pub fn increment_load(&mut self, c: &HttpConnection) -> Option<CapacityReservationResult> {
		match c {
			HttpConnection::Http1(_) => None,
			HttpConnection::Http2(h2) => {
				let res = h2.load.try_reserve_stream_slot();
				if res == CapacityReservationResult::ReservedAndFilled {
					self.mark_full(h2);
				}
				Some(res)
			},
		}
	}
	pub fn mark_full(&mut self, c: &ReservedHttp2Connection) {
		if let Some(old) = self.remove(c) {
			// Push to the back of the queue
			self.0.push_back(old)
		}
	}
	pub fn remove_by_load(&mut self, rc: &Arc<H2Load>) -> Option<ReservedHttp2Connection> {
		let pos = self
			.0
			.iter()
			.position(|entry| Arc::ptr_eq(&entry.load, rc))?;
		self.0.remove(pos)
	}
	pub fn remove(&mut self, rc: &ReservedHttp2Connection) -> Option<ReservedHttp2Connection> {
		let pos = self
			.0
			.iter()
			.position(|entry| Arc::ptr_eq(&entry.load, &rc.load))?;
		self.0.remove(pos)
	}
	fn mark_active_by_load(&mut self, c: &Arc<H2Load>) {
		if let Some(v) = self.remove_by_load(c) {
			// Push to the front of the queue; it will be the next connection to get used.
			self.0.push_front(v);
		}
	}
	fn mark_active(&mut self, c: ReservedHttp2Connection) {
		self.remove(&c);
		// Push to the front of the queue; it will be the next connection to get used.
		self.0.push_front(c);
	}
	/// maybe_insert_new inserts the connection as an active one (if it is HTTP2).
	fn maybe_insert_new(&mut self, conn: HttpConnection, reserve: bool) -> HttpConnection {
		if let HttpConnection::Http2(h) = conn {
			self.0.push_front(h.clone_without_load_incremented());
			if reserve {
				// IMPORTANT: must not wrap this `try_reserve_stream_slot` call in a
				// `debug_assert!` — `debug_assert!` is stripped entirely in release
				// builds, which also strips the side-effecting reserve. Callers pass
				// `reserve=true` to get a `ReservedHttp2Connection` whose slot is
				// accounted; without the increment the corresponding Drop releases
				// an unreserved slot, wrapping `active_streams` to `usize::MAX` and
				// permanently blocking the connection from further reservations
				// (and preventing it from ever returning to `idle`, which leaks the
				// underlying TCP connection).
				let result = h.load.try_reserve_stream_slot();
				debug_assert!(
					result != CapacityReservationResult::NoCapacity,
					"a new stream should always be able to be reserved"
				);
			}
			HttpConnection::Http2(ReservedHttp2Connection {
				info: h.info,
				tx: h.tx,
				load: h.load,
			})
		} else {
			conn
		}
	}
	fn reserve(&mut self) -> Option<ReservedHttp2Connection> {
		while let Some(h) = self.0.front() {
			if !h.tx.is_ready() {
				// Connection is dead... remove it.
				let _ = self.0.pop_front();
				debug!("removing dead http2 connection");
				continue;
			}
			match h.load.try_reserve_stream_slot() {
				CapacityReservationResult::NoCapacity => {
					// We know the front is the one that was most recently returned, thus must be available
					return None;
				},
				CapacityReservationResult::ReservedAndFilled => {
					let ret = Some(ReservedHttp2Connection {
						info: h.info.clone(),
						tx: h.tx.clone(),
						load: h.load.clone(),
					});
					// Move the connection to the back of the queue.
					if let Some(v) = self.0.pop_front() {
						self.0.push_back(v);
					}
					return ret;
				},
				CapacityReservationResult::ReservedButNotFilled => {
					// Keep the connection at the front.
					return Some(ReservedHttp2Connection {
						info: h.info.clone(),
						tx: h.tx.clone(),
						load: h.load.clone(),
					});
				},
			}
		}
		None
	}
}

pub(crate) struct ReservedHttp1Connection {
	pub(crate) info: Connected,
	pub(crate) tx: hyper::client::conn::http1::SendRequest<RequestBody>,
}

pub(crate) enum HttpConnection {
	Http1(ReservedHttp1Connection),
	Http2(ReservedHttp2Connection),
}

impl fmt::Debug for HttpConnection {
	fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
		let v = match self {
			HttpConnection::Http1(_) => "http1",
			HttpConnection::Http2(_) => "http2",
		};
		f.debug_struct("HttpConnection")
			.field("version", &v)
			.finish()
	}
}

impl HttpConnection {
	pub fn maybe_clone(&self) -> Option<Self> {
		match self {
			HttpConnection::Http1(_) => None,
			HttpConnection::Http2(inner) => Some(HttpConnection::Http2(
				inner.clone_without_load_incremented(),
			)),
		}
	}
	pub fn capacity(&self) -> usize {
		match self {
			HttpConnection::Http1(_) => 1,
			HttpConnection::Http2(h) => h.load.remaining_capacity(),
		}
	}
	pub fn try_send_request(
		&mut self,
		req: Request<RequestBody>,
	) -> impl Future<
		Output = Result<
			Response<hyper::body::Incoming>,
			hyper::client::conn::TrySendError<Request<RequestBody>>,
		>,
	> {
		match self {
			HttpConnection::Http1(h) => Either::Left(h.tx.try_send_request(req)),
			HttpConnection::Http2(h) => Either::Right(h.tx.try_send_request(req)),
		}
	}
	pub fn conn_info(&self) -> &Connected {
		match self {
			HttpConnection::Http1(h) => &h.info,
			HttpConnection::Http2(h) => &h.info,
		}
	}
	pub fn is_open(&self) -> bool {
		match self {
			HttpConnection::Http1(h1) => h1.tx.is_ready(),
			HttpConnection::Http2(h2) => h2.tx.is_ready(),
		}
	}
}

#[derive(Debug)]
pub struct H2CapacityGuard<K: Key> {
	value: Option<(K, Arc<H2Load>)>,
	pool: Weak<HostShards<K>>,
	settings: Arc<PoolSettings>,
}

pub(crate) struct ReservedHttp2Connection {
	pub(crate) info: Connected,
	pub(crate) tx: hyper::client::conn::http2::SendRequest<RequestBody>,
	pub(crate) load: Arc<H2Load>,
}

impl ReservedHttp2Connection {
	fn clone_without_load_incremented(&self) -> Self {
		Self {
			info: self.info.clone(),
			tx: self.tx.clone(),
			load: self.load.clone(),
		}
	}
}

#[derive(Debug)]
pub(crate) struct H2Load {
	active_streams: AtomicUsize,
	max_streams: AtomicUsize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum CapacityReservationResult {
	NoCapacity,
	ReservedAndFilled,
	ReservedButNotFilled,
}

impl H2Load {
	pub(crate) fn new(max_streams: usize) -> Self {
		Self {
			active_streams: AtomicUsize::new(0),
			max_streams: AtomicUsize::new(max_streams.max(1)),
		}
	}

	fn remaining_capacity(&self) -> usize {
		self.max_streams.load(Ordering::Acquire) - self.active_streams.load(Ordering::Acquire)
	}
	fn try_reserve_stream_slot(&self) -> CapacityReservationResult {
		let max = self.max_streams.load(Ordering::Acquire);
		let prev = self
			.active_streams
			.fetch_update(Ordering::AcqRel, Ordering::Acquire, |active| {
				if active < max { Some(active + 1) } else { None }
			});

		match prev {
			Err(_) => CapacityReservationResult::NoCapacity,
			Ok(prev_val) => {
				if prev_val + 1 >= max {
					CapacityReservationResult::ReservedAndFilled
				} else {
					CapacityReservationResult::ReservedButNotFilled
				}
			},
		}
	}

	fn release_stream_slot(&self) -> (usize, bool) {
		let prev = self.active_streams.fetch_sub(1, Ordering::AcqRel);
		let max = self.max_streams.load(Ordering::Acquire);
		debug_assert!(prev > 0, "active_streams must be > 0 before release");
		(prev - 1, prev == max)
	}
}

// HostPool stores information for a single host.
#[derive(Debug)]
struct HostPool<K: Key> {
	// The number of currently establishing connections
	connecting: usize,
	// The expected number of requests the `connecting` connections are estimated to handle.
	expected_connecting_capacity: usize,
	// Expected capacity
	per_connection_capacity_cache: CapacityCache,
	// These are internal Conns sitting in the event loop in the KeepAlive
	// state, waiting to receive a new Request to send on the socket.
	idle: Vec<Idle>,
	// Active h2 connections. These are stored (unlike http/1.1) as active connections may be used.
	// Busy items are pushed to the backend of the queue, while free items are in the front.
	// If the first item is busy, that implies all items are busy; grabbing a free connection never requires
	// a search.
	active_h2: H2Pool,
	// These are outstanding Checkouts that are waiting for a socket to be
	// able to send a Request one. This is used when "racing" for a new
	// connection.
	//
	// The Client starts 2 tasks, 1 to connect a new socket, and 1 to wait
	// for the Pool to receive an idle Conn. When a Conn becomes idle,
	// this list is checked for any parked Checkouts, and tries to notify
	// them that the Conn could be used instead of waiting for a brand new
	// connection.
	waiters: VecDeque<oneshot::Sender<Result<Pooled<K>, ClientConnectError>>>,
}

impl<K: Key> HostPool<K> {
	fn new(capacity: ExpectedCapacity) -> HostPool<K> {
		Self {
			connecting: 0,
			expected_connecting_capacity: 0,
			per_connection_capacity_cache: CapacityCache::Guess(capacity),
			idle: Vec::new(),
			active_h2: H2Pool::default(),
			waiters: Default::default(),
		}
	}
	fn return_h2_stream(
		&mut self,
		settings: Arc<PoolSettings>,
		pool: Arc<HostShards<K>>,
		k: K,
		load: Arc<H2Load>,
	) {
		let (remaining, was_at_max) = load.release_stream_slot();
		if remaining == 0 {
			if let Some(v) = self.active_h2.remove_by_load(&load) {
				if v.tx.is_ready() {
					self.return_idle(settings, pool, k, HttpConnection::Http2(v))
				} else {
					trace!("skip moving h2 connection to idle; not open")
				}
			}
		} else if was_at_max {
			self.active_h2.mark_active_by_load(&load);
		}
	}
	fn release_h2_stream_without_returning_to_idle(&mut self, s: &HttpConnection) {
		let HttpConnection::Http2(h2) = s else {
			return;
		};
		let (remaining, was_at_max) = h2.load.release_stream_slot();
		if remaining == 0 {
			// Do NOT remove it here; this is the caller responsibility
			// This ensures we don't end up dropping it if we need to rollback.
		} else if was_at_max {
			self.active_h2.mark_active_by_load(&h2.load);
		}
	}
	fn return_connection(
		&mut self,
		settings: Arc<PoolSettings>,
		pool: Arc<HostShards<K>>,
		k: K,
		value: HttpConnection,
	) {
		match value {
			HttpConnection::Http1(h) => self.return_idle(settings, pool, k, HttpConnection::Http1(h)),
			HttpConnection::Http2(h) => {
				let (remaining, was_at_max) = h.load.release_stream_slot();
				if remaining == 0 {
					self.active_h2.remove(&h);
					self.return_idle(settings, pool, k, HttpConnection::Http2(h))
				} else if was_at_max {
					self.active_h2.mark_active(h);
				}
			},
		}
	}
	fn return_dead_connection(&mut self, value: HttpConnection) {
		match value {
			HttpConnection::Http1(_) => {
				// Just drop it
			},
			HttpConnection::Http2(h) => {
				// Even if it has capacity its dead now; do not track it
				self.active_h2.remove(&h);
			},
		}
	}
	pub fn forget_pending_connection(
		&mut self,
		key: K,
		capacity: usize,
		mut err: Option<crate::Error>,
		for_under_capacity_new_connection: bool,
	) {
		if !for_under_capacity_new_connection {
			// for_under_capacity_new_connection means we got a connection, it just was too small
			self.connecting -= 1;
		}
		self.expected_connecting_capacity -= capacity;

		let mut to_notify = capacity;
		if !for_under_capacity_new_connection {
			to_notify = to_notify.saturating_sub(1);
			// For the first, notify with the original error. The rest get an error to just retry.
			loop {
				let Some(tx) = self.waiters.pop_front() else {
					break;
				};
				if tx.is_canceled() {
					trace!("insert new error; removing canceled waiter for {:?}", key);
					continue;
				}

				let res = if let Some(e) = err.take() {
					tx.send(Err(ClientConnectError::Normal(e)))
				} else {
					tx.send(Err(ClientConnectError::CheckoutIsClosed(
						pool::Error::ConnectionDroppedWithoutCompletion,
					)))
				};
				if let Err(Err(ClientConnectError::Normal(e))) = res {
					err = Some(e);
					continue;
				}

				break;
			}
		}

		while to_notify > 0 {
			let Some(tx) = self.waiters.pop_front() else {
				break;
			};
			if tx.is_canceled() {
				trace!("insert new error; removing canceled waiter for {:?}", key);
				continue;
			}
			to_notify -= 1;
			let e = if for_under_capacity_new_connection {
				pool::Error::ConnectionLowCapacity
			} else {
				pool::Error::WaitingOnSharedFailedConnection
			};
			let _ = tx.send(Err(ClientConnectError::CheckoutIsClosed(e)));
		}
	}
	pub fn return_idle(
		&mut self,
		settings: Arc<PoolSettings>,
		pool: Arc<HostShards<K>>,
		key: K,
		conn: HttpConnection,
	) {
		trace!(waiters=%self.waiters.len(), "return idle");
		// we are returning, so there should only ever been 1 additional spot free
		let capacity = 1;
		Pool::send_connection("idle", key, capacity, self, &pool, &settings, conn);
	}

	fn push_idle_with_cap(
		&mut self,
		max_idle_per_host: usize,
		key: K,
		value: HttpConnection,
		idle_at: Instant,
	) {
		if max_idle_per_host == 0 {
			debug!(
				"dropping idle connection for {:?}; max_idle_per_host=0",
				key
			);
			return;
		}
		if self.idle.len() >= max_idle_per_host {
			debug!(
				"evicting oldest idle connection for {:?}; max_idle_per_host reached",
				key
			);
			let _ = self.idle.remove(0);
		}
		debug!("pooling idle connection for {:?}", key);
		self.idle.push(Idle { value, idle_at });
	}
}

#[derive(Clone, Copy, Debug)]
pub struct Config {
	pub idle_timeout: Option<Duration>,
	pub max_idle_per_host: usize,
	pub expected_http2_capacity: usize,
}

impl<K: Key> Pool<K> {
	pub fn new<E, M>(config: Config, executor: E, timer: M) -> Pool<K>
	where
		E: hyper::rt::Executor<exec::BoxSendFuture> + Send + Sync + Clone + 'static,
		M: hyper::rt::Timer + Send + Sync + Clone + 'static,
	{
		let exec = Exec::new(executor);
		let timer = Timer::new(timer);

		Pool {
			hosts: Arc::new(HostShards::new()),
			settings: Arc::new(PoolSettings {
				idle_interval_spawned: AtomicBool::new(false),
				max_idle_per_host: config.max_idle_per_host,
				exec,
				timer,
				timeout: config.idle_timeout,
				expected_http2_capacity: config.expected_http2_capacity,
			}),
		}
	}
}

#[derive(Debug)]
pub(crate) struct WaitForConnection<K: Key> {
	pub should_connect: Option<ShouldConnect<K>>,
	pub waiter: oneshot::Receiver<Result<Pooled<K>, ClientConnectError>>,
}

#[derive(Debug)]
struct ShouldConnectInner<K: Key> {
	expected_capacity: usize,
	key: K,
	pool: Weak<HostShards<K>>,
}

#[derive(Debug)]
pub(crate) struct ShouldConnect<K: Key> {
	inner: Option<ShouldConnectInner<K>>,
}

impl<K: Key> Drop for ShouldConnect<K> {
	fn drop(&mut self) {
		let Some(inner) = self.inner.take() else {
			return;
		};
		if let Some(pool) = inner.pool.upgrade() {
			let mut hosts = Pool::lock_hosts(pool.as_ref(), &inner.key);
			hosts.forget_pending_connection(inner.key, inner.expected_capacity, None, false);
		}
	}
}

#[derive(Debug)]
pub(crate) enum CheckoutResult<K: Key> {
	Checkout(Pooled<K>),
	Wait(WaitForConnection<K>),
}

impl<K: Key> Pool<K> {
	pub(crate) fn insert_new_connection_error(
		&self,
		mut should_connect: ShouldConnect<K>,
		err: crate::Error,
	) {
		let ShouldConnectInner {
			expected_capacity,
			key,
			..
		} = should_connect
			.inner
			.take()
			.expect("insert_new_connection requires an active should_connect token");
		let mut host = self.host(&key);
		host.forget_pending_connection(key, expected_capacity, Some(err), false)
	}
	pub(crate) fn insert_new_connection(
		&self,
		mut should_connect: ShouldConnect<K>,
		conn: HttpConnection,
	) {
		let ShouldConnectInner {
			expected_capacity,
			key,
			..
		} = should_connect
			.inner
			.take()
			.expect("insert_new_connection requires an active should_connect token");
		let mut host = self.host(&key);
		// Do not drop again as we explicitly inserted
		let capacity = conn.capacity();
		host.connecting -= 1;
		// Min of capacity and expected to handle the over-capacity case.
		// For under capacity, we handle it below in forget_pending_connection
		host.expected_connecting_capacity -= std::cmp::min(capacity, expected_capacity);
		trace!(?key, ?host.connecting, %host.expected_connecting_capacity, "inserting new connection");

		let conn = host.active_h2.maybe_insert_new(conn, false);
		trace!(waiters=%host.waiters.len(), "insert new");
		// First, send to any waiters...
		Pool::send_connection(
			"new",
			key.clone(),
			capacity,
			&mut host,
			&self.hosts,
			&self.settings,
			conn,
		);

		// If we had expected this to have more capacity, we need to notify any waiters that its not going to
		// arrive...
		if capacity < expected_capacity {
			trace!(
				"handle capacity mismatch: expected {} but got {} ",
				expected_capacity, capacity
			);
			let excess = expected_capacity - capacity;
			host.per_connection_capacity_cache = CapacityCache::Cached(capacity);
			host.forget_pending_connection(key, excess, None, true);
		}
	}

	fn ensure_idle_interval(pool: &Arc<HostShards<K>>, settings: &Arc<PoolSettings>) {
		let Some(duration) = settings.timeout else {
			return;
		};
		if settings.idle_interval_spawned.swap(true, Ordering::AcqRel) {
			return;
		}

		let timer = settings.timer.clone();
		let interval = IdleTask {
			timer: timer.clone(),
			duration,
			deadline: Instant::now(),
			fut: timer.sleep_until(Instant::now()), // ready at first tick
			pool: Arc::downgrade(pool),
			settings: settings.clone(),
		};

		settings.exec.execute(interval);
	}

	fn send_connection(
		reason: &str,
		key: K,
		mut capacity: usize,
		host: &mut HostPool<K>,
		pool: &Arc<HostShards<K>>,
		settings: &Arc<PoolSettings>,
		original_con: HttpConnection,
	) {
		let mut next_conn = Some(original_con);
		let mut sent = 0;
		while capacity > 0 {
			let Some(tx) = host.waiters.pop_front() else {
				break;
			};
			if tx.is_canceled() {
				trace!("insert new; removing canceled waiter for {:?}", key);
				continue;
			}

			let Some(this_conn) = next_conn.take() else {
				break;
			};
			next_conn = this_conn.maybe_clone();

			if let Some(CapacityReservationResult::NoCapacity) = host.active_h2.increment_load(&this_conn)
			{
				break;
			}
			let pooled = Pooled {
				value: Some((key.clone(), this_conn)),
				is_reused: reason == "idle",
				pool: Arc::downgrade(pool),
				settings: settings.clone(),
			};

			match tx.send(Ok(pooled)) {
				Ok(()) => {
					capacity -= 1;
					sent += 1;
					if let Some(HttpConnection::Http2(h2)) = &next_conn {
						// We need to make sure its actively tracked; if we hit this from the idle flow it may have been removed.
						host.active_h2.ensure_tracked(h2);
					}
				},
				Err(Ok(mut e)) => {
					trace!("send failed");
					// Recover the connection without dropping the pooled wrapper
					// We verify its Ok() explicitly above
					next_conn = e.value.take().map(|(_, c)| c);
					if let Some(next_conn) = &next_conn {
						// We reserved it above, now drop it back to avoid double counting
						host.release_h2_stream_without_returning_to_idle(next_conn);
					}
				},
				Err(_) => unreachable!("Ok() always above"),
			}
		}
		trace!(fulfilled=%sent, "sent {reason} connection");
		if sent == 0
			&& let Some(c) = next_conn
		{
			if let HttpConnection::Http2(h2) = &c {
				// If we tried to send, we may have put it in the active_h2 list and need to remove it
				let _ = host.active_h2.remove(h2);
			}
			trace!("nobody wanted {reason} connection; inserting as idle");
			Self::ensure_idle_interval(pool, settings);
			let now = settings.timer.now();
			host.push_idle_with_cap(settings.max_idle_per_host, key, c, now);
		}
	}

	pub(crate) fn checkout_or_register_waker(&self, key: K) -> CheckoutResult<K> {
		let mut host = self.host(&key);
		// First attempt: find any active H2 streams with available capacity and attach to that.
		if let Some(reserved) = host.active_h2.reserve() {
			trace!("found active h2 connection with capacity");
			let p = Pooled {
				value: Some((key, HttpConnection::Http2(reserved))),
				is_reused: true,
				pool: Arc::downgrade(&self.hosts),
				settings: self.settings.clone(),
			};
			return CheckoutResult::Checkout(p);
		}

		{
			let expiration = Expiration::new(self.settings.timeout);
			let now = self.settings.timer.now();
			let popper = IdlePopper {
				key: &key,
				list: &mut host.idle,
			};
			if let Some(got) = popper.pop(&expiration, now) {
				trace!("found idle connection");
				let c = got.value;
				// For HTTP2, as they are shared, we keep active connections tracked.
				// Otherwise, there is no need and we just return is as Owned.
				let c = host.active_h2.maybe_insert_new(c, true);
				let p = Pooled {
					value: Some((key, c)),
					is_reused: true,
					pool: Arc::downgrade(&self.hosts),
					settings: self.settings.clone(),
				};
				return CheckoutResult::Checkout(p);
			}
		}
		// At this point nothing is immediately available to us.
		// We will register ourselves as a waiter, and indicate to the caller if they should spawn
		// a connection or not.
		let pending = host.expected_connecting_capacity;
		// Clear cancelled waiters
		host.waiters.retain(|w| !w.is_canceled());
		let waiters = host.waiters.len();
		trace!("checkout waiting for idle connection: {:?}", key);
		let should_connect = if pending <= waiters {
			// We need more capacity! Start a connection
			// We will assume the caller is actually going to do this
			let expected = host
				.per_connection_capacity_cache
				.expected_capacity(self.settings.expected_http2_capacity);
			host.connecting += 1;
			host.expected_connecting_capacity += expected;
			Some(ShouldConnect {
				inner: Some(ShouldConnectInner {
					expected_capacity: expected,
					key,
					pool: Arc::downgrade(&self.hosts),
				}),
			})
		} else {
			None
		};
		trace!(should_connect=%should_connect.is_some(), "no active or idle connections available");
		let (tx, rx) = oneshot::channel();
		host.waiters.push_back(tx);
		CheckoutResult::Wait(WaitForConnection {
			waiter: rx,
			should_connect,
		})
	}
}

/// Pop off this list, looking for a usable connection that hasn't expired.
struct IdlePopper<'a, K> {
	key: &'a K,
	list: &'a mut Vec<Idle>,
}

impl<'a, K: Debug> IdlePopper<'a, K> {
	fn pop(self, expiration: &Expiration, now: Instant) -> Option<Idle> {
		while let Some(entry) = self.list.pop() {
			// If the connection has been closed, or is older than our idle
			// timeout, simply drop it and keep looking...
			if !entry.value.is_open() {
				trace!("removing closed connection for {:?}", self.key);
				continue;
			}
			// TODO: Actually, since the `idle` list is pushed to the end always,
			// that would imply that if *this* entry is expired, then anything
			// "earlier" in the list would *have* to be expired also... Right?
			//
			// In that case, we could just break out of the loop and drop the
			// whole list...
			if expiration.expires(entry.idle_at, now) {
				trace!("removing expired connection for {:?}", self.key);
				continue;
			}

			return Some(entry);
		}

		None
	}
}

/// A wrapped poolable value that tries to reinsert to the Pool on Drop.
pub(crate) struct Pooled<K: Key> {
	value: Option<(K, HttpConnection)>,
	is_reused: bool,
	pool: Weak<HostShards<K>>,
	settings: Arc<PoolSettings>,
}

impl<K: Key> Debug for Pooled<K> {
	fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
		f.debug_struct("Pooled")
			.field("value", &self.value.is_some())
			.field("is_reused", &self.is_reused)
			.finish()
	}
}

impl<K: Key> Pooled<K> {}

impl<K: Key> Pooled<K> {
	pub(crate) fn into_h2_parts(mut self) -> (ReservedHttp2Connection, H2CapacityGuard<K>) {
		let (k, v) = self.value.take().expect("not dropped");
		let HttpConnection::Http2(h2) = v else {
			panic!("into_h2_parts must be used on http2")
		};
		let guard = H2CapacityGuard {
			value: Some((k, h2.load.clone())),
			pool: self.pool.clone(),
			settings: self.settings.clone(),
		};
		(h2, guard)
	}

	pub fn is_reused(&self) -> bool {
		self.is_reused
	}

	fn as_ref(&self) -> &HttpConnection {
		self.value.as_ref().map(|v| &v.1).expect("not dropped")
	}

	fn as_mut(&mut self) -> &mut HttpConnection {
		self.value.as_mut().map(|v| &mut v.1).expect("not dropped")
	}
	pub fn is_http2(&self) -> bool {
		match self.as_ref() {
			HttpConnection::Http1(_) => false,
			HttpConnection::Http2(_) => true,
		}
	}
	pub fn is_http1(&self) -> bool {
		!self.is_http2()
	}
}

impl<K: Key> Deref for Pooled<K> {
	type Target = HttpConnection;
	fn deref(&self) -> &HttpConnection {
		self.as_ref()
	}
}

impl<K: Key> DerefMut for Pooled<K> {
	fn deref_mut(&mut self) -> &mut HttpConnection {
		self.as_mut()
	}
}

impl<K: Key> Drop for Pooled<K> {
	fn drop(&mut self) {
		let Some((k, value)) = self.value.take() else {
			// Already handled
			return;
		};
		let Some(pool) = self.pool.upgrade() else {
			trace!("pool dropped, dropping pooled ({:?})", k);
			return;
		};
		let mut hosts = Pool::lock_hosts(pool.as_ref(), &k);
		if value.is_open() {
			trace!(key=?k, "returning connection to pool");
			hosts.return_connection(self.settings.clone(), pool.clone(), k, value);
		} else {
			trace!("connection already closed; skip idle pool insertion");
			// If we *already* know the connection is done here,
			// it shouldn't be re-inserted back into the pool.
			hosts.return_dead_connection(value)
		}
	}
}

impl<K: Key> Drop for H2CapacityGuard<K> {
	fn drop(&mut self) {
		let Some((k, value)) = self.value.take() else {
			// Already handled
			return;
		};
		let Some(pool) = self.pool.upgrade() else {
			trace!("pool dropped, dropping pooled ({:?})", k);
			return;
		};
		let mut hosts = Pool::lock_hosts(pool.as_ref(), &k);
		hosts.return_h2_stream(self.settings.clone(), pool.clone(), k, value);
	}
}

#[derive(Debug)]
struct Idle {
	idle_at: Instant,
	value: HttpConnection,
}

#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
	PoolDisabled,
	CheckoutNoLongerWanted,
	CheckedOutClosedValue,
	WaitingOnSharedFailedConnection,
	ConnectionDroppedWithoutCompletion,
	ConnectionLowCapacity,
}

impl fmt::Display for Error {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.write_str(match self {
			Error::PoolDisabled => "pool is disabled",
			Error::CheckedOutClosedValue => "checked out connection was closed",
			Error::CheckoutNoLongerWanted => "request was canceled",
			Error::WaitingOnSharedFailedConnection => "shared wait failed",
			Error::ConnectionDroppedWithoutCompletion => "connection dropped without completion",
			Error::ConnectionLowCapacity => "connection didn't have enough capacity",
		})
	}
}

impl StdError for Error {}

struct Expiration(Option<Duration>);

impl Expiration {
	fn new(dur: Option<Duration>) -> Expiration {
		Expiration(dur)
	}

	fn expires(&self, instant: Instant, now: Instant) -> bool {
		match self.0 {
			// Avoid `Instant::elapsed` to avoid issues like rust-lang/rust#86470.
			Some(timeout) => now.saturating_duration_since(instant) > timeout,
			None => false,
		}
	}
}

#[derive(Debug)]
pub(crate) enum ClientConnectError {
	Normal(crate::Error),
	CheckoutIsClosed(Error),
}

pin_project_lite::pin_project! {
	struct IdleTask<K: Key> {
		timer: Timer,
		duration: Duration,
		deadline: Instant,
		fut: Pin<Box<dyn Sleep>>,
		pool: Weak<HostShards<K>>,
		settings: Arc<PoolSettings>,
	}
}

impl<K: Key> Future for IdleTask<K> {
	type Output = ();

	fn poll(self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> Poll<Self::Output> {
		let mut this = self.project();
		loop {
			ready!(Pin::new(&mut this.fut).poll(cx));
			// Set this task to run after the next deadline
			// If the poll missed the deadline by a lot, set the deadline
			// from the current time instead
			*this.deadline += *this.duration;
			if *this.deadline < Instant::now() - Duration::from_millis(5) {
				*this.deadline = Instant::now() + *this.duration;
			}
			*this.fut = this.timer.sleep_until(*this.deadline);

			if let Some(inner) = this.pool.upgrade() {
				trace!("idle interval checking for expired");
				inner.clear_expired(this.settings.as_ref());
				continue;
			}
			trace!("pool closed, canceling idle interval");
			return Poll::Ready(());
		}
	}
}
