use std::collections::VecDeque;
use std::time::{Duration, Instant, SystemTime};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WindowEvent {
	Success,
	Failure,
	Timeout,
	SafetyViolation,
}

#[derive(Debug, Clone)]
pub struct SlidingWindow {
	window: Duration,
	buckets: VecDeque<Bucket>,
	bucket_size: Duration,
}

#[derive(Debug, Clone)]
struct Bucket {
	opened_at: Instant,
	requests: u64,
	failures: u64,
	timeouts: u64,
	safety_violations: u64,
}

impl Default for Bucket {
	fn default() -> Self {
		Self {
			opened_at: Instant::now(),
			requests: 0,
			failures: 0,
			timeouts: 0,
			safety_violations: 0,
		}
	}
}

impl SlidingWindow {
	pub fn new(window: Duration) -> Self {
		Self::with_bucket_size(window, Duration::from_secs(1))
	}

	pub fn with_bucket_size(window: Duration, bucket_size: Duration) -> Self {
		assert!(!window.is_zero(), "window must be non-zero");
		assert!(!bucket_size.is_zero(), "bucket_size must be non-zero");
		Self {
			window,
			buckets: VecDeque::new(),
			bucket_size,
		}
	}

	pub fn record(&mut self, event: WindowEvent) {
		let now = Instant::now();
		self.prune(now);
		match self.buckets.back_mut() {
			Some(bucket) if now.duration_since(bucket.opened_at) < self.bucket_size => {
				bucket.apply(event);
			},
			_ => {
				let mut bucket = Bucket {
					opened_at: now,
					..Default::default()
				};
				bucket.apply(event);
				self.buckets.push_back(bucket);
			},
		}
	}

	pub fn totals(&mut self) -> WindowTotals {
		let now = Instant::now();
		self.prune(now);
		let mut totals = WindowTotals::default();
		for bucket in &self.buckets {
			totals.requests += bucket.requests;
			totals.failures += bucket.failures;
			totals.timeouts += bucket.timeouts;
			totals.safety_violations += bucket.safety_violations;
		}
		totals
	}

	fn prune(&mut self, now: Instant) {
		while self
			.buckets
			.front()
			.is_some_and(|bucket| now.duration_since(bucket.opened_at) > self.window)
		{
			self.buckets.pop_front();
		}
	}
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct WindowTotals {
	pub requests: u64,
	pub failures: u64,
	pub timeouts: u64,
	pub safety_violations: u64,
}

#[derive(Debug, Clone, Copy)]
pub struct MetricSample {
	pub timestamp: SystemTime,
	pub value: f64,
}

#[derive(Debug, Clone)]
pub struct MetricWindow {
	window: Duration,
	samples: VecDeque<MetricSample>,
}

impl MetricWindow {
	pub fn new(window: Duration) -> Self {
		Self {
			window,
			samples: VecDeque::new(),
		}
	}

	pub fn record(&mut self, value: f64) {
		let now = SystemTime::now();
		self.prune(now);
		self.samples.push_back(MetricSample {
			timestamp: now,
			value,
		});
	}

	pub fn average(&mut self) -> Option<f64> {
		let now = SystemTime::now();
		self.prune(now);
		if self.samples.is_empty() {
			return None;
		}
		let sum: f64 = self.samples.iter().map(|s| s.value).sum();
		Some(sum / self.samples.len() as f64)
	}

	pub fn len(&mut self) -> usize {
		let now = SystemTime::now();
		self.prune(now);
		self.samples.len()
	}

	pub fn is_empty(&mut self) -> bool {
		self.len() == 0
	}

	fn prune(&mut self, now: SystemTime) {
		while self
			.samples
			.front()
			.is_some_and(|sample| now.duration_since(sample.timestamp).unwrap_or_default() > self.window)
		{
			self.samples.pop_front();
		}
	}
}

impl Bucket {
	fn apply(&mut self, event: WindowEvent) {
		match event {
			WindowEvent::Success => self.requests += 1,
			WindowEvent::Failure => {
				self.requests += 1;
				self.failures += 1;
			},
			WindowEvent::Timeout => {
				self.requests += 1;
				self.timeouts += 1;
			},
			WindowEvent::SafetyViolation => {
				self.requests += 1;
				self.safety_violations += 1;
			},
		}
	}
}
