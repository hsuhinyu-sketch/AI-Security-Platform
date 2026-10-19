//! Private, bounded audit segments. Retention deletes only expired CLOSED prefixes.
//! Exhaustion preserves unexpired evidence and denies admission rather than overwriting it.
use crate::{StateJournal, StateJournalConfig};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::{collections::VecDeque, fs::File, io, path::PathBuf};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuditJournalConfig {
	pub directory: PathBuf,
	#[serde(default = "segment_bytes")]
	pub max_segment_bytes: u64,
	#[serde(default = "segments")]
	pub max_segments: usize,
	#[serde(default = "retention")]
	pub retention_seconds: u64,
}
fn segment_bytes() -> u64 {
	16 * 1024 * 1024
}
fn segments() -> usize {
	8
}
fn retention() -> u64 {
	604800
}
impl AuditJournalConfig {
	pub fn validate(&self) -> Result<(), String> {
		if !self.directory.is_absolute()
			|| !(1_048_576..=67_108_864).contains(&self.max_segment_bytes)
			|| !(2..=32).contains(&self.max_segments)
			|| self
				.max_segment_bytes
				.saturating_mul(self.max_segments as u64)
				> 536_870_912
			|| !(1..=31_536_000).contains(&self.retention_seconds)
		{
			return Err("invalid audit directory/segment/retention limits".into());
		}
		Ok(())
	}
}
#[derive(Serialize, Deserialize)]
#[serde(tag = "kind", deny_unknown_fields)]
enum Control {
	Configuration {
		version: u32,
		config: AuditJournalConfig,
	},
	Head {
		start: u64,
	},
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Entry<T> {
	version: u32,
	sequence: u64,
	millis: i64,
	event: T,
}
struct Segment {
	start: u64,
	last_millis: i64,
	journal: StateJournal,
	path: PathBuf,
}
pub struct RotatingAuditJournal<T> {
	config: AuditJournalConfig,
	control: StateJournal,
	segments: VecDeque<Segment>,
	next_sequence: u64,
	highwater: i64,
	healthy: bool,
	marker: std::marker::PhantomData<T>,
}
impl<T: Serialize + DeserializeOwned> RotatingAuditJournal<T> {
	pub fn open(mut config: AuditJournalConfig, capacity: usize) -> io::Result<(Self, VecDeque<T>)> {
		config.validate().map_err(io::Error::other)?;
		// Persist and use the resolved private directory for both IO and retention deletion.
		// Later changes to a caller's symlink alias must never retarget cleanup.
		config.directory = config.directory.canonicalize()?;
		if capacity == 0 || capacity > 10000 {
			return Err(io::Error::other("audit projection capacity out of range"));
		}
		let spec = StateJournalConfig {
			path: config.directory.join("writer.jsonl"),
			max_bytes: 67_108_864,
		};
		let mut configured = false;
		let mut head = 0;
		let mut control = StateJournal::open::<Control>(&spec, |record| {
			match record {
				Control::Configuration {
					version: 1,
					config: found,
				} if !configured && found == config => configured = true,
				Control::Head { start } if configured && start > head => head = start,
				_ => return Err(io::Error::other("invalid audit control journal")),
			}
			Ok(())
		})?;
		if control.is_fresh() {
			control.append(&Control::Configuration {
				version: 1,
				config: config.clone(),
			})?;
		}
		let mut paths = Vec::new();
		for item in std::fs::read_dir(&config.directory)? {
			let item = item?;
			let name = item.file_name();
			let name = name
				.to_str()
				.ok_or_else(|| io::Error::other("invalid audit filename"))?;
			if name == "writer.jsonl" {
				continue;
			}
			let number = name
				.strip_prefix("segment-")
				.and_then(|v| v.strip_suffix(".jsonl"))
				.filter(|v| v.len() == 20)
				.and_then(|v| v.parse::<u64>().ok())
				.filter(|v| *v > 0)
				.ok_or_else(|| io::Error::other("unknown file in dedicated audit directory"))?;
			paths.push((number, item.path()));
			if paths.len() > config.max_segments {
				return Err(io::Error::other("audit segment capacity exceeded"));
			}
		}
		paths.sort_by_key(|v| v.0);
		if paths.last().map_or(0, |v| v.0) != head {
			return Err(io::Error::other(
				"audit head missing or interrupted rotation",
			));
		}
		let now = chrono::Utc::now().timestamp_millis();
		let cutoff = now.saturating_sub(config.retention_seconds as i64 * 1000);
		let mut output = VecDeque::new();
		let mut journals = VecDeque::new();
		let mut previous = None;
		let mut highwater = 0;
		for (start, path) in paths {
			let mut first = true;
			let mut last_millis = 0;
			let journal = StateJournal::open::<Entry<T>>(
				&StateJournalConfig {
					path: path.clone(),
					max_bytes: config.max_segment_bytes,
				},
				|entry| {
					if entry.version != 1
						|| entry.millis < highwater
						|| entry.millis > now
						|| first && entry.sequence != start
						|| previous.is_some_and(|p: u64| p.checked_add(1) != Some(entry.sequence))
						|| StateJournal::encoded_len(&entry, 16383).is_err()
					{
						return Err(io::Error::other("invalid audit sequence/clock/record"));
					}
					first = false;
					previous = Some(entry.sequence);
					highwater = entry.millis;
					last_millis = entry.millis;
					if entry.millis >= cutoff {
						if output.len() == capacity {
							output.pop_front();
						}
						output.push_back(entry.event);
					}
					Ok(())
				},
			)?;
			if first {
				return Err(io::Error::other("empty audit segment"));
			}
			journals.push_back(Segment {
				start,
				last_millis,
				journal,
				path,
			});
		}
		let next_sequence = previous
			.unwrap_or(0)
			.checked_add(1)
			.ok_or_else(|| io::Error::other("audit sequence exhausted"))?;
		let mut journal = Self {
			config,
			control,
			segments: journals,
			next_sequence,
			highwater,
			healthy: true,
			marker: Default::default(),
		};
		journal.prune(now)?;
		Ok((journal, output))
	}
	fn check(&mut self) -> io::Result<i64> {
		let now = chrono::Utc::now().timestamp_millis();
		let valid =
			self.control.check().is_ok() && self.segments.iter_mut().all(|s| s.journal.check().is_ok());
		if !self.healthy || !valid || now < self.highwater {
			self.healthy = false;
			return Err(io::Error::other("audit journal unavailable"));
		}
		Ok(now)
	}
	fn prune(&mut self, now: i64) -> io::Result<()> {
		let cutoff = now.saturating_sub(self.config.retention_seconds as i64 * 1000);
		while self.segments.len() > 1
			&& self
				.segments
				.front()
				.is_some_and(|s| s.last_millis < cutoff)
		{
			let old = self.segments.pop_front().expect("checked");
			let path = old.path.clone();
			drop(old);
			if std::fs::remove_file(&path)
				.and_then(|_| File::open(&self.config.directory)?.sync_all())
				.is_err()
			{
				self.healthy = false;
				return Err(io::Error::other("audit retention cleanup failed"));
			}
		}
		Ok(())
	}
	pub fn append(&mut self, event: &T) -> io::Result<()> {
		let result = self.append_inner(event);
		if result.is_err() {
			self.healthy = false;
		}
		result
	}
	fn append_inner(&mut self, event: &T) -> io::Result<()> {
		let millis = self.check()?;
		self.prune(millis)?;
		let sequence = self.next_sequence;
		let entry = Entry {
			version: 1,
			sequence,
			millis,
			event,
		};
		let bytes = StateJournal::encoded_len(&entry, 16383)? as u64;
		if self
			.segments
			.back()
			.is_none_or(|s| s.journal.remaining_bytes() < bytes)
		{
			if self.segments.len() >= self.config.max_segments {
				return Err(io::Error::other(
					"audit capacity exhausted; unexpired evidence retained",
				));
			}
			let path = self
				.config
				.directory
				.join(format!("segment-{sequence:020}.jsonl"));
			if std::fs::symlink_metadata(&path).is_ok() {
				return Err(io::Error::other("audit segment already exists"));
			}
			let mut journal = StateJournal::open::<Entry<T>>(
				&StateJournalConfig {
					path: path.clone(),
					max_bytes: self.config.max_segment_bytes,
				},
				|_| Err(io::Error::other("unexpected audit record")),
			)?;
			journal.append(&entry)?;
			self.control.append(&Control::Head { start: sequence })?;
			self.segments.push_back(Segment {
				start: sequence,
				last_millis: millis,
				journal,
				path,
			});
		} else {
			let last = self.segments.back_mut().expect("exists");
			last.journal.append(&entry)?;
			last.last_millis = millis;
		}
		self.next_sequence = sequence
			.checked_add(1)
			.ok_or_else(|| io::Error::other("audit sequence exhausted"))?;
		self.highwater = millis;
		self.prune(millis)
	}
	pub fn history(&mut self, before: Option<u64>, limit: usize) -> io::Result<VecDeque<T>> {
		if !(1..=1000).contains(&limit) {
			return Err(io::Error::other("history limit out of range"));
		}
		let now = self.check()?;
		self.prune(now)?;
		let cutoff = now.saturating_sub(self.config.retention_seconds as i64 * 1000);
		let mut result = VecDeque::new();
		for segment in self.segments.iter_mut().rev() {
			if before.is_some_and(|id| segment.start >= id) {
				continue;
			}
			let remaining = limit - result.len();
			let mut page = VecDeque::new();
			let mut expected = segment.start;
			segment.journal.visit::<Entry<T>>(|entry| {
				if entry.sequence != expected || entry.version != 1 || entry.millis > now {
					return Err(io::Error::other("audit history sequence/clock mismatch"));
				}
				expected = expected
					.checked_add(1)
					.ok_or_else(|| io::Error::other("audit sequence exhausted"))?;
				if entry.millis >= cutoff && before.is_none_or(|id| entry.sequence < id) {
					if page.len() == remaining {
						page.pop_front();
					}
					page.push_back(entry.event);
				}
				Ok(())
			})?;
			for event in page.into_iter().rev() {
				result.push_front(event);
			}
			if result.len() == limit {
				break;
			}
		}
		Ok(result)
	}
	pub fn next_sequence(&self) -> u64 {
		self.next_sequence
	}
}
