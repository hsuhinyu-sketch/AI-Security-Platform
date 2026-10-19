//! Bounded, private single-writer journal for security state (not a credential or MAC).
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::{
	fs::{File, OpenOptions},
	io::{self, BufRead, BufReader, Read, Write},
	path::PathBuf,
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StateJournalConfig {
	pub path: PathBuf,
	#[serde(default = "default_max_bytes")]
	pub max_bytes: u64,
}
fn default_max_bytes() -> u64 {
	67_108_864
}
impl StateJournalConfig {
	pub fn validate(&self) -> Result<(), String> {
		if !self.path.is_absolute()
			|| self.path.file_name().is_none()
			|| !(1_048_576..=67_108_864).contains(&self.max_bytes)
		{
			return Err(
				"state journal requires an absolute file path and maxBytes in 1048576..=67108864".into(),
			);
		}
		Ok(())
	}
	pub fn canonical_path(&self) -> io::Result<PathBuf> {
		self.validate().map_err(io::Error::other)?;
		let parent = self
			.path
			.parent()
			.ok_or_else(|| io::Error::other("missing journal parent"))?
			.canonicalize()?;
		#[cfg(unix)]
		{
			use std::os::unix::fs::MetadataExt;
			if std::fs::metadata(&parent)?.mode() & 0o077 != 0 {
				return Err(io::Error::other("state directory must be private"));
			}
		}
		Ok(
			parent.join(
				self
					.path
					.file_name()
					.ok_or_else(|| io::Error::other("missing journal name"))?,
			),
		)
	}
}

pub struct StateJournal {
	file: File,
	path: PathBuf,
	max_bytes: u64,
	length: u64,
	healthy: bool,
	fresh: bool,
}
impl StateJournal {
	pub fn remaining_bytes(&self) -> u64 {
		self.max_bytes.saturating_sub(self.length)
	}
	pub fn encoded_len<T: Serialize>(value: &T, max: usize) -> io::Result<usize> {
		struct Counter {
			len: usize,
			max: usize,
		}
		impl Write for Counter {
			fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
				if self.len.saturating_add(bytes.len()) > self.max {
					return Err(io::Error::other("serialized record exceeds budget"));
				}
				self.len += bytes.len();
				Ok(bytes.len())
			}
			fn flush(&mut self) -> io::Result<()> {
				Ok(())
			}
		}
		let mut counter = Counter { len: 0, max };
		serde_json::to_writer(&mut counter, value).map_err(io::Error::other)?;
		Ok(counter.len + 1)
	}
	/// Read under the caller's owning journal lock. O_APPEND keeps subsequent writes at EOF.
	pub fn visit<T: DeserializeOwned>(
		&mut self,
		visitor: impl FnMut(T) -> io::Result<()>,
	) -> io::Result<()> {
		let result = self.visit_inner(visitor);
		if result.is_err() {
			self.healthy = false;
		}
		result
	}
	fn visit_inner<T: DeserializeOwned>(
		&mut self,
		mut visitor: impl FnMut(T) -> io::Result<()>,
	) -> io::Result<()> {
		self.check()?;
		let mut reader = BufReader::new(File::open(&self.path)?);
		loop {
			let mut line = Vec::new();
			let n = reader
				.by_ref()
				.take((Self::MAX_RECORD + 1) as u64)
				.read_until(b'\n', &mut line)?;
			if n == 0 {
				break;
			}
			if n > Self::MAX_RECORD || line.last() != Some(&b'\n') {
				return Err(io::Error::other("invalid journal record"));
			}
			visitor(serde_json::from_slice(&line).map_err(io::Error::other)?)?;
		}
		self.check()
	}
	pub const MAX_RECORD: usize = 1_048_576;
	/// Calls replay for every complete record while holding the writer lock. Never repairs.
	pub fn open<T: DeserializeOwned>(
		config: &StateJournalConfig,
		mut replay: impl FnMut(T) -> io::Result<()>,
	) -> io::Result<Self> {
		let path = config.canonical_path()?;
		let mut options = OpenOptions::new();
		options.create_new(true).read(true).append(true);
		#[cfg(unix)]
		{
			use std::os::unix::fs::OpenOptionsExt;
			options.mode(0o600);
		}
		let (file, fresh) = match options.open(&path) {
			Ok(file) => (file, true),
			Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
				if !std::fs::symlink_metadata(&path)?.file_type().is_file() {
					return Err(io::Error::other(
						"state journal must be a regular non-symlink file",
					));
				}
				(
					OpenOptions::new().read(true).append(true).open(&path)?,
					false,
				)
			},
			Err(error) => return Err(error),
		};
		file.try_lock().map_err(io::Error::other)?;
		let length = file.metadata()?.len();
		let mut journal = Self {
			file,
			path,
			max_bytes: config.max_bytes,
			length,
			healthy: true,
			fresh,
		};
		journal.check()?;
		if length > config.max_bytes || (!fresh && length == 0) {
			return Err(io::Error::other("state journal empty or exceeds capacity"));
		}
		{
			let mut reader = BufReader::new(&journal.file);
			loop {
				let mut line = Vec::new();
				let count = reader
					.by_ref()
					.take((Self::MAX_RECORD + 1) as u64)
					.read_until(b'\n', &mut line)?;
				if count == 0 {
					break;
				}
				if count > Self::MAX_RECORD || line.last() != Some(&b'\n') {
					return Err(io::Error::other("truncated or oversized state record"));
				}
				replay(serde_json::from_slice(&line).map_err(io::Error::other)?)?;
			}
		}
		Ok(journal)
	}
	pub fn is_fresh(&self) -> bool {
		self.fresh
	}
	/// Detect replacement, truncation, foreign appends and permissions changes. Quarantine forever.
	pub fn check(&mut self) -> io::Result<()> {
		let valid = (|| -> io::Result<bool> {
			let open = self.file.metadata()?;
			let current = std::fs::symlink_metadata(&self.path)?;
			if !current.file_type().is_file() || open.len() != self.length || current.len() != self.length
			{
				return Ok(false);
			}
			#[cfg(unix)]
			{
				use std::os::unix::fs::MetadataExt;
				Ok(
					open.dev() == current.dev()
						&& open.ino() == current.ino()
						&& current.mode() & 0o077 == 0
						&& current.nlink() == 1,
				)
			}
			#[cfg(not(unix))]
			{
				Ok(true)
			}
		})()
		.unwrap_or(false);
		if !self.healthy || !valid {
			self.healthy = false;
			return Err(io::Error::other("state journal quarantined"));
		}
		Ok(())
	}
	pub fn append<T: Serialize>(&mut self, event: &T) -> io::Result<()> {
		self.check()?;
		// Enforce the byte budget DURING serialization, not after allocating an arbitrary Vec.
		struct BoundedBuffer(Vec<u8>);
		impl Write for BoundedBuffer {
			fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
				if self.0.len().saturating_add(bytes.len()) >= StateJournal::MAX_RECORD {
					return Err(io::Error::other("state record exceeds byte budget"));
				}
				self.0.extend_from_slice(bytes);
				Ok(bytes.len())
			}
			fn flush(&mut self) -> io::Result<()> {
				Ok(())
			}
		}
		let mut buffer = BoundedBuffer(Vec::new());
		if let Err(error) = serde_json::to_writer(&mut buffer, event) {
			self.healthy = false;
			return Err(io::Error::other(error));
		}
		let mut bytes = buffer.0;
		bytes.push(b'\n');
		if bytes.len() > Self::MAX_RECORD
			|| self.length.saturating_add(bytes.len() as u64) > self.max_bytes
		{
			self.healthy = false;
			return Err(io::Error::other("state journal capacity exhausted"));
		}
		let result = (|| {
			self.file.write_all(&bytes)?;
			self.file.sync_data()?;
			if self.fresh {
				File::open(self.path.parent().expect("validated"))?.sync_all()?;
			}
			Ok(())
		})();
		if result.is_err() {
			self.healthy = false;
			return result;
		}
		self.length += bytes.len() as u64;
		self.fresh = false;
		self.check()
	}
}
