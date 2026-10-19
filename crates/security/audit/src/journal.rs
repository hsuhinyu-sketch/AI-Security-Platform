//! Single-writer append-only journal. Callers own retention and event redaction.
use std::collections::VecDeque;
use std::fs::{File, OpenOptions};
use std::io::{self, BufRead, BufReader, Write};
use std::path::Path;

use serde::{Serialize, de::DeserializeOwned};

pub struct JsonlJournal {
	file: File,
}

impl JsonlJournal {
	/// Locks the file for this writer's lifetime. Refuses corrupt or truncated records;
	/// never silently repairs or discards audit evidence. Keeps only the latest `capacity`
	/// records in memory while validating the entire journal.
	pub fn open<T: DeserializeOwned>(
		path: &Path,
		capacity: usize,
	) -> io::Result<(Self, VecDeque<T>)> {
		let mut options = OpenOptions::new();
		options.create(true).read(true).append(true);
		#[cfg(unix)]
		{
			use std::os::unix::fs::OpenOptionsExt;
			options.mode(0o600);
		}
		let file = options.open(path)?;
		file.try_lock().map_err(io::Error::other)?;
		let mut retained = VecDeque::new();
		let mut reader = BufReader::new(&file);
		let mut line = String::new();
		loop {
			line.clear();
			if reader.read_line(&mut line)? == 0 {
				break;
			}
			if !line.ends_with('\n') {
				return Err(io::Error::new(
					io::ErrorKind::InvalidData,
					"truncated audit record",
				));
			}
			let event = serde_json::from_str(&line).map_err(io::Error::other)?;
			if retained.len() == capacity.max(1) {
				retained.pop_front();
			}
			retained.push_back(event);
		}
		Ok((Self { file }, retained))
	}

	/// Success means the complete record was written and sync_data succeeded.
	pub fn append<T: Serialize>(&mut self, event: &T) -> io::Result<()> {
		let mut bytes = serde_json::to_vec(event).map_err(io::Error::other)?;
		bytes.push(b'\n');
		self.file.write_all(&bytes)?;
		self.file.sync_data()
	}
}
