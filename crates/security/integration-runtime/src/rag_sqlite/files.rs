//! Private local SQLite files. Never chmod, repair or replace existing state.
use std::{
	fs::{File, Metadata, OpenOptions},
	path::{Path, PathBuf},
};

pub(super) struct Files {
	pub path: PathBuf,
	pub fresh: bool,
	identity: Metadata,
	owner_path: PathBuf,
	owner: File,
}
impl Files {
	pub fn open(path: &Path) -> Result<Self, String> {
		let parent = path
			.parent()
			.ok_or("missing SQLite directory")?
			.canonicalize()
			.map_err(|_| "SQLite directory unavailable")?;
		#[cfg(unix)]
		{
			use std::os::unix::fs::MetadataExt;
			if std::fs::metadata(&parent)
				.map_err(|_| "SQLite directory unavailable")?
				.mode()
				& 0o077
				!= 0
			{
				return Err("SQLite directory must be private".into());
			}
		}
		let path = parent.join(path.file_name().ok_or("missing SQLite file name")?);
		let owner_path = sidecar(&path, ".owner");
		let (owner, _) = protected_file(&owner_path)?;
		owner.try_lock().map_err(|_| "SQLite file already owned")?;
		let (file, fresh) = protected_file(&path)?;
		let identity = file.metadata().map_err(|_| "SQLite file unavailable")?;
		// Do not retain a separate descriptor on the database. Closing such a descriptor can
		// release SQLite's process-scoped POSIX locks while its worker is still finishing I/O.
		drop(file);
		let files = Self {
			path,
			fresh,
			identity,
			owner_path,
			owner,
		};
		files.check()?;
		Ok(files)
	}
	pub fn check(&self) -> Result<(), String> {
		let current = private_file(&self.path)?;
		let owner = private_file(&self.owner_path)?;
		let original_owner = self
			.owner
			.metadata()
			.map_err(|_| "SQLite owner unavailable")?;
		#[cfg(unix)]
		{
			use std::os::unix::fs::MetadataExt;
			if (self.identity.dev(), self.identity.ino()) != (current.dev(), current.ino())
				|| (original_owner.dev(), original_owner.ino()) != (owner.dev(), owner.ino())
			{
				return Err("SQLite file/owner replaced".into());
			}
		}
		#[cfg(not(unix))]
		let _ = (owner, original_owner);
		if current.len() < self.identity.len() {
			return Err("SQLite database truncated".into());
		}
		for suffix in ["-wal", "-shm", "-journal"] {
			let path = self.sidecar(suffix);
			match std::fs::symlink_metadata(&path) {
				Ok(_) => {
					private_file(&path)?;
				},
				Err(e) if e.kind() == std::io::ErrorKind::NotFound => {},
				Err(_) => return Err("SQLite sidecar unavailable".into()),
			}
		}
		Ok(())
	}
	pub fn sidecar(&self, suffix: &str) -> PathBuf {
		sidecar(&self.path, suffix)
	}
	pub fn seal(mut self) -> Result<Self, String> {
		self.check()?;
		if self.fresh {
			File::open(self.path.parent().ok_or("missing SQLite directory")?)
				.and_then(|f| f.sync_all())
				.map_err(|_| "cannot sync SQLite directory")?;
		}
		self.identity = private_file(&self.path)?;
		if self.identity.len() == 0 {
			return Err("SQLite initialization left an empty database".into());
		}
		Ok(self)
	}
}
fn sidecar(path: &Path, suffix: &str) -> PathBuf {
	let mut path = path.as_os_str().to_os_string();
	path.push(suffix);
	PathBuf::from(path)
}
fn protected_file(path: &Path) -> Result<(File, bool), String> {
	let mut options = OpenOptions::new();
	options.read(true).write(true).create_new(true);
	#[cfg(unix)]
	{
		use std::os::unix::fs::OpenOptionsExt;
		options.mode(0o600);
	}
	match options.open(path) {
		Ok(file) => Ok((file, true)),
		Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
			private_file(path)?;
			Ok((
				OpenOptions::new()
					.read(true)
					.write(true)
					.open(path)
					.map_err(|_| "SQLite file unavailable")?,
				false,
			))
		},
		Err(_) => Err("cannot create SQLite file".into()),
	}
}
fn private_file(path: &Path) -> Result<Metadata, String> {
	let meta = std::fs::symlink_metadata(path).map_err(|_| "SQLite file unavailable")?;
	if !meta.is_file() {
		return Err("SQLite files must be regular, not symlinks".into());
	}
	#[cfg(unix)]
	{
		use std::os::unix::fs::MetadataExt;
		if meta.mode() & 0o077 != 0 || meta.nlink() != 1 {
			return Err("SQLite files must be private with one hard link".into());
		}
	}
	Ok(meta)
}
