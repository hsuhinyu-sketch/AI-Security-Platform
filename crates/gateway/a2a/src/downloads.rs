//! Strict remote-file descriptor parsing. Download execution and egress checks are Host-owned.
use crate::{Error as ObjectError, objects::object};
use serde_json::Value;
pub struct FileReference {
	pub url: url::Url,
	pub sha256: [u8; 32],
	pub size: usize,
}
impl FileReference {
	pub fn parse(part: &Value) -> Result<Self, ObjectError> {
		let uri = part["file"]["uri"]
			.as_str()
			.filter(|s| s.len() <= 2048)
			.ok_or(ObjectError::DownloadSource)?;
		let url = url::Url::parse(uri).map_err(|_| ObjectError::DownloadSource)?;
		if url.as_str() != uri
			|| url.scheme() != "https"
			|| !url.username().is_empty()
			|| url.password().is_some()
			|| url.query().is_some()
			|| url.fragment().is_some()
		{
			return Err(ObjectError::DownloadSource);
		}
		let manifest = &part["metadata"]["aispDownload"];
		object(manifest, &["sha256", "sizeBytes"])?;
		let hash = manifest["sha256"]
			.as_str()
			.filter(|s| {
				s.len() == 64
					&& s
						.bytes()
						.all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
			})
			.ok_or(ObjectError::DownloadIntegrity)?;
		let mut sha256 = [0; 32];
		for (i, byte) in sha256.iter_mut().enumerate() {
			*byte = u8::from_str_radix(&hash[i * 2..i * 2 + 2], 16)
				.map_err(|_| ObjectError::DownloadIntegrity)?;
		}
		let size = manifest["sizeBytes"]
			.as_u64()
			.and_then(|n| usize::try_from(n).ok())
			.ok_or(ObjectError::DownloadIntegrity)?;
		Ok(Self { url, sha256, size })
	}
}
