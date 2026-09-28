//! Domain-separated, versioned integrity proofs over deterministic JSON values.
//!
//! This proves that a holder of the configured symmetric key created the metadata. It does not
//! independently authenticate a document publisher or prove that an untrusted URI was fetched.

use hmac::{Hmac, KeyInit, Mac};
use serde::{Deserialize, Serialize};
use sha2::Digest;
use sha2::Sha256;

const PROTOCOL_VERSION: u8 = 1;
type HmacSha256 = Hmac<Sha256>;

pub fn sha256_hex(bytes: &[u8]) -> String {
	hex::encode(Sha256::digest(bytes))
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct IntegrityProof {
	pub version: u8,
	pub key_id: String,
	pub tag_hex: String,
}

/// The secret is intentionally excluded from Debug and Serialize. Deployments should load it
/// from a secret provider; the PoC adapter accepts a hex value from a named environment variable.
pub struct IntegrityKey {
	key_id: String,
	secret: Vec<u8>,
}

impl IntegrityKey {
	pub fn from_hex(key_id: impl Into<String>, hex_secret: &str) -> Result<Self, String> {
		let key_id = key_id.into();
		let secret =
			hex::decode(hex_secret).map_err(|_| "integrity key must be hex encoded".to_string())?;
		if key_id.is_empty() || key_id.len() > 128 || secret.len() < 32 {
			return Err("integrity key requires a nonempty key ID and at least 32 secret bytes".into());
		}
		Ok(Self { key_id, secret })
	}

	pub fn sign_json(
		&self,
		purpose: &str,
		value: &serde_json::Value,
	) -> Result<IntegrityProof, String> {
		let mac = self.mac(purpose, value)?;
		Ok(IntegrityProof {
			version: PROTOCOL_VERSION,
			key_id: self.key_id.clone(),
			tag_hex: hex::encode(mac.finalize().into_bytes()),
		})
	}

	pub fn verify_json(
		&self,
		purpose: &str,
		value: &serde_json::Value,
		proof: &IntegrityProof,
	) -> Result<(), String> {
		if proof.version != PROTOCOL_VERSION || proof.key_id != self.key_id {
			return Err("integrity proof version or key ID mismatch".into());
		}
		let tag =
			hex::decode(&proof.tag_hex).map_err(|_| "invalid integrity proof encoding".to_string())?;
		self
			.mac(purpose, value)?
			.verify_slice(&tag)
			.map_err(|_| "integrity proof mismatch".to_string())
	}

	fn mac(&self, purpose: &str, value: &serde_json::Value) -> Result<HmacSha256, String> {
		if purpose.is_empty() || purpose.len() > 128 {
			return Err("integrity purpose must be between 1 and 128 bytes".into());
		}
		let payload = serde_json::to_vec(value)
			.map_err(|error| format!("unable to encode integrity payload: {error}"))?;
		let mut mac = <HmacSha256 as KeyInit>::new_from_slice(&self.secret)
			.map_err(|_| "invalid integrity key".to_string())?;
		mac.update(b"AISP-integrity-v1\0");
		mac.update(&(self.key_id.len() as u64).to_be_bytes());
		mac.update(self.key_id.as_bytes());
		mac.update(&(purpose.len() as u64).to_be_bytes());
		mac.update(purpose.as_bytes());
		mac.update(&(payload.len() as u64).to_be_bytes());
		mac.update(&payload);
		Ok(mac)
	}
}

impl Drop for IntegrityKey {
	fn drop(&mut self) {
		self.secret.fill(0);
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn rejects_tampering_wrong_purpose_and_key() {
		let key = IntegrityKey::from_hex("key-1", &"ab".repeat(32)).unwrap();
		let payload = serde_json::json!({"tenant":"a","classification":"restricted"});
		let proof = key.sign_json("rag-chunk", &payload).unwrap();
		assert!(key.verify_json("rag-chunk", &payload, &proof).is_ok());
		assert!(key.verify_json("model-context", &payload, &proof).is_err());
		assert!(
			key
				.verify_json(
					"rag-chunk",
					&serde_json::json!({"tenant":"b","classification":"restricted"}),
					&proof
				)
				.is_err()
		);
		let other = IntegrityKey::from_hex("key-2", &"ab".repeat(32)).unwrap();
		assert!(other.verify_json("rag-chunk", &payload, &proof).is_err());
	}
}
