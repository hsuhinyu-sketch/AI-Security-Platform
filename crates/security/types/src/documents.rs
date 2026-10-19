//! Trusted document references; these values are not credentials.
use serde::{Deserialize, Serialize};
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DocumentKey {
	pub tenant_id: String,
	pub corpus_id: String,
	pub document_id: String,
}
impl DocumentKey {
	pub fn validate(&self) -> Result<(), String> {
		if [&self.tenant_id, &self.corpus_id, &self.document_id]
			.iter()
			.any(|v| v.is_empty() || v.trim() != v.as_str() || v.len() > 256)
		{
			return Err("invalid document key".into());
		}
		Ok(())
	}
}
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DocumentVersion {
	pub authority: String,
	pub key: DocumentKey,
	pub revision: u64,
}
pub trait DocumentVersionValidator: Send + Sync {
	fn authority_id(&self) -> Option<&str> {
		None
	}
	fn validate_documents(
		&self,
		subject: &super::Subject,
		documents: &[DocumentVersion],
	) -> Result<(), String>;
}
