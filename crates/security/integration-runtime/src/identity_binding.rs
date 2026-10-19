//! Protocol-neutral owner binding; callers must supply an already verified identity and issuer.
use security_pipeline::GatewayIdentity;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IdentityBindingError;

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerifiedOwner {
	pub(crate) issuer: String,
	pub(crate) tenant: String,
	pub(crate) user: Option<String>,
	pub(crate) agent: Option<String>,
	pub(crate) client: Option<String>,
	pub(crate) delegation: Option<String>,
}

impl VerifiedOwner {
	/// Correlation data only: this does not create credentials or authenticate a request.
	pub fn identity(&self) -> GatewayIdentity {
		GatewayIdentity {
			user_id: self.user.clone(),
			agent_id: self.agent.clone(),
			tenant_id: Some(self.tenant.clone()),
			delegation_id: self.delegation.clone(),
			client_id: self.client.clone(),
			session_id: None,
		}
	}
	pub fn from_identity(
		identity: &GatewayIdentity,
		issuer: &str,
	) -> Result<Self, IdentityBindingError> {
		let valid = |value: &str| !value.is_empty() && value.trim() == value;
		if !valid(issuer) || issuer.len() > 2048 {
			return Err(IdentityBindingError);
		}
		let tenant = identity
			.tenant_id
			.as_ref()
			.filter(|v| valid(v))
			.ok_or(IdentityBindingError)?;
		if identity.user_id.is_none() && identity.agent_id.is_none() {
			return Err(IdentityBindingError);
		}
		for value in [
			&identity.user_id,
			&identity.agent_id,
			&identity.client_id,
			&identity.delegation_id,
		]
		.into_iter()
		.flatten()
		{
			if !valid(value) {
				return Err(IdentityBindingError);
			}
		}
		Ok(Self {
			issuer: issuer.into(),
			tenant: tenant.clone(),
			user: identity.user_id.clone(),
			agent: identity.agent_id.clone(),
			client: identity.client_id.clone(),
			delegation: identity.delegation_id.clone(),
		})
	}
}
