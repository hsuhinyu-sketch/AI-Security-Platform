use std::fmt;
use std::future::Future;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use quick_cache::sync::{Cache, EntryAction, EntryResult};
use secrecy::{ExposeSecret, SecretString};
use sha2::{Digest, Sha256};

use super::transport::TokenEndpointResponse;
use super::{ExchangeRequest, decode_unverified_jwt_claims};

pub(super) const DEFAULT_CACHE_CAPACITY: usize = 8192;
pub(super) const DEFAULT_CACHE_TTL: Duration = Duration::from_secs(300);

// Avoid caching tokens near expiry
const CACHE_SAFETY_MARGIN: Duration = Duration::from_secs(15);

#[derive(Clone)]
pub(super) struct InMemoryTokenCache {
	entries: Arc<Cache<TokenCacheKey, CachedToken>>,
	default_ttl: Duration,
}

impl InMemoryTokenCache {
	pub(super) fn new(max_entries: usize, default_ttl: Duration) -> Self {
		Self {
			entries: Arc::new(Cache::new(max_entries)),
			default_ttl,
		}
	}

	pub(super) async fn get_or_insert_with<F, Fut, E>(
		&self,
		req: &ExchangeRequest,
		fetch: F,
	) -> Result<TokenCacheResult, E>
	where
		F: FnOnce() -> Fut,
		Fut: Future<Output = Result<TokenEndpointResponse, E>>,
	{
		let now = SystemTime::now();
		let cache_key = TokenCacheKey::from(req);
		let guard = match self
			.entries
			.entry_async(&cache_key, |_key, cached| {
				if is_fresh(cached.expires_at, now) {
					EntryAction::Retain(cached.access_token.clone())
				} else {
					EntryAction::ReplaceWithGuard
				}
			})
			.await
		{
			EntryResult::Retained(access_token) => return Ok(TokenCacheResult::Hit(access_token)),
			EntryResult::Vacant(guard) | EntryResult::Replaced(guard, _) => guard,
			EntryResult::Removed(_, _) | EntryResult::Timeout => unreachable!(),
		};

		let subject_token = req.subject_token.expose_secret();

		let TokenEndpointResponse {
			access_token,
			expires_in,
		} = fetch().await?;

		if let Some(expires_at) = cache_expiry(expires_in, subject_token, self.default_ttl) {
			let _ = guard.insert(CachedToken {
				access_token: access_token.clone(),
				expires_at,
			});
		}
		Ok(TokenCacheResult::Miss(access_token))
	}
}

impl Default for InMemoryTokenCache {
	fn default() -> Self {
		Self::new(DEFAULT_CACHE_CAPACITY, DEFAULT_CACHE_TTL)
	}
}

impl fmt::Debug for InMemoryTokenCache {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.write_str("InMemoryTokenCache")
	}
}

/// SHA-256 digest of the per-request exchange inputs. Keyed by digest so the raw
/// bearer credential is never retained as a cache key.
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
struct TokenCacheKey([u8; 32]);

impl From<&ExchangeRequest> for TokenCacheKey {
	fn from(req: &ExchangeRequest) -> Self {
		let mut digest = CacheKeyDigest::new();
		digest.field(req.subject_token.expose_secret().as_bytes());
		digest.field(req.subject_token_type.as_str().as_bytes());

		match &req.actor {
			Some((token, token_type)) => {
				digest.field([1]);
				digest.field(token.expose_secret().as_bytes());
				digest.field(token_type.as_str().as_bytes());
			},
			None => digest.field([0]),
		}

		// Expects sorted keys to ensure a stable digest.
		for (key, value) in &req.extra_params {
			digest.field(key.as_bytes());
			digest.field(value.as_bytes());
		}

		digest.finish()
	}
}

struct CacheKeyDigest(Sha256);

impl CacheKeyDigest {
	fn new() -> Self {
		Self(Sha256::new())
	}

	fn field(&mut self, bytes: impl AsRef<[u8]>) {
		let bytes = bytes.as_ref();
		self.0.update((bytes.len() as u64).to_le_bytes());
		self.0.update(bytes);
	}

	fn finish(self) -> TokenCacheKey {
		TokenCacheKey(self.0.finalize().into())
	}
}

#[derive(Clone)]
struct CachedToken {
	access_token: SecretString,
	expires_at: SystemTime,
}

pub enum TokenCacheResult {
	Hit(SecretString),
	Miss(SecretString),
}

impl TokenCacheResult {
	pub fn into_token(self) -> SecretString {
		match self {
			Self::Hit(token) | Self::Miss(token) => token,
		}
	}
}

// Best-effort `exp` from a JWT-shaped subject token; opaque tokens yield None.
// Decoded without signature or expiry validation — we only need the raw `exp`.
fn subject_token_exp(token: &str) -> Option<SystemTime> {
	#[derive(serde::Deserialize)]
	struct ExpClaim {
		exp: Option<u64>,
	}
	let claims = decode_unverified_jwt_claims::<ExpClaim>(token)?;
	UNIX_EPOCH.checked_add(Duration::from_secs(claims.exp?))
}

fn cache_expiry(
	expires_in: Option<u64>,
	subject_token: &str,
	default_ttl: Duration,
) -> Option<SystemTime> {
	let now = SystemTime::now();
	let mut expires_at = now.checked_add(expires_in.map_or(default_ttl, Duration::from_secs))?;
	if let Some(subject_exp) = subject_token_exp(subject_token) {
		expires_at = expires_at.min(subject_exp);
	}
	is_fresh(expires_at, now).then_some(expires_at)
}

fn is_fresh(expires_at: SystemTime, now: SystemTime) -> bool {
	expires_at
		.duration_since(now)
		.is_ok_and(|remaining| remaining > CACHE_SAFETY_MARGIN)
}
