use std::cmp;
use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::fmt::{Display, Formatter};
use std::net::{IpAddr, SocketAddr};
use std::num::NonZeroU16;
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::anyhow;
use hashbrown::Equivalent;
use heck::ToSnakeCase;
use macro_rules_attribute::apply;
use once_cell::sync::Lazy;
use openapiv3::OpenAPI;
use prometheus_client::encoding::EncodeLabelValue;
use regex::Regex;
use rustls::ServerConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::danger::ClientCertVerifier;
use rustls_pki_types::pem::{PemObject, SectionKind};
use serde::{Serialize, Serializer};
use serde_json::Value;

use crate::control::caclient::CaClient;
use crate::http::auth::BackendAuth;
use crate::http::authorization::RuleSet;
use crate::http::{
	HeaderOrPseudo, HeaderValue, ext_authz, ext_proc, filters, health, remoteratelimit, retry,
	timeout,
};
use crate::mcp::{FailureMode, McpAuthorization};
use crate::store::RequestPolicy;
use crate::telemetry::log::OrderedStringMap;
use crate::transport::tls;
use crate::types::discovery::{NamespacedHostname, Service};
use crate::types::local::{InternalBackend, SimpleLocalBackend};
use crate::types::{agent, backend, frontend};
use crate::*;

#[apply(schema_ser_schema!)]
pub struct Bind {
	pub key: BindKey,
	pub address: SocketAddr,
	pub protocol: BindProtocol,
	pub tunnel_protocol: TunnelProtocol,
	/// Controls whether this bind opens an OS listener socket.
	/// `standard` (default) binds the `address`; `internal` does not bind a socket and is only
	/// reachable via in-process routing (e.g. CONNECT tunnel re-entry by other listeners).
	pub mode: BindMode,
	pub listeners: ListenerSet,
}

impl Bind {
	/// An internal bind with no concrete port (address port 0) acts as the wildcard fallback:
	/// it handles CONNECT re-entry for any destination port that no other bind matches by port.
	pub fn is_wildcard(&self) -> bool {
		self.mode == BindMode::Internal && self.address.port() == 0
	}
}

pub type BindKey = Strng;

#[apply(schema_ser_schema!)]
#[derive(Eq, PartialEq)]
pub struct Listener {
	pub key: ListenerKey,
	// User facing name
	#[serde(flatten)]
	pub name: ListenerName,

	/// Can be a wildcard
	pub hostname: Strng,
	pub protocol: ListenerProtocol,
}

impl Listener {
	pub fn matches(&self, hostname: &str) -> bool {
		self.hostname == hostname
			|| self.hostname.is_empty()
			|| (self.hostname.starts_with("*") && hostname.ends_with(&self.hostname[1..]))
	}
}

type Alpns = Vec<Vec<u8>>;

#[derive(Debug, Clone, Eq, PartialEq)]
struct ServerTlsInputs {
	cert_pem: Vec<u8>,
	key_pem: Vec<u8>,
	// If present, require and verify client certificates using these roots.
	root_pem: Option<Vec<u8>>,
	// If true, request client certs but allow absent or invalid certs as insecure fallback.
	allow_insecure_mtls: bool,
	// Default ALPNs configured at creation time.
	default_alpns: Alpns,
	// Default cipher suites configured at creation time.
	default_cipher_suites: Vec<crate::transport::tls::CipherSuite>,
	// Default key exchange groups configured at creation time.
	default_key_exchange_groups: Vec<crate::transport::tls::KeyExchangeGroup>,
	dynamic_ca_cert_cache: crate::DynamicCaCertCacheConfig,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct ServerTlsProfileKey {
	alpns: Alpns,
	min_version: Option<TLSVersion>,
	max_version: Option<TLSVersion>,
	// Order-sensitive: we intentionally preserve user-provided cipher suite ordering.
	cipher_suites: Vec<crate::transport::tls::CipherSuite>,
	key_exchange_groups: Vec<crate::transport::tls::KeyExchangeGroup>,
}

impl frontend::TLS {
	/// Fast path: no overrides
	fn is_fast_path(&self) -> bool {
		// empty list is the same as no overrides
		let no_cipher_suite_override = self
			.cipher_suites
			.as_deref()
			.is_none_or(|suites| suites.is_empty());

		self.alpn.is_none()
			&& self.min_version.is_none()
			&& self.max_version.is_none()
			&& self
				.key_exchange_groups
				.as_deref()
				.is_none_or(|groups| groups.is_empty())
			&& no_cipher_suite_override
	}

	fn server_tls_profile_key(&self, inputs: &ServerTlsInputs) -> ServerTlsProfileKey {
		let alpns = self
			.alpn
			.clone()
			.unwrap_or_else(|| inputs.default_alpns.clone());
		let min_version = self.min_version.map(Into::into);
		let max_version = self.max_version.map(Into::into);
		let cipher_suites = self
			.cipher_suites
			.clone()
			.filter(|suites| !suites.is_empty())
			.unwrap_or_else(|| inputs.default_cipher_suites.clone());
		let key_exchange_groups = self
			.key_exchange_groups
			.clone()
			.filter(|groups| !groups.is_empty())
			.unwrap_or_else(|| inputs.default_key_exchange_groups.clone());
		ServerTlsProfileKey {
			alpns,
			min_version,
			max_version,
			cipher_suites,
			key_exchange_groups,
		}
	}
}

#[derive(Debug, Clone)]
pub struct ServerTLSConfig {
	source: ServerTlsCertificateSource,
	/// Cached base config (built from `inputs` using defaults). Kept for fast path when no overrides
	/// are requested.
	base_config: Option<Arc<ServerConfig>>,
	/// Original inputs required to rebuild a fresh `ServerConfig` for a given profile.
	inputs: Option<Arc<ServerTlsInputs>>,
	/// Original strict verifier used when ALLOW_INSECURE_FALLBACK is enabled.
	insecure_fallback_verifier: Option<Arc<dyn ClientCertVerifier>>,
	per_profile_config: Arc<RwLock<HashMap<ServerTlsProfileKey, Arc<ServerConfig>>>>,
}

#[derive(Debug, Clone, Eq, PartialEq)]
enum ServerTlsCertificateSource {
	Static,
	DynamicCa,
	IstioWorkload { mtls: bool, default_alpns: Alpns },
}

impl Eq for ServerTLSConfig {}
impl PartialEq for ServerTLSConfig {
	fn eq(&self, other: &Self) -> bool {
		self.source == other.source && self.inputs == other.inputs
	}
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, EncodeLabelValue)]
#[allow(non_camel_case_types)]
pub enum TLSVersion {
	TLS_V1_0,
	TLS_V1_1,
	TLS_V1_2,
	TLS_V1_3,
}

impl ServerTLSConfig {
	pub fn new(config: Arc<ServerConfig>) -> Self {
		Self {
			source: ServerTlsCertificateSource::Static,
			base_config: Some(config),
			inputs: None,
			insecure_fallback_verifier: None,
			per_profile_config: Arc::new(Default::default()),
		}
	}

	pub fn from_pem(
		cert_pem: Vec<u8>,
		key_pem: Vec<u8>,
		root_pem: Option<Vec<u8>>,
		default_alpns: Alpns,
	) -> anyhow::Result<Self> {
		Self::from_pem_with_profile(
			cert_pem,
			key_pem,
			root_pem,
			default_alpns,
			None,
			None,
			None,
			None,
			false,
		)
	}

	#[allow(clippy::too_many_arguments)]
	pub fn from_pem_with_profile(
		cert_pem: Vec<u8>,
		key_pem: Vec<u8>,
		root_pem: Option<Vec<u8>>,
		default_alpns: Alpns,
		min_version: Option<TLSVersion>,
		max_version: Option<TLSVersion>,
		cipher_suites: Option<Vec<crate::transport::tls::CipherSuite>>,
		key_exchange_groups: Option<Vec<crate::transport::tls::KeyExchangeGroup>>,
		allow_insecure_mtls: bool,
	) -> anyhow::Result<Self> {
		let inputs = Arc::new(ServerTlsInputs {
			cert_pem,
			key_pem,
			root_pem,
			allow_insecure_mtls,
			default_alpns,
			default_cipher_suites: cipher_suites.clone().unwrap_or_default(),
			default_key_exchange_groups: key_exchange_groups.clone().unwrap_or_default(),
			dynamic_ca_cert_cache: Default::default(),
		});
		let suites = cipher_suites.as_deref().filter(|s| !s.is_empty());
		let groups = key_exchange_groups.as_deref().filter(|g| !g.is_empty());
		let (base, insecure_fallback_verifier) = Self::build_server_config(
			&inputs,
			None,
			min_version,
			max_version,
			suites.unwrap_or(&[]),
			groups.unwrap_or(&[]),
		)?;
		Ok(Self {
			source: ServerTlsCertificateSource::Static,
			base_config: Some(Arc::new(base)),
			inputs: Some(inputs),
			insecure_fallback_verifier,
			per_profile_config: Arc::new(Default::default()),
		})
	}

	#[allow(clippy::too_many_arguments)]
	pub(crate) fn dynamic_ca_with_profile(
		ca_cert_pem: Vec<u8>,
		ca_key_pem: Vec<u8>,
		default_alpns: Vec<Vec<u8>>,
		min_version: Option<TLSVersion>,
		max_version: Option<TLSVersion>,
		cipher_suites: Option<Vec<crate::transport::tls::CipherSuite>>,
		key_exchange_groups: Option<Vec<crate::transport::tls::KeyExchangeGroup>>,
		dynamic_ca_cert_cache: crate::DynamicCaCertCacheConfig,
	) -> anyhow::Result<Self> {
		let inputs = Arc::new(ServerTlsInputs {
			cert_pem: ca_cert_pem,
			key_pem: ca_key_pem,
			root_pem: None,
			allow_insecure_mtls: false,
			default_alpns,
			default_cipher_suites: cipher_suites.clone().unwrap_or_default(),
			default_key_exchange_groups: key_exchange_groups.clone().unwrap_or_default(),
			dynamic_ca_cert_cache,
		});
		let suites = cipher_suites.as_deref().filter(|s| !s.is_empty());
		let groups = key_exchange_groups.as_deref().filter(|g| !g.is_empty());
		let base = crate::types::dynamic_ca_cert::build_dynamic_ca_server_config(
			&inputs.cert_pem,
			&inputs.key_pem,
			None,
			&inputs.default_alpns,
			min_version,
			max_version,
			suites.unwrap_or(&[]),
			groups.unwrap_or(&[]),
			&inputs.dynamic_ca_cert_cache,
		)?;
		Ok(Self {
			source: ServerTlsCertificateSource::DynamicCa,
			base_config: Some(Arc::new(base)),
			inputs: Some(inputs),
			insecure_fallback_verifier: None,
			per_profile_config: Arc::new(Default::default()),
		})
	}

	/// new_invalid returns a ServerTLSConfig that always rejects connections
	pub fn new_invalid() -> Self {
		Self {
			source: ServerTlsCertificateSource::Static,
			base_config: None,
			inputs: None,
			insecure_fallback_verifier: None,
			per_profile_config: Arc::new(Default::default()),
		}
	}

	pub fn istio_workload(mtls: bool, default_alpns: Alpns) -> Self {
		Self {
			source: ServerTlsCertificateSource::IstioWorkload {
				mtls,
				default_alpns,
			},
			base_config: None,
			inputs: None,
			insecure_fallback_verifier: None,
			per_profile_config: Arc::new(Default::default()),
		}
	}

	/// config_for returns the appropriate config for the requested ALPN
	/// If none is return, it means the certificates were invalid.
	pub async fn config_for(
		&self,
		tls: Option<&frontend::TLS>,
		ca: Option<&Arc<CaClient>>,
	) -> anyhow::Result<Arc<ServerConfig>> {
		if let ServerTlsCertificateSource::IstioWorkload {
			mtls,
			default_alpns,
		} = &self.source
		{
			let ca = ca.ok_or_else(|| anyhow!("CA is required for Istio workload TLS"))?;
			let alpns = tls
				.and_then(|t| t.alpn.clone())
				.unwrap_or_else(|| default_alpns.clone());
			let cert = ca.get_identity().await?;
			return Ok(Arc::new(cert.server_config(alpns, *mtls)?));
		}

		let inputs = match self.inputs.as_ref() {
			Some(i) => Arc::clone(i),
			None => {
				return self
					.base_config
					.clone()
					.ok_or_else(|| anyhow!("TLS config invalid"));
			},
		};

		// Fast path: no overrides
		if tls.is_none_or(|t| t.is_fast_path())
			&& let Some(c) = self.base_config.clone()
		{
			return Ok(c);
		}

		let key = match tls {
			Some(tls) => tls.server_tls_profile_key(&inputs),
			None => ServerTlsProfileKey {
				alpns: inputs.default_alpns.clone(),
				min_version: None,
				max_version: None,
				cipher_suites: inputs.default_cipher_suites.clone(),
				key_exchange_groups: inputs.default_key_exchange_groups.clone(),
			},
		};

		{
			let reader = self.per_profile_config.read().unwrap();
			if let Some(cached_config) = reader.get(&key) {
				return Ok(Arc::clone(cached_config));
			}
		}
		let mut writer = self.per_profile_config.write().unwrap();
		if let Some(cached_config) = writer.get(&key) {
			return Ok(Arc::clone(cached_config));
		}

		let base = match self.source {
			ServerTlsCertificateSource::Static => {
				let (base, _insecure_fallback_verifier) = Self::build_server_config(
					&inputs,
					Some(&key.alpns),
					key.min_version,
					key.max_version,
					&key.cipher_suites,
					&key.key_exchange_groups,
				)?;
				base
			},
			ServerTlsCertificateSource::DynamicCa => {
				crate::types::dynamic_ca_cert::build_dynamic_ca_server_config(
					&inputs.cert_pem,
					&inputs.key_pem,
					Some(&key.alpns),
					&inputs.default_alpns,
					key.min_version,
					key.max_version,
					&key.cipher_suites,
					&key.key_exchange_groups,
					&inputs.dynamic_ca_cert_cache,
				)?
			},
			ServerTlsCertificateSource::IstioWorkload { .. } => unreachable!(),
		};
		let base = Arc::new(base);
		writer.insert(key.clone(), Arc::clone(&base));
		Ok(base)
	}

	pub fn allow_insecure_mtls(&self) -> bool {
		if matches!(
			self.source,
			ServerTlsCertificateSource::IstioWorkload { mtls: true, .. }
		) {
			return false;
		}
		self
			.inputs
			.as_ref()
			.is_some_and(|inputs| inputs.allow_insecure_mtls)
	}

	pub fn include_src_identity_for_connection(&self, conn: &rustls::ServerConnection) -> bool {
		if matches!(
			self.source,
			ServerTlsCertificateSource::IstioWorkload { mtls: true, .. }
		) {
			return true;
		}
		if !self.allow_insecure_mtls() {
			return true;
		}

		let Some(peer_certs) = conn.peer_certificates() else {
			return false;
		};
		let Some((end_entity, intermediates)) = peer_certs.split_first() else {
			return false;
		};

		let Some(verifier) = self.insecure_fallback_verifier.as_ref() else {
			return false;
		};

		let now = match SystemTime::now().duration_since(UNIX_EPOCH) {
			Ok(duration) => rustls::pki_types::UnixTime::since_unix_epoch(duration),
			Err(_) => return false,
		};

		verifier
			.verify_client_cert(end_entity, intermediates, now)
			.is_ok()
	}

	fn build_server_config(
		inputs: &ServerTlsInputs,
		alpns: Option<&[Vec<u8>]>,
		min_version: Option<TLSVersion>,
		max_version: Option<TLSVersion>,
		cipher_suites: &[crate::transport::tls::CipherSuite],
		key_exchange_groups: &[crate::transport::tls::KeyExchangeGroup],
	) -> anyhow::Result<(ServerConfig, Option<Arc<dyn ClientCertVerifier>>)> {
		let provider = crate::transport::tls::provider_with_options(cipher_suites, key_exchange_groups);

		let versions = tls_versions_for_range(min_version, max_version)?;
		let scb = ServerConfig::builder_with_provider(provider.clone())
			.with_protocol_versions(&versions)
			.expect("server config must be valid");

		let mut insecure_fallback_verifier = None;

		let scb = if let Some(root) = &inputs.root_pem {
			let mut roots_store = rustls::RootCertStore::empty();
			let certs = CertificateDer::pem_slice_iter(root).collect::<Result<Vec<_>, _>>()?;
			roots_store.add_parsable_certificates(certs);
			let verify = rustls::server::WebPkiClientVerifier::builder_with_provider(
				Arc::new(roots_store),
				provider,
			)
			.build()?;
			let verify: Arc<dyn ClientCertVerifier> = if inputs.allow_insecure_mtls {
				insecure_fallback_verifier = Some(verify.clone());
				tls::insecure::AllowInsecureMtlsVerifier::new(verify)
			} else {
				verify
			};
			scb.with_client_cert_verifier(verify)
		} else {
			scb.with_no_client_auth()
		};

		let cert_chain = parse_cert(&inputs.cert_pem)?;
		let private_key = parse_key(&inputs.key_pem)?;
		let mut sc = scb.with_single_cert(cert_chain, private_key)?;
		sc.key_log = crate::transport::tls::key_log();
		sc.alpn_protocols = alpns
			.map(|a| a.to_vec())
			.unwrap_or_else(|| inputs.default_alpns.clone());
		Ok((sc, insecure_fallback_verifier))
	}
}

pub(super) fn tls_versions_for_range(
	min_version: Option<TLSVersion>,
	max_version: Option<TLSVersion>,
) -> anyhow::Result<Vec<&'static rustls::SupportedProtocolVersion>> {
	// rustls currently supports TLS1.2 and TLS1.3 in this repo (see `transport::tls::ALL_TLS_VERSIONS`).
	// If older versions are requested, reject early.
	fn ord(v: TLSVersion) -> anyhow::Result<u8> {
		match v {
			TLSVersion::TLS_V1_2 => Ok(12),
			TLSVersion::TLS_V1_3 => Ok(13),
			_ => Err(anyhow!("unsupported TLS version: {v:?}")),
		}
	}

	let min = min_version.map(ord).transpose()?;
	let max = max_version.map(ord).transpose()?;
	if let (Some(min), Some(max)) = (min, max)
		&& min > max
	{
		return Err(anyhow!("invalid TLS version range"));
	}

	let min = min.unwrap_or(12);
	let max = max.unwrap_or(13);

	let mut out = Vec::new();
	if min <= 12 && max >= 12 {
		out.push(&rustls::version::TLS12);
	}
	if min <= 13 && max >= 13 {
		out.push(&rustls::version::TLS13);
	}
	if out.is_empty() {
		return Err(anyhow!("invalid TLS version range"));
	}
	Ok(out)
}

impl serde::Serialize for ServerTLSConfig {
	fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
	where
		S: Serializer,
	{
		// TODO: store raw pem
		serializer.serialize_none()
	}
}

#[cfg(feature = "schema")]
impl JsonSchema for ServerTLSConfig {
	fn schema_name() -> std::borrow::Cow<'static, str> {
		"ServerTLSConfig".into()
	}

	fn json_schema(_gen: &mut schemars::SchemaGenerator) -> schemars::Schema {
		schemars::json_schema!({ "type": "null" })
	}
}

pub fn parse_cert(cert: &[u8]) -> Result<Vec<CertificateDer<'static>>, anyhow::Error> {
	let parsed = <(SectionKind, Vec<u8>)>::pem_slice_iter(cert).collect::<Result<Vec<_>, _>>()?;
	if parsed.is_empty() {
		return Err(anyhow!("no certificate"));
	}

	parsed
		.into_iter()
		.map(|(kind, der)| {
			if kind != SectionKind::Certificate {
				return Err(anyhow!("no certificate"));
			}
			Ok(CertificateDer::from(der))
		})
		.collect()
}

pub fn parse_key(key: &[u8]) -> Result<PrivateKeyDer<'static>, anyhow::Error> {
	let (kind, der) = <(SectionKind, Vec<u8>)>::from_pem_slice(key).map_err(|e| match e {
		rustls_pki_types::pem::Error::NoItemsFound => anyhow!("no key"),
		_ => anyhow!(e),
	})?;
	match kind {
		SectionKind::PrivateKey => Ok(PrivateKeyDer::Pkcs8(der.into())),
		SectionKind::RsaPrivateKey => Ok(PrivateKeyDer::Pkcs1(der.into())),
		SectionKind::EcPrivateKey => Ok(PrivateKeyDer::Sec1(der.into())),
		_ => Err(anyhow!("unsupported key")),
	}
}
#[derive(Debug, Clone, Eq, PartialEq, serde::Serialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
pub enum ListenerProtocol {
	/// HTTP
	HTTP,
	/// HTTPS, terminating TLS then treating as HTTP
	HTTPS(ServerTLSConfig),
	/// TLS (passthrough or termination)
	TLS(Option<ServerTLSConfig>),
	/// Opaque TCP
	TCP,
	HBONE,
}

impl ListenerProtocol {
	pub async fn tls(
		&self,
		tls: Option<&frontend::TLS>,
		ca: Option<&Arc<CaClient>>,
	) -> Option<anyhow::Result<Arc<rustls::ServerConfig>>> {
		match self {
			ListenerProtocol::HTTPS(t) => Some(t.config_for(tls, ca).await),
			ListenerProtocol::TLS(t) => match t.as_ref() {
				Some(t) => Some(t.config_for(tls, ca).await),
				None => None,
			},
			_ => None,
		}
	}

	pub fn allow_insecure_mtls(&self) -> bool {
		match self {
			ListenerProtocol::HTTPS(t) => t.allow_insecure_mtls(),
			ListenerProtocol::TLS(Some(t)) => t.allow_insecure_mtls(),
			_ => false,
		}
	}

	pub fn include_src_identity_for_connection(&self, conn: &rustls::ServerConnection) -> bool {
		match self {
			ListenerProtocol::HTTPS(t) => t.include_src_identity_for_connection(conn),
			ListenerProtocol::TLS(Some(t)) => t.include_src_identity_for_connection(conn),
			_ => true,
		}
	}
}

// Protocol of the entire bind.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, EncodeLabelValue, Serialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[allow(non_camel_case_types)]
pub enum BindProtocol {
	http,
	// Note: TLS can be TLS (passthrough or termination) or HTTPS
	tls,
	tcp,
	/// Auto-detect protocol by peeking at the first byte of each connection.
	/// If the byte is 0x16 (TLS ClientHello), dispatch as `tls`; otherwise as `http`.
	auto,
}

#[apply(schema!)]
#[derive(Default, Copy, PartialEq, Eq, Hash, EncodeLabelValue)]
pub enum TunnelProtocol {
	#[default]
	Direct,
	HboneWaypoint,
	HboneGateway,
	Proxy,
	Connect,
}

// Controls whether a bind opens an OS listener socket.
#[apply(schema!)]
#[derive(Default, Copy, PartialEq, Eq, Hash, EncodeLabelValue)]
pub enum BindMode {
	/// Open a listener socket on the bind's address (the normal behavior).
	#[default]
	Standard,
	/// Do not open a socket. The bind is registered for routing only and is reachable
	/// via in-process re-entry (e.g. another listener redirecting CONNECT traffic to it).
	Internal,
}

// Protocol of the request
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, EncodeLabelValue)]
#[allow(non_camel_case_types)]
pub enum TransportProtocol {
	http,
	https,
	hbone,
	tcp,
	tls,
}

pub type ListenerKey = Strng;

#[apply(schema_ser_schema!)]
pub struct Route {
	// Internal name
	pub key: RouteKey,
	/// Service this route targets (set when parentRef is a Service).
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub service_key: Option<crate::types::discovery::NamespacedHostname>,
	/// Port of the targeted service this route is scoped to. Zero matches any port.
	#[serde(default, skip_serializing_if = "crate::serdes::is_default")]
	pub service_port: u16,
	#[serde(flatten)]
	// User facing name of the route
	pub name: RouteName,
	/// Can be a wildcard
	#[serde(default, skip_serializing_if = "Vec::is_empty")]
	pub hostnames: Vec<Strng>,
	#[serde(default, skip_serializing_if = "Vec::is_empty")]
	pub matches: Vec<RouteMatch>,
	#[serde(default, skip_serializing_if = "Vec::is_empty")]
	pub backends: Vec<RouteBackendReference>,
	#[serde(default, skip_serializing_if = "Vec::is_empty")]
	#[cfg_attr(feature = "schema", schemars(with = "Vec<serde_json::Value>"))]
	pub inline_policies: Vec<TrafficPolicy>,
}

pub type RouteKey = Strng;
pub type RouteGroupKey = Strng;
pub type RouteRuleName = Strng;

#[apply(schema!)]
#[derive(Hash, Eq, PartialEq)]
pub struct RouteName {
	pub name: Strng,
	pub namespace: Strng,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub rule_name: Option<Strng>,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub kind: Option<Strng>,
}

impl RouteName {
	pub fn as_route_name(&self) -> Strng {
		strng::format!("{}/{}", self.namespace, self.name)
	}
	pub fn as_route_target_ref(&self) -> PolicyTargetRef {
		PolicyTargetRef::Route {
			name: self.name.as_ref(),
			namespace: self.namespace.as_ref(),
			rule_name: None,
			kind: self.kind.as_deref(),
		}
	}
	pub fn as_route_rule_target_ref(&self) -> PolicyTargetRef {
		PolicyTargetRef::Route {
			name: self.name.as_ref(),
			namespace: self.namespace.as_ref(),
			rule_name: self.rule_name.as_deref(),
			kind: self.kind.as_deref(),
		}
	}
}

#[apply(schema!)]
#[derive(Hash, Eq, PartialEq)]
pub struct ListenerName {
	pub gateway_name: Strng,
	pub gateway_namespace: Strng,
	pub listener_name: Strng,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub listener_set: Option<ResourceName>,
}

impl ListenerName {
	pub fn as_gateway_name(&self) -> Strng {
		strng::format!("{}/{}", self.gateway_namespace, self.gateway_name)
	}
	pub fn as_gateway_target_ref(&self) -> PolicyTargetRef {
		PolicyTargetRef::Gateway {
			gateway_name: self.gateway_name.as_ref(),
			gateway_namespace: self.gateway_namespace.as_ref(),
			listener_name: None,
			port: None,
		}
	}
	pub fn as_listener_target_ref(&self) -> PolicyTargetRef {
		PolicyTargetRef::Gateway {
			gateway_name: self.gateway_name.as_ref(),
			gateway_namespace: self.gateway_namespace.as_ref(),
			listener_name: Some(self.listener_name.as_ref()),
			port: None,
		}
	}
	pub fn as_listenerset_target_ref(&self) -> Option<PolicyTargetRef<'_>> {
		self
			.listener_set
			.as_ref()
			.map(|ls| PolicyTargetRef::ListenerSet {
				name: ls.name.as_ref(),
				namespace: ls.namespace.as_ref(),
				section: None,
			})
	}

	pub fn as_listenerset_listener_target_ref(&self) -> Option<PolicyTargetRef<'_>> {
		self
			.listener_set
			.as_ref()
			.map(|ls| PolicyTargetRef::ListenerSet {
				name: ls.name.as_ref(),
				namespace: ls.namespace.as_ref(),
				section: Some(self.listener_name.as_ref()),
			})
	}
}

impl From<ListenerName> for ListenerTarget {
	fn from(l: ListenerName) -> Self {
		Self {
			gateway_name: l.gateway_name.clone(),
			gateway_namespace: l.gateway_namespace.clone(),
			listener_name: Some(l.listener_name.clone()),
			port: None,
		}
	}
}

#[apply(schema!)]
#[derive(Hash, Eq, PartialEq)]
pub struct ListenerTarget {
	pub gateway_name: Strng,
	pub gateway_namespace: Strng,
	pub listener_name: Option<Strng>,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub port: Option<u16>,
}

impl ListenerTarget {
	pub fn validate(&self) -> anyhow::Result<()> {
		anyhow::ensure!(
			!(self.listener_name.is_some() && self.port.is_some()),
			"gateway policy target cannot set both listener_name and port"
		);
		Ok(())
	}

	pub fn strip_listener_fields(&self) -> ListenerTarget {
		Self {
			gateway_name: self.gateway_name.clone(),
			gateway_namespace: self.gateway_namespace.clone(),
			listener_name: None,
			port: None,
		}
	}
}

#[apply(schema!)]
#[derive(Hash, Eq, PartialEq)]
pub struct ResourceName {
	pub name: Strng,
	pub namespace: Strng,
}

impl ResourceName {
	pub fn new(name: Strng, namespace: Strng) -> Self {
		Self { name, namespace }
	}
}

impl fmt::Display for ResourceName {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		write!(f, "{}/{}", self.namespace, self.name)
	}
}

#[apply(schema!)]
#[derive(Hash, Eq, PartialEq)]
pub struct TypedResourceName {
	pub kind: Strng,
	pub name: Strng,
	pub namespace: Strng,
}

impl fmt::Display for TypedResourceName {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		write!(f, "{}/{}/{}", self.kind, self.namespace, self.name)
	}
}

#[apply(schema!)]
#[derive(Hash, Eq, PartialEq)]
pub enum BackendTarget {
	Backend {
		name: Strng,
		namespace: Strng,
		#[serde(default, skip_serializing_if = "Option::is_none")]
		section: Option<Strng>,
	},
	Service {
		hostname: Strng,
		namespace: Strng,
		#[serde(default, skip_serializing_if = "Option::is_none")]
		port: Option<u16>,
	},
	Invalid,
}

#[derive(Hash, Eq, PartialEq, Clone, Debug)]
pub enum BackendTargetRef<'a> {
	Backend {
		name: &'a str,
		namespace: &'a str,
		section: Option<&'a str>,
	},
	Service {
		hostname: &'a str,
		namespace: &'a str,
		port: Option<u16>,
	},
	Invalid,
}

impl<'a> From<&'a BackendTarget> for BackendTargetRef<'a> {
	fn from(value: &'a BackendTarget) -> Self {
		match value {
			BackendTarget::Backend {
				name,
				namespace,
				section,
			} => BackendTargetRef::Backend {
				name,
				namespace,
				section: section.as_deref(),
			},
			BackendTarget::Service {
				hostname,
				namespace,
				port,
			} => BackendTargetRef::Service {
				hostname,
				namespace,
				port: *port,
			},
			BackendTarget::Invalid => BackendTargetRef::Invalid,
		}
	}
}

impl BackendTargetRef<'_> {
	pub fn strip_section(&self) -> BackendTargetRef {
		match self {
			BackendTargetRef::Backend {
				name, namespace, ..
			} => BackendTargetRef::Backend {
				name,
				namespace,
				section: None,
			},
			BackendTargetRef::Service {
				namespace,
				hostname,
				..
			} => BackendTargetRef::Service {
				namespace,
				hostname,
				port: None,
			},
			BackendTargetRef::Invalid => BackendTargetRef::Invalid,
		}
	}
}

#[apply(schema_ser_schema!)]
pub struct TCPRoute {
	// Internal name
	pub key: RouteKey,
	/// Service this route targets (set when parentRef is a Service).
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub service_key: Option<crate::types::discovery::NamespacedHostname>,
	/// Port of the targeted service this route is scoped to. Zero matches any port.
	#[serde(default, skip_serializing_if = "crate::serdes::is_default")]
	pub service_port: u16,
	// User facing name of the route
	#[serde(flatten)]
	pub name: RouteName,
	// Can be a wildcard. Not applicable for TCP, only for TLS
	#[serde(default, skip_serializing_if = "Vec::is_empty")]
	pub hostnames: Vec<Strng>,
	#[serde(default, skip_serializing_if = "Vec::is_empty")]
	pub backends: Vec<TCPRouteBackendReference>,
}

#[apply(schema_ser_schema!)]
pub struct TCPRouteBackendReference {
	#[serde(default = "default_weight")]
	pub weight: usize,
	pub backend: SimpleBackendReference,
	// Inline policies ("filters") of the route backend
	#[serde(default, skip_serializing_if = "Vec::is_empty")]
	#[cfg_attr(feature = "schema", schemars(with = "Vec<serde_json::Value>"))]
	pub inline_policies: Vec<BackendTrafficPolicy>,
}

#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TCPRouteBackend {
	#[serde(default = "default_weight")]
	pub weight: usize,
	pub backend: SimpleBackendWithPolicies,
	// Inline policies ("filters") of the route backend
	#[serde(default, skip_serializing_if = "Vec::is_empty")]
	pub inline_policies: Vec<BackendTrafficPolicy>,
}

#[apply(schema!)]
pub struct RouteMatch {
	#[serde(default, skip_serializing_if = "Vec::is_empty")]
	pub headers: Vec<HeaderMatch>,
	#[serde(default = "default_route_match_path")]
	pub path: PathMatch,
	#[serde(default, flatten, skip_serializing_if = "Option::is_none")]
	pub method: Option<MethodMatch>,
	#[serde(default, skip_serializing_if = "Vec::is_empty")]
	pub query: Vec<QueryMatch>,
}

fn default_route_match_path() -> PathMatch {
	PathMatch::PathPrefix("/".into())
}

#[apply(schema!)]
pub struct MethodMatch {
	pub method: Strng,
}

#[apply(schema!)]
pub struct HeaderMatch {
	#[serde(serialize_with = "ser_display", deserialize_with = "de_parse")]
	#[cfg_attr(feature = "schema", schemars(with = "String"))]
	pub name: HeaderOrPseudo,
	pub value: HeaderValueMatch,
}

#[apply(schema!)]
pub struct QueryMatch {
	#[serde(serialize_with = "ser_display")]
	pub name: Strng,
	pub value: QueryValueMatch,
}

#[apply(schema!)]
pub enum QueryValueMatch {
	Exact(Strng),
	Regex(
		#[serde(with = "serde_regex")]
		#[cfg_attr(feature = "schema", schemars(with = "String"))]
		regex::Regex,
	),
	Invalid,
}

#[apply(schema!)]
pub enum HeaderValueMatch {
	Exact(
		#[serde(serialize_with = "ser_bytes", deserialize_with = "de_parse")]
		#[cfg_attr(feature = "schema", schemars(with = "String"))]
		HeaderValue,
	),
	Regex(
		#[serde(with = "serde_regex")]
		#[cfg_attr(feature = "schema", schemars(with = "String"))]
		regex::Regex,
	),
	Invalid,
}

#[apply(schema!)]
pub enum PathMatch {
	Exact(Strng),
	PathPrefix(Strng),
	Regex(
		#[serde(with = "serde_regex")]
		#[cfg_attr(feature = "schema", schemars(with = "String"))]
		regex::Regex,
	),
	Invalid,
}

#[apply(schema!)]
#[derive(Eq, PartialEq)]
pub enum HostRedirect {
	/// Replace the full authority, including host and optional port.
	Full(Strng),
	/// Replace only the host and preserve the effective port.
	Host(Strng),
	/// Replace only the port.
	Port(NonZeroU16),
	/// Use the selected backend host when possible.
	Auto,
	/// Leave the authority unchanged.
	None,
}

#[apply(schema!)]
#[derive(Eq, PartialEq, Copy)]
pub enum HostRedirectOverride {
	/// Use the selected backend host when possible.
	Auto,
	/// Leave the authority unchanged.
	None,
}

#[apply(schema!)]
#[derive(Eq, PartialEq)]
pub enum PathRedirect {
	/// Replace the full request path.
	Full(Strng),
	/// Replace only the matched path prefix.
	Prefix(Strng),
}

#[apply(schema_ser_schema!)]
pub enum RouteBackendTarget {
	Service { name: NamespacedHostname, port: u16 },
	Backend(BackendKey),
	RouteGroup(RouteGroupKey),
	Invalid,
}

impl From<BackendReference> for RouteBackendTarget {
	fn from(value: BackendReference) -> Self {
		match value {
			BackendReference::Service { name, port } => Self::Service { name, port },
			BackendReference::Backend(key) => Self::Backend(key),
			BackendReference::Invalid => Self::Invalid,
		}
	}
}

impl RouteBackendTarget {
	pub fn as_backend_reference(&self) -> Option<BackendReference> {
		match self {
			Self::Service { name, port } => Some(BackendReference::Service {
				name: name.clone(),
				port: *port,
			}),
			Self::Backend(key) => Some(BackendReference::Backend(key.clone())),
			Self::Invalid => Some(BackendReference::Invalid),
			Self::RouteGroup(_) => None,
		}
	}
}

#[apply(schema_ser_schema!)]
pub struct RouteBackendReference {
	#[serde(default = "default_weight")]
	pub weight: usize,
	#[serde(flatten)]
	pub target: RouteBackendTarget,
	// Inline policies ("filters") of the route backend
	#[serde(default, skip_serializing_if = "Vec::is_empty")]
	#[cfg_attr(feature = "schema", schemars(with = "Vec<serde_json::Value>"))]
	pub inline_policies: Vec<BackendTrafficPolicy>,
}

#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RouteBackend {
	#[serde(default = "default_weight")]
	pub weight: usize,
	pub backend: BackendWithPolicies,
	// Inline policies ("filters") of the route backend
	#[serde(default, skip_serializing_if = "Vec::is_empty")]
	pub inline_policies: Vec<BackendTrafficPolicy>,
}

#[allow(unused)]
fn default_weight() -> usize {
	1
}

#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BackendWithPolicies {
	pub backend: Backend,

	#[serde(default, skip_serializing_if = "Vec::is_empty")]
	pub inline_policies: Vec<BackendTrafficPolicy>,
}

impl From<SimpleBackendWithPolicies> for BackendWithPolicies {
	fn from(backend: SimpleBackendWithPolicies) -> Self {
		Self {
			backend: Backend::from(backend.backend),
			inline_policies: backend.inline_policies,
		}
	}
}

#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub enum Backend {
	Service(Arc<Service>, u16),
	#[serde(rename = "host", serialize_with = "serialize_backend_tuple")]
	Opaque(ResourceName, Target), // Hostname or IP
	#[serde(rename = "mcp", serialize_with = "serialize_backend_tuple")]
	MCP(ResourceName, McpBackend),
	#[serde(rename = "ai", serialize_with = "serialize_backend_tuple")]
	#[cfg(feature = "gateway-llm")]
	AI(ResourceName, crate::llm::AIBackend),
	#[serde(rename = "llmRouter", serialize_with = "serialize_backend_tuple")]
	#[cfg(feature = "gateway-llm")]
	LLMRouter(ResourceName, Arc<crate::llm::model_router::ModelRouter>),
	#[serde(rename = "aws", serialize_with = "serialize_backend_tuple")]
	Aws(ResourceName, crate::aws::AwsBackendConfig),
	#[serde(serialize_with = "serialize_backend_tuple")]
	Dynamic(ResourceName, ()),
	/// In-process admin service backend. This is only valid for HTTP routes.
	#[serde(serialize_with = "serialize_backend_tuple")]
	Internal(ResourceName, InternalBackend),
	Invalid,
}

impl From<Backend> for BackendWithPolicies {
	fn from(val: Backend) -> Self {
		BackendWithPolicies {
			backend: val,
			inline_policies: vec![],
		}
	}
}

pub fn serialize_backend_tuple<S: Serializer, T: serde::Serialize>(
	name: &ResourceName,
	t: T,
	serializer: S,
) -> Result<S::Ok, S::Error> {
	#[derive(Debug, Clone, serde::Serialize)]
	#[serde(rename_all = "camelCase")]
	struct BackendTuple<'a, T: serde::Serialize> {
		#[serde(flatten)]
		name: &'a ResourceName,
		target: &'a T,
	}
	BackendTuple { name, target: &t }.serialize(serializer)
}

#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub enum BackendReference {
	Service { name: NamespacedHostname, port: u16 },
	Backend(BackendKey),
	Invalid,
}

impl From<SimpleBackend> for Backend {
	fn from(value: SimpleBackend) -> Self {
		match value {
			SimpleBackend::Service(svc, port) => Backend::Service(svc, port),
			SimpleBackend::Opaque(name, target) => Backend::Opaque(name, target),
			SimpleBackend::Aws(name, cfg) => Backend::Aws(name, cfg),
			SimpleBackend::Invalid => Backend::Invalid,
		}
	}
}

#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub enum SimpleBackend {
	Service(Arc<Service>, u16),
	#[serde(rename = "host")]
	Opaque(ResourceName, Target), // Hostname or IP
	Aws(ResourceName, crate::aws::AwsBackendConfig),
	Invalid,
}

impl fmt::Display for SimpleBackend {
	fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
		match self {
			SimpleBackend::Service(service, port) => write!(f, "{}:{}", service.hostname, port),
			SimpleBackend::Opaque(name, _) => write!(f, "{}", name),
			SimpleBackend::Aws(name, _) => write!(f, "{}", name),
			SimpleBackend::Invalid => write!(f, "invalid"),
		}
	}
}

impl TryFrom<Backend> for SimpleBackend {
	type Error = anyhow::Error;

	fn try_from(value: Backend) -> Result<Self, Self::Error> {
		match value {
			Backend::Service(svc, port) => Ok(SimpleBackend::Service(svc, port)),
			Backend::Opaque(name, tgt) => Ok(SimpleBackend::Opaque(name, tgt)),
			Backend::Aws(rn, cfg) => Ok(SimpleBackend::Aws(rn, cfg)),
			Backend::Invalid => Ok(SimpleBackend::Invalid),
			_ => anyhow::bail!("unsupported backend type"),
		}
	}
}

#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SimpleBackendWithPolicies {
	pub backend: SimpleBackend,

	#[serde(default, skip_serializing_if = "Vec::is_empty")]
	pub inline_policies: Vec<BackendTrafficPolicy>,
}

impl From<SimpleBackend> for SimpleBackendWithPolicies {
	fn from(value: SimpleBackend) -> Self {
		Self {
			backend: value,
			inline_policies: vec![],
		}
	}
}

#[derive(Eq, PartialEq)]
#[apply(schema_ser_schema!)]
#[cfg_attr(feature = "schema", schemars(with = "SimpleLocalBackend"))]
pub enum SimpleBackendReference {
	Service { name: NamespacedHostname, port: u16 },
	Backend(BackendKey),
	InlineBackend(Target),
	Invalid,
}

impl<'de> serde::Deserialize<'de> for SimpleBackendReference {
	fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
	where
		D: Deserializer<'de>,
	{
		let slb = SimpleLocalBackend::deserialize(deserializer)?;
		match slb {
			SimpleLocalBackend::Service { name, port } => {
				Ok(SimpleBackendReference::Service { name, port })
			},
			SimpleLocalBackend::Opaque(t) => Ok(SimpleBackendReference::InlineBackend(t)),
			SimpleLocalBackend::Backend(n) => Ok(SimpleBackendReference::Backend(n)),
			SimpleLocalBackend::Invalid => Ok(SimpleBackendReference::Invalid),
		}
	}
}

impl SimpleBackend {
	pub fn hostport(&self) -> String {
		match self {
			SimpleBackend::Service(svc, port) => {
				format!("{}:{port}", svc.hostname)
			},
			SimpleBackend::Aws(_, cfg) => format!("{}:{}", cfg.get_host(), 443),
			SimpleBackend::Opaque(_, tgt) => tgt.hostport(),
			SimpleBackend::Invalid => "invalid".to_string(),
		}
	}

	pub fn target(&self) -> BackendTargetRef {
		match self {
			SimpleBackend::Service(svc, port) => BackendTargetRef::Service {
				hostname: svc.hostname.as_ref(),
				namespace: svc.namespace.as_ref(),
				port: Some(*port),
			},
			SimpleBackend::Opaque(name, _) => BackendTargetRef::Backend {
				name: name.name.as_ref(),
				namespace: name.namespace.as_ref(),
				section: None,
			},
			SimpleBackend::Aws(name, _) => BackendTargetRef::Backend {
				name: name.name.as_ref(),
				namespace: name.namespace.as_ref(),
				section: None,
			},
			SimpleBackend::Invalid => BackendTargetRef::Invalid,
		}
	}

	pub fn backend_type(&self) -> cel::BackendType {
		match self {
			SimpleBackend::Service(_, _) => cel::BackendType::Service,
			SimpleBackend::Opaque(_, _) => cel::BackendType::Static,
			SimpleBackend::Aws(_, _) => cel::BackendType::Dynamic,
			SimpleBackend::Invalid => cel::BackendType::Unknown,
		}
	}

	pub fn backend_info(&self) -> BackendInfo {
		BackendInfo {
			backend_type: self.backend_type(),
			backend_name: strng::format!("{}", self),
		}
	}
}

impl Backend {
	/// Reject control-plane/embedder values that bypass local YAML deserialization.
	pub(crate) fn validate_compiled(&self) -> Result<(), crate::proxy::ProxyError> {
		match self {
			#[cfg(not(feature = "gateway-mcp"))]
			Self::MCP(..) => Err(crate::proxy::ProxyError::ProcessingString(
				"MCP support is not compiled; enable gateway-mcp".into(),
			)),
			#[cfg(not(feature = "providers-aws"))]
			Self::Aws(..) => Err(crate::proxy::ProxyError::ProcessingString(
				"AWS support is not compiled; enable providers-aws".into(),
			)),
			_ => Ok(()),
		}
	}

	pub(crate) fn resource_name(&self) -> Option<&ResourceName> {
		match self {
			Self::Opaque(name, _)
			| Self::MCP(name, _)
			| Self::Aws(name, _)
			| Self::Dynamic(name, _)
			| Self::Internal(name, _) => Some(name),
			#[cfg(feature = "gateway-llm")]
			Self::AI(name, _) | Self::LLMRouter(name, _) => Some(name),
			Self::Service(..) | Self::Invalid => None,
		}
	}

	pub(crate) fn is_llm(&self) -> bool {
		match self {
			#[cfg(feature = "gateway-llm")]
			Self::AI(..) | Self::LLMRouter(..) => true,
			_ => false,
		}
	}

	pub fn target(&self) -> BackendTarget {
		match self {
			Backend::Service(svc, port) => BackendTarget::Service {
				hostname: svc.hostname.clone(),
				namespace: svc.namespace.clone(),
				port: Some(*port),
			},
			backend if backend.resource_name().is_some() => {
				let name = backend.resource_name().expect("named backend");
				BackendTarget::Backend {
					name: name.name.clone(),
					namespace: name.namespace.clone(),
					section: None,
				}
			},
			_ => BackendTarget::Invalid,
		}
	}

	pub fn target_ref(&self) -> BackendTargetRef {
		match self {
			Backend::Service(svc, port) => BackendTargetRef::Service {
				hostname: svc.hostname.as_ref(),
				namespace: svc.namespace.as_ref(),
				port: Some(*port),
			},
			backend if backend.resource_name().is_some() => {
				let name = backend.resource_name().expect("named backend");
				BackendTargetRef::Backend {
					name: name.name.as_ref(),
					namespace: name.namespace.as_ref(),
					section: None,
				}
			},
			_ => BackendTargetRef::Invalid,
		}
	}

	pub fn name(&self) -> Strng {
		match self {
			Backend::Service(svc, port) => strng::format!("{}:{}", svc.hostname.clone(), port),
			backend if backend.resource_name().is_some() => {
				let name = backend.resource_name().expect("named backend");
				let mut s = String::with_capacity(name.namespace.len() + name.name.len() + 1);
				s.push_str(&name.namespace);
				s.push('/');
				s.push_str(&name.name);
				strng::new(&s)
			},
			_ => strng::literal!("invalid"),
		}
	}

	pub fn backend_type(&self) -> cel::BackendType {
		match self {
			Backend::Service(_, _) => cel::BackendType::Service,
			Backend::Opaque(_, _) => cel::BackendType::Static,
			Backend::MCP(_, _) => cel::BackendType::MCP,
			#[cfg(feature = "gateway-llm")]
			Backend::AI(_, _) | Backend::LLMRouter(_, _) => cel::BackendType::AI,
			Backend::Aws(_, _) => cel::BackendType::Unknown,
			Backend::Dynamic(_, _) => cel::BackendType::Dynamic,
			Backend::Internal(_, _) => cel::BackendType::Unknown,
			Backend::Invalid => cel::BackendType::Unknown,
		}
	}

	pub fn backend_protocol(&self) -> Option<cel::BackendProtocol> {
		match self {
			Backend::MCP(_, _) => Some(cel::BackendProtocol::mcp),
			#[cfg(feature = "gateway-llm")]
			Backend::AI(_, _) | Backend::LLMRouter(_, _) => Some(cel::BackendProtocol::llm),
			_ => None,
		}
	}

	pub fn backend_info(&self) -> BackendInfo {
		BackendInfo {
			backend_type: self.backend_type(),
			backend_name: self.name(),
		}
	}
}

#[derive(Debug, Clone)]
pub struct BackendInfo {
	pub backend_type: cel::BackendType,
	pub backend_name: Strng,
}

#[apply(schema_ser_schema!)]
pub struct McpBackend {
	pub targets: Vec<Arc<McpTarget>>,
	pub stateful: bool,
	pub always_use_prefix: bool,
	/// Behavior when one or more MCP targets fail to initialize or fail during fanout.
	/// Defaults to `failClosed`.
	pub failure_mode: FailureMode,
	#[serde(with = "crate::serdes::serde_dur")]
	#[cfg_attr(feature = "schema", schemars(with = "String"))]
	pub session_idle_ttl: Duration,
}

impl McpBackend {
	pub fn find(&self, name: &str) -> Option<Arc<McpTarget>> {
		self
			.targets
			.iter()
			.find(|target| target.name.as_str() == name)
			.cloned()
	}
}

#[apply(schema_ser_schema!)]
pub struct McpTarget {
	pub name: McpTargetName,
	#[serde(flatten)]
	pub spec: McpTargetSpec,
}

pub type McpTargetName = Strng;

// Gateway API SectionName: https://gateway-api.sigs.k8s.io/reference/spec/#sectionname
const MCP_TARGET_NAME_MAX_LEN: usize = 253;

static MCP_TARGET_NAME_RE: Lazy<Regex> = Lazy::new(|| {
	Regex::new(r"^[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*$").unwrap()
});

pub fn validate_mcp_target_name(name: &str) -> Result<(), String> {
	if name.is_empty() {
		return Err("invalid MCP target name: must not be empty".to_string());
	}
	if name.len() > MCP_TARGET_NAME_MAX_LEN {
		return Err(format!(
			"invalid MCP target name {name:?}: length {} exceeds max {MCP_TARGET_NAME_MAX_LEN}",
			name.len()
		));
	}
	if !MCP_TARGET_NAME_RE.is_match(name) {
		return Err(format!(
			"invalid MCP target name {name:?}: must match Gateway API SectionName pattern (lowercase letters, digits, '-' and '.'; '+' and '_' are reserved MCP delimiters)"
		));
	}
	Ok(())
}

#[apply(schema_ser_schema!)]
pub enum McpTargetSpec {
	#[serde(rename = "sse")]
	Sse(SseTargetSpec),
	#[serde(rename = "mcp")]
	Mcp(StreamableHTTPTargetSpec),
	#[serde(rename = "stdio")]
	Stdio {
		cmd: String,
		#[serde(default, skip_serializing_if = "Vec::is_empty")]
		args: Vec<String>,
		#[serde(default, skip_serializing_if = "HashMap::is_empty")]
		env: HashMap<String, String>,
		#[serde(default, skip_serializing_if = "std::ops::Not::not")]
		clear_env: bool,
	},
	#[serde(rename = "openapi")]
	OpenAPI(OpenAPITarget),
}

impl McpTargetSpec {
	pub fn backend(&self) -> Option<&SimpleBackendReference> {
		match self {
			McpTargetSpec::Sse(s) => Some(&s.backend),
			McpTargetSpec::Mcp(s) => Some(&s.backend),
			McpTargetSpec::OpenAPI(s) => Some(&s.backend),
			McpTargetSpec::Stdio { .. } => None,
		}
	}
}

#[apply(schema_ser_schema!)]
pub struct SseTargetSpec {
	pub backend: SimpleBackendReference,
	pub path: String,
}

#[apply(schema_ser_schema!)]
pub struct StreamableHTTPTargetSpec {
	pub backend: SimpleBackendReference,
	pub path: String,
}

#[apply(schema_ser_schema!)]
pub struct OpenAPITarget {
	pub backend: SimpleBackendReference,
	#[serde(skip_serializing)]
	#[cfg_attr(feature = "schema", schemars(with = "serde_json::value::RawValue"))]
	pub schema: Arc<OpenAPI>,
}

#[derive(Debug, Clone, Default)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[cfg_attr(
	feature = "schema",
	schemars(with = "std::collections::HashMap<ListenerKey, Arc<Listener>>")
)]
pub struct ListenerSet {
	pub inner: HashMap<ListenerKey, Arc<Listener>>,
}

impl serde::Serialize for ListenerSet {
	fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
	where
		S: Serializer,
	{
		self.inner.serialize(serializer)
	}
}

impl ListenerSet {
	pub fn from_list<const N: usize>(l: [Listener; N]) -> ListenerSet {
		let mut listeners = HashMap::with_capacity(l.len());
		for ls in l.into_iter() {
			listeners.insert(ls.key.clone(), Arc::new(ls));
		}
		ListenerSet { inner: listeners }
	}

	pub fn best_match(&self, host: &str) -> Option<Arc<Listener>> {
		self.best_match_filtered(host, |_| true)
	}

	/// Match only listeners with HTTP protocol (no TLS).
	pub fn best_match_http(&self, host: &str) -> Option<Arc<Listener>> {
		self.best_match_filtered(host, |p| matches!(p, ListenerProtocol::HTTP))
	}

	/// Match only listeners with TLS-capable protocol (HTTPS or TLS).
	pub fn best_match_tls(&self, host: &str) -> Option<Arc<Listener>> {
		self.best_match_filtered(host, |p| {
			matches!(p, ListenerProtocol::HTTPS(_) | ListenerProtocol::TLS(_))
		})
	}

	fn best_match_filtered(
		&self,
		host: &str,
		filter: impl Fn(&ListenerProtocol) -> bool,
	) -> Option<Arc<Listener>> {
		if let Some(best) = self
			.inner
			.values()
			.filter(|l| filter(&l.protocol))
			.find(|l| l.hostname == host)
		{
			trace!("found best match for {host} (exact)");
			return Some(best.clone());
		}
		if let Some(best) = self
			.inner
			.values()
			.filter(|l| {
				filter(&l.protocol)
					&& l.hostname.starts_with("*")
					&& host.ends_with(&l.hostname.as_str()[1..])
			})
			.max_by_key(|l| l.hostname.len())
		{
			trace!("found best match for {host} (wildcard {})", best.hostname);
			return Some(best.clone());
		}
		trace!("trying to find best match for {host} (empty hostname)");
		self
			.inner
			.values()
			.filter(|l| filter(&l.protocol))
			.find(|l| l.hostname.is_empty())
			.cloned()
	}

	pub fn insert(&mut self, v: Listener) {
		self.inner.insert(v.key.clone(), Arc::new(v));
	}

	pub fn contains(&self, key: &ListenerKey) -> bool {
		self.inner.contains_key(key)
	}

	pub fn get(&self, key: &ListenerKey) -> Option<&Listener> {
		self.inner.get(key).map(Arc::as_ref)
	}

	pub fn get_exactly_one(&self) -> anyhow::Result<Arc<Listener>> {
		if self.inner.len() != 1 {
			anyhow::bail!("expecting only one listener for TCP");
		}
		self
			.inner
			.iter()
			.next()
			.ok_or_else(|| anyhow::anyhow!("expecting one listener"))
			.map(|(_k, v)| v.clone())
	}

	pub fn remove(&mut self, key: &ListenerKey) -> Option<Arc<Listener>> {
		self.inner.remove(key)
	}

	pub fn iter(&self) -> impl Iterator<Item = &Listener> {
		self.inner.values().map(Arc::as_ref)
	}
}

#[derive(Debug, Clone, Hash, Eq, PartialEq, Serialize)]
pub enum HostnameMatch {
	Exact(Strng),
	// *.example.com -> Wildcard(example.com)
	Wildcard(Strng),
	None,
}

#[derive(Debug, Clone, Hash, Eq, PartialEq, Serialize)]
pub enum HostnameMatchRef<'a> {
	Exact(&'a str),
	// *.example.com -> Wildcard(example.com)
	Wildcard(&'a str),
	None,
}
impl Equivalent<HostnameMatch> for HostnameMatchRef<'_> {
	fn equivalent(&self, key: &HostnameMatch) -> bool {
		self == &HostnameMatchRef::from(key)
	}
}

impl<'a> From<&'a HostnameMatch> for HostnameMatchRef<'a> {
	fn from(value: &'a HostnameMatch) -> Self {
		match value {
			HostnameMatch::Exact(e) => HostnameMatchRef::Exact(e.as_str()),
			HostnameMatch::Wildcard(w) => HostnameMatchRef::Wildcard(w.as_str()),
			HostnameMatch::None => HostnameMatchRef::None,
		}
	}
}

impl From<Strng> for HostnameMatch {
	fn from(s: Strng) -> Self {
		if let Some(s) = s.strip_prefix("*.") {
			HostnameMatch::Wildcard(strng::new(s))
		} else {
			HostnameMatch::Exact(s.clone())
		}
	}
}

impl HostnameMatch {
	pub fn all_matches_or_none<'a>(
		hostname: Option<&'a str>,
	) -> Box<dyn Iterator<Item = HostnameMatchRef<'a>> + '_> {
		match hostname {
			None => Box::new(std::iter::once(HostnameMatchRef::None)),
			Some(h) => Box::new(Self::all_matches(h)),
		}
	}
	pub fn all_matches<'a>(hostname: &'a str) -> impl Iterator<Item = HostnameMatchRef<'a>> + '_ {
		Self::all_actual_matches(hostname).chain(std::iter::once(HostnameMatchRef::None))
	}
	fn all_actual_matches<'a>(hostname: &'a str) -> impl Iterator<Item = HostnameMatchRef<'a>> + '_ {
		let has_wildcard_prefix = hostname.starts_with("*.");

		let exact_match = if has_wildcard_prefix {
			None
		} else {
			Some(HostnameMatchRef::Exact(hostname))
		};

		let wildcards = hostname.char_indices().filter_map(move |(i, c)| {
			if c == '.' {
				Some(HostnameMatchRef::Wildcard(&hostname[i + 1..]))
			} else {
				None
			}
		});

		exact_match.into_iter().chain(wildcards)
	}
}

#[derive(Debug, Clone, Hash, Eq, PartialEq, Serialize)]
pub struct SingleRouteMatch {
	key: RouteKey,
	index: usize,
}

#[derive(Debug, Clone, Default)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[cfg_attr(
	feature = "schema",
	schemars(with = "std::collections::HashMap<RouteKey, Arc<Route>>")
)]
pub struct RouteSet {
	// Hostname -> []routes, sorted so that route matching can do a linear traversal
	inner: hashbrown::HashMap<HostnameMatch, Vec<SingleRouteMatch>>,
	// All routes
	all: HashMap<RouteKey, Arc<Route>>,
}

impl serde::Serialize for RouteSet {
	fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
	where
		S: Serializer,
	{
		self.all.serialize(serializer)
	}
}

impl RouteSet {
	pub fn from_list(l: Vec<Route>) -> RouteSet {
		let mut rs = RouteSet::default();
		for ls in l.into_iter() {
			rs.insert(ls);
		}
		rs
	}

	pub fn get_hostname(
		&self,
		hnm: &HostnameMatchRef,
	) -> impl Iterator<Item = (Arc<Route>, &RouteMatch)> {
		self.inner.get(hnm).into_iter().flatten().flat_map(|rl| {
			self
				.all
				.get(&rl.key)
				.map(|r| (r.clone(), r.matches.get(rl.index).expect("corrupted state")))
		})
	}

	pub fn get_by_name(&self, name: &RouteName) -> Option<Arc<Route>> {
		self.all.values().find(|route| route.name == *name).cloned()
	}

	pub fn insert(&mut self, r: Route) {
		if self.all.contains_key(&r.key) {
			self.remove(&r.key);
		}
		let r = Arc::new(r);
		// Insert the route into all HashMap first so it's available during binary search
		self.all.insert(r.key.clone(), r.clone());

		for hostname_match in Self::hostname_matchers(&r) {
			let v = self.inner.entry(hostname_match).or_default();
			for (idx, m) in r.matches.iter().enumerate() {
				let to_insert = v.binary_search_by(|existing| {
					let have = self.all.get(&existing.key).expect("corrupted state");
					let have_match = have.matches.get(existing.index).expect("corrupted state");

					cmp::Ordering::reverse(Self::compare_route(
						(m, &r.key),
						(have_match, &existing.key),
					))
				});
				let insert_idx = to_insert.unwrap_or_else(|pos| pos);
				v.insert(
					insert_idx,
					SingleRouteMatch {
						key: r.key.clone(),
						index: idx,
					},
				);
			}
		}
	}

	fn compare_route(a: (&RouteMatch, &RouteKey), b: (&RouteMatch, &RouteKey)) -> Ordering {
		let (a, a_key) = a;
		let (b, b_key) = b;
		// Compare RouteMatch according to Gateway API sorting requirements
		// 1. Path match type (Exact > PathPrefix > Regex)
		let path_rank1 = get_path_rank(&a.path);
		let path_rank2 = get_path_rank(&b.path);
		if path_rank1 != path_rank2 {
			return cmp::Ordering::reverse(path_rank1.cmp(&path_rank2));
		}
		// 2. Path length (longer paths first)
		let path_len1 = get_path_length(&a.path);
		let path_len2 = get_path_length(&b.path);
		if path_len1 != path_len2 {
			return cmp::Ordering::reverse(path_len1.cmp(&path_len2)); // Reverse order for longer first
		}
		// 3. Method match (routes with method matches first)
		let method1 = a.method.is_some();
		let method2 = b.method.is_some();
		if method1 != method2 {
			return cmp::Ordering::reverse(method1.cmp(&method2));
		}
		// 4. Number of header matches (more headers first)
		let header_count1 = a.headers.len();
		let header_count2 = b.headers.len();
		if header_count1 != header_count2 {
			return cmp::Ordering::reverse(header_count1.cmp(&header_count2));
		}
		// 5. Number of query matches (more query params first)
		let query_count1 = a.query.len();
		let query_count2 = b.query.len();
		if query_count1 != query_count2 {
			return cmp::Ordering::reverse(query_count1.cmp(&query_count2));
		}
		// Finally, by order in the route list. This is the tie-breaker
		a_key.cmp(b_key)
	}

	pub fn contains(&self, key: &RouteKey) -> bool {
		self.all.contains_key(key)
	}

	pub fn remove(&mut self, key: &RouteKey) {
		let Some(old_route) = self.all.remove(key) else {
			return;
		};

		for hostname_match in Self::hostname_matchers(&old_route) {
			let entry = self
				.inner
				.entry(hostname_match)
				.and_modify(|v| v.retain(|r| &r.key != key));
			match entry {
				hashbrown::hash_map::Entry::Occupied(v) => {
					if v.get().is_empty() {
						v.remove();
					}
				},
				hashbrown::hash_map::Entry::Vacant(_) => {},
			}
		}
	}

	fn hostname_matchers(r: &Route) -> Vec<HostnameMatch> {
		if r.hostnames.is_empty() {
			vec![HostnameMatch::None]
		} else {
			r.hostnames
				.iter()
				.map(|h| HostnameMatch::from(h.clone()))
				.collect()
		}
	}

	pub fn is_empty(&self) -> bool {
		self.inner.is_empty()
	}

	pub fn iter(&self) -> impl Iterator<Item = &Arc<Route>> {
		self.all.values()
	}
}

#[derive(Debug, Clone, Default)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[cfg_attr(
	feature = "schema",
	schemars(with = "std::collections::HashMap<RouteKey, TCPRoute>")
)]
pub struct TCPRouteSet {
	// Hostname -> []routes, sorted so that route matching can do a linear traversal
	inner: hashbrown::HashMap<HostnameMatch, Vec<RouteKey>>,
	// All routes
	all: HashMap<RouteKey, TCPRoute>,
}

impl serde::Serialize for TCPRouteSet {
	fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
	where
		S: Serializer,
	{
		self.all.serialize(serializer)
	}
}

impl TCPRouteSet {
	pub fn from_list(l: Vec<TCPRoute>) -> Self {
		let mut rs = Self::default();
		for ls in l.into_iter() {
			rs.insert(ls);
		}
		rs
	}

	pub fn get_hostname(&self, hnm: &HostnameMatchRef) -> Option<&TCPRoute> {
		self
			.inner
			.get(hnm)
			.and_then(|r| r.first())
			.and_then(|rl| self.all.get(rl))
	}

	/// All routes for a hostname, in precedence order (oldest/alphabetical key first).
	pub fn get_hostname_routes(&self, hnm: &HostnameMatchRef) -> impl Iterator<Item = &TCPRoute> {
		self
			.inner
			.get(hnm)
			.into_iter()
			.flatten()
			.filter_map(|rl| self.all.get(rl))
	}

	pub fn insert(&mut self, r: TCPRoute) {
		if self.all.contains_key(&r.key) {
			self.remove(&r.key);
		}
		// Insert the route into all HashMap first so it's available during binary search
		self.all.insert(r.key.clone(), r.clone());

		for hostname_match in Self::hostname_matchers(&r) {
			let v = self.inner.entry(hostname_match).or_default();
			let to_insert = v.binary_search_by(|existing| existing.cmp(&r.key));
			let insert_idx = to_insert.unwrap_or_else(|pos| pos);
			v.insert(insert_idx, r.key.clone());
		}
	}

	pub fn contains(&self, key: &RouteKey) -> bool {
		self.all.contains_key(key)
	}

	pub fn remove(&mut self, key: &RouteKey) {
		let Some(old_route) = self.all.remove(key) else {
			return;
		};

		for hostname_match in Self::hostname_matchers(&old_route) {
			let entry = self
				.inner
				.entry(hostname_match)
				.and_modify(|v| v.retain(|r| r != key));
			match entry {
				hashbrown::hash_map::Entry::Occupied(v) => {
					if v.get().is_empty() {
						v.remove();
					}
				},
				hashbrown::hash_map::Entry::Vacant(_) => {},
			}
		}
	}

	fn hostname_matchers(r: &TCPRoute) -> Vec<HostnameMatch> {
		if r.hostnames.is_empty() {
			vec![HostnameMatch::None]
		} else {
			r.hostnames
				.iter()
				.map(|h| HostnameMatch::from(h.clone()))
				.collect()
		}
	}

	pub fn is_empty(&self) -> bool {
		self.inner.is_empty()
	}
}

// Helper functions for RouteMatch comparison
fn get_path_rank(path: &PathMatch) -> i32 {
	match path {
		// Best match: exact
		PathMatch::Exact(_) => 3,
		// Prefix/Regex -- we will defer to the length
		PathMatch::PathPrefix(_) => 2,
		PathMatch::Regex(_) => 2,
		PathMatch::Invalid => 0,
	}
}

fn get_path_length(path: &PathMatch) -> usize {
	match path {
		PathMatch::Exact(s) => s.len(),
		PathMatch::PathPrefix(s) => s.len(),
		PathMatch::Regex(r) => r.as_str().len(),
		PathMatch::Invalid => 0,
	}
}

#[derive(Debug, Eq, PartialEq, Clone, Copy, serde::Serialize)]
pub enum IpFamily {
	Dual,
	IPv4,
	IPv6,
}

pub type PolicyKey = Strng;
pub type BackendKey = Strng;

#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TargetedPolicy {
	pub key: PolicyKey,
	pub name: Option<TypedResourceName>,
	pub target: PolicyTarget,
	#[serde(default, skip_serializing_if = "PolicyInheritance::is_default")]
	pub inheritance: PolicyInheritance,
	pub policy: PolicyType,
}

#[derive(Debug, Default, Clone, Copy, Eq, PartialEq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub enum PolicyInheritance {
	#[default]
	Default,
	Override,
}

impl PolicyInheritance {
	pub fn is_default(&self) -> bool {
		matches!(self, Self::Default)
	}
}

/// Configuration for dynamic tracing policy
#[apply(schema!)]
pub struct TracingConfig {
	/// Backend that receives exported traces.
	#[serde(flatten)]
	pub provider_backend: SimpleBackendReference,
	/// Backend policies used when exporting traces.
	#[serde(default, skip_serializing_if = "Vec::is_empty")]
	#[serde(deserialize_with = "crate::types::local::de_from_local_backend_policy")]
	#[cfg_attr(
		feature = "schema",
		schemars(with = "Option<crate::types::local::SimpleLocalBackendPolicies>")
	)]
	pub policies: Vec<BackendTrafficPolicy>,
	/// Span attributes to add, keyed by attribute name.
	#[serde(default)]
	pub attributes: OrderedStringMap<Arc<cel::Expression>>,
	/// Resource attributes to add to the tracer provider (OTel `Resource`).
	/// This can be used to set things like `service.name` dynamically.
	#[serde(default)]
	pub resources: OrderedStringMap<Arc<cel::Expression>>,
	/// Attribute keys to remove from the emitted span attributes.
	///
	/// This is applied before `attributes` are evaluated/added, so it can be used to drop
	/// default attributes or avoid duplication.
	#[serde(default)]
	pub remove: Vec<String>,
	/// Optional per-policy override for random sampling. If set, overrides global config for
	/// requests that use this frontend policy.
	#[serde(default, deserialize_with = "deserialize_sampling_expr_opt")]
	#[cfg_attr(feature = "schema", schemars(with = "Option<crate::StringBoolFloat>"))]
	pub random_sampling: Option<Arc<cel::Expression>>,
	/// Optional per-policy override for client sampling. If set, overrides global config for
	/// requests that use this frontend policy.
	#[serde(default, deserialize_with = "deserialize_sampling_expr_opt")]
	#[cfg_attr(feature = "schema", schemars(with = "Option<crate::StringBoolFloat>"))]
	pub client_sampling: Option<Arc<cel::Expression>>,
	/// Optional CEL filter with KEEP semantics. When set, only requests for which the expression
	/// evaluates to `true` have their trace span(s) exported; all other spans are dropped. When
	/// unset, no filtering is applied (all sampled spans are exported). Composes after sampling
	/// (only sampled spans are evaluated). This matches `accessLog.filter` (keep-semantics):
	/// `true` keeps. Missing/errored fields evaluate to `false`, so on eval error the span is
	/// dropped (fail closed).
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub filter: Option<Arc<cel::Expression>>,
	/// OTLP HTTP path used to export traces.
	#[serde(default = "default_otlp_path")]
	pub path: String,
	/// OTLP protocol used to export traces. Defaults to HTTP.
	#[serde(default)]
	pub protocol: TracingProtocol,
}

fn default_otlp_path() -> String {
	"/v1/traces".to_string()
}

fn deserialize_sampling_expr_opt<'de, D>(
	deserializer: D,
) -> Result<Option<Arc<cel::Expression>>, D::Error>
where
	D: serde::Deserializer<'de>,
{
	let v = Option::<crate::StringBoolFloat>::deserialize(deserializer)?;
	v.map(|v| cel::Expression::new_strict(&v.0))
		.transpose()
		.map(|o| o.map(Arc::new))
		.map_err(|e| serde::de::Error::custom(e.to_string()))
}

#[derive(serde::Serialize, serde::Deserialize, Default, Copy, Eq, PartialEq, Clone, Debug)]
#[serde(rename_all = "lowercase", deny_unknown_fields)]
#[cfg_attr(feature = "schema", derive(crate::JsonSchema))]
pub enum TracingProtocol {
	#[default]
	Grpc,
	Http,
}

/// TracingPolicy holds both the configuration and the compiled OpenTelemetry tracer
#[derive(Clone, Debug)]
pub struct TracingPolicy {
	pub config: TracingConfig,
	/// CEL fields used by the tracer for span attributes. Stored so we can lazily
	/// create the tracer at first use with the correct attribute set.
	pub fields: Arc<crate::telemetry::log::LoggingFields>,
	/// Lazily initialized tracer. Created on first access in the dataplane
	/// using a PolicyClient so that backend routing and auth can be applied.
	#[cfg(feature = "telemetry-otlp")]
	pub tracer: once_cell::sync::OnceCell<Arc<crate::telemetry::trc::Tracer>>,
}

impl serde::Serialize for TracingPolicy {
	fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
	where
		S: serde::Serializer,
	{
		self.config.serialize(serializer)
	}
}

#[cfg(feature = "telemetry-otlp")]
impl TracingPolicy {
	pub fn get_or_init(
		&self,
		policy_client: crate::proxy::httpproxy::PolicyClient,
	) -> anyhow::Result<&Arc<crate::telemetry::trc::Tracer>> {
		self.tracer.get_or_try_init(|| {
			let tracer =
				crate::telemetry::trc::Tracer::new(&self.config, self.fields.clone(), policy_client)?;
			Ok(Arc::new(tracer))
		})
	}
}

#[derive(Clone, Debug)]
pub struct AccessLogPolicy {
	pub config: crate::types::frontend::OtlpLoggingConfig,
	#[cfg(feature = "telemetry-otlp")]
	pub logger: once_cell::sync::OnceCell<Arc<crate::telemetry::log::OtelAccessLogger>>,
}

#[cfg(feature = "telemetry-otlp")]
impl AccessLogPolicy {
	pub fn get_or_init(
		&self,
		policy_client: crate::proxy::httpproxy::PolicyClient,
	) -> anyhow::Result<&Arc<crate::telemetry::log::OtelAccessLogger>> {
		self.logger.get_or_try_init(|| {
			let logger = crate::telemetry::log::OtelAccessLogger::new(
				policy_client,
				self.config.provider_backend.clone(),
				self.config.policies.clone(),
				self.config.protocol,
				self.config.path.clone(),
			)?;
			Ok(Arc::new(logger))
		})
	}
}

impl serde::Serialize for AccessLogPolicy {
	fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
	where
		S: serde::Serializer,
	{
		self.config.serialize(serializer)
	}
}

impl From<BackendTrafficPolicy> for PolicyType {
	fn from(value: BackendTrafficPolicy) -> Self {
		Self::Backend(value)
	}
}

impl From<FrontendPolicy> for PolicyType {
	fn from(value: FrontendPolicy) -> Self {
		Self::Frontend(value)
	}
}

impl From<TrafficPolicy> for PolicyType {
	fn from(value: TrafficPolicy) -> Self {
		// Default to route for simplicity.
		(value, PolicyPhase::Route).into()
	}
}
impl From<(TrafficPolicy, PolicyPhase)> for PolicyType {
	fn from((p, phase): (TrafficPolicy, PolicyPhase)) -> Self {
		Self::Traffic(PhasedTrafficPolicy { phase, policy: p })
	}
}

#[apply(schema!)]
#[derive(Copy, Default, Eq, PartialEq)]
pub enum PolicyPhase {
	#[default]
	Route,
	Gateway,
}

#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PhasedTrafficPolicy {
	pub phase: PolicyPhase,
	#[serde(flatten)]
	pub policy: TrafficPolicy,
}

#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub enum PolicyType {
	Frontend(FrontendPolicy),
	Traffic(PhasedTrafficPolicy),
	Backend(BackendTrafficPolicy),
}

impl PolicyType {
	pub fn as_traffic_gateway_phase(&self) -> Option<&TrafficPolicy> {
		match self {
			PolicyType::Traffic(t) if t.phase == PolicyPhase::Gateway => Some(&t.policy),
			_ => None,
		}
	}
	pub fn as_traffic_route_phase(&self) -> Option<&TrafficPolicy> {
		match self {
			PolicyType::Traffic(t) if t.phase == PolicyPhase::Route => Some(&t.policy),
			_ => None,
		}
	}
	pub fn as_backend(&self) -> Option<&BackendTrafficPolicy> {
		match self {
			PolicyType::Backend(t) => Some(t),
			_ => None,
		}
	}
	pub fn as_frontend(&self) -> Option<&FrontendPolicy> {
		match self {
			PolicyType::Frontend(t) => Some(t),
			_ => None,
		}
	}
}

pub type RouteTarget = RouteName;

#[apply(schema!)]
#[derive(Hash, Eq, PartialEq)]
pub struct ListenerSetTarget {
	pub name: Strng,
	pub namespace: Strng,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub section: Option<Strng>,
}

#[apply(schema!)]
#[derive(Hash, Eq, PartialEq)]
pub enum PolicyTarget {
	Gateway(ListenerTarget),
	Route(RouteTarget),
	Backend(BackendTarget),
	ListenerSet(ListenerSetTarget),
}

impl PolicyTarget {
	pub fn validate(&self) -> anyhow::Result<()> {
		if let PolicyTarget::Gateway(target) = self {
			target.validate()?;
		}
		Ok(())
	}
}

impl Equivalent<PolicyTarget> for PolicyTargetRef<'_> {
	fn equivalent(&self, key: &PolicyTarget) -> bool {
		self == &PolicyTargetRef::from(key)
	}
}

#[derive(Hash, Eq, PartialEq)]
pub enum PolicyTargetRef<'a> {
	Gateway {
		gateway_name: &'a str,
		gateway_namespace: &'a str,
		listener_name: Option<&'a str>,
		port: Option<u16>,
	},
	Route {
		name: &'a str,
		namespace: &'a str,
		rule_name: Option<&'a str>,
		kind: Option<&'a str>,
	},
	Backend(BackendTargetRef<'a>),
	ListenerSet {
		name: &'a str,
		namespace: &'a str,
		section: Option<&'a str>,
	},
}

impl<'a> From<&'a PolicyTarget> for PolicyTargetRef<'a> {
	fn from(value: &'a PolicyTarget) -> Self {
		match value {
			PolicyTarget::Gateway(v) => PolicyTargetRef::Gateway {
				gateway_name: &v.gateway_name,
				gateway_namespace: v.gateway_namespace.as_ref(),
				listener_name: v.listener_name.as_deref(),
				port: v.port,
			},
			PolicyTarget::Route(v) => PolicyTargetRef::Route {
				name: &v.name,
				namespace: v.namespace.as_ref(),
				rule_name: v.rule_name.as_deref(),
				kind: v.kind.as_deref(),
			},
			PolicyTarget::Backend(v) => PolicyTargetRef::Backend(v.into()),
			PolicyTarget::ListenerSet(v) => PolicyTargetRef::ListenerSet {
				name: v.name.as_ref(),
				namespace: v.namespace.as_ref(),
				section: v.section.as_deref(),
			},
		}
	}
}

#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub enum FrontendPolicy {
	#[serde(rename = "http")]
	HTTP(frontend::HTTP),
	#[serde(rename = "tls")]
	TLS(frontend::TLS),
	#[serde(rename = "tcp")]
	TCP(frontend::TCP),
	NetworkAuthorization(frontend::NetworkAuthorization),
	Proxy(frontend::Proxy),
	Connect(frontend::Connect),
	AccessLog(frontend::LoggingPolicy),
	Tracing(Arc<TracingPolicy>),
	Metrics(frontend::MetricsFieldsPolicy),
}

#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub enum TrafficPolicy {
	Timeout(timeout::Policy),
	Retry(retry::Policy),
	#[serde(rename = "ai")]
	AI(Arc<llm::Policy>),
	Authorization(Authorization),
	LocalRateLimit(RequestPolicy<Vec<crate::http::localratelimit::RateLimit>>),
	RemoteRateLimit(RequestPolicy<remoteratelimit::RemoteRateLimit>),
	ExtAuthz(RequestPolicy<ext_authz::ExtAuthz>),
	ExtProc(RequestPolicy<ext_proc::ExtProc>),
	JwtAuth(RequestPolicy<JwtAuthentication>),
	Oidc(RequestPolicy<crate::http::oidc::OidcPolicy>),
	BasicAuth(RequestPolicy<crate::http::basicauth::BasicAuthentication>),
	APIKey(RequestPolicy<crate::http::apikey::APIKeyAuthentication>),
	Transformation(RequestPolicy<crate::http::transformation_cel::Transformation>),
	Csrf(RequestPolicy<crate::http::csrf::Csrf>),

	RequestHeaderModifier(RequestPolicy<filters::HeaderModifier>),
	ResponseHeaderModifier(RequestPolicy<filters::HeaderModifier>),
	RequestRedirect(RequestPolicy<filters::RequestRedirect>),
	UrlRewrite(RequestPolicy<filters::UrlRewrite>),
	HostRewrite(agent::HostRedirectOverride),
	RequestMirror(Vec<filters::RequestMirror>),
	DirectResponse(RequestPolicy<filters::DirectResponse>),
	Buffer(RequestPolicy<http::buffer::Buffer>),
	#[serde(rename = "cors")]
	CORS(RequestPolicy<http::cors::Cors>),
}

/// Compatibility declaration normalized once into the shared configuration owner.
/// Its mode cannot be changed; serialization retains the original securityPipeline shape.
#[derive(Debug, Clone)]
pub struct LegacySecurityPipeline(Arc<security_integration_runtime::SecurityConfig>);

impl From<security_pipeline::SecurityPipelineConfig> for LegacySecurityPipeline {
	fn from(pipeline: security_pipeline::SecurityPipelineConfig) -> Self {
		Self(Arc::new(
			security_integration_runtime::SecurityConfig::from(
				security_integration_runtime::SecurityConfigData {
					mode: security_integration_runtime::SecurityMode::Enforce,
					pipeline,
					..Default::default()
				},
			),
		))
	}
}

impl LegacySecurityPipeline {
	pub fn configuration(&self) -> &Arc<security_integration_runtime::SecurityConfig> {
		&self.0
	}
}

impl serde::Serialize for LegacySecurityPipeline {
	fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
		self.0.pipeline.serialize(serializer)
	}
}

#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub enum BackendTrafficPolicy {
	Authorization(Authorization),
	McpAuthorization(McpAuthorization),
	McpAuthentication(McpAuthentication),
	McpGuardrails(Arc<crate::mcp::guardrails::McpGuardrails>),
	SecurityPipeline(LegacySecurityPipeline),
	SecurityAudit(Arc<security_integration_runtime::SecurityConfig>),
	A2a(A2aPolicy),
	#[serde(rename = "http")]
	HTTP(backend::HTTP),
	#[serde(rename = "tcp")]
	TCP(backend::TCP),
	Tunnel(backend::Tunnel),
	#[serde(rename = "backendTLS")]
	BackendTLS(http::backendtls::BackendTLS),
	BackendAuth(BackendAuth),
	InferenceRouting(ext_proc::InferenceRouting),
	#[serde(rename = "ai")]
	AI(Arc<llm::Policy>),
	ExtAuthz(Arc<ext_authz::ExtAuthz>),
	SessionPersistence(http::sessionpersistence::Policy),
	Transformation(Arc<crate::http::transformation_cel::Transformation>),
	Health(health::Policy),

	RequestHeaderModifier(filters::HeaderModifier),
	ResponseHeaderModifier(Arc<filters::HeaderModifier>),
	RequestRedirect(filters::RequestRedirect),
	RequestMirror(Vec<filters::RequestMirror>),
}

#[apply(schema!)]
pub struct A2aPolicy {}

#[apply(schema!)]
pub struct Authorization(pub Arc<RuleSet>);

// Do not use schema! as it will reject the `extra` field
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
pub struct ResourceMetadata {
	#[serde(flatten)]
	pub extra: BTreeMap<String, Value>,
}

impl ResourceMetadata {
	/// Build RFC-compliant JSON for the protected resource metadata.
	///
	/// - Defaults computed `resource` and `authorization_servers`.
	/// - Converts any additional config keys from camelCase to snake_case.
	/// - Adds MCP-specific fields used by the gateway.
	pub fn to_rfc_json(&self, resource_uri: String, issuer: String) -> Value {
		let mut map = serde_json::Map::new();

		// Computed fields. User can override them if they explicitly configure them.
		map.insert("resource".into(), Value::String(resource_uri));
		map.insert(
			"authorization_servers".into(),
			Value::Array(vec![Value::String(issuer)]),
		);
		// MCP-specific additions
		map.insert(
			"mcp_protocol_version".into(),
			Value::String("2025-06-18".into()),
		);
		map.insert("resource_type".into(), Value::String("mcp-server".into()));

		// Copy user-provided extra keys, converting to snake_case
		for (key, value) in &self.extra {
			let snake = key.to_snake_case();
			map.insert(snake, value.clone());
		}

		Value::Object(map)
	}
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct JwtAuthentication {
	#[serde(flatten)]
	pub jwt: crate::http::jwt::Jwt,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub mcp: Option<McpAuthentication>,
}

impl store::RequestPolicyTrait for JwtAuthentication {
	async fn apply(
		&self,
		_client: &crate::proxy::httpproxy::PolicyClient,
		log: &mut crate::telemetry::log::RequestLog,
		req: &mut crate::http::Request,
	) -> Result<crate::http::PolicyResponse, crate::proxy::ProxyResponse> {
		if !cfg!(feature = "gateway-mcp") && self.mcp.is_some() {
			return Err(
				crate::proxy::ProxyError::ProcessingString(
					"MCP support is not compiled; enable gateway-mcp".into(),
				)
				.into(),
			);
		}
		#[cfg(feature = "gateway-mcp")]
		if let Some(auth) = &self.mcp {
			if !crate::mcp::auth::is_well_known_endpoint(req.uri().path()) {
				self.jwt.apply(Some(log), req).await.map_err(|e| {
					crate::proxy::ProxyResponse::from(crate::mcp::auth::create_auth_required_response(
						crate::proxy::ProxyError::JwtAuthenticationFailure(e),
						req,
						auth,
					))
				})?;
			}

			if let Some(resp) = crate::mcp::auth::handle_mcp_request(req, auth, _client).await? {
				return Err(crate::proxy::ProxyResponse::DirectResponse(Box::new(resp)));
			}
			return Ok(crate::http::PolicyResponse::default());
		}

		self
			.jwt
			.apply(Some(log), req)
			.await
			.map_err(crate::proxy::ProxyError::JwtAuthenticationFailure)
			.map_err(crate::proxy::ProxyResponse::from)?;
		Ok(crate::http::PolicyResponse::default())
	}

	fn expressions(&self) -> impl Iterator<Item = &crate::cel::Expression> {
		self.jwt.expressions()
	}
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct McpAuthentication {
	pub issuer: String,
	pub audiences: Vec<String>,
	pub provider: Option<McpIDP>,
	pub resource_metadata: ResourceMetadata,
	pub jwt_validator: Arc<crate::http::jwt::Jwt>,
	pub mode: McpAuthenticationMode,
	pub client_id: Option<String>,
}

#[apply(schema_enum!)]
#[derive(Default)]
pub enum McpAuthenticationMode {
	/// A valid token, issued by a configured issuer, must be present.
	/// This is the default option.
	#[default]
	Strict,
	/// If a token exists, validate it.
	/// Warning: this allows requests without a JWT token! Additionally, 401 errors will not be returned,
	/// which will not trigger clients to initiate an oauth flow.
	Optional,
	/// Requests are never rejected. This is useful for usage of claims in later steps (authorization, logging, etc).
	/// Warning: this allows requests without a JWT token! Additionally, 401 errors will not be returned,
	/// which will not trigger clients to initiate an oauth flow.
	Permissive,
}

impl From<McpAuthenticationMode> for crate::http::jwt::Mode {
	fn from(value: McpAuthenticationMode) -> crate::http::jwt::Mode {
		match value {
			McpAuthenticationMode::Strict => crate::http::jwt::Mode::Strict,
			McpAuthenticationMode::Optional => crate::http::jwt::Mode::Optional,
			McpAuthenticationMode::Permissive => crate::http::jwt::Mode::Permissive,
		}
	}
}

// Local configuration for MCP authentication
#[apply(schema_de!)]
pub struct LocalMcpAuthentication {
	/// Expected token issuer, matched against the JWT `iss` claim.
	pub issuer: String,
	/// Accepted token audiences, matched against the JWT `aud` claim.
	pub audiences: Vec<String>,
	/// Identity provider type used to derive MCP authorization metadata and default JWKS URLs.
	pub provider: Option<McpIDP>,
	/// Protected resource metadata returned to MCP clients.
	pub resource_metadata: ResourceMetadata,
	/// JSON Web Key Set used to verify token signatures. Can be inline, from a file, or fetched remotely.
	pub jwks: FileInlineOrRemote,
	/// Controls whether MCP requests must include a valid JWT.
	#[serde(default)]
	pub mode: McpAuthenticationMode,
	/// Where to read the JWT from in incoming MCP requests.
	#[serde(default)]
	pub authorization_location: http::auth::AuthorizationLocation,
	/// Claim requirements to enforce after the token signature is verified.
	#[serde(default)]
	pub jwt_validation_options: http::jwt::JWTValidationOptions,
	/// OAuth client ID advertised to MCP clients when needed.
	pub client_id: Option<String>,
}

impl LocalMcpAuthentication {
	pub fn as_jwt(&self) -> anyhow::Result<http::jwt::LocalJwtConfig> {
		let jwks = match &self.jwks {
			FileInlineOrRemote::Remote { url } => FileInlineOrRemote::Remote {
				url: if !url.to_string().is_empty() {
					url.clone()
				} else {
					match &self.provider {
						None | Some(McpIDP::Auth0 { .. }) | Some(McpIDP::Okta { .. }) => {
							format!("{}/.well-known/jwks.json", self.issuer).parse()?
						},
						Some(McpIDP::Descope {}) => {
							// For agentic issuers (https://api.descope.com/v1/apps/agentic/{project-id}/{server-id}),
							// JWKS lives at the project level: https://api.descope.com/{project-id}/.well-known/jwks.json
							let parsed: url::Url = self.issuer.parse()?;
							let segments: Vec<&str> = parsed.path().trim_start_matches('/').split('/').collect();
							if segments.len() >= 5
								&& segments[0] == "v1"
								&& segments[1] == "apps"
								&& segments[2] == "agentic"
							{
								let project_id = segments[3];
								let base = format!(
									"{}://{}/{}",
									parsed.scheme(),
									parsed.host_str().unwrap_or_default(),
									project_id
								);
								format!("{base}/.well-known/jwks.json").parse()?
							} else {
								format!("{}/.well-known/jwks.json", self.issuer).parse()?
							}
						},
						Some(McpIDP::Keycloak { .. }) => {
							format!("{}/protocol/openid-connect/certs", self.issuer).parse()?
						},
					}
				},
			},
			FileInlineOrRemote::Inline(_) | FileInlineOrRemote::File { .. } => self.jwks.clone(),
		};

		Ok(http::jwt::LocalJwtConfig::Single {
			mode: self.mode.into(),
			location: self.authorization_location.clone(),
			issuer: self.issuer.clone(),
			audiences: Some(self.audiences.clone()),
			jwks,
			jwt_validation_options: self.jwt_validation_options.clone(),
		})
	}

	/// Translate the local (file/env) config into a runtime `McpAuthentication` with a ready validator.
	pub async fn translate(
		&self,
		resources: &crate::resource_manager::ResourceFetcher,
	) -> anyhow::Result<McpAuthentication> {
		let jwt_cfg = self.as_jwt()?;
		let jwt = jwt_cfg.try_into(resources).await?;
		Ok(McpAuthentication {
			issuer: self.issuer.clone(),
			audiences: self.audiences.clone(),
			provider: self.provider.clone(),
			resource_metadata: self.resource_metadata.clone(),
			jwt_validator: Arc::new(jwt),
			mode: self.mode,
			client_id: self.client_id.clone(),
		})
	}
}

#[apply(schema!)]
pub enum McpIDP {
	Auth0 {},
	Keycloak {},
	Okta {},
	Descope {},
}

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[cfg_attr(feature = "schema", schemars(with = "String"))]
pub enum Target {
	Address(SocketAddr),
	Hostname(Strng, u16),
	/// Unix domain socket path (e.g., "unix:/path/to/socket")
	UnixSocket(PathBuf),
}

impl<'de> serde::Deserialize<'de> for Target {
	fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
	where
		D: serde::Deserializer<'de>,
	{
		serdes::de_parse(deserializer)
	}
}

impl serde::Serialize for Target {
	fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
	where
		S: serde::Serializer,
	{
		serializer.serialize_str(&self.to_string())
	}
}

impl From<(&str, u16)> for Target {
	fn from((host, port): (&str, u16)) -> Self {
		match host.parse::<IpAddr>() {
			Ok(target) => Target::Address(SocketAddr::new(target, port)),
			Err(_) => Target::Hostname(host.into(), port),
		}
	}
}

impl TryFrom<&str> for Target {
	type Error = anyhow::Error;

	fn try_from(hostport: &str) -> Result<Self, Self::Error> {
		// Check for unix socket prefix
		if let Some(path) = hostport.strip_prefix("unix:") {
			return Ok(Target::UnixSocket(PathBuf::from(path)));
		}
		let Some((host, port)) = hostport.split_once(":") else {
			anyhow::bail!("invalid host:port: {hostport}");
		};
		let port: u16 = port.parse()?;
		Ok((host, port).into())
	}
}

impl Display for Target {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		let str = match self {
			Target::Address(addr) => addr.to_string(),
			Target::Hostname(hostname, port) => format!("{hostname}:{port}"),
			Target::UnixSocket(path) => format!("unix:{}", path.display()),
		};
		write!(f, "{str}")
	}
}

impl Target {
	pub fn hostport(&self) -> String {
		match self {
			Target::Address(addr) => addr.to_string(),
			Target::Hostname(hostname, port) => format!("{hostname}:{port}"),
			Target::UnixSocket(path) => path
				.file_name()
				.and_then(|os| os.to_str())
				.unwrap_or_default()
				.to_string(),
		}
	}
}

#[apply(schema!)]
pub struct KeepaliveConfig {
	#[serde(default = "defaults::always_true")]
	pub enabled: bool,
	#[serde(with = "serde_dur")]
	#[cfg_attr(feature = "schema", schemars(with = "String"))]
	#[serde(default = "defaults::keepalive_time")]
	pub time: Duration,
	#[serde(with = "serde_dur")]
	#[cfg_attr(feature = "schema", schemars(with = "String"))]
	#[serde(default = "defaults::keepalive_interval")]
	pub interval: Duration,
	#[serde(default = "defaults::keepalive_retries")]
	pub retries: u32,
}

impl Default for KeepaliveConfig {
	fn default() -> Self {
		KeepaliveConfig {
			enabled: true,
			time: defaults::keepalive_time(),
			interval: defaults::keepalive_interval(),
			retries: defaults::keepalive_retries(),
		}
	}
}

pub mod defaults {
	use std::time::Duration;

	pub fn always_true() -> bool {
		true
	}
	pub fn keepalive_retries() -> u32 {
		9
	}
	pub fn keepalive_interval() -> Duration {
		Duration::from_secs(180)
	}
	pub fn keepalive_time() -> Duration {
		Duration::from_secs(180)
	}
}
