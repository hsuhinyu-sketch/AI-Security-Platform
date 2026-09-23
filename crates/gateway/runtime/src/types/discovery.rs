use std::collections::HashMap;
use std::fmt;
use std::fmt::{Formatter, Write};
use std::hash::Hash;
use std::net::IpAddr;
use std::str::FromStr;

use anyhow::anyhow;
use prometheus_client::encoding::{EncodeLabelValue, LabelValueEncoder};
use serde::de::Visitor;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::types::loadbalancer;
use crate::types::proto::ProtoError;
use crate::*;

#[derive(Debug, Eq, PartialEq, Hash, Clone)]
pub struct NamespacedHostname {
	pub namespace: Strng,
	pub hostname: Strng,
}

#[cfg(feature = "schema")]
impl schemars::JsonSchema for NamespacedHostname {
	fn schema_name() -> std::borrow::Cow<'static, str> {
		"NamespacedHostname".into()
	}

	fn schema_id() -> std::borrow::Cow<'static, str> {
		"NamespacedHostname".into()
	}

	fn json_schema(_gen: &mut schemars::SchemaGenerator) -> schemars::Schema {
		schemars::json_schema!({
			"type": "string"
		})
	}
}

impl NamespacedHostname {
	pub fn as_policy_target_ref(&self) -> super::agent::PolicyTargetRef {
		super::agent::PolicyTargetRef::Backend(super::agent::BackendTargetRef::Service {
			hostname: &self.hostname,
			namespace: &self.namespace,
			port: None,
		})
	}
}

impl FromStr for NamespacedHostname {
	type Err = ProtoError;

	fn from_str(value: &str) -> Result<Self, Self::Err> {
		let Some((namespace, hostname)) = value.split_once('/') else {
			return Err(ProtoError::NamespacedHostnameParse(value.to_string()));
		};
		Ok(Self {
			namespace: namespace.into(),
			hostname: hostname.into(),
		})
	}
}

// we need custom serde serialization since NamespacedHostname is keying maps
impl Serialize for NamespacedHostname {
	fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
	where
		S: Serializer,
	{
		serializer.collect_str(&self)
	}
}

// we need custom serde deserialization because we have custom serialization
impl<'de> Deserialize<'de> for NamespacedHostname {
	fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
	where
		D: Deserializer<'de>,
	{
		struct NamespacedHostnameVisitor;

		impl Visitor<'_> for NamespacedHostnameVisitor {
			type Value = NamespacedHostname;

			fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
				formatter.write_str("string for NamespacedHostname with format namespace/hostname")
			}

			fn visit_str<E>(self, value: &str) -> Result<NamespacedHostname, E>
			where
				E: serde::de::Error,
			{
				NamespacedHostname::from_str(value)
					.map_err(|_| serde::de::Error::invalid_value(serde::de::Unexpected::Str(value), &self))
			}
		}
		deserializer.deserialize_str(NamespacedHostnameVisitor)
	}
}

impl fmt::Display for NamespacedHostname {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		write!(f, "{}/{}", self.namespace, self.hostname)
	}
}

/// Structured identity for a waypoint proxy, used for self-verification
/// when routing HBONE waypoint traffic.
#[derive(Debug, Clone, serde::Serialize)]
pub struct WaypointIdentity {
	pub gateway: Strng,
	pub namespace: Strng,
}

impl WaypointIdentity {
	/// Returns the default full Kubernetes FQDN for this waypoint.
	/// TODO: we don't know the cluster domain, so we potentially return the wrong hostname for this waypoint.
	pub fn hostname(&self) -> Strng {
		strng::format!("{}.{}.svc.cluster.local", self.gateway, self.namespace)
	}

	/// Checks whether this waypoint identity matches a NamespacedHostname waypoint destination.
	/// Assumes the hostname starts with `{gateway name}.{namespace}` but the suffix
	/// may be customized.
	pub fn matches_hostname(&self, nh: &NamespacedHostname) -> bool {
		nh.namespace == self.namespace
			&& nh
				.hostname
				.strip_prefix(self.gateway.as_str())
				.and_then(|s| s.strip_prefix('.'))
				.and_then(|s| s.strip_prefix(self.namespace.as_str()))
				.is_some_and(|s| s.starts_with('.') && s.len() > 1)
	}

	/// Checks whether this waypoint identity matches an Address-based waypoint destination
	/// by resolving the service at `addr` and comparing its (name, namespace) to this waypoint's
	/// (gateway, namespace).
	pub fn matches_address(
		&self,
		addr: &NetworkAddress,
		get_service_at: impl FnOnce(&NetworkAddress) -> Option<(Strng, Strng)>,
	) -> bool {
		match get_service_at(addr) {
			Some((name, ns)) => name == self.gateway && ns == self.namespace,
			None => {
				warn!(
					"waypoint {}.{} cannot resolve service at {} for address verification",
					self.gateway, self.namespace, addr
				);
				false
			},
		}
	}
}

#[derive(Debug, Eq, PartialEq, Hash, Clone)]
pub struct NetworkAddress {
	pub network: Strng,
	pub address: IpAddr,
}

// we need custom serde serialization since NetworkAddress is keying maps
impl Serialize for NetworkAddress {
	fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
	where
		S: Serializer,
	{
		serializer.collect_str(&self)
	}
}

impl fmt::Display for NetworkAddress {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		f.write_str(&self.network)?;
		f.write_char('/')?;
		f.write_str(&self.address.to_string())
	}
}

// we need custom serde deserialization because we have custom serialization
impl<'de> Deserialize<'de> for NetworkAddress {
	fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
	where
		D: Deserializer<'de>,
	{
		struct NetworkAddressVisitor;

		impl Visitor<'_> for NetworkAddressVisitor {
			type Value = NetworkAddress;

			fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
				formatter.write_str("string for NetworkAddress with format network/IP")
			}

			fn visit_str<E>(self, value: &str) -> Result<NetworkAddress, E>
			where
				E: serde::de::Error,
			{
				let Some((network, address)) = value.split_once('/') else {
					return Err(serde::de::Error::invalid_value(
						serde::de::Unexpected::Str(value),
						&self,
					));
				};
				let Ok(ip_addr) = IpAddr::from_str(address) else {
					return Err(serde::de::Error::invalid_value(
						serde::de::Unexpected::Str(value),
						&self,
					));
				};
				Ok(NetworkAddress {
					network: network.into(),
					address: ip_addr,
				})
			}
		}
		deserializer.deserialize_str(NetworkAddressVisitor)
	}
}

/// Identifies the agentgateway's own workload for locality-aware load balancing.
///
/// All fields come directly from the standalone configuration or environment.
#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub enum SelfIdentitySource {
	Static(Arc<Workload>),
}

#[derive(Debug, Eq, PartialEq, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Workload {
	pub workload_ips: Vec<IpAddr>,

	#[serde(default, skip_serializing_if = "is_default")]
	pub waypoint: Option<GatewayAddress>,
	#[serde(default, skip_serializing_if = "is_default")]
	pub network_gateway: Option<GatewayAddress>,

	#[serde(default)]
	pub protocol: InboundProtocol,
	#[serde(default)]
	pub network_mode: NetworkMode,

	#[serde(default, skip_serializing_if = "is_default")]
	pub uid: Strng,
	#[serde(default)]
	pub name: Strng,
	pub namespace: Strng,
	#[serde(default, skip_serializing_if = "is_default")]
	pub trust_domain: Strng,
	#[serde(default, skip_serializing_if = "is_default")]
	pub service_account: Strng,
	#[serde(default, skip_serializing_if = "is_default")]
	pub network: Strng,

	#[serde(default, skip_serializing_if = "is_default")]
	pub workload_name: Strng,
	#[serde(default, skip_serializing_if = "is_default")]
	pub workload_type: Strng,
	#[serde(default, skip_serializing_if = "is_default")]
	pub canonical_name: Strng,
	#[serde(default, skip_serializing_if = "is_default")]
	pub canonical_revision: Strng,

	#[serde(default, skip_serializing_if = "is_default")]
	pub hostname: Strng,

	#[serde(default, skip_serializing_if = "is_default")]
	pub node: Strng,

	#[serde(default, skip_serializing_if = "is_default")]
	pub authorization_policies: Vec<Strng>,

	#[serde(default)]
	pub status: HealthStatus,

	#[serde(default)]
	pub cluster_id: Strng,

	#[serde(default, skip_serializing_if = "is_default")]
	pub locality: Locality,

	#[serde(default, skip_serializing_if = "is_default")]
	pub services: HashMap<NamespacedHostname, HashMap<u16, u16>>,

	#[serde(default, skip_serializing_if = "is_default")]
	pub hbone_mtls_port: u16,

	#[serde(default = "default_capacity")]
	pub capacity: u32,
}

pub fn default_capacity() -> u32 {
	1
}

impl Default for Workload {
	fn default() -> Self {
		Self {
			workload_ips: Default::default(),
			waypoint: Default::default(),
			network_gateway: Default::default(),
			protocol: Default::default(),
			network_mode: Default::default(),
			uid: Default::default(),
			name: Default::default(),
			namespace: Default::default(),
			trust_domain: Default::default(),
			service_account: Default::default(),
			network: Default::default(),
			workload_name: Default::default(),
			workload_type: Default::default(),
			canonical_name: Default::default(),
			canonical_revision: Default::default(),
			hostname: Default::default(),
			node: Default::default(),
			authorization_policies: Default::default(),
			status: Default::default(),
			cluster_id: Default::default(),
			locality: Default::default(),
			services: Default::default(),
			hbone_mtls_port: Default::default(),

			// default capacity to 1, as 0 means this workload should not receive traffic
			capacity: default_capacity(),
		}
	}
}

impl Workload {
	pub fn identity(&self) -> Identity {
		Identity::Spiffe {
			trust_domain: self.trust_domain.clone(),
			namespace: self.namespace.clone(),
			service_account: self.service_account.clone(),
		}
	}
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Hash)]
pub enum Identity {
	Spiffe {
		trust_domain: Strng,
		namespace: Strng,
		service_account: Strng,
	},
}

impl EncodeLabelValue for Identity {
	fn encode(&self, writer: &mut LabelValueEncoder) -> Result<(), std::fmt::Error> {
		writer.write_str(&self.to_string())
	}
}

impl serde::Serialize for Identity {
	fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
	where
		S: serde::Serializer,
	{
		self.to_string().serialize(serializer)
	}
}

impl<'de> serde::Deserialize<'de> for Identity {
	fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
	where
		D: serde::Deserializer<'de>,
	{
		let s = String::deserialize(deserializer)?;
		Identity::from_str(&s).map_err(serde::de::Error::custom)
	}
}

impl FromStr for Identity {
	type Err = anyhow::Error;
	fn from_str(s: &str) -> Result<Self, Self::Err> {
		const URI_PREFIX: &str = "spiffe://";
		const SERVICE_ACCOUNT: &str = "sa";
		const NAMESPACE: &str = "ns";
		if !s.starts_with(URI_PREFIX) {
			return Err(anyhow!("invalid spiffe: {s}"));
		}
		let split: Vec<_> = s[URI_PREFIX.len()..].split('/').collect();
		if split.len() != 5 {
			return Err(anyhow!("invalid spiffe: {s}"));
		}
		if split[1] != NAMESPACE || split[3] != SERVICE_ACCOUNT {
			return Err(anyhow!("invalid spiffe: {s}"));
		}
		Ok(Identity::Spiffe {
			trust_domain: split[0].into(),
			namespace: split[2].into(),
			service_account: split[4].into(),
		})
	}
}

impl Display for Identity {
	fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
		match self {
			Identity::Spiffe {
				trust_domain,
				namespace,
				service_account,
			} => {
				write!(
					f,
					"spiffe://{trust_domain}/ns/{namespace}/sa/{service_account}"
				)
			},
		}
	}
}

impl Identity {
	pub fn from_parts(td: Strng, ns: Strng, sa: Strng) -> Identity {
		Identity::Spiffe {
			trust_domain: td,
			namespace: ns,
			service_account: sa,
		}
	}

	pub fn to_strng(self: &Identity) -> Strng {
		match self {
			Identity::Spiffe {
				trust_domain,
				namespace,
				service_account,
			} => {
				strng::format!("spiffe://{trust_domain}/ns/{namespace}/sa/{service_account}")
			},
		}
	}

	pub fn trust_domain(&self) -> Strng {
		match self {
			Identity::Spiffe { trust_domain, .. } => trust_domain.clone(),
		}
	}
}

fn is_default<T: Default + PartialEq>(t: &T) -> bool {
	*t == Default::default()
}

// The protocol that the sender should use to send data. Can be different from ServerProtocol when there is a
// agentgateway in the middle (e.g. e/w gateway with double hbone).
#[derive(
	Default,
	Debug,
	Hash,
	Eq,
	PartialEq,
	Ord,
	PartialOrd,
	Clone,
	Copy,
	serde::Serialize,
	serde::Deserialize,
)]
pub enum OutboundProtocol {
	#[default]
	TCP,
	HBONE,
	DOUBLEHBONE,
}

#[derive(
	Default, Debug, Hash, Eq, PartialEq, Clone, Copy, serde::Serialize, serde::Deserialize,
)]
pub enum NetworkMode {
	#[default]
	Standard,
	HostNetwork,
}

#[derive(
	Default, Debug, Hash, Eq, PartialEq, Clone, Copy, serde::Serialize, serde::Deserialize,
)]
pub enum HealthStatus {
	#[default]
	Healthy,
	Unhealthy,
}

#[derive(Default, Debug, Hash, Eq, PartialEq, Clone, serde::Serialize, serde::Deserialize)]
pub struct Locality {
	pub region: Strng,
	pub zone: Strng,
	pub subzone: Strng,
}

impl Locality {
	/// Parse an Istio-style locality string "region/zone/subzone" (trailing parts optional).
	pub fn parse(s: &str) -> Self {
		let mut parts = s.splitn(3, '/');
		Locality {
			region: parts.next().unwrap_or_default().into(),
			zone: parts.next().unwrap_or_default().into(),
			subzone: parts.next().unwrap_or_default().into(),
		}
	}
}

#[derive(Debug, Hash, Eq, PartialEq, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GatewayAddress {
	pub destination: gatewayaddress::Destination,
	pub hbone_mtls_port: u16,
}

pub mod gatewayaddress {
	use super::{NamespacedHostname, NetworkAddress};
	#[derive(Debug, Hash, Eq, PartialEq, Clone, serde::Serialize, serde::Deserialize)]
	#[serde(untagged)]
	pub enum Destination {
		Address(NetworkAddress),
		Hostname(NamespacedHostname),
	}
}

// The protocol that the final workload expects
#[derive(
	Default,
	Debug,
	Hash,
	Eq,
	PartialEq,
	Ord,
	PartialOrd,
	Clone,
	Copy,
	serde::Serialize,
	serde::Deserialize,
)]
pub enum InboundProtocol {
	#[default]
	TCP,
	HBONE,
	LegacyIstioMtls,
}

#[derive(Debug, Default, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Service {
	pub name: Strng,
	pub namespace: Strng,
	pub hostname: Strng,
	pub vips: Vec<NetworkAddress>,
	pub ports: HashMap<u16, u16>,
	#[serde(default)]
	pub app_protocols: HashMap<u16, AppProtocol>,

	/// Maps endpoint UIDs to service [Endpoint]s.
	#[serde(default, skip_deserializing)]
	pub endpoints: loadbalancer::EndpointSet<Endpoint>,
	#[serde(default)]
	pub subject_alt_names: Vec<Identity>,

	#[serde(default, skip_serializing_if = "is_default")]
	pub waypoint: Option<GatewayAddress>,

	#[serde(default, skip_serializing_if = "is_default")]
	pub load_balancer: Option<LoadBalancer>,

	#[serde(default, skip_serializing_if = "is_default")]
	pub ip_families: Option<IpFamily>,

	/// When true, ingress gateways should send traffic destined for this service
	/// through the service's waypoint proxy.
	#[serde(default, skip_serializing_if = "is_default")]
	pub ingress_use_waypoint: bool,
}

impl Service {
	pub fn port_is_http2(&self, port: u16) -> bool {
		matches!(
			self.app_protocols.get(&port),
			Some(AppProtocol::Http2 | AppProtocol::Grpc)
		)
	}
	pub fn port_is_http1(&self, port: u16) -> bool {
		matches!(self.app_protocols.get(&port), Some(AppProtocol::Http11))
	}
	pub fn port_is_tcp(&self, port: u16) -> bool {
		matches!(
			self.app_protocols.get(&port),
			Some(AppProtocol::Tcp | AppProtocol::Tls)
		)
	}
	pub fn port_is_tls(&self, port: u16) -> bool {
		matches!(self.app_protocols.get(&port), Some(AppProtocol::Tls))
	}
	pub fn namespaced_hostname(&self) -> NamespacedHostname {
		NamespacedHostname {
			namespace: self.namespace.clone(),
			hostname: self.hostname.clone(),
		}
	}
	pub fn should_include_endpoint(&self, ep_health: HealthStatus) -> bool {
		ep_health == HealthStatus::Healthy
			|| self
				.load_balancer
				.as_ref()
				.map(|lb| lb.health_policy == LoadBalancerHealthPolicy::AllowAll)
				.unwrap_or(false)
	}
}

#[derive(Debug, Eq, PartialEq, Clone, Copy, serde::Serialize, serde::Deserialize)]
pub enum AppProtocol {
	Http11,
	Http2,
	Grpc,
	Tls,
	Tcp,
}

#[derive(Debug, Eq, PartialEq, Clone, Copy, serde::Serialize, serde::Deserialize)]
pub enum IpFamily {
	Dual,
	IPv4,
	IPv6,
}

impl IpFamily {
	/// accepts_ip returns true if the provided IP is supposed by the IP family
	pub fn accepts_ip(&self, ip: IpAddr) -> bool {
		match self {
			IpFamily::Dual => true,
			IpFamily::IPv4 => ip.is_ipv4(),
			IpFamily::IPv6 => ip.is_ipv6(),
		}
	}
}

#[derive(Debug, Eq, PartialEq, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LoadBalancer {
	pub routing_preferences: Vec<LoadBalancerScopes>,
	pub mode: LoadBalancerMode,
	pub health_policy: LoadBalancerHealthPolicy,
}

#[derive(Debug, Eq, PartialEq, Clone, serde::Serialize, serde::Deserialize)]
pub enum LoadBalancerScopes {
	Region,
	Zone,
	Subzone,
	Node,
	Cluster,
	Network,
}

#[derive(Default, Debug, Eq, PartialEq, Clone, serde::Serialize, serde::Deserialize)]
pub enum LoadBalancerHealthPolicy {
	#[default]
	OnlyHealthy,
	AllowAll,
}
#[derive(Debug, Eq, PartialEq, Clone, serde::Serialize, serde::Deserialize)]
pub enum LoadBalancerMode {
	// Do not consider LoadBalancerScopes when picking endpoints
	Standard,
	// Only select endpoints matching all LoadBalancerScopes when picking endpoints; otherwise, fail.
	Strict,
	// Prefer select endpoints matching all LoadBalancerScopes when picking endpoints but allow mismatches
	Failover,
	// In PASSTHROUGH mode, endpoint selection will not be done and traffic passes directly through to the original
	// destination address.
	Passthrough,
}

#[derive(Debug, Eq, PartialEq, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Endpoint {
	/// The workload UID for this endpoint.
	pub workload_uid: Strng,

	/// The port mapping.
	pub port: HashMap<u16, u16>,

	/// Health status for the endpoint
	pub status: HealthStatus,
}
