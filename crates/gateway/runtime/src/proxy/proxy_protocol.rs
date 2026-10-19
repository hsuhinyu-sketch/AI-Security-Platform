//! PROXY protocol parser for downstream connections.
//!
//! When agentgateway operates as an Istio ambient mesh waypoint in "sandwich" mode,
//! ztunnel handles mTLS termination and forwards traffic to the waypoint using
//! PROXY protocol. This module parses the PROXY header to extract:
//!
//! - Original source/destination addresses (standard PROXY protocol)
//! - Peer identity from TLV 0xD0 (SPIFFE URI of the source workload, v2 only)
//!
//! The extracted identity flows through to CEL authorization via TLSConnectionInfo.

use std::net::SocketAddr;

use anyhow::{anyhow, bail};
use ppp::{HeaderResult, PartialResult, v1, v2};
use tokio::io::{AsyncRead, AsyncReadExt};
use tracing::trace;

use crate::transport::tls::IstioIdentity;
use crate::types::discovery::Identity;
use crate::types::frontend;

/// TLV type for peer identity (SPIFFE URI) - matches ztunnel's PROXY_PROTOCOL_AUTHORITY_TLV
const PROXY_PROTOCOL_AUTHORITY_TLV: u8 = 0xD0;

/// PROXY protocol v1 prefix
const PROXY_V1_PREFIX: &[u8] = b"PROXY";

/// Maximum allowed PROXY v1 header length.
const PROXY_V1_MAX_HEADER_LEN: usize = 107;

/// PROXY protocol v2 signature (12 bytes)
const PROXY_V2_SIGNATURE: [u8; 12] = [
	0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A,
];

/// Minimum header size: 12 (signature) + 4 (version/command/family/length)
const PROXY_V2_MIN_HEADER: usize = 16;

/// Maximum allowed address/TLV data size.
/// IPv6 addresses need 36 bytes, plus TLVs. 512 bytes is plenty for typical use
/// (ztunnel only sends identity TLV) while preventing allocation attacks.
const PROXY_V2_MAX_ADDR_LEN: usize = 512;
const PROXY_V2_MAX_HEADER_LEN: usize = PROXY_V2_MIN_HEADER + PROXY_V2_MAX_ADDR_LEN;
const READ_CHUNK_LEN: usize = 64;

/// Information extracted from a PROXY protocol header.
#[derive(Debug)]
pub struct ProxyProtocolInfo {
	/// Original source address of the client (before the forwarding proxy), when provided.
	pub src_addr: Option<SocketAddr>,
	/// Original destination address (the service VIP), when provided.
	pub dst_addr: Option<SocketAddr>,
	/// Peer identity extracted from TLV 0xD0, if present
	pub peer_identity: Option<IstioIdentity>,
}

#[derive(Debug)]
pub struct ParsedProxyProtocol {
	pub info: ProxyProtocolInfo,
	pub consumed_len: usize,
}

fn parse_v1_header(header: v1::Header<'_>) -> anyhow::Result<ProxyProtocolInfo> {
	let (src_addr, dst_addr) = match header.addresses {
		v1::Addresses::Tcp4(a) => (
			Some(SocketAddr::new(a.source_address.into(), a.source_port)),
			Some(SocketAddr::new(
				a.destination_address.into(),
				a.destination_port,
			)),
		),
		v1::Addresses::Tcp6(a) => (
			Some(SocketAddr::new(a.source_address.into(), a.source_port)),
			Some(SocketAddr::new(
				a.destination_address.into(),
				a.destination_port,
			)),
		),
		v1::Addresses::Unknown => (None, None),
	};

	trace!(src = ?src_addr, dst = ?dst_addr, "parsed PROXY protocol v1 header");

	Ok(ProxyProtocolInfo {
		src_addr,
		dst_addr,
		peer_identity: None,
	})
}

fn parse_v2_header(header: v2::Header<'_>) -> anyhow::Result<ProxyProtocolInfo> {
	if header.command == v2::Command::Local {
		trace!("parsed PROXY protocol v2 LOCAL header");
		return Ok(ProxyProtocolInfo {
			src_addr: None,
			dst_addr: None,
			peer_identity: None,
		});
	}

	let (src_addr, dst_addr) = match header.addresses {
		v2::Addresses::IPv4(ref a) => (
			Some(SocketAddr::new(a.source_address.into(), a.source_port)),
			Some(SocketAddr::new(
				a.destination_address.into(),
				a.destination_port,
			)),
		),
		v2::Addresses::IPv6(ref a) => (
			Some(SocketAddr::new(a.source_address.into(), a.source_port)),
			Some(SocketAddr::new(
				a.destination_address.into(),
				a.destination_port,
			)),
		),
		v2::Addresses::Unspecified => (None, None),
		v2::Addresses::Unix(_) => bail!("unsupported PROXY protocol address family"),
	};

	let peer_identity = header
		.tlvs()
		.filter_map(|t| t.ok())
		.find(|t| t.kind == PROXY_PROTOCOL_AUTHORITY_TLV)
		.and_then(|t| parse_spiffe_identity(&t.value));

	trace!(
		src = ?src_addr,
		dst = ?dst_addr,
		identity = ?peer_identity,
		"parsed PROXY protocol v2 header"
	);

	Ok(ProxyProtocolInfo {
		src_addr,
		dst_addr,
		peer_identity,
	})
}

fn could_be_v1_prefix(buffer: &[u8]) -> bool {
	if buffer.len() <= PROXY_V1_PREFIX.len() {
		PROXY_V1_PREFIX.starts_with(buffer)
	} else {
		buffer.starts_with(PROXY_V1_PREFIX)
	}
}

fn could_be_v2_prefix(buffer: &[u8]) -> bool {
	if buffer.len() <= PROXY_V2_SIGNATURE.len() {
		PROXY_V2_SIGNATURE.starts_with(buffer)
	} else {
		buffer.starts_with(&PROXY_V2_SIGNATURE)
	}
}

fn v1_header_complete(buffer: &[u8]) -> bool {
	buffer.windows(2).any(|w| w == b"\r\n")
}

/// Detect and parse a PROXY protocol header from stream.
///
/// Returns `Ok(None)` when the stream clearly does not start with a PROXY header.
/// The caller is responsible for rewinding any consumed bytes if passthrough is allowed.
pub async fn detect_proxy_protocol<S: AsyncRead + Unpin>(
	stream: &mut S,
	allowed_version: frontend::ProxyVersion,
) -> anyhow::Result<Option<ParsedProxyProtocol>> {
	let mut buffer = Vec::with_capacity(PROXY_V2_MIN_HEADER);
	let mut chunk = [0; READ_CHUNK_LEN];

	loop {
		let could_be_proxy = could_be_v1_prefix(&buffer) || could_be_v2_prefix(&buffer);
		match HeaderResult::parse(&buffer) {
			HeaderResult::V1(Ok(header)) => {
				if !allowed_version.allows_v1() {
					bail!(
						"received PROXY protocol v1 header but policy only allows {}",
						allowed_version
					);
				}
				let consumed_len = header.header.len();
				return Ok(Some(ParsedProxyProtocol {
					info: parse_v1_header(header)?,
					consumed_len,
				}));
			},
			HeaderResult::V2(Ok(header)) => {
				if !allowed_version.allows_v2() {
					bail!(
						"received PROXY protocol v2 header but policy only allows {}",
						allowed_version
					);
				}
				let consumed_len = header.len();
				return Ok(Some(ParsedProxyProtocol {
					info: parse_v2_header(header)?,
					consumed_len,
				}));
			},
			result if result.is_incomplete() => {
				if !could_be_proxy {
					return Ok(None);
				}
				if buffer.starts_with(PROXY_V1_PREFIX) && buffer.len() > PROXY_V1_MAX_HEADER_LEN {
					bail!(
						"PROXY protocol v1 header exceeded maximum {} bytes",
						PROXY_V1_MAX_HEADER_LEN
					);
				}
				if could_be_v2_prefix(&buffer) && buffer.len() > PROXY_V2_MAX_HEADER_LEN {
					bail!(
						"PROXY protocol header exceeded maximum {} bytes",
						PROXY_V2_MAX_HEADER_LEN
					);
				}
			},
			HeaderResult::V1(Err(err)) => {
				if could_be_v1_prefix(&buffer)
					&& !v1_header_complete(&buffer)
					&& buffer.len() < PROXY_V1_MAX_HEADER_LEN
				{
					// Keep reading until the line terminator or the maximum header length.
				} else if could_be_proxy {
					bail!("invalid PROXY protocol v1 header: {err:?}");
				} else {
					return Ok(None);
				}
			},
			HeaderResult::V2(Err(err)) => {
				if could_be_proxy {
					bail!("invalid PROXY protocol v2 header: {err:?}");
				}
				return Ok(None);
			},
		}

		match stream.read(&mut chunk).await {
			Ok(0) => {
				if buffer.is_empty() {
					return Ok(None);
				}
				if could_be_v1_prefix(&buffer) || could_be_v2_prefix(&buffer) {
					return Err(anyhow!(
						"unexpected EOF while reading PROXY protocol header"
					));
				}
				return Ok(None);
			},
			Ok(n) => buffer.extend_from_slice(&chunk[..n]),
			Err(err) => return Err(err.into()),
		}
	}
}

/// Parse a required PROXY protocol header from stream.
pub async fn parse_proxy_protocol<S: AsyncRead + Unpin>(
	stream: &mut S,
	allowed_version: frontend::ProxyVersion,
) -> anyhow::Result<ParsedProxyProtocol> {
	detect_proxy_protocol(stream, allowed_version)
		.await?
		.ok_or_else(|| anyhow!("expected PROXY protocol {} header", allowed_version))
}

/// Parse a SPIFFE URI into IstioIdentity components.
///
/// Uses the existing `Identity::FromStr` implementation for parsing,
/// then converts to `IstioIdentity` for compatibility with `TLSConnectionInfo`.
///
/// Expected format: `spiffe://trust-domain/ns/namespace/sa/service-account`
fn parse_spiffe_identity(data: &[u8]) -> Option<IstioIdentity> {
	let uri = std::str::from_utf8(data).ok()?;
	// Use existing Identity::FromStr impl (types/discovery.rs)
	let identity: Identity = uri.parse().ok()?;
	// Convert to IstioIdentity (same pattern as tls.rs:577-588)
	let Identity::Spiffe {
		trust_domain,
		namespace,
		service_account,
	} = identity;
	Some(IstioIdentity::new(trust_domain, namespace, service_account))
}
