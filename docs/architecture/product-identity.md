# AI Security Platform identity and architecture

## Product boundary

This repository is a composable AI Security Platform. Its product capabilities are LLM Gateway,
Inference Routing, A2A Gateway, MCP Gateway, and protocol-neutral security controls.

Security is a first-class, optional layer; it does not define the outer product boundary.

## Runtime ownership

The complete Rust runtime is owned by `crates/gateway/runtime` as the `ai-security-platform-runtime`
package. The application and all product binaries are owned by `crates/gateway/app` as
`ai-security-platform-app`. No `agentgateway` or `agentgateway-app` package remains in the workspace.

Some runtime source originated from AgentGateway and retains the required Apache-2.0 license and
source attribution. That provenance does not create a compatibility layer or a dependency boundary
in the current project.

## First-party entry points

| Package | Role | Current implementation |
| --- | --- | --- |
| `ai-security-platform-runtime` | Product runtime API | Complete protocol runtime implementation. |
| `ai-security-platform-app` | Product application and `ai-security-platform` binary | Complete CLI and application implementation. |
| `gateway-composition` | Compile-time capability contract | First-party implementation. |
| `security-*` | Security contracts and controls | First-party implementation. |

## Security maturity

- S0 provides shared identity normalization and structured audit decisions.
- S1 provides tenant/user/agent/action/resource least-privilege enforcement.
- S2 maps protocol operations into this vocabulary: MCP discovery and per-Tool filtering, MCP
  argument controls, A2A method-level actions, and inference-endpoint authorization.
- S3-A declares high-risk Tools and applies a fail-closed approval gate. `approval` binds a trusted
  HTTPS/mTLS authority to the common runtime pipeline; its response is bound to the normalized
  request, argument hash, and expiry. The core also has a one-time,
  subject/action/resource/argument-bound `CapabilityBroker`. `capabilityBroker` issues the shared
  broker's opaque token after an approved MCP Tool call and forwards it with the gateway-normalized
  action context only through internal upstream headers; caller-supplied capability/context headers
  are stripped. A protected Tool/API consumer hashes the actual parameters and atomically consumes
  the token before it performs a side effect.
- S3-C validates direct user-to-Agent delegation from a verified `delegationId` claim against
  configured tenant-scoped, time-bounded operation scopes. The grant only constrains an existing
  policy allow; issuance/revocation and Agent-to-sub-Agent chains remain future work.
- S3-D treats `agentId` as a registered principal rather than a free-form authorization attribute.
  `agentIdentity` binds an already verified JWT claim to an enabled Agent record, its tenant, an
  allowed OAuth client/workload identity, and an optional validity period before policy or
  delegation evaluation. The static registry is replaceable through the identity-control seam by a
  remote directory or certificate/SPIFFE-backed attestation source. `remoteAgentIdentity` is the
  first implementation of that seam: an HTTPS/mTLS, no-allow-cache directory lookup bound to the
  verified Agent, tenant, and OAuth client identity.
- S4-A adds a second dynamic PDP stage. Verified session/client context and time-bounded dynamic
  policies can only narrow a static allow. PDP errors deny by default; an explicit, TTL-bounded
  cache option is limited to low-risk reads.
- S4-B implements the versioned remote PDP contract at runtime. The gateway uses a reusable,
  timeout-bounded Rustls HTTPS client with optional mTLS identity and private CA files; response
  request binding, policy version, and expiry are validated before a decision is accepted. The
  cache is capped by PDP expiry and all transport/configuration failures deny. It also provides a
  fail-closed `DelegationRevocationCheck` brick. `delegationRevocation` now connects that stage to
  a shared HTTPS/mTLS source and queries it without an allow cache for each verified delegation;
  the in-process registry remains available only for tests and local PoCs.

## Development rule

New functionality is added directly to `crates/gateway`, `crates/security`, or
`crates/platform`. Protocol modules are extracted from `ai-security-platform-runtime` only after their
request, response, configuration, and test interfaces are stable.
