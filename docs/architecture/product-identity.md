# AI Gateway Platform identity and migration

## Product boundary

This repository is a composable AI Gateway Platform. Its product capabilities are LLM Gateway,
Inference Routing, A2A Gateway, MCP Gateway, and protocol-neutral security controls.

Security is a first-class, optional layer; it does not define the outer product boundary.

## Compatibility boundary

`agentgateway` and `agentgateway-app` are AgentGateway-derived compatibility packages used to
reuse the mature HTTP/proxy runtime during migration. They remain buildable to preserve existing
configuration and integration behavior, but new first-party code must not take a new dependency
on either package when a `crates/gateway/*`, `crates/security/*`, or `crates/platform/*` boundary
is available.

The Apache-2.0 license and upstream attribution for reused AgentGateway code remain in force.

## First-party entry points

| Package | Role | Current implementation |
| --- | --- | --- |
| `ai-gateway-runtime` | Product runtime API | Re-exports the compatibility runtime during migration. |
| `ai-gateway-app` | Product application and `ai-gateway` binary | Delegates to the compatibility application during migration. |
| `gateway-composition` | Compile-time capability contract | First-party implementation. |
| `security-*` | Security contracts and controls | First-party implementation. |

## Security maturity

- S0 provides shared identity normalization and structured audit decisions.
- S1 provides tenant/user/agent/action/resource least-privilege enforcement.
- S2 maps protocol operations into this vocabulary: MCP discovery and per-Tool filtering, MCP
  argument controls, A2A method-level actions, and inference-endpoint authorization.
- S3-A declares high-risk Tools and applies a fail-closed approval gate. The core also has a
  one-time, subject/action/resource/argument-bound `CapabilityBroker`; trusted approval issuance
  and Tool-side consumption remain S3 work.
- S3-C validates direct user-to-Agent delegation from a verified `delegationId` claim against
  configured tenant-scoped, time-bounded operation scopes. The grant only constrains an existing
  policy allow; issuance/revocation and Agent-to-sub-Agent chains remain future work.
- S4-A adds a second dynamic PDP stage. Verified session/client context and time-bounded dynamic
  policies can only narrow a static allow. PDP errors deny by default; an explicit, TTL-bounded
  cache option is limited to low-risk reads. `DynamicPdp` is the integration seam for a remote
  PDP in the next increment.

## Migration rule

New gateway functionality is added to the first-party namespace first. Code is extracted from
the compatibility runtime only after its request, response, configuration, and test interfaces
are stable. This prevents a repository-wide rename from obscuring functional changes.
