# AI Gateway Platform

Composable Rust-first AI gateway platform. Security is a core, optional capability rather than
the boundary of the product.

## Current scope

- Gateway: compose LLM, inference-routing, A2A, and MCP protocol gateways for each AI system.
- Security engine: normalize requests and return fail-closed ALLOW / DENY decisions.
- Policy: tenant/user/agent/action/resource matching, deny override, and priority.
- Tool enforcement: issue short-lived, one-time capabilities bound to an authorized request and its arguments.
- Audit: create an event for every security decision; the PoC includes an in-memory sink.
- Composition: assemble an identity control, an authorizer, optional action controls, optional capability broker, and an audit sink into a `SecurityPipeline`.

`agentgateway` is an AgentGateway-derived compatibility runtime used during migration; it is not
the product boundary. New platform code is introduced under `crates/gateway/*`,
`crates/security/*`, and `crates/platform/*`.

The capability broker is intentionally process-local for the PoC. A production deployment must
replace it with a durable, encrypted broker and place the protected Tool/API behind a network
boundary that only the broker can reach.

## Composable security pipeline

`gateway-adapter` provides small security bricks rather than a mandatory all-in-one gateway:

```rust
let pipeline = SecurityPipeline::new(PolicyAuthorizer::new(policies), audit_sink)
    .add_identity_control(RequiredIdentity::user_agent_tenant())
    .add_action_control(RequiredToolArguments::new("db.delete", ["recordId"]))
    .add_action_control(ToolApproval::new("db.delete", approval_provider))
    .with_capability_broker();
```

Identity controls run first, authorization is mandatory, action controls run only after an
allow decision, and the capability broker is optional. Each outcome is sent to the configured
audit sink.

## MCP route configuration

Attach `securityPipeline` under a route or MCP backend `policies` block. When this block is
present, every MCP `tools/call` is normalized from the validated JWT claims and checked before
the upstream Tool is contacted. `sub`, `agentId`/`agent_id`, and `tenantId`/`tenant_id` map to
the security User, Agent, and Tenant respectively.

```yaml
binds:
- port: 3000
  listeners:
  - routes:
    - policies:
        securityPipeline:
          requiredIdentity:
            user: true
            agent: true
            tenant: true
          policies:
          - id: allow-maintenance-delete
            tenantId: tenant-a
            userId: alice
            agentId: maintenance-agent
            actionType: toolInvoke
            actionName: db.delete
            resourceId: db.delete
            resourceType: tool
            effect: allow
            enabled: true
          requiredToolArguments:
          - toolName: db.delete
            requiredFields: [recordId]
      backends:
      - mcp:
          targets: [] # configure actual MCP targets here
```

The configuration is dynamically reloaded with the existing local configuration watcher. The
first production integration deliberately covers `tools/call`; Tool-list filtering and LLM-route
enforcement are the next route adapters to add.

## AI system gateway composition

`aiSystems` assembles protocol gateways for one AI system. Each enabled gateway gets a separate
listener, route, and backend namespace, so a system may expose only LLM, LLM with endpoint-picker
inference routing, LLM plus A2A, or all three LLM/A2A/MCP gateways without changing code.

```yaml
aiSystems:
- name: support-agent
  llm:
    port: 4100
    policies:
      inferenceRouting:
        endpointPicker:
          host: 127.0.0.1:9300
        destinationMode: passthrough
    models:
    - name: support-chat
      provider: openAI
  a2a:
    port: 4101
    backend:
      host: 127.0.0.1:8100 # Agent runtime
  mcp:
    port: 4102
    targets:
    - name: customer-tools
      mcp:
        host: 127.0.0.1:8200
```

The A2A gateway automatically adds the A2A protocol adapter to its backend route. LLM
`inferenceRouting` is attached to each generated model backend, allowing an endpoint picker to
select an edge or cloud inference destination. Ports must be unique across all listeners.

### Compile-time gateway profiles

The default `ai-gateway` build retains every gateway capability for compatibility. A selected
profile rejects configuration for
capabilities that were not selected at build time, so deployment configuration cannot accidentally
enable an unapproved gateway surface.

```bash
# LLM only
cargo build -p ai-gateway-app --bin ai-gateway --no-default-features \
  --features tls-aws-lc,mimalloc,runtime-base,gateway-llm

# LLM plus multiple inference endpoints / routing
cargo build -p ai-gateway-app --bin ai-gateway --no-default-features \
  --features tls-aws-lc,mimalloc,runtime-base,gateway-llm,inference-routing

# LLM plus an A2A agent runtime
cargo build -p ai-gateway-app --bin ai-gateway --no-default-features \
  --features tls-aws-lc,mimalloc,runtime-base,gateway-llm,gateway-a2a

# LLM, A2A, and MCP, with common S1 security controls
cargo build -p ai-gateway-app --bin ai-gateway --no-default-features \
  --features tls-aws-lc,mimalloc,runtime-base,gateway-llm,gateway-a2a,gateway-mcp,security-s1
```

`gateway-composition` owns the compile-time capability profile and its small trait boundary.
This is deliberately a light split: protocol implementation remains in the `agentgateway`
compatibility runtime until its standalone API is stable, while feature profiles already provide
distinct deployable contracts.
`runtime-base` is temporarily required because cloud SDK, storage, and telemetry modules have not
yet all been conditionally compiled; the profile already constrains the enabled gateway surface,
but those dependencies are not yet removed from a smaller binary.

### S0/S1 common security controls

Add `security` to an AI system to normalize identity from verified JWT claims, evaluate common
security controls, and emit a structured audit decision for LLM, A2A, MCP Tool, and inference
routing actions. `audit` records decisions, `shadow` additionally logs every decision that would
be denied, and `enforce` rejects denied requests before they reach the upstream.

```yaml
aiSystems:
- name: support-agent
  security:
    mode: shadow
    requiredIdentity: { user: true, agent: true, tenant: true }
    policies: [] # Empty policies produce a fail-closed DENY; audit/shadow do not interrupt traffic.
```

Use `enforce` only with explicit least-privilege allow policies. Policy matching is scoped by
tenant, user, agent, action, and resource; a matching deny overrides an allow and no matching
allow is denied.

```yaml
aiSystems:
- name: support-agent
  security:
    mode: enforce
    requiredIdentity: { user: true, agent: true, tenant: true }
    policies:
    - id: tenant-a-support-chat
      tenantId: tenant-a
      userId: alice
      agentId: support-agent
      actionType: modelInvoke
      actionName: invoke
      resourceId: support-chat
      resourceType: model
    effect: allow
    enabled: true
```

### S1-A registered Agent identity

`agentIdentity` turns a verified JWT `agentId` claim into a registered Agent principal. It is an
identity-stage control: it runs before policy, delegation, approval, and Capability issuance. Each
Agent is bound to one tenant, one or more verified OAuth `azp`/`clientId` values, an enabled flag,
and an optional validity period. This prevents a client from gaining an Agent's privileges by only
adding a matching `agentId` claim.

```yaml
security:
  mode: enforce
  agentIdentity:
    required: true
    agents:
    - agentId: support-agent
      tenantId: tenant-a
      clientIds: [support-agent-workload]
      enabled: true
      notBefore: 2026-09-01T00:00:00Z
      expiresAt: 2027-09-01T00:00:00Z
  policies:
  - id: allow-support-agent
    tenantId: tenant-a
    agentId: support-agent
    actionType: toolInvoke
    actionName: tickets.create
    resourceId: tickets.create
    resourceType: tool
    effect: allow
    enabled: true
```

The static registry is the PoC source of truth. `AgentIdentityRegistry` is itself an identity-stage
security control, so a remote Agent Directory, certificate/SPIFFE attestation provider, or lifecycle
service can replace the source without changing protocol adapters or authorization policies.

`remoteAgentIdentity` is the implemented HTTPS/mTLS directory adapter. It is mutually exclusive
with `agentIdentity` and sends the normalized, verified request context on every Agent action; it
does not cache an allow, so an Agent disablement takes effect on the next action.

```yaml
security:
  mode: enforce
  remoteAgentIdentity:
    endpoint: https://agent-directory.security.internal/v1/identities/check
    required: true
    timeoutMillis: 100
    identityPemFile: /run/secrets/gateway-agent-directory-identity.pem
    rootCaPemFile: /run/secrets/agent-directory-root-ca.pem
```

The directory response must echo the verified `agentId`, `tenantId`, and OAuth `clientId`, return
`active: true`, and, if it supplies `expiresAt`, keep that time in the future. Network, TLS,
response-binding, inactive, and expired-directory responses are denied in `enforce` mode.

### S2 protocol-level controls

S2 turns protocol operations into the same policy vocabulary. In `enforce` mode, MCP `tools/list`
is authorized as `toolList` and every returned Tool is then filtered by its `toolInvoke` policy.
MCP Tool arguments are passed to shared required-argument controls. A2A JSON-RPC methods such as
`tasks/send` and `tasks/cancel` are distinct `agentInvoke` actions, while model and inference
endpoint selection remain `modelInvoke` and `inferenceRoute` actions.

```yaml
security:
  mode: enforce
  policies:
  # Permit discovery of this MCP gateway.
  - id: allow-tool-discovery
    actionType: toolList
    actionName: list
    resourceId: mcp-gateway
    resourceType: mcpServer
    effect: allow
  # Only this tool appears in tools/list and can be invoked.
  - id: allow-create-ticket
    actionType: toolInvoke
    actionName: tickets.create
    resourceId: tickets.create
    resourceType: tool
    effect: allow
  # Permit one explicit A2A operation; tasks/cancel remains denied.
  - id: allow-send-task
    actionType: agentInvoke
    actionName: tasks/send
    resourceId: support-agent-backend
    resourceType: agent
    effect: allow
  # Constrain route selection to an approved inference endpoint picker.
  - id: allow-edge-routing
    actionType: inferenceRoute
    actionName: select-destination
    resourceId: edge-picker
    resourceType: inferenceEndpoint
    effect: allow
  requiredToolArguments:
  - toolName: tickets.create
    requiredFields: [customerId]
```

### S3-A high-risk Tool gate

Declare operations that must never proceed solely because a static policy matched. The approval
control is fail-closed until a trusted approval authority is configured; `shadow` records a denied
approval without interrupting traffic.

```yaml
security:
  mode: enforce
  requiredToolApprovals:
  - toolName: records.delete
```

`approval` connects high-risk Tools to a reusable HTTPS/mTLS approval authority. The gateway sends
only the normalized `ActionRequest` plus an `argumentsHash`, never raw Tool arguments or a
caller-supplied approval header. A positive response is accepted only when its `requestId` and
`argumentsHash` match and it has a future `expiresAt`.

```yaml
security:
  mode: enforce
  requiredToolApprovals:
  - toolName: records.delete
  approval:
    endpoint: https://approval.security.internal/v1/check
    timeoutMillis: 250
    identityPemFile: /run/secrets/approval-client-identity.pem
    rootCaPemFile: /run/secrets/approval-root-ca.pem
```

The approval authority response contains `approvalId`, `requestId`, `argumentsHash`, `approved`,
and, for an allow, `expiresAt`. HTTPS/mTLS configuration errors, transport failures, non-2xx
responses, mismatched bindings, and expired approvals deny the Tool call.

`capabilityBroker` connects approved high-risk MCP Tool calls to a shared capability broker. After
approval and authorization succeed, the gateway requests an opaque token bound to the normalized
request and `argumentsHash`, validates the returned binding and TTL, then injects it as the
internal `x-ai-security-capability` header for the upstream Tool/API. A caller-supplied header of
the same name is stripped and cannot be used as a grant.

```yaml
security:
  capabilityBroker:
    issueEndpoint: https://capability.security.internal/v1/capabilities/issue
    timeoutMillis: 250
    ttlSeconds: 30
    identityPemFile: /run/secrets/capability-client-identity.pem
    rootCaPemFile: /run/secrets/capability-root-ca.pem
```

The broker issues `{ token, requestId, argumentsHash, expiresAt }`. The protected Tool/API must
consume the token once through the broker using the same normalized request and argument hash;
reuse, expiry, request mismatch, and parameter mismatch are denied. This allows broker state to be
durable and shared across gateway instances without treating a client header as authority.

`security-capability-broker` implements that shared service contract. It exposes
`POST /v1/capabilities/issue` and `POST /v1/capabilities/consume`, with one atomic consume
operation. Its PoC `InMemoryCapabilityStore` is replaceable through `CapabilityStore`; a production
store must make `consume` a durable delete-and-validate transaction. The router deliberately
requires a `BrokerPrincipal` supplied by the mTLS listener or service mesh: gateway principals may
issue, protected Tool/API principals may consume, and anonymous HTTP requests are denied.

The consuming Tool/API submits the opaque token plus the normalized `ActionRequest` and the hash
it computed from the actual Tool parameters. A successful consume returns the bound request for a
final local action/resource check; any binding mismatch burns the token before it can be replayed.
See [`docs/architecture/capability-broker.md`](docs/architecture/capability-broker.md) for the wire
contract and deployment boundary.

Protected Tool/API services use the optional `security-capability-broker` `client` feature. Its
`HttpCapabilityConsumer` extracts the gateway-only capability/context headers, hashes the actual
parameters, consumes through mTLS, and validates the response before the Tool performs a side
effect. The MCP gateway strips caller-provided values of both headers and replaces them only after
it receives a broker-issued capability.

### S3-C Agent delegation

`delegations` is an additional identity-stage brick for user-owned Agents. The JWT must be
validated by the existing gateway authentication path and carry `delegationId` (or
`delegation_id`), as well as the existing user, Agent, and tenant claims. A delegation only
narrows authority: the normal `policies` allow rule must still match. An unknown grant, missing
grant, expired grant, wrong tenant, or operation outside `scopes` is denied in `enforce` mode.

```yaml
security:
  mode: enforce
  policies:
  - id: alice-support-policy
    tenantId: tenant-a
    userId: alice
    agentId: support-agent
    actionType: toolInvoke
    actionName: tickets.create
    resourceId: tickets.create
    resourceType: tool
    effect: allow
    enabled: true
  delegations:
  - id: delegation-alice-support-01
    userId: alice
    agentId: support-agent
    tenantId: tenant-a
    expiresAt: 2026-12-31T23:59:59Z
    scopes:
    - actionType: toolInvoke
      actionName: tickets.create
      resourceId: tickets.create
      resourceType: tool
```

The normalized subject and audit event retain `delegationId`, so LLM, A2A, MCP, and inference
actions can be correlated to the same user-to-Agent grant. This first PoC supports one direct
user → Agent grant. Delegation-grant issuance/revocation, signed grant exchange, and Agent →
sub-Agent delegation chains remain later S3 work.

### S4-A dynamic least privilege

`dynamicAuthorization` adds a second, context-aware PDP stage after a normal static policy
allow. It can restrict a permission to a verified JWT session (`sid`, `sessionId`) or client
(`azp`, `clientId`) and a time window. It never widens a static permission: both stages must
allow. No matching dynamic policy, an expired policy, or a PDP error is denied.

```yaml
security:
  mode: enforce
  policies:
  - id: allow-alice-ticket-create
    tenantId: tenant-a
    userId: alice
    agentId: support-agent
    actionType: toolInvoke
    actionName: tickets.create
    resourceId: tickets.create
    resourceType: tool
    effect: allow
    enabled: true
  dynamicAuthorization:
    policyVersion: s4-v1
    failureMode: failClosed
    cacheTtlSeconds: 0
    policies:
    - id: allow-current-support-session
      tenantId: tenant-a
      userId: alice
      agentId: support-agent
      actionType: toolInvoke
      actionName: tickets.create
      resourceId: tickets.create
      resourceType: tool
      sessionId: session-42
      clientId: support-console
      expiresAt: 2026-12-31T23:59:59Z
      effect: allow
      enabled: true
```

`failClosed` is the default and calls the PDP on every request. `useCachedDecision` can reuse a
still-valid decision for `cacheTtlSeconds`; use it only for explicitly low-risk read operations.
The cache key includes the policy version, subject, action, resource, session, and client, so it
cannot be reused across a different security context. The PoC provides `LocalDynamicPdp` and a
replaceable `DynamicPdp` trait. A trusted HTTPS remote PDP can now be selected through
`remotePdp` as described below.

### S4-B remote PDP and delegation revocation

The security core now defines the transport-neutral remote PDP contract. A runtime adapter must
send a versioned `RemotePdpRequest` containing only normalized identity, delegation, action,
resource, and authorization context. Its `RemotePdpResponse` is accepted only when all of the
following match:

- `requestId` is the request being authorized;
- `policyVersion` is the version expected by the gateway, when one is pinned;
- `expiresAt` is in the future.

The returned policy version and expiry are written to the structured audit event. A cached decision
is bounded by the smaller of the local TTL and PDP `expiresAt`, so a remote allow cannot survive
past its PDP validity window.

The running gateway now supplies the HTTP/mTLS transport. It accepts only absolute `https` PDP
URLs, has a required bounded `timeoutMillis` (250 ms by default), reuses one Rustls HTTP client
per loaded AI-system configuration, and maps invalid TLS/configuration, timeout, network, non-2xx,
or invalid-response failures to a deny. `identityPemFile` references one PEM containing the PDP
client certificate and private key; `rootCaPemFile` pins an additional private CA when needed.
Neither a bearer token nor raw Tool arguments are sent to the PDP.

```yaml
security:
  mode: enforce
  dynamicAuthorization:
    policyVersion: pdp-bundle-2026-09-14
    failureMode: failClosed
    cacheTtlSeconds: 0
  remotePdp:
    endpoint: https://pdp.security.internal/v1/decisions
    timeoutMillis: 250
    identityPemFile: /run/secrets/pdp-client-identity.pem
    rootCaPemFile: /run/secrets/pdp-root-ca.pem
```

The current gateway security hook is synchronous, so this PoC uses `reqwest`'s bounded blocking
client. Moving the hook to async I/O is a runtime-performance follow-up; it does not change the
PDP contract or security semantics.

`DelegationRevocationCheck` and `DelegationRevocationProvider` provide the corresponding realtime
revocation brick. The in-process `DelegationRevocationRegistry` remains useful for tests, while
`delegationRevocation` now connects every gateway instance to a shared HTTPS/mTLS source. A
request carrying a verified `delegationId` issues an uncached `POST` on every protected action:

```json
{ "protocolVersion": "v1", "delegationId": "delegation-alice-support-01" }
```

The source must return the same `delegationId` and a Boolean `revoked` value. A mismatched ID,
timeout, TLS/network failure, non-2xx response, or malformed response is fail-closed; requests
without a delegation do not query the source. This makes a revocation visible to all configured
gateway instances on their next protected request.

```yaml
security:
  delegationRevocation:
    endpoint: https://identity.security.internal/v1/delegations/revocation
    timeoutMillis: 100
    identityPemFile: /run/secrets/revocation-client-identity.pem
    rootCaPemFile: /run/secrets/identity-root-ca.pem
```

## Core crates

```text
crates/contracts
crates/policy
crates/security-engine
crates/audit-core
crates/gateway-adapter
crates/gateway/composition
crates/gateway/runtime       # ai-gateway-runtime, compatibility facade
crates/gateway/app           # ai-gateway-app / ai-gateway binary
crates/agentgateway*         # AgentGateway-derived compatibility runtime
```

## Build and test

```bash
cargo check -p security-contracts -p security-policy -p security-engine -p audit-core -p gateway-adapter -p ai-gateway-app
cargo test -p security-engine -p security-policy -p audit-core -p gateway-adapter
```

## License

Apache License 2.0. See [LICENSE](LICENSE).
