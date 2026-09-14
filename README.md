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

Declare operations that must never proceed solely because a static policy matched. Until the
deployment connects a trusted `ApprovalProvider`, this control is deliberately fail-closed in
`enforce` mode; `shadow` records the missing approval without interrupting traffic.

```yaml
security:
  mode: enforce
  requiredToolApprovals:
  - toolName: records.delete
```

The security core already provides a short-lived, one-time `CapabilityBroker`. A Capability is
bound to the authorized subject, action, resource, request ID, and Tool argument hash. S3-B will
connect a trusted approval authority to this broker and a Tool-side capability consumer; no
untrusted request header is treated as an approval grant.

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
replaceable `DynamicPdp` trait; wiring a remote PDP is the next S4 increment.

### S4-B1 remote PDP and delegation revocation contract

The security core now defines the transport-neutral remote PDP contract. A runtime adapter must
send a versioned `RemotePdpRequest` containing only normalized identity, delegation, action,
resource, and authorization context. Its `RemotePdpResponse` is accepted only when all of the
following match:

- `requestId` is the request being authorized;
- `policyVersion` is the version expected by the gateway, when one is pinned;
- `expiresAt` is in the future.

The returned policy version and expiry are written to the structured audit event. A cached decision
is bounded by the smaller of the local TTL and PDP `expiresAt`, so a remote allow cannot survive
past its PDP validity window. `RemotePdpTransport` is intentionally a runtime integration seam:
the next increment supplies its HTTP/mTLS implementation and injects it into the running gateway.

`DelegationRevocationCheck` and `DelegationRevocationProvider` provide the corresponding realtime
revocation brick. The PoC includes an in-process `DelegationRevocationRegistry`; its production
replacement will be a shared revocation index or the PDP itself. A failed revocation lookup is
fail-closed.

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
