# 配置与已有能力参考

<!-- doc-role: reference -->

本文件介绍已有配置与接口。项目目标见[项目入口](../README.md)，组件职责和扩展方式见[架构说明](../architecture/README.md)。

示例包含片段、占位地址与不同安全模式，需要按业务补全凭据、认证和安全策略；不表示可以直接投产。构建能力选择见[发布指南](../release/README.md)。编译安全组件不等于开启 Enforce，观察模式不会一般性阻断。

平台面向生产级端侧开发，但目标设备发布门禁尚未通过。文中“PoC/进程内”只描述特定示例或后端，不定义整个平台目标。已有文件审计/状态日志和远程受信 Broker 接入；本地 Broker 的默认 Store 仍为进程内实现，跨重启/多实例保证须按实际存储验证。受保护 Tool/API 必须校验可信身份/Capability，不能以示例配置代替执行边界。

## RAG retrieval security

`security-rag` is a vector-database-neutral security brick. A `SecureRetriever` first normalizes
a corpus search as `KnowledgeRetrieve` and passes it through the common `SecurityPipeline`. It
then derives a trusted `RetrievalFilter` from verified User/Agent/Tenant identity for the vector
backend and independently re-checks every returned Chunk. A Chunk is rejected unless its corpus,
tenant, ACL, expiry, provenance hash, labels, requested Chunk limit, and context-token budget all
pass. This prevents an overly broad or stale vector index from becoming an authorization bypass.

The RAG audit record contains a query hash, corpus and Chunk IDs, rejection reasons, and the
security subject; it intentionally excludes the query and Chunk text. `KnowledgeIngest`,
`KnowledgeRetrieve`, and `ContextAssemble` are now first-class runtime action types, so static or
dynamic policy can protect the full knowledge path.

`SecureIngestor` protects the other end of the chain. A document is authorized as
`KnowledgeIngest`, checked against trusted source-scheme and document-size limits, assigned a
SHA-256 provenance hash, and classified with deterministic label rules. High-risk content is sent
to a separate quarantine backend rather than the vector index. `IndexedDocument::to_chunk` then
inherits its corpus, tenant, labels, and provenance hash into every `KnowledgeChunk`, while a
trusted controller supplies only the Chunk ACL and expiry.

`gateway-rag` now composes these stages as a transport-neutral `RagGatewayAdapter`. An HTTP,
MCP, or application transport authenticates a request first, then supplies `GatewayIdentity` to
the adapter; its request models deliberately contain no Tenant, ACL, or vector-filter fields. The
adapter executes asynchronous ingestion and retrieval backends, then returns only
`GuardedContext` after the separately authorized context-assembly stage. A Qdrant or pgvector
adapter therefore implements only the backend traits and cannot bypass the common security chain.

The first concrete provider is `gateway-rag::QdrantBackend`. It receives an injected HTTP client
(so deployment can require mTLS and custom CA roots), an embedding provider, and a trusted Chunk
access policy. It writes Chunk security metadata into Qdrant Payload and performs a query with
mandatory `tenantId` and `corpusId` matches plus a `min_should` ACL condition over tenant-wide,
User, or Agent access. The `SecureRetriever` still revalidates every returned point. Qdrant
collections must be provisioned ahead of time with the matching vector dimension and keyword
Payload indexes for `tenantId`, `corpusId`, `allowedUsers`, and `allowedAgents`.

After retrieval, `ContextGuard` separately authorizes `ContextAssemble` and examines the approved
Chunk text before it reaches the LLM. Its default Enforce mode removes Chunk content that matches
configured indirect-instruction signals; Shadow mode preserves it while producing a finding for
staged rollout. Chunks with configured sensitive labels can instead retain their provenance while
their content is replaced by a redaction marker. This deterministic signal is a PoC safety net;
a classifier or DLP engine can be added behind the same context-guard boundary later.

For example, corpus retrieval remains deny-by-default until an explicit policy permits it:

```yaml
security:
  mode: enforce
  policies:
  - id: allow-support-knowledge-ingestion
    tenantId: tenant-a
    userId: alice
    agentId: knowledge-curator
    actionType: knowledgeIngest
    actionName: ingest
    resourceId: password-guide
    resourceType: document
    effect: allow
    enabled: true
  - id: allow-support-knowledge
    tenantId: tenant-a
    userId: alice
    agentId: support-agent
    actionType: knowledgeRetrieve
    actionName: retrieve
    resourceId: support-corpus
    resourceType: knowledgeBase
    effect: allow
    enabled: true
  - id: allow-support-context-assembly
    tenantId: tenant-a
    userId: alice
    agentId: support-agent
    actionType: contextAssemble
    actionName: assemble
    resourceId: support-corpus
    resourceType: knowledgeBase
    effect: allow
    enabled: true
```

## Composable security pipeline

`security-pipeline` provides small security bricks rather than a mandatory all-in-one gateway:

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

`securityPipeline` is a compatibility entry and always enforces its declaration. If it is
configured together with `aiSystems[].security` or `securityAudit`, both declarations must permit
the operation according to their own modes. Audit/Shadow on the common declaration cannot disable
the legacy constraint. The gateway prepares both through the shared security implementation;
it does not concatenate their policy lists or share approval providers between them.

The configuration is dynamically reloaded with the existing local configuration watcher.
MCP authorization, outbound checks, and protected-stream rechecks share normalized operations;
discovery is authorized per actual upstream server. See [protocol execution constraints](../protocol/execution-contract.md).

## AI system gateway composition

`aiSystems` assembles protocol gateways for one AI system. Each enabled gateway gets a separate
listener, route, and backend namespace, so a system may expose only LLM, LLM with endpoint-picker
inference routing, LLM plus A2A, or all three LLM/A2A/MCP gateways without changing code.

```yaml
aiSystems:
- id: support-agent # `name` remains supported for compatibility
  # RAG requires enforced policy. These three rules separately authorize document writes,
  # corpus retrieval, and final context assembly for a verified tenant principal.
  security:
    mode: enforce
    policies:
    - id: support-ingest
      actionType: knowledgeIngest
      actionName: ingest
      resourceType: document
      tenantId: tenant-a
      effect: allow
    - id: support-retrieve
      actionType: knowledgeRetrieve
      actionName: retrieve
      resourceType: knowledgeBase
      tenantId: tenant-a
      effect: allow
    - id: support-context
      actionType: contextAssemble
      actionName: assemble
      resourceType: knowledgeBase
      tenantId: tenant-a
      effect: allow
  # System-wide inference controls compile into the existing LLM execution policies.
  # They are shared by every model below, while model-level settings can refine them.
  inference:
    parameters:
      defaults:
        temperature: 0.2
        max_tokens: 1024
      overrides:
        max_tokens: 512
    quota:
      requests:
        maxTokens: 120
        tokensPerFill: 120
        fillInterval: 1m
      tokens:
        maxTokens: 100000
        tokensPerFill: 100000
        fillInterval: 1m
    routing:
      endpointPicker:
        host: 127.0.0.1:9300
      destinationMode: passthrough
  llm:
    port: 4100
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
  # The application starts this RAG listener from the validated configuration.
  # Its HTTP input deliberately has no tenantId, ACL, or vector-store filter fields.
  rag:
    port: 4103
    qdrant:
      endpoint: https://qdrant.internal.example
      collection: support-knowledge
      quarantineCollection: support-knowledge-quarantine
      defaultChunkAccess:
        allowTenantAuthenticated: true
    embedding:
      endpoint: https://embeddings.internal.example/v1/embeddings
      model: text-embedding-3-small
    chunkMaxChars: 2000
    ingestion:
      allowedSourceSchemes: [https, s3]
      maxDocumentBytes: 10485760
    retrieval:
      maxChunks: 8
      maxContextTokens: 6000
    contextGuard:
      mode: enforce
    authentication:
      mode: strict
      issuer: https://issuer.example
      audiences: [support-rag]
      jwks:
        url: https://issuer.example/.well-known/jwks.json
```

The A2A gateway automatically adds the A2A protocol adapter to its backend route. `inference`
is a configuration-compiler input: `parameters` becomes the existing per-model LLM request
policy, `quota` becomes request and token local-rate-limit policies, and `routing` is attached to
each generated model backend so an endpoint picker can select an edge or cloud destination. The
legacy `llm.policies.localRateLimit` and `llm.policies.inferenceRouting` locations remain valid;
local rate limits compose, while routing must be declared in only one location. Ports must be
unique across all listeners. `rag` is the corresponding RAG-gateway configuration boundary: it
selects Qdrant, an OpenAI-compatible embedding endpoint, chunking, ingestion controls, retrieval
budgets, and context-injection handling. RAG requires a strict JWT validator and
`security.mode: enforce`; the runtime starts its listener and derives identity only from validated
claims before mounting `gateway_rag::router`. The route contract rejects caller-supplied tenant or
ACL fields.

The mounted RAG router exposes `POST /v1/rag/documents` and `POST /v1/rag/query`. Its host must
verify authentication and insert `gateway_rag::VerifiedGatewayIdentity` into the request before
the router runs. The document endpoint accepts only `corpusId`, `documentId`, `sourceUri`, and
`content`; the query endpoint accepts only `corpusId`, `query`, and `limit`. Therefore tenant,
principal ACL, and Qdrant filtering are exclusively derived inside the trusted processing chain.

### Compile-time gateway profiles

The default `ai-security-platform` build retains every gateway capability. A selected
profile rejects configuration for
capabilities that were not selected at build time, so deployment configuration cannot accidentally
enable an unapproved gateway surface.

```bash
# LLM only
cargo build -p ai-security-platform-app --bin ai-security-platform --no-default-features \
  --features tls-aws-lc,mimalloc,security-s1,gateway-llm

# LLM plus multiple inference endpoints / routing
cargo build -p ai-security-platform-app --bin ai-security-platform --no-default-features \
  --features tls-aws-lc,mimalloc,security-s1,gateway-llm,inference-routing

# LLM plus an A2A agent runtime
cargo build -p ai-security-platform-app --bin ai-security-platform --no-default-features \
  --features tls-aws-lc,mimalloc,security-s1,gateway-llm,gateway-a2a

# LLM, A2A, and MCP, with common S1 security controls
cargo build -p ai-security-platform-app --bin ai-security-platform --no-default-features \
  --features tls-aws-lc,mimalloc,security-s1,gateway-llm,gateway-a2a,gateway-mcp
```

`gateway-composition` owns the compile-time capability profile and its small trait boundary.
Protocol implementation is shared between independent `gateway-*` components and the
`ai-security-platform-runtime` Host. Their responsibilities are described in
[the architecture](../architecture/README.md); a compiled profile does not certify full protocol independence.
`runtime-base` bundles cloud SDK, database and OTLP features for broad compatibility; it is
optional. Select `database`, `telemetry-otlp` and `providers-*` only when the scenario needs them.
Disabled SQL/OTLP configuration is rejected at startup and hot update; ordinary request logging
and Trace Context remain available. Required Audit has its own security persistence contract.
The Runtime still has shared LLM data dependencies, so feature selection does not yet imply
complete protocol implementation isolation.

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

The static registry is a local configured identity source. `AgentIdentityRegistry` is itself an identity-stage
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
`message/send` and `tasks/cancel` are distinct `agentInvoke` actions, while model and inference
endpoint selection remain `modelInvoke` and `inferenceRoute` actions.

```yaml
security:
  mode: enforce
  policies:
  # Permit discovery on the configured MCP target named local-tools.
  - id: allow-tool-discovery
    actionType: toolList
    actionName: list
    resourceId: local-tools
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
    actionName: message/send
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
The crate API and configuration schema define the wire contract and deployment boundary.

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
actions can be correlated to the same user-to-Agent grant. The current adapter supports one direct
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
cannot be reused across a different security context. The current implementation provides `LocalDynamicPdp` and a
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

The current gateway security hook is synchronous, so the current adapter uses `reqwest`'s bounded blocking
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
crates/security/types
crates/security/policy
crates/security/engine
crates/security/audit
crates/security/pipeline
crates/gateway/composition
crates/security/integration-runtime # configured security and lifecycle adapters
crates/security/capability-broker    # existing broker/consumer contract and service
crates/security/rag                  # ingestion, retrieval and context security
crates/gateway/contracts             # shared configuration revision/lease
crates/gateway/protocol-core         # shared execution/data contracts
crates/gateway/llm                   # extracted LLM core; execution extraction incomplete
crates/gateway/mcp                   # extracted MCP rules/merge and three-method dispatcher
crates/gateway/a2a                   # extracted A2A envelope/card core
crates/gateway/rag                   # independent secure RAG adapter
crates/gateway/runtime               # shared Host plus remaining protocol implementation
crates/gateway/app           # ai-security-platform-app / ai-security-platform binary
crates/platform/*            # shared first-party platform utilities
crates/third-party/*         # retained third-party source dependencies
```

## Build

```bash
cargo check -p security-types -p security-policy -p security-engine -p security-audit -p security-pipeline -p ai-security-platform-app
```

## License

Apache License 2.0. See [LICENSE](../../LICENSE).


## PII Security Component V0.1

`security-pii` 是协议无关的可选内容安全组件，集中检查经本网关受控模型入口发送的请求。可信身份/授权 → 请求默认值、转换前变更、prompt enrichment 与原请求 guard → 完整请求 PII → Provider 编码 → 原最终授权、配置失效、出口、预算和受控发送。直接模型调用、MCP Sampling 和业务组装的 RAG→LLM 使用同一检查点。RAG 本身只执行原有检索授权、Chunk ACL、ContextGuard、分类、Provenance 和预算，返回授权原文；不再额外做 PII。

### 编译与配置

仅原生检测不需要 Python 或 Sidecar：

```sh
cargo build --locked -p ai-security-platform-app --no-default-features \
  --features gateway-llm,security-s1,security-pii,tls-aws-lc \
  --bin ai-security-platform
```

需要 Analyzer 时，将 `security-pii` 替换为 `security-pii-presidio`。该 feature 保留原生检测，不自动选择外部后端，也不隐式编译 LLM/RAG 协议。现有五种候选发布 profile 默认不启用 PII；未编译相关能力或未选择 LLM 时，启用配置明确拒绝。缺省 `security.pii`、`enabled: false` 或 `mode: disabled` 不创建检测组件；旧 LLM regex guardrails 配置保持。原先未发布的 `rag.pii` 已移除，Host 会明确报错并要求迁移。

在现有 `aiSystems[].security` 内增加下列配置；该 aiSystem 必须包含 LLM。可信模型路由/后端也可使用已有 `securityAudit` 安全配置入口；继承的 PII 要求不会被子策略省略而消除。完整身份与模型配置见[RAG→LLM 示例](../examples/rag-llm-poc.md)：

```yaml
pii:
  enabled: true
  mode: enforce
  backend: native
  language: en
  timeoutMs: 1000
  maxTextBytes: 65536
  maxOutputBytes: 131072
  maxResponseBytes: 131072
  maxFindings: 256
  policy:
    entities:
      EMAIL_ADDRESS: { action: replace, value: '[EMAIL_ADDRESS]' }
      PHONE_NUMBER: { action: mask }
      IP_ADDRESS: { action: redact }
```

`mode` 为独立内容控制模式，不能代替原安全配置：PII 不授予模型调用权限，身份、ModelInvoke 授权及其他既有安全要求仍需配置。`audit`/`shadow` 产生检测/错误审计，不改写也不阻断正文；`enforce` 执行策略，检测异常拒绝模型出站，禁止静默转为未检测透传。V0.1 没有 Enforce fail-open 开关。`enabled` 在提供配置对象时默认 true，`mode` 默认 enforce，`backend` 默认 native。

动作支持 `detectOnly`、`replace`、`mask`、`redact`、`block`。Mask 替换每个敏感 Unicode 字符为 `*`，Redact 删除对应片段，Block 阻止整个模型请求出站，返回固定 403。重叠改写合并其覆盖范围，冲突采用 Redact > Mask > Replace；任何 Block 优先阻断。未命中的正文保持。配置可按不同 aiSystem/模型安全域分别选择实体及动作，不根据用户文本猜测是否允许外传。

原生后端提供 Email 格式检测、由 phonenumber 元数据校验的有限区域 Phone 检测，以及由 Rust IpAddr 校验的 IPv4/IPv6；它们是确定性信号，不是身份真实性证明。可用 `customRules: { EMPLOYEE_ID: 'EMP-[0-9]{4}' }` 配置其他规则，并在 `policy.entities` 指定相应动作。`customRules` 仅适用于 Native；Presidio 配置非空 customRules 会拒绝，额外识别器应部署到 Sidecar。未知原生实体、非法/空规则、超限参数和未知 PII 字段拒绝配置；没有可靠姓名识别器时，不声称姓名已脱敏。旧 SSN/银行卡 regex 配置没有被替换或升级为可靠校验器。

PII Core 的 Finding 使用 UTF-8 字节范围 `[start,end)`；Presidio Adapter 将 Python Unicode 字符下标转换为字节边界。重复结果规范化，无效范围/置信度/未知实体拒绝。请求投影保留消息角色和工具关联；工具参数修改后必须仍是合法 JSON。

PII 检查消息正文、系统指令、历史、工具结果与参数；工具定义/Schema、metadata、`user`、停止文本、工具名称/关联标识及未知扩展继续作为只读数据检查，需要改写时拒绝。仅排除根级类型正确的已知控制字段：`model`、`stream`、`temperature`、`top_p`，以及对应请求格式的 token 上限、Completions 的 penalty/seed 和仅含布尔 `include_usage` 的 `stream_options`；固定角色与已验证的内容 `type` 也不送入检测器。模型名仍受原路由/授权控制，不属于正文脱敏范围。未知角色、控制字段的异常类型、带扩展的 `stream_options` 不因此获得豁免；metadata/工具参数内部即使含有同名键，也继续检查。

`maxTextBytes`/`maxOutputBytes` 限制整个序列化请求，包含未送检的控制字段；`maxFindings` 同时限制单片段和完整请求，最多 128 个送检片段、16 层内容结构，`timeoutMs` 也限制一次完整检查。计价/分词在 PII 之后沿原机制执行，原 Context Budget 不变。

### 可选的本地 Presidio Analyzer

Adapter 使用官方 `POST /analyze`，只发送文本、语言、配置的实体列表并关闭 decision-process 返回；匿名化在 Rust 本地完成，不需要 Anonymizer 服务。接口依据见 [Presidio REST 定义](https://github.com/microsoft/presidio/blob/main/docs/api-docs/api-docs.yml)。

按照[官方启动示例](https://github.com/microsoft/presidio/blob/main/docs/getting_started/getting_started_text.md)，PoC 可使用官方容器：

```sh
docker run --rm --name aisp-presidio \
  -p 127.0.0.1:5002:3000 mcr.microsoft.com/presidio-analyzer:latest
```

这里的 latest 是官方快速开始标签，实际环境应固定经过验证的镜像摘要；本轮没有拉取镜像或模型，不能将协议替身测试描述为官方 NLP 模型验收。Sidecar 应按其版本关闭请求正文/调试日志，且不能暴露到外部网络。新增 PII 组件不记录原文、匹配片段、上游错误正文或检测响应；它不负责净化其他既有组件显式启用的请求正文日志，不能将局部 PII 保护当作全平台日志匿名化保证。

```yaml
pii:
  enabled: true
  mode: enforce
  backend: presidio
  presidioEndpoint: http://127.0.0.1:5002
  language: en
  timeoutMs: 1000
  policy:
    entities:
      EMAIL_ADDRESS: { action: replace, value: '[EMAIL_ADDRESS]' }
      PHONE_NUMBER: { action: block }
```

V0.1 仅接受 literal loopback IP（127.0.0.1/IPv6 loopback 等）和根路径或 `/analyze`，拒绝 DNS 名称、远程地址、userinfo、query、fragment 与任意检测路径；关闭重定向及环境代理。普通 HTTP 请求不能选择后端或地址。若配置 `security.dependencyEgress`，需在已有 `guardrail` 类别显式允许实际 Sidecar host:port，并保持原 Qdrant/Embedding 许可；HTTP loopback 需显式满足该策略的 TLS 规则。候选本地配置发布前会用固定非敏感文本检查 Analyzer 响应，服务不可达/响应非法时拒绝新配置，保留旧配置。

用合成文本检查 Analyzer（返回结果不包含原始匹配文本）：

```sh
curl --fail http://127.0.0.1:5002/analyze \
  -H 'Content-Type: application/json' \
  -d '{"text":"Contact alice@example.com","language":"en","entities":["EMAIL_ADDRESS"],"return_decision_process":false}'
```

启动网关后，直接发送模型请求，或按 RAG→LLM 示例将授权 chunks 与用户问题、历史消息、工具结果组装为请求。Completions、Messages、Responses 的支持文本在完整组装后检查；多模态、远程 previous_response_id/conversation/prompt 等无法本地检查的内容，Enforce 明确拒绝。PII 审计使用现有安全事件持久化，事件类型 `piiInspection`，仅含实体类别/数量、模式、改写结果及固定错误，不携带正文/匹配片段。启用 ModelInvoke 的 Required Audit 时，PII 审计确认持久化后才能继续发送。该事件是内容检查结果，不是上游已执行的回执。

### 验证与边界

```sh
cargo test --locked -p security-pii --no-default-features
cargo test --locked -p security-pii -p gateway-llm --all-features
cargo test --locked -p security-integration-runtime --features pii --lib pii::tests
python3 tests/protocol/run_full_tcp.py --profile pii --rounds 3 \
  --binary target/debug/ai-security-platform --report /tmp/aisp-pii.json
```

后一个命令需使用已经编译 LLM、MCP、RAG 与 `security-pii-presidio` 的网关；驱动在隔离 loopback 验证直接模型请求、RAG→LLM、MCP Sampling 和可控 Analyzer HTTP 契约，不需要 Python NLP 包、云模型或权重。首次失败和固定轮次均保留。

V0.1 只覆盖经本网关受控模型入口的请求文本；响应/SSE 输出、HTTP headers、多模态、直接 RAG 返回、入库/Embedding 原文、MCP 工具和 A2A 对外载荷不覆盖。外部 Agent 绕过本网关调用模型也不在保护范围。`stream: true` 的完整请求仍可检查，但不表示 SSE 响应已做实体脱敏。检测按结构化片段执行，不保证识别跨字段拼接、编码或其他混淆实体。Context ID 继续是身份/策略/文档凭证，不是正文净化证明；现在 `security.pii` 参与原安全配置指纹，变更会沿原机制使相关旧 Context 和请求失效，未新增第二套撤销系统。

模型入口启用 PII Enforce 时，仅接纳上述 Completions、Messages、Responses 支持文本；Embeddings、Rerank、TokenCount、Detect、Passthrough、Realtime 等未支持路由明确拒绝。Audit/Shadow 对这些路由记录 unsupported 后保留原行为，不声称已检查其内容。RAG 内部直接调用 Embedding 服务不经过该模型入口，不会因此自动加入 PII。

后续 NER/GLiNER/ONNX 后端实现 `PiiDetector` 即可接入同一规范化、策略、匿名化和错误边界；模型实体需显式映射为部署配置的实体名，不能创建新身份/授权引擎。中文姓名质量、模型权重、跨帧缓冲与可逆密钥管理分别验证，不在 V0.1 中预建空框架。
