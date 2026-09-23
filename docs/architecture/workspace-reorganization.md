# AI Security Platform workspace architecture

## Goal

Keep AI gateway protocols independently composable while ensuring security controls remain
protocol-neutral. The desired structure follows the Rust workspace pattern used by LibAFL:
small crates own stable contracts and mechanics; runtime-specific adapters live at the edge.

```text
crates/
  gateway/
    runtime/                         # ai-security-platform-runtime implementation
    app/                             # ai-security-platform-app / binary
    protocol-llm/                    # future extraction
    protocol-mcp/                    # future extraction
    protocol-a2a/                    # future extraction
    inference-routing/               # future extraction
  security/
    types/                           # security-types
    policy/                          # current security-policy
    engine/                          # current security-engine
    audit/                           # security-audit
    pipeline/                        # security-pipeline
    integration-runtime/             # runtime adapter
  platform/
    core/, pool/, hbone/, protos/, celx/
  third-party/
    cel-fork/, htpasswd-verify-fork/ # retained compatibility dependencies
```

`ai-security-platform-runtime` and `ai-security-platform-app` contain the complete runtime and application
implementations. The workspace has no AgentGateway compatibility package.

## Dependency rules

```text
security/types -> security/policy -> security/engine -> security/pipeline
                                                        ^
gateway/* ---------------------------------------------|
gateway/runtime -> security/integration-runtime -> security/pipeline
```

- Security core crates must not depend on the gateway runtime, HTTP, MCP, LLM, or A2A types.
- Protocol normalization belongs in gateway adapters; policy evaluation and audit event creation
  belong in security crates.
- `ai-security-platform-runtime` remains the composition runtime until protocol crates have stable standalone APIs.
- Applications depend on gateway runtime, never directly on security implementation crates.

## Migration phases

### Phase 0 — boundary inventory (complete)

- Record ownership and dependency rules in this document.
- Mark workspace members by domain without changing code paths.
- Preserve configuration schema compatibility while establishing first-party package names.

### Phase 1 — extract security runtime integration (complete)

- Move audit dispatch and audit-only/enforce mode handling from `gateway/runtime/src/security.rs`
  into `security/integration-runtime`.
- Keep JWT-claim extraction in the gateway runtime initially; it depends on request extensions.
- Make LLM, A2A, MCP, and inference-routing adapters call one shared security integration API.

### Phase 1.5 — compile-time gateway profiles (complete)

- `gateway-composition` owns the protocol/security capability vocabulary and the profile trait.
- `ai-security-platform-runtime` and `ai-security-platform-app` forward `gateway-llm`, `gateway-a2a`, `gateway-mcp`,
  `inference-routing`, and `security-s1` Cargo features.
- The runtime rejects local `llm`, `mcp`, and `aiSystems` configuration that requests a capability
  omitted from the compiled profile. This establishes deployable composition contracts without
  prematurely extracting protocol implementation modules.

### Phase 2 — stabilize the security pipeline (complete)

- Move the security pipeline to `crates/security/pipeline` as the `security-pipeline` package.
- Add explicit `audit`, `shadow`, and `enforce` modes to the shared integration API.
- Move capability broker implementations behind a durable-broker trait.

### Phase 3 — extract protocol boundaries only when justified

- Extract `protocol-mcp`, `protocol-llm`, or `protocol-a2a` only after each has a stable request,
  response, configuration, and test surface.
- Do not split modules merely to match the target directory diagram.

### Phase 4 — physical layout and product-baseline migration (complete)

- Move all runtime and application source to `crates/gateway/*` and remove the temporary
  `agentgateway` / `agentgateway-app` packages.
- Move security and platform source to their owned namespaces; retain only third-party forks in
  `crates/third-party/*`.
- Update workspace paths, embedded-asset paths, build-script paths, examples, and documentation.

## Acceptance criteria for every phase

- `cargo check` succeeds for the default workspace members and schema feature.
- Configuration behavior and serialized field names remain backward compatible.
- No security-core crate gains a dependency on gateway protocol code.
- Integration tests cover every moved adapter and at least one composed `aiSystems` topology.
