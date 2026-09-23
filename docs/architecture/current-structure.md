# AI Security Platform current workspace structure

The workspace is organized by ownership rather than by the source history of a module.

```text
crates/
  gateway/                         # AI interaction ingress and gateway composition
    runtime/                       # protocol runtime integration kernel
    app/                           # CLI and deployable binaries
    composition/                   # feature/profile contract
    rag/                           # RAG transport and vector-backend adapters
  security/                        # protocol-neutral security capabilities
    types/ -> policy/ -> engine/ -> pipeline/
    audit/                         # structured audit contract and sinks
    integration-runtime/           # runtime-edge configuration adapter
    capability-broker/, rag/
  platform/                        # reusable infrastructure with no gateway policy ownership
    core/, pool/, hbone/, celx/, protos/
  third-party/                     # vendored/forked external dependencies only
  xtask/                           # developer automation
```

## Dependency direction

```text
platform/* ─────────────────────────────────────────────┐
                                                        │
security/types -> security/policy -> security/engine -> security/pipeline
                                                        ^
gateway/composition, gateway/rag ───────────────────────┤
gateway/runtime -> security/integration-runtime ────────┘
gateway/app -> gateway/runtime
```

Security crates do not depend on gateway protocol, HTTP, MCP, LLM, or A2A implementation types.
The runtime is the only integration kernel that converts protocol requests into the security
contract and invokes the configured pipeline.

## Why `gateway/runtime` remains substantial

`ai-security-platform-runtime` currently contains mature LLM, MCP, A2A, routing, authentication,
telemetry, and administrative implementations. Splitting it solely to obtain more directories
would create forwarding crates without improving ownership or testability. A protocol module is
extracted only when it owns stable request/response/configuration interfaces and can be tested
independently.

New capability work follows these rules:

- Add protocol-neutral controls to `security/*`.
- Add protocol transport or backend adaptations to `gateway/*`.
- Add shared infrastructure to `platform/*`.
- Do not add product functionality to `third-party/*`.
