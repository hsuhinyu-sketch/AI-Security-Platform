# Platform demonstration profiles

These files are validated, runnable configuration profiles used to demonstrate that the same
platform can compose a minimal knowledge assistant or a full autonomous Agent system.

| Profile | Gateway capabilities | Screenshot intent |
| --- | --- | --- |
| `minimal-trusted-rag.yaml` | LLM + RAG | Tenant-scoped knowledge assistant with Context Guard and no Agent/Tool surface. |
| `autonomous-service-agent.yaml` | LLM + Inference Routing + A2A + MCP + RAG | Autonomous Agent with delegation, route controls, Tool approval, and capability-bound execution. |

Validate either profile before use:

```bash
cargo run -p ai-security-platform-app --bin ai-security-platform -- --file examples/profiles/minimal-trusted-rag.yaml --validate-only
cargo run -p ai-security-platform-app --bin ai-security-platform -- --file examples/profiles/autonomous-service-agent.yaml --validate-only
```

For an isolated UI demonstration, start each process with its own `ADMIN_ADDR`, `STATS_ADDR`, and
`READINESS_ADDR`. Set `SECURITY_UI_DEMO=1` to seed sanitized events. The optional
`SECURITY_UI_DEMO_PROFILE=trusted-rag` setting restricts seeded events to LLM/RAG actions so the
minimal profile's Security Events page does not show unavailable Agent or Tool capabilities.
