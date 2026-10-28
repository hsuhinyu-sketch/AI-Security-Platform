# UI provenance

The source in this directory is based on the `ui/` directory from
[`agentgateway/agentgateway`](https://github.com/agentgateway/agentgateway), commit
`1f7ebbf87cbdbe9517f6f181221879d04dc50692`, imported for the AI Security Platform UI migration.

The upstream project is licensed under Apache-2.0. This repository retains the upstream
attribution and its root Apache-2.0 license. Platform-specific pages and API adapters are
maintained here and must preserve this notice when upstream components are modified.

## Platform adaptation boundary

The upstream UI shell, primitives, configuration editors, Logs, Analytics, Costs and protocol
pages are the reusable baseline. AI Security Platform adds Platform capability composition,
security controls, security-event timelines, audit journals and restricted evidence views through
separate API adapters; it does not present the upstream runtime as the product boundary.

## Transitional build compatibility

The primary TypeScript project no longer uses `noCheck`. AgentGateway-era pages that still target
the upstream `gateways`/`ui`/`routes` contract are explicitly quarantined in `LEGACY.md` and are
outside the routed P0 console. New platform pages must typecheck against the current schema; a
legacy page may only return after it is migrated and added back to `tsconfig.app.json`.
