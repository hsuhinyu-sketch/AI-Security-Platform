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

`tsconfig.app.json` currently uses `noCheck`. The imported UI's generated TypeScript schema
targets a newer upstream standalone configuration contract than the current Rust compatibility
runtime. Vite still type-transpiles and bundles the UI, while platform routes use explicit local
API adapters. This setting is temporary: it will be removed when the remaining configuration
pages are migrated to the platform configuration schema.
