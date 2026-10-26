# Third-party source dependencies

<!-- doc-role: vendor-reference -->

> 上游/第三方依赖说明，仅适用于对应依赖；保留原文与许可语境。平台架构见源码仓库 `docs/architecture/README.md`。


The source directory [crates/third-party](../../crates/third-party) contains vendored or forked third-party libraries retained as source dependencies.
They are not AI Gateway Platform runtime modules.

| Directory | Rust packages | Purpose |
| --- | --- | --- |
| `cel-fork` | `cel`, `cel-derive` | CEL implementation required by policy and configuration processing. |
| `htpasswd-verify-fork` | `htpasswd-verify-fork` | HTTP basic-auth verification dependency. |

New platform functionality belongs under `crates/gateway`, `crates/security`, or
`crates/platform`; changes here should be limited to dependency maintenance.

Vendored documentation is archived here: [htpasswd-verify](htpasswd-verify-fork/README.md),
[cel-derive](cel-fork/cel-derive/README.md), [CEL changelog](cel-fork/cel/CHANGELOG.md).
