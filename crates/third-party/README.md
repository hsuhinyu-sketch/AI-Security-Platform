# Third-party source dependencies

This directory contains vendored or forked third-party libraries retained as source dependencies.
They are not AI Gateway Platform runtime modules.

| Directory | Rust packages | Purpose |
| --- | --- | --- |
| `cel-fork` | `cel`, `cel-derive` | CEL implementation required by policy and configuration processing. |
| `htpasswd-verify-fork` | `htpasswd-verify-fork` | HTTP basic-auth verification dependency. |

New platform functionality belongs under `crates/gateway`, `crates/security`, or
`crates/platform`; changes here should be limited to dependency maintenance.
