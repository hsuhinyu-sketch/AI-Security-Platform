# AI Security Platform

<!-- doc-role: entrypoint -->

面向端侧部署的模块化 AI 安全平台。按实际 AI 场景，在编译期组合 LLM、MCP、A2A、RAG 协议、安全控制和必要基础设施，支持后续能力扩展。

项目使用 Rust Workspace、Cargo features 和静态装配，保留共享 Runtime Host、统一受控执行与安全配置热更新。当前定位为 PoC 候选版本；真实设备、生产 Linux 和完整外部服务集成仍需验证。UI 用于演示，不决定底层架构。

## 场景能力

| 场景 | 协议组合与安全边界 |
| --- | --- |
| 模型接入与推理 | LLM、模型路由、身份与模型授权、内容和出口控制、预算与审计 |
| Agent 工具调用 | MCP；需要网关侧模型执行时组合 LLM，保留工具、会话、任务授权及审批/Capability |
| 多 Agent 协作 | A2A，按业务组合 MCP/LLM，保留委托与 Task/Artifact 对象权限 |
| 知识检索与问答 | RAG，需要生成时组合 LLM，保留租户、文档权限、ContextGuard 和出口约束 |

协议组件处理协议规则，Host 装配依赖并承担可信入口、基础设施和最终安全执行；复用已有 Security Core，不实现运行时热插拔。安全能力按场景组合，配置要求的能力缺失时明确拒绝。

## 构建与运行

使用 [rust-toolchain.toml](../rust-toolchain.toml) 指定的 Rust 工具链。示例构建不带其他协议实现的模型网关：

```sh
cargo build --locked --release -p ai-security-platform-app \
  --no-default-features --features gateway-llm,security-s1,tls-aws-lc \
  --bin ai-security-platform
./target/release/ai-security-platform --file /path/to/config.yaml --validate-only
./target/release/ai-security-platform --file /path/to/config.yaml
```

配置与凭据由业务方提供。使用 `--no-default-features` 才能排除默认组合；五种场景的候选版本打包方式见[发布指南](release/README.md)。

**编译安全能力不等于开启强制执行。** `SecurityMode` 默认 `Audit`；安全场景需明确配置 Enforce、可信认证及专项要求。普通请求日志与 Required Audit 是不同边界，关闭前者不能绕过后者。RAG Listener 拓扑变更需要重启；已发出的外部副作用无法撤回。

可选的 `security-pii` 提供原生 PII 检测与统一模型请求出口脱敏，`security-pii-presidio` 增加本地 Presidio Analyzer Adapter。配置、模式及覆盖边界见[PII V0.1 使用说明](reference/configuration-guide.md#pii-security-component-v01)。

## 文档

- [架构与扩展边界](architecture/README.md)
- [配置与已有能力参考](reference/configuration-guide.md)
- [协议职责](protocol/README.md)与[统一安全执行约束](protocol/execution-contract.md)
- [RAG → LLM 示例](examples/rag-llm-poc.md)与[工具／Agent 协作示例](examples/tool-agent-poc.md)
- [候选版本构建与发布](release/README.md)、[变更记录](CHANGELOG.md)、[第三方来源说明](third-party/README.md)

开发交接、阶段计划、审查记录、性能原始数据和本机验证结果仅在本地保留，不属于仓库公开文档或 release 包。文档提交检查：`python3 tests/docs/check_docs.py --public`。

Apache License 2.0，见 [LICENSE](../LICENSE)。
