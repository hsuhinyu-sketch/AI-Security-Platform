# 架构与扩展边界

<!-- doc-role: reference -->

平台按 AI 场景编译组合协议、安全和基础设施能力。共享 Host 承载配置、网络与生命周期；协议组件负责协议处理。采用 Cargo features、optional dependencies 和静态装配，支持安全配置热更新，不实现动态插件系统。

| 位置 | 职责 |
| --- | --- |
| `crates/gateway/app`、`composition` | CLI、能力声明、场景组合与启动入口 |
| `crates/gateway/runtime` | 可信入口、配置装配、Listener、连接/凭据、必要安全状态与最终受控执行 |
| `crates/gateway/{llm,mcp,a2a,rag}` | 协议类型、编解码、分类、路由、协议状态与请求处理 |
| `crates/gateway/{contracts,protocol-core}` | 最小共享生命周期、值类型与实际跨组件执行契约 |
| `crates/security/*` | 统一身份、授权、PDP、审计、Capability、预算、撤销与 RAG 安全控制 |

依赖方向是 App → Runtime Host → 协议组件；协议组件可以使用共享契约和必要安全类型，不能反向依赖 Runtime 或兄弟协议内部实现。Host 可以实现组件定义的窄接口，保留与授权原子性绑定的状态；不为拆分数量复制模型或增加通用注册中心。

## 安全执行

可信身份、授权、审批、预算、审计和出口约束贯穿实际执行链。路由结果、候选 Allow、普通 HTTP 调用或布尔标记不是执行许可。最终目标/参数变化、重试和配置失效必须重新校验；取消、撤销或预算终止后，受保护响应流停止输出数据。

安全能力采用场景级组合，保证依赖完整，不要求每个控制任意单项裁剪。配置引用未编译的能力时明确拒绝；已要求的安全控制不得静默降级。详细语义见[统一执行约束](../protocol/execution-contract.md)。

## 扩展方式

新增协议在对应协议组件实现处理规则，通过 Host 装配和 Cargo 能力声明接入。跨协议执行使用受控契约，例如 MCP Sampling 通过模型执行契约调用模型，不绑定 LLM Runtime 内部实现。

新增安全能力优先复用既有 `SecurityControl`、`RuntimeSecurityControls`、`Authorizer`、`DynamicPdp`、`ApprovalProvider` 和 `AuditSink` 等扩展点；仅在有实际调用需要时增加接口，不建立第二套身份或策略引擎。

变更需验证正常链路、授权拒绝、跨租户访问、配置失效、取消/重试及相关持久化故障。源代码、Cargo features 和本次执行的测试结果决定实现状态，文档不替代安全回归。构建选择见[发布指南](../release/README.md)，业务使用见[配置参考](../reference/configuration-guide.md)。
