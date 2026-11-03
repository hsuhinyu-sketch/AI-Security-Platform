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

安全配置的静态校验、声明身份、PII 引擎、策略数据、参数/委托校验器和本地 Agent 注册表在配置所有者中复用；字段修改自动使静态结果失效，热更新候选准备成功后才能发布。每次执行仍绑定当前审计目标、远程 Provider、请求与 Capability，并检查身份有效期、审批、撤销、预算及配置 Lease。静态准备不新增授权结果缓存；动态 PDP 继续遵循显式配置的缓存和 Fail-Closed 规则，零 TTL 禁用缓存。

Host 模型／推理路由的最终授权和模型响应续权通过可等待的远程评估入口复用原安全管线；本地策略继续同步执行。远程等待与 Tokio 内的同步兼容桥共用 32 个接纳名额，在入队前取得、实际工作结束后释放；名额不代表进程总线程上限。续权未完成时停止读取及输出响应帧，完成后再次检查配置和 Context。取消等待不会抢占已经运行的阻塞 HTTP，调用方仍须执行最终 Lease、预算及取消检查；Core 同步兼容 API 保留。

MCP 工具请求、Session 接纳／绑定及响应保护也等待同一安全管线；高风险工具审批通过后才向 Broker 申请 Capability。公共与兼容声明均通过且请求仍有效时才将凭证写入请求，等待期间的配置失效、凭据过期或预算取消会丢弃结果。HTTP 发送前和 stdio 队列出队时重检本地状态，已过期的内部凭证不得转发。Task、反向交互及列表对象过滤等其余同步调用按原安全约束保留。

RAG 的检索、入库、来源导入预授权、Context 组装、文档生命周期操作和 Context 撤销通过可等待入口执行授权。Host 的 `SecurityConfigAuthorizer` 复用上述远程评估；`Authorizer` 的默认异步方法兼容原同步实现，本身不自动消除自定义实现的阻塞。同步与异步入口共用身份检查 → 决策 → 动作检查 → 审计顺序，保留租户／ACL、ContextGuard、文档版本和大小／Token 限额。RAG HTTP 请求及响应 Body 继续监听配置失效，并检查已验证 JWT 的有效期；等待期间失效即丢弃后续结果。RAG 接口未因此接入工作流执行账本或新增取消 API。

Rust 嵌入方可反序列化为 `SecurityConfig`，或用 `SecurityConfigData { ... }.into()` 构造；原 `SecurityConfig { ... }` 字面量需迁移。字段读取和直接修改语法保留，消费声明用 `into_data()`。`PreparedPii::get` 返回就绪引擎的 `Arc`，准备句柄克隆共享未变的引擎但独立跟踪后续配置。YAML/JSON 结构和外部 HTTP API 不因此改变。

MCP 的 `securityPipeline` 兼容声明在 Host 装配时归一成固定 Enforce 的共享配置所有者，序列化仍保留原形状。它与公共安全声明分别判断并取交集，通过统一的 MCP 执行入口调用原 Security Core；审批 Provider、观察模式和策略列表不在声明之间混用。Rust 嵌入方构造 `BackendTrafficPolicy::SecurityPipeline` 或 `BackendPolicies.security_pipeline` 时，用 `SecurityPipelineConfig::into()` 转为 `LegacySecurityPipeline`。

Host 的 [LLM 请求准备阶段](../../crates/gateway/runtime/src/proxy/llm_request.rs)集中处理 Provider 请求转换、连接路径设置、Token 限流和响应控制准备。PII 与内容控制共用协议组件的路由支持判断；不支持的控制保持原拒绝和审计语义。准备结果只描述请求适配，最终授权、预算、配置失效检查和模型请求发送继续由共享 Host 执行链负责。

## Schema 维护

Rust 类型及其序列化声明是配置和 Admin Schema 的来源。修改字段、校验范围或序列化契约后运行 `cargo xtask schema`，再运行只读的 `cargo xtask schema --check`；后者在文件缺失或过期时失败并列出文件，不改写产物。生成器使用完整默认能力组合，配置采用反序列化契约，Admin dump 采用序列化契约；单场景构建仍由 Host 验证实际编译能力。

UI 消费这些 JSON 生成类型及编辑器校验。更新 Schema 后，在 `ui/` 使用固定工具链运行 `pnpm test:schema`、`pnpm check` 和 `pnpm build`，同步提交生成的 Schema 与 `ui/out` 产物。消费方测试通过实际 UI 校验器验证限额范围和模型可见性，Rust CI 同时检查生成产物一致性。Schema 校验不能替代 Host 的配置准备、能力检查或安全授权。

## 扩展方式

新增协议在对应协议组件实现处理规则，通过 Host 装配和 Cargo 能力声明接入。跨协议执行使用受控契约，例如 MCP Sampling 通过模型执行契约调用模型，不绑定 LLM Runtime 内部实现。

新增安全能力优先复用既有 `SecurityControl`、`RuntimeSecurityControls`、`Authorizer`、`DynamicPdp`、`ApprovalProvider` 和 `AuditSink` 等扩展点；仅在有实际调用需要时增加接口，不建立第二套身份或策略引擎。

变更需验证正常链路、授权拒绝、跨租户访问、配置失效、取消/重试及相关持久化故障。源代码、Cargo features 和本次执行的测试结果决定实现状态，文档不替代安全回归。构建选择见[发布指南](../release/README.md)，业务使用见[配置参考](../reference/configuration-guide.md)。
