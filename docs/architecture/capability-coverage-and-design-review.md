# AI Security Platform 能力覆盖与设计评估

## 目的与结论

本文从产品和安全架构角度评估平台应覆盖的能力、组件间的安全约束，以及当前设计的完整性。评估对象是通用 AI 系统网关平台，涵盖 LLM、Inference Routing、MCP、A2A 和 RAG 场景；不把实现完成度、性能或生产部署就绪度作为本文的评估标准。

总体判断：现有方向合理，已经具备主要协议入口和安全控制主干。下一阶段的设计重点应从单次请求的身份与授权，拓展到跨步骤行为、数据流向、任务资源预算及管理面治理。网关能力按实际协议和场景组合；安全策略则应跨越所有启用的入口和后端执行边界。

## 产品能力模型

平台中的网关能力分为协议入口、执行路径和知识路径。它们可以组合部署，但语义并不相同。

| 能力 | 职责 | 组合关系 |
|---|---|---|
| LLM Gateway | 模型 API 接入、Provider 适配、模型级策略及调用控制 | 需要模型服务接入时启用；可单独部署 |
| Inference Routing | 在多个合格模型后端之间选择、故障切换及路由治理 | LLM Gateway 的可选执行能力；路由不得削弱安全约束 |
| MCP Gateway | MCP Server、Tool、Resource、Prompt 等 MCP 能力的代理与治理 | 系统使用 MCP 交互时启用 |
| A2A Gateway | 跨 Agent 协议调用、任务交互及 Agent 访问治理 | 仅在系统使用 A2A 协议时启用；Agent 使用 MCP 不自动要求 A2A |
| RAG Gateway | 文档接入、检索、Chunk 筛选及上下文装配 | 作为可选知识路径，可与 LLM 及其他网关组合 |
| 通用 HTTP/API 接入 | 接入未采用 MCP/A2A 的应用 API、工具和模型服务 | 复用统一安全合同；具体协议适配仍由网关边缘负责 |

可将一套 AI 系统视为若干交互路径的组合：

```text
用户 / 上游系统
   ├── LLM 请求 ──> LLM Gateway ──> Inference Routing ──> 模型后端
   ├── Tool 请求 ──> MCP Gateway ──> Tool / API
   ├── Agent 请求 ─> A2A Gateway ──> Agent Runtime
   └── 知识请求 ──> RAG Gateway ──> 检索后端 ──> 上下文装配 ──> LLM

所有已纳入治理的路径均执行统一身份、授权、策略约束和审计。
```

重要边界：启用安全控制的路径必须覆盖所有可达入口。若模型、Tool、Agent 或向量库仍有不经网关的可用访问路径，平台只能保护经过网关的流量，不能声称其策略覆盖整个系统。

## 安全控制模型

每个入口把已验证的主体、操作和资源映射为共同的授权请求：

```text
已验证身份 + 可信上下文
        ↓
Subject / Action / Resource
        ↓
身份校验 → 静态授权 → 动态约束 → 动作约束 / 审批
        ↓
允许 / 拒绝 / 附带执行约束 → 后端适配器执行 → 审计
```

平台目前的主体包含 User、Agent、Tenant、委托标识及 Session/Client 上下文；操作覆盖模型调用、推理路由、Agent 调用、Tool 列举与执行、知识入库、检索和上下文装配。扩展新协议时，协议适配器负责生成可信的通用操作，不应让安全核心依赖具体协议类型。

策略决策与动作执行应当分开表达。授权核心给出允许或拒绝；当策略还要求脱敏、指定模型区域、限制出口、设置预算或要求审批时，应返回可验证的结构化约束。协议适配器必须证明自己执行了适用约束；缺少执行能力时应拒绝该组合或拒绝请求，不能静默忽略。

组合规则应由配置校验及运行时共同保证：

| 场景 | 必需约束 |
|---|---|
| MCP Tool 执行 | 已验证主体、Tool 级授权、参数约束；高风险 Tool 按策略加入审批及执行凭证 |
| A2A 任务及产物 | Agent 身份与调用授权，并对任务所有者、租户、状态及操作类型实施资源级检查 |
| RAG 检索 | 严格身份、租户/语料授权、后端过滤、返回 Chunk 复核及上下文预算 |
| 多模型路由 | 先按身份、数据类别和目的过滤合格后端，再在合格集合内选择；Fallback/重试重新满足相同约束 |
| 长时间 Agent 工作流 | 委托权限逐级收窄；持续执行受撤销、时限、费用和动作次数约束 |
| 高风险副作用 | 审批绑定主体、操作、资源及关键参数；后端对实际执行请求验证凭证和幂等键 |

### 当前已接入的组合校验

`aiSystems` 配置在规范化前校验以下关系：Inference Routing 需要 LLM Gateway；RAG 需要已编入二进制的 RAG 能力、强制执行模式、严格 JWT 验证及可用的 RAG 配置；Tool 审批项和 Capability Broker 需要 MCP Gateway。安全配置同时拒绝本地和远程 Agent 身份源并存、缺少动态授权的远程 PDP、没有审批项的审批提供方，以及非强制执行模式或缺少可信审批提供方的 Capability Broker。

只声明 `requiredToolApprovals` 而不配置审批提供方仍然有效：该场景按设计在执行时拒绝高风险 Tool，可用于先声明高风险边界。需要让高风险 Tool 实际通过时，再配置可信审批源；需要后端一次性执行凭证时，额外配置 Capability Broker 及受保护 Tool 端的消费适配器。

远程安全服务当前保留同步 trait。集成层把调用限制在最多 32 个并发阻塞线程，并在多线程 Tokio 环境中交还等待中的运行时工作线程；超出上限时拒绝请求。后续若高并发场景成为目标，应将该边界升级为异步安全合同，而不是扩大线程上限。

## 能力覆盖评估

### 身份与授权

已有统一身份映射、租户/用户/Agent 维度策略、默认拒绝、Agent 注册绑定、直接用户到 Agent 委托、动态 PDP 和撤销检查，作为基础模型是合适的。

后续设计需明确工作负载身份、Issuer/Audience 验证边界、凭据轮换、Agent 停用传播，以及 OAuth Client/用户授权的生命周期。多级 Agent 委托不能把父权限复制给子 Agent：每次委托都应限制资源、操作、参数范围和有效时间，且撤销应传播至后续动作。

### Tool、MCP 与 A2A 行为控制

Tool 调用级别的授权和参数绑定是必要基础。还需治理 Tool 注册来源、版本、描述与 Schema 变更、服务目标和风险等级，以免名称不变而实际能力扩大。对状态变更操作，应把幂等性纳入执行合同，防止超时重试造成重复副作用。

A2A 控制不能止于 JSON-RPC 方法。Task、Task 查询/取消、流式订阅、Artifact 和推送通知都是独立资源或操作，需要检查任务主体、所属租户和当前状态。应在协议适配层将这些操作映射为资源级安全动作。

### 数据流向与内容安全

提示注入、模型输入/输出检查和 RAG 上下文保护属于必要的内容控制，但内容检测无法代替授权。即使一个主体有权读取数据，仍需判断这些数据是否可以传给特定模型、Agent、Tool、外部 API 或租户。

建议逐步建立数据分类与目的地策略：数据标签在入库或可信来源处产生并随 Chunk/上下文传播；路由器和 Tool 出口根据标签、租户、后端信任级别及区域作决定。第一阶段可采用明确标签和目标白名单，随后再增加通用数据流追踪。

首版已提供 `aiSystems[].security.dataEgress`：管理员给一个 AI 系统指定 `public` / `internal` / `restricted` 分类，再以实际出站目标的精确标识配置 `modelDestinations`、`inferenceDestinations`、`agentDestinations` 和 `toolDestinations`。启用时必须使用 `security.mode: enforce`；某类目标列表为空即拒绝该类出口。LLM/A2A/推理在最终后端调用前按实际 `host:port` 检查，重试/路由重选会重新检查；MCP Tool 在发出调用或签发执行凭证前，按 `MCP Server ID/Tool Name` 检查。决策通过原有安全审计通道进入 UI，保留分类策略 ID 与目标标识，不记录请求内容。启用该策略的 HTTP CONNECT 隧道及请求镜像被拒绝，以免绕过检查。

示例（目标地址仅作配置格式说明，部署时须替换为实际后端标识）：

```yaml
aiSystems:
  - id: private-assistant
    security:
      mode: enforce
      dataEgress:
        classification: restricted
        modelDestinations: ["private-model.internal:443"]
        inferenceDestinations: ["private-model.internal:443"]
        agentDestinations: ["trusted-agent.internal:8443"]
        toolDestinations: ["service-tools/ticket.create"]
```

这只是系统级静态标签和出口白名单，不会自动识别提示内容的敏感度，也没有把 RAG Chunk 标签传播到模型请求。启用该策略的 AI 系统若通过没有相应出口适配器的普通 HTTP/API 或 MCP 透传链路出站，将被拒绝；RAG 自身的 Qdrant/Embedding 出站和绕过网关的直连仍需单独治理。因此不能将首版描述为全链路数据流追踪，实际部署还需阻断绕过网关的网络路径。

RAG 侧现已增加分级元数据：`rag.ingestion.defaultClassification` 默认为 `restricted`，管理员可配置 `classificationRules`，按内容规则将文档升级到更高等级。规则有稳定 `id`；入库响应和审计记录最终等级与规则来源，生成的 Chunk 继承相同元数据，Qdrant 存储和检索、上下文装配以及查询响应继续保留。装配结果取实际保留 Chunk 的最高等级；脱敏不自动降级。旧索引缺少等级或规则来源时按 `restricted` 处理。例如：

```yaml
rag:
  ingestion:
    defaultClassification: internal
    classificationRules:
      - id: customer-data
        classification: restricted
        pattern: customer email
```

此阶段的规则来源是服务端配置，而不是请求 JSON/Header；但 Qdrant 负载中的分类元数据目前未签名，必须把向量库完整性纳入部署信任边界。文档分类也尚未跨 RAG HTTP 边界可信地传给 LLM Gateway，因此现有 `dataEgress` 仍按 AI 系统静态等级执行。下一步需要定义可验证的上下文摘要/凭据与模型请求绑定，再让路由器按实际数据等级筛选目标。

RAG 安全应覆盖完整数据生命周期：接入校验、来源和版本、Chunk ACL、索引更新、权限变更、撤回/删除传播、备份与缓存失效，以及最终上下文装配。检索时过滤和逐 Chunk 复核应继续保留为双重边界。

### 预算、路由和韧性

LLM Token 限额和请求速率是必要控制，但 Agent 工作流的资源消耗跨越多次调用。平台应定义按 Tenant、User、Agent、Task/Session 维度累计的费用、Token、模型调用、Tool 调用、并发、持续时间、递归深度和检索规模上限，并说明不同网关之间如何共享预算与取消信号。

路由策略必须服从安全资格约束。比如只允许私有区域处理的数据，不应因私有模型故障而自动回退到公共模型。每次切换模型、跨区路由或重试时，应检查后端资格、数据策略及请求幂等性。Fallback 是可用性策略，不能隐式扩大权限或数据暴露面。

### 审计与管理面

审计应覆盖身份校验、授权结果、实际执行目标、数据分类/转换结果、审批、路由切换、预算耗尽、撤销及管理操作。事件需有稳定的请求/任务关联标识、策略版本、执行阶段和后端结果；按敏感度控制字段，避免记录原始提示、Token 或密钥。

策略管理、Agent/Tool 注册、模型与路由配置、审批人配置、审计访问本身也属于安全边界。管理面需要独立的身份与角色授权、租户隔离、变更记录、版本校验和回滚机制。操作型 UI 可后续建设，但策略对象及变更合同应先纳入平台设计。

## 安全能力与外部系统的责任边界

平台应负责协议流量上的身份映射、策略决策、参数/内容控制、路由约束、预算执行和事件关联。身份提供商、密钥管理服务、审批系统、持久审计系统、向量数据库和 Tool 后端可作为可替换集成，但其信任合同必须清楚。

传输加密、密钥签发和密钥保管不由 Hash 替代。Hash 可用于内容指纹、参数绑定和审计关联；TLS/mTLS 保护网络传输及服务身份，签名凭据用于可验证授权，密钥管理系统负责密钥生命周期。部署还需以网络策略或后端鉴权阻止绕过网关的直接访问。

平台本身不能保证模型内部行为正确，也不能单独提供容器/进程隔离、身份提供商安全或业务数据治理。应把这些明确列为外部系统责任和部署前提，而不是通过增加网关策略名称来暗示已覆盖。

## 建议演进顺序

1. **明确组合契约**：为每类系统定义最小安全依赖和不允许的能力组合，配置校验能指出缺失的执行器。
2. **先覆盖数据和行为边界**：补数据分类/出口策略、任务级预算、受策略约束的路由与 Fallback。
3. **完善 Agent 与 Tool 资源模型**：加入 A2A Task/Artifact 授权、多级委托收窄、Tool 版本治理和副作用幂等合同。
4. **补齐治理与数据生命周期**：为策略、注册表、审计和 RAG 删除/撤销定义生命周期与责任边界。
5. **以端到端威胁场景验收**：验证绕过路径、跨租户访问、注入后调用、Fallback 越权、工作流预算耗尽、委托撤销和 RAG 权限变更，而不只验证单个策略匹配。

该顺序把数据出口和工作流预算列为下一批通用控制；协议特殊语义和管理 UI 可按实际集成阶段逐步交付。

## 外部依据

- [MCP Security Best Practices](https://modelcontextprotocol.io/docs/draft/tutorials/security/security_best_practices)：覆盖混淆代理、Token 透传、SSRF、状态句柄和授权服务器 URL 校验等 MCP 风险。
- [A2A Protocol Specification](https://a2a-protocol.org/latest/specification/)：用于界定 Agent Card、Task、状态更新及 Artifact 等 A2A 交互对象。
- [OWASP GenAI LLM06:2025 Excessive Agency](https://genai.owasp.org/llmrisk/llm062025-excessive-agency/) 与 [LLM10:2025 Unbounded Consumption](https://genai.owasp.org/llmrisk/llm102025-unbounded-consumption/)：支持将最小权限和跨调用资源预算作为不同但互补的安全控制。

## 相关架构文档

- [当前 Workspace 结构](current-structure.md)
- [产品身份与当前安全能力阶段](product-identity.md)
- [Capability Broker 信任边界](capability-broker.md)
