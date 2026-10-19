# Changelog

## 2026-10-19 — 核心执行安全阶段

对比基线：`7413e1b`（`Remove obsolete design docs and smoke scripts`）。

### 新增

- 建立执行安全闭环：统一执行预算、并发/超时/取消控制、依赖出口约束、强制审计，以及本地持久化和生命周期清理。
- 扩展 MCP 安全能力：对象级授权、会话归属与持续校验、反向交互、异步 Task、Elicitation、Roots，以及通过 LLM Gateway 执行且共享预算的受控 Sampling。
- 扩展 A2A 安全能力：Task/Artifact 对象级授权、SQLite 状态持久化、长连接重校验、事件恢复、Push 收发一致性、受限 Artifact 下载与安全清理。
- 增加安全感知推理路由：候选后端预筛选、最终授权、重试/降级时重新校验，以及跨组件安全约束继承。
- 增加 RAG 文档生命周期与上下文绑定：版本、撤销、上下文失效，并将检索来源约束传递至 LLM、A2A 和 MCP 执行链。
- 增加真实 Tool 副作用执行保护：一次性 Capability、操作日志、执行回执和重复提交防护。
- 增加管理面访问模式与配套配置示例，区分演示、诊断和端侧受限部署场景。

### 调整

- 扩展统一的 `Subject / Action / Resource` 安全语义，覆盖模型、Agent、Tool、MCP Session/Task、A2A Task/Artifact、RAG Document/Context 与依赖调用。
- 将执行预算、跨组件约束、MCP 会话、A2A 对象、依赖出口和强制审计统一纳入 `SecurityConfig`、配置 Schema 与运行时装配链。
- 补充 LLM 流式响应安全处理，支持输出检查、中途阻断、断连取消与预算回收。
- 更新管理 UI、安全事件视图、配置 Schema 与部署示例。

### 清理

- 删除第一方单元测试、集成测试、基准测试、Fixtures/Snapshots、Playwright E2E 及其测试依赖。
- 删除阶段性实施记录、验证证据、临时脚本及分散的架构说明；第一方 Markdown 收敛为根目录 README 与本 Changelog。
- 移除上游 Go 工具链、AgentGateway 安装脚本、失效验证流程、旧 Git Hook 与无关演示；Schema 和构建版本信息改由 Rust 原生生成。

### 验证与边界

- Rust 全功能、MCP 精简组合、A2A + SQLite 组合均通过 `cargo check`；UI 生产构建、格式检查、补丁检查和文档链接检查通过。
- 当前验证仅覆盖编译与构建；清理后不再包含自动化回归测试套件。
- 当前仍定位为单节点 PoC：持久化以本地 SQLite/日志为主，分布式协调、MCP 交互任务跨进程恢复和 Realtime/WebSocket 独立安全合同尚待完善。
