# 工具、模型与 Agent 协作 PoC

<!-- doc-role: reference -->

本场景复用[RAG→LLM 配置与客户端](rag-llm-poc.md)，在同一 `aiSystems` 安全域内组合已有 MCP 和 A2A 能力。使用已有 HTTP API，由业务客户端按顺序传递数据，不增加中央调度器或新的聚合协议。

1. 入库并检索知识，获取通过 ContextGuard 的 chunks 与 `x-aisp-context-id`。
2. 携带相同可信 JWT、Context ID 初始化 MCP Session，通过 `tools/list` 发现允许的 Tool，再调用 `tools/call` 处理证据。
3. 携带相同 Context ID 调用模型；模型输出交给 A2A `message/send`。
4. 使用 A2A 返回的 Task ID 读取 Task，取得授权可见的 Artifact。A2A `contextId` 和 RAG 的 `x-aisp-context-id` 各有用途，不混用。

安全配置需显式允许对应 Tool、Agent 和精确出口。`crossComponent.destinations` 的分级限制同时约束 Model/Tool/Agent；MCP 配置需 `mcpSessions`，A2A 配置需 `a2aObjects` 和严格 JWT 策略。业务测试按现有 Route Key 为 A2A 注入 JWT 策略，没有在协议 Crate 添加 Host 依赖。

可重复验证命令：

```sh
python3 tests/protocol/run_full_tcp.py --profile workflow --rounds 3 \
  --binary target/debug/ai-security-platform-full --report /tmp/poc-workflow.json
python3 tests/protocol/run_full_tcp.py --profile workflow-durable --rounds 3 \
  --binary target/debug/ai-security-platform-full --report /tmp/poc-workflow-durable.json
```

测试会生成临时身份、私有状态日志及本地上游，使用真实 Gateway Listener 完成链路。模型与 Agent 是确定性替身，验证传入内容、Task/Artifact 访问和拒绝后无上游副作用，不评价模型能力或真实外部服务质量。

Task 的既有工作流绑定同时包含预算和 Context 来源；同一用户不能用另一个新 Context 接管旧 Task。配置未启用 crossComponent 时，预算绑定保持原表示。升级前已经创建、未带 Context 绑定的 Task 在启用该约束时会安全拒绝，需要新建 Task；不自动为旧元数据补发权限。取消清理、Push 和恢复继续使用同一绑定及各自原有授权。
