# Changelog

<!-- doc-role: changelog -->

## Unreleased — 组件化 PoC 候选版本

- 支持按场景编译组合 LLM、MCP、A2A、RAG，保留共享 Host、安全配置热更新和统一受控执行。
- 提供 RAG → LLM 与知识检索 → 工具 → 模型 → A2A Task/Artifact 的示例链路。
- 严格拒绝未知安全字段；不支持内容检查的路径在出站前拒绝，响应 guard 默认检查流，非流式工具参数纳入检查和实际遮蔽。
- 旧 MCP stdio/SSE 关联限制为每连接 128 项和 120 秒期限，连接关闭与新注册保持同步；不自动重发不确定的副作用。
- A2A Task 绑定原 Context 与预算，同一用户不能用新 Context 接管旧 Task；旧 Task 缺少所需绑定时拒绝并要求新建。
- 移除 Runtime 演示事件注入；真实授权、拒绝和审计持久化保留。
- 提供五种场景的候选构建、版本/提交核验、manifest 和 SHA-256，不自动发布。见[发布指南](release/README.md)。

当前仍为 PoC 候选版本；真实设备、生产环境和完整外部服务集成需要进一步验证。变更记录不表示版本已经发布。
