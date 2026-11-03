# Changelog

<!-- doc-role: changelog -->

## Unreleased — 组件化 PoC 候选版本

- 支持按场景编译组合 LLM、MCP、A2A、RAG，保留共享 Host、安全配置热更新和统一受控执行。
- 提供 RAG → LLM 与知识检索 → 工具 → 模型 → A2A Task/Artifact 的示例链路。
- 严格拒绝未知安全字段；不支持内容检查的路径在出站前拒绝，响应 guard 默认检查流，非流式工具参数纳入检查和实际遮蔽。
- 旧 MCP stdio/SSE 关联限制为每连接 128 项和 120 秒期限，连接关闭与新注册保持同步；不自动重发不确定的副作用。
- A2A Task 绑定原 Context 与预算，同一用户不能用新 Context 接管旧 Task；旧 Task 缺少所需绑定时拒绝并要求新建。
- 移除 Runtime 演示事件注入；真实授权、拒绝和审计持久化保留。
- 移除未使用的 Rust `SecurityGateway` facade，嵌入方迁移至 `SecurityPipeline`；现用 Capability、安全控制及配置/API 保留。迁移方式见[配置参考](reference/configuration-guide.md#composable-security-pipeline)。
- 同步配置／Admin Schema 与源码，修复 UI 对已有 Streaming 限额配置的误拒绝；增加只读生成一致性检查和实际 UI 校验器回归。
- 修复非法 discovery 热更新留下监听的问题；MCP Session/Task 及流式续权执行双声明约束，安全声明下禁止原始元数据透传；PDP 缓存仅在显式启用时使用并限制容量。
- 修复响应 guard 对未知 SSE 文本字段的漏检，并独立检查已知引用／注解／logprobs；默认 RAG chunk ID 改为租户／corpus／文档范围内的稳定 UUID，保留已有 lifecycle ID。
- 审批 receipt 与绝对期限贯穿 Capability 签发和消费；限制票据有效期不超过审批期限，并拒绝错配或超期的签发响应。
- 修复 MCP 会话空闲续期、失败 Task 的本地资源释放和反向请求额度占用；进度通知只转发当前请求绑定的内容。
- 修复 RAG 文档传输预算、失败阶段审计、删除失败重试及主体字段透传；保留租户、文档权限和最终 Context 校验。
- 修复配置／依赖文件监听恢复、HTTP 资源刷新和 Listener 生命周期；启动专属配置变更明确要求重启，远程安全 Provider 配置在发布前预检。
- 收敛重复安全入口和请求处理，修复 Provider 路径编码并减少普通日志中的凭据暴露。
- 提供可选 `security-integration-runtime/rag-sqlite` 异步 Context／文档联合存储及恢复测试；尚未接入 Host／YAML／HTTP，网关继续使用现有存储。
- 提供五种场景的候选构建、版本/提交核验、manifest 和 SHA-256，不自动发布。见[发布指南](release/README.md)。

当前仍为 PoC 候选版本；真实设备、生产环境和完整外部服务集成需要进一步验证。变更记录不表示版本已经发布。
