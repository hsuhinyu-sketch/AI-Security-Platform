# 协议与安全执行边界

<!-- doc-role: reference -->

LLM、MCP、A2A、RAG 组件承担协议编解码、分类、路由和协议状态转换；共享 Runtime Host 提供可信入口、配置装配、网络/凭据、必要安全状态及最终受保护执行。依赖关系见[架构说明](../architecture/README.md)。

## 执行约束

[统一安全执行约束](execution-contract.md)描述跨协议的身份、请求关联、授权、出口、流和恢复边界。其概念名称表示职责与语义，不要求为每个概念创建 API、通用框架或新的安全模型。

`SecurityMode` 默认 `Audit`；Audit/Shadow 中一般策略拒绝不阻断，Enforce 才执行拒绝。会话、对象、预算等专项控制、解析错误和硬性传输限制有各自的条件。编译 `security-s1` 不等于开启强制模式；具体行为见 [SecurityConfig/evaluate_with_audit](../../crates/security/integration-runtime/src/lib.rs)。

配置引用未编译的能力应在接纳时拒绝。协议 Handler 只能通过受保护操作产生副作用，不能把路由结果或普通网络接口当作执行许可。MCP Sampling 使用受控模型执行契约；对象与长生命周期操作继续保留身份绑定、持续校验、预算和审计。

支持的协议名称、版本和传输以源码为准；项目不据旧阶段文档推断最新外部规范符合性。使用方式见[配置参考](../reference/configuration-guide.md)与[业务示例](../examples/rag-llm-poc.md)。
