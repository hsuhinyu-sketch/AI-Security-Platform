# 候选版本构建与发布准备

<!-- doc-role: reference -->

当前交付定位为 PoC 候选版本，版本号由维护者确定，建议使用 `vX.Y.Z-rc.N`。本目录不声明任何版本已经发布。生产 Linux 和设备认证尚未验收，本机性能数据不能外推到目标设备。

## 构建和核验

使用项目锁定的 Rust 1.96 工具链、Cargo.lock 和原生 Linux GNU 环境。先完成源码审阅与必要回归，再在已提交的干净工作区执行；打包工具拒绝未跟踪文件或未提交改动，不会提交、推送、创建标签或发布 Release。

```sh
python3 scripts/prepare_release.py --version vX.Y.Z-rc.N --profile llm --check
python3 scripts/prepare_release.py --version vX.Y.Z-rc.N --profile llm
```

示例版本需替换为维护者选择的数字版本；依赖已缓存时可增加 `--offline`。工具执行 `cargo build --locked --release --no-default-features`，显式指定本机 target 和场景 features，并用 VERSION/GIT_REVISION 固定二进制标识。打包前检查实际 `--version` JSON 的版本、提交、release profile 与 target，再次确认工作区未发生变化。

| profile | 显式编译能力 |
| --- | --- |
| llm | gateway-llm、security-s1、tls-aws-lc |
| mcp | gateway-mcp、security-s1、tls-aws-lc |
| a2a | gateway-a2a、security-s1、security-a2a-sqlite、tls-aws-lc |
| rag | gateway-rag、security-s1、tls-aws-lc |
| full | gateway-full、security-a2a-sqlite、tls-aws-lc |

五种产物均使用 `ai-security-platform` 入口，场景名体现在压缩包和 manifest 中。Full 含 LLM/MCP/A2A/RAG 与模型路由；上述组合不启用演示 UI、普通请求日志数据库、OTLP 或云身份 SDK。需要这些集成时另选已有 features 并重新验证，不能把不同组合的结果混用。`security-s1` 提供统一执行底座；安全配置仍须明确 Enforce、可信身份及场景所需控制，默认 Audit 行为没有改变。

输出位于 `target/release-dist/`：场景/版本/target 命名的 tar.gz 及 SHA-256 文件。包内仅含可执行文件、manifest、Cargo.lock、许可和本说明，不带测试替身、密钥、缓存、基准原始数据或开发日志。manifest 记录 features、构建命令、源码提交、二进制构建标识及各载荷文件摘要；同名产物拒绝覆盖。

```sh
cd target/release-dist
sha256sum -c ai-security-platform-*.sha256
```

运行时所需配置和凭据由业务方提供。配置参考和第三方来源说明见源码仓库的 `docs/reference/configuration-guide.md`、`docs/third-party/README.md`。许可证条款以对应来源为准，Cargo.lock 保留依赖版本和来源；此候选产物不是独立依赖许可审计证明。

## GitHub 候选产物

新增 `Release candidate` 工作流仅由维护者手动触发，在所选提交上构建上述五种组合，对各组合的实际 release 二进制运行已有协议/安全 TCP 回归，成功后上传候选压缩包和校验和；失败证据单独保留。工作流只有 `contents: read` 权限，不创建 Release，不推送、不创建标签。尚未在远程运行的工作流不能视为已通过。

上传仓库前核对 `git status --short` 和提交范围，确保代码、测试、脚本及公开使用文档完整纳入，不要只提交 tracked 文件。阶段计划、交接说明、审查与性能报告及验证数据仅本地保留并由 Git 忽略；Python 缓存、target、环境变量文件不属于源码交付。发布时以相同提交上的 Rust CI 与候选产物回归结果为依据，最终选择版本和发布操作另行进行。

已移除 Runtime 的 `SECURITY_UI_DEMO` / `SECURITY_UI_DEMO_PROFILE` 演示事件注入路径；这些旧环境设置不再向安全事件流及持久化日志写入虚构记录，演示界面从实际业务请求获得数据。注册到现有 IdP 客户端的 MCP 元数据应答仍保留，生产诊断接口和配置兼容路径也保留。

发布说明应包含：组件化场景及功能、严格安全配置与内容 guard 等兼容性变化、实际验证范围、已知限制。兼容性变化和职责边界见源码仓库 `docs/CHANGELOG.md`、`docs/architecture/README.md`。候选提交必须运行对应验证，不能沿用历史测试结果。
