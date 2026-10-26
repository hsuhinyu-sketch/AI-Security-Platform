# RAG→LLM 业务 PoC 配置与调用

<!-- doc-role: reference -->

以下配置使用已有接口：文档入库、检索及 Context 签发，再由业务客户端组装模型请求。自动化业务测试读取此 JSON 配置块，替换占位值并启动真实 Gateway HTTP Listener。`${...}` 是本文示例的替换占位符，不代表新增的网关配置语法。

```json
{
  "aiSystems": [{
    "name": "knowledge-poc",
    "security": {
      "mode": "enforce",
      "requiredIdentity": {"user": true, "tenant": true, "agent": false},
      "policies": [
        {"id": "ingest", "actionType": "knowledgeIngest", "effect": "allow", "enabled": true, "tenantId": "tenant-a"},
        {"id": "retrieve", "actionType": "knowledgeRetrieve", "effect": "allow", "enabled": true, "tenantId": "tenant-a"},
        {"id": "assemble", "actionType": "contextAssemble", "effect": "allow", "enabled": true, "tenantId": "tenant-a"},
        {"id": "documents", "actionType": "knowledgeDocumentOperation", "effect": "allow", "enabled": true, "tenantId": "tenant-a"},
        {"id": "contexts", "actionType": "contextOperation", "effect": "allow", "enabled": true, "tenantId": "tenant-a"},
        {"id": "model", "actionType": "modelInvoke", "effect": "allow", "enabled": true, "tenantId": "tenant-a"}
      ],
      "crossComponent": {
        "namespace": "knowledge-poc", "ttlSeconds": 60, "maxContexts": 128,
        "storage": {"path": "${CONTEXT_JOURNAL}", "maxBytes": 1048576},
        "destinations": [
          {"classification": "public", "modelDestinations": ["${MODEL_TARGET}"]},
          {"classification": "internal", "modelDestinations": ["${MODEL_TARGET}"]},
          {"classification": "restricted", "modelDestinations": ["${MODEL_TARGET}"]}
        ]
      }
    },
    "rag": {
      "port": "${RAG_PORT}",
      "qdrant": {
        "endpoint": "${VECTOR_URL}", "collection": "docs", "quarantineCollection": "quarantine",
        "defaultChunkAccess": {"allowTenantAuthenticated": true},
        "integrity": {"keyId": "poc-vector", "keyEnvVar": "${INTEGRITY_ENV}"}
      },
      "embedding": {"endpoint": "${EMBEDDING_URL}", "model": "local"},
      "lifecycle": {
        "namespace": "knowledge-poc", "maxDocuments": 128,
        "storage": {"path": "${DOCUMENT_JOURNAL}", "maxBytes": 1048576}
      },
      "authentication": {
        "mode": "strict", "issuer": "https://issuer.example", "audiences": ["mcp"], "jwks": "${JWKS_JSON}"
      }
    },
    "llm": {
      "port": "${LLM_PORT}",
      "models": [{"name": "local", "provider": "openAI", "params": {"baseUrl": "${MODEL_BASE_URL}"}}],
      "policies": {"jwtAuth": {
        "mode": "strict", "issuer": "https://issuer.example", "audiences": ["mcp"], "jwks": "${JWKS_JSON}"
      }}
    }
  }]
}
```

替换端口、上游 URL、JWKS 公钥和私有日志路径；`INTEGRITY_ENV` 指向保存至少 32 随机字节十六进制值的环境变量。使用同一 AI system 的安全配置和可信 JWT 身份连接检索与模型请求。测试会生成临时签名身份和环境密钥，不向业务配置写入私钥。

调用顺序：

1. `POST /v1/rag/documents` 写入 `corpusId`、`documentId`、`sourceUri`、`content`。
2. `POST /v1/rag/query` 传入 `corpusId`、`query`、`limit`；保存返回的 `x-aisp-context-id` 和已通过 ContextGuard 的 `chunks`。
3. 将这些 chunks 组装为模型 messages，携带相同身份 JWT 和 `x-aisp-context-id`，调用 LLM Listener 的 `POST /v1/chat/completions`。
4. 使用 `/v1/rag/documents/lifecycle` 或 `/v1/rag/contexts/revoke` 更新权限/撤销；后续模型发送与正在消费的模型流必须重新检查。

Context ID 是身份、配置、分级及文档版本约束的引用，不是独立凭证，也不是客户端任意 messages 已经经过净化的证明。业务客户端负责按第 3 步组装请求；Gateway 继续验证身份、文档状态、模型授权和真实出口。上下文正文不存入安全状态日志；向量载荷完整性由已配置的 MAC 校验。

PoC 使用可观察的本地模型/Embedding/向量接口替身，验证真实网络路径、模型收到的内容和拒绝后无上游调用，不宣称模型生成质量或真实外部服务已经验收。无需新增聚合问答 API 或生产测试接口。

配置上述 Listener 后，可用附带业务客户端调用（JWT 从环境变量读取）：

```sh
python3 tests/protocol/rag_llm_client.py \
  --rag-url http://127.0.0.1:8081 --llm-url http://127.0.0.1:8082 \
  --corpus docs --query '根据文档回答问题' --token-env AISP_POC_TOKEN
```

客户端将问题与已授权 chunks 一起组装到 messages，保留 documentId/sourceHash，并将检索内容标记为数据；检索拒绝、缺少 Context 或没有可用证据时不会调用模型。HTTP 重定向不会携带 JWT 被自动跟随。它是可替换的业务侧示例，不改变 Gateway 的 HTTP API 或新增模型执行通道。
