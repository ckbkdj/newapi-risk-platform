# 请求体大小与模型上下文限制

平台区分三个阶段，不能把它们混为同一种“超限”：

1. `REQUEST_TOO_LARGE`：**Risk Gateway 入口 HTTP 请求体字节限制**。由 `REQUEST_MAX_BYTES` 触发，审计模型和真实上游都还没有被调用。
2. `AUDIT_CONTEXT_TOO_LARGE`：审计模型自己报告 prompt/input tokens 超过审计模型上下文。
3. 上游模型上下文错误：真实上游返回 HTTP/流式错误，Trace 的 `failure_stage` 为 `upstream_http`、`upstream_response` 或 `upstream_stream`，并保存上游错误原因。

## REQUEST_TOO_LARGE：来源是 Risk Gateway

新版 Trace 会明确包含：

```json
{
  "error_class": "request_body_too_large",
  "error_origin": "risk_gateway",
  "failure_stage": "gateway_ingress",
  "failure_component": "request_body_guard",
  "limit_owner": "risk_gateway",
  "limit_config": "REQUEST_MAX_BYTES",
  "limit_scope": "inbound_http_request_body",
  "limit_unit": "bytes",
  "audit_started": false,
  "upstream_started": false
}
```

这表示请求在进入风控平台时就因 HTTP body 太大被拒绝，既不是审计模型超限，也不是上游模型超限。

如果客户端携带可靠 `Content-Length`，Trace 会记录精确：

```text
request_body_bytes
request_body_limit_bytes
request_body_over_limit_bytes
request_body_size_exact=true
```

对于 HTTP chunked 或没有 Content-Length 的请求，为避免通过“读完整个超大请求”绕过防 DoS 上限，平台只读取到安全边界并记录：

```text
request_body_size_exact=false
request_body_bytes=至少 REQUEST_MAX_BYTES+1
```

Web 会明确显示“至少”，不会把下界伪装成精确大小。

### 60,853,983 bytes 的请求

该大小约为 58.04 MiB，低于平台支持的 64 MiB 配置上限。要允许该请求，服务器 `.env` 可设置：

```env
REQUEST_MAX_BYTES=67108864
```

然后重新部署 Risk Gateway。不要把 `AUDIT_TEXT_MAX_BYTES` 当成同一个参数：它限制从 JSON 中抽取给审计模型的文本，内联图片/文件的 base64 应由抽取器跳过。如果实际文本本身也非常大，应拆分会话或请求，而不是无限提高内存上限。

对于高并发商业部署，不建议全局长期放开大 body 后仍保持很高并发。优先使用对象存储 URL 代替内联 base64，并对大请求路由降低 `max_concurrency`。

## 审计模型 Token 上下文

`AUDIT_CONTEXT_TARGET_TOKENS=0` 为默认值，表示平台不设置固定 token 天花板。平台先发送完整审计请求；只有审计模型明确返回 context-length 错误后，才使用模型报告的最大上下文和实际 input tokens 动态计算重叠分段。

例如 Qwen vLLM 使用：

```text
--max-model-len 260000
```

则 260,000 是这个 Qwen 实例的模型上下文上限，不是风控平台硬编码的限制。

## 判断来源

```text
REQUEST_TOO_LARGE
+ error_origin=risk_gateway
+ failure_stage=gateway_ingress
+ audit_started=false
+ upstream_started=false
    => Risk Gateway 请求体字节限制

AUDIT_CONTEXT_TOO_LARGE
+ audit_input_tokens / audit_context_window_tokens
    => 审计模型上下文限制

UPSTREAM_*
+ failure_stage=upstream_*
+ upstream_error_reason
    => 真实上游或上游链路错误
```
