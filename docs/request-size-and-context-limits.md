# 请求体大小与模型上下文限制

平台现在区分两个完全不同的限制：

1. `REQUEST_TOO_LARGE`：HTTP 请求体超过网关的字节安全上限 `REQUEST_MAX_BYTES`。这是防 DoS 限制，不是模型 token 限制。
2. `AUDIT_CONTEXT_TOO_LARGE`：审计模型自己报告 prompt/input tokens 超过模型上下文。

## REQUEST_TOO_LARGE

如果客户端携带可靠 `Content-Length`，Trace 会记录精确：

```text
request_body_bytes
request_body_limit_bytes
request_body_over_limit_bytes
request_body_size_exact=true
```

对于 HTTP chunked 或没有 Content-Length 的请求，为了不通过“读完整个超大请求”绕过防 DoS 上限，平台只读取到安全边界并记录：

```text
request_body_size_exact=false
request_body_bytes=至少 REQUEST_MAX_BYTES+1
```

Web 会明确显示“至少”，不会把下界伪装成精确大小。

## 审计模型 Token 上下文

`AUDIT_CONTEXT_TARGET_TOKENS=0` 为默认值，表示平台不设置固定 token 天花板。平台先发送完整审计请求；只有审计模型明确返回 context-length 错误后，才使用模型报告的最大上下文和实际 input tokens 动态计算重叠分段。

例如 Qwen vLLM 使用：

```text
--max-model-len 260000
```

则 260,000 是这个 Qwen 实例的模型上下文上限，不是风控平台硬编码的限制。
