# Qwen3.8 请求层长上下文快速审计

这次只修改风控平台调用审计模型的请求方式，不要求修改 Qwen3.8 / vLLM 的部署参数。

Qwen3.8/vLLM 的上下文上限由模型服务自己的 `--max-model-len` 决定。平台默认 `AUDIT_CONTEXT_TARGET_TOKENS=0`，不再固定卡 260K；只有模型真实返回 context-length 错误后，平台才读取模型报告的 maximum/requested tokens 并动态分段。审计输出仍压到 128 tokens。

## 正常请求路径

```text
完整请求文本
  → 本地 Cyber 规则
  → 一次完整审计模型请求
  → Qwen no-thinking
  → 直接输出紧凑 JSON
```

平台对 Qwen 审计请求强制发送：

```json
{
  "temperature": 0,
  "max_tokens": 128,
  "chat_template_kwargs": {
    "enable_thinking": false,
    "preserve_thinking": false
  }
}
```

用户内容末尾还会追加 `/no_think` 作为旧模板兼容兜底。模型必须直接返回：

```json
{"decision":"allow|block|review","risk_code":"","category":"","confidence":0.99,"reason":"brief"}
```

## 超过上下文时如何处理

平台不会再发送 `truncate_prompt_tokens`，也不会只保留开头或结尾。静默截断会漏审中间内容，容易被绕过。

实际流程是：

```text
先提交完整文本
  ↓
模型明确返回 context-length 错误
  ↓
解析 maximum context / requested tokens
  ↓
按实际比例计算分段大小，额外保留 10% 安全余量
  ↓
按 UTF-8 安全边界切分，分段之间默认重叠 4096 bytes
  ↓
最多 2 段并行审计
  ↓
任意一段 block → 整个请求 block
任意一段 review 且无 block → 整个请求 review
所有段 allow → 整个请求 allow
```

如果上游错误没有提供 token 数量，平台退回到 192 KiB 的保守分段；若某一段仍然超限，分段大小减半后自动重试，最多四轮。任何分段失败时，fail-closed 路由返回 555，不会把未完整审计的请求放给真实上游。

## 风控平台参数

```env
AUDIT_TEXT_MAX_BYTES=8388608
AUDIT_OUTPUT_MAX_TOKENS=128
AUDIT_DISABLE_THINKING=true
AUDIT_LONG_CONTEXT_THRESHOLD_BYTES=131072
AUDIT_LONG_CONTEXT_TIMEOUT=120s
AUDIT_CONTEXT_TARGET_TOKENS=0  # 自动，以模型真实上下文错误为准
AUDIT_FALLBACK_CHUNK_BYTES=196608
AUDIT_CHUNK_OVERLAP_BYTES=4096
AUDIT_CHUNK_CONCURRENCY=2
AUDIT_MAX_CHUNKS=64
```

这些参数只作用于 `newapi-risk-platform → 审计模型` 的请求，不改变 Qwen 服务本身。

## 模型名是别名时

模型名称包含 `qwen` 时会自动启用 no-thinking。如果你的 vLLM served-model-name 被改成了 `audit-fast` 等别名，在审计 Profile 的 Extra 中填写：

```json
{
  "_risk_qwen_fast_mode": true
}
```

`_risk_` 开头的字段只供平台内部使用，不会传给模型服务。

## Trace 中可见

超限分段后，请求追踪 Metadata 会记录：

```text
audit_mode=chunked_after_context_limit
audit_chunk_count
audit_chunk_bytes
audit_requested_tokens
audit_context_window_tokens
audit_retry_count
```

因此 Web 端可以确认某条请求是否发生过超限、切了多少段，以及模型报告的最大/实际 token 数。

## 延迟说明

关闭 thinking 会显著减少无用输出和 `AUDIT_MODEL_ERROR`，但无法消除长输入的 prefill。未超限请求只调用模型一次；只有模型明确报告上下文超限时才分段，因此不会给普通请求增加额外 tokenizer 请求或第二次预检查。
