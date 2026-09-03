# 上游流式超时与 Token 用量

## 误报原因

旧版把渠道路由的 `request_timeout_ms` 应用于整个 SSE 生命周期。以
`4,970` 输出 Tokens、`41 t/s` 为例，仅解码就需要约 `121.2s`；再加上
`17,969` 输入 Tokens 的 prefill 和网络时间，会超过常见的 `120000ms`。
网关因此主动取消一个仍持续输出的健康流，并记录
`UPSTREAM_STREAM_INTERRUPTED`。

新版语义：

- 普通非流式响应：`request_timeout_ms` 仍是完整响应超时；
- SSE 流：收到响应头之前是建立响应超时；收到响应头之后变成**流空闲超时**；
- 每收到一个 SSE event 都会重置空闲计时器；
- 只要上游持续输出，总生成时间可以超过 `request_timeout_ms`；
- 已看到 `[DONE]`、`finish_reason`、`response.completed` 或 `message_stop` 后，
  即使服务端随后用 TCP reset 关闭连接，也按已完成处理，不再伪造逻辑 555。

Trace 会记录：

```text
upstream_timeout_scope
upstream_stream_idle_timeout_ms
upstream_header_latency_ms
upstream_response_duration_ms
upstream_completion_semantics
upstream_stream_read_error
```

## Token 用量

网关会解析 OpenAI Chat Completions、Responses API、Anthropic 和 Gemini
兼容返回中的 usage 字段，并写入：

```text
upstream_input_tokens
upstream_output_tokens
upstream_total_tokens
upstream_cached_tokens
upstream_cache_creation_tokens
upstream_reasoning_tokens
upstream_output_tokens_per_second
upstream_usage_source
upstream_usage_exact
```

Web 请求列表以 `输入 / 输出` 的形式展示，例如：

```text
17,969 / 4,970
缓存：9,984
41.0 t/s
```

这些值来自上游返回的 usage，因此是精确值。若渠道没有在流中返回 usage，
平台不会伪造精确数字；字段保持为空。对于 OpenAI 兼容流，NewAPI/调用方应
保留 `stream_options.include_usage=true`，Responses API 通常会在
`response.completed` 事件中携带 usage。
