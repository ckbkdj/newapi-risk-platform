# 自动请求体、时间线与角色感知审计

## 自动实际请求体大小

默认 `REQUEST_MAX_BYTES=0`。当 NewAPI 发送可靠 `Content-Length` 时，Risk Gateway 按实际请求体大小放行，只受 `REQUEST_HARD_MAX_BYTES` 绝对安全上限约束。默认硬上限为 64 MiB，因此 60,853,983 bytes（约 58.04 MiB）无需手工修改软限制即可通过。未知长度的 chunked 请求最多读取到硬上限。

大请求通过独立并发门禁保留内存槽，默认 8 MiB 以上最多同时处理 4 个，避免自动放宽后在商业并发中放大内存。

```env
REQUEST_MAX_BYTES=0
REQUEST_HARD_MAX_BYTES=67108864
REQUEST_LARGE_BODY_THRESHOLD_BYTES=8388608
REQUEST_LARGE_BODY_MAX_CONCURRENCY=4
```

## 对齐 NewAPI 的时间线

每条 Trace 独立保存 `started_at`、`completed_at` 和 `ingested_at`。页面和查询默认按完成时间展示/过滤，因为 NewAPI 的日志和计费结果通常在请求完成时生成。详情页同时显示三种时间和浏览器时区。NewAPI 主动追踪事件可发送 `started_at`、`completed_at` 或兼容字段 `occurred_at`。

## 只审计最终用户意图

系统、developer、assistant、tool、function、工具 schema 和历史生成内容不再进入规则/模型的执法文本。只有 user/end_user/human/customer/client 角色以及顶层用户 `input`、`prompt`、`query` 可以触发 Block。正常 AI 编程系统提示词中的依赖解析、导入、构建修复、项目内 symlink 或 Windows junction 不会再被当作攻击。

Trace 会记录 `audit_input_scope=end_user_intent_only`、用户意图字节数、忽略的上下文字节数和角色，但不保存完整系统提示词。

## NewAPI 请求关联

Risk Gateway 识别 `X-NewAPI-Request-ID`、`X-Oneapi-Request-Id` 和 `X-Request-ID`。响应同时返回 `X-Risk-Request-ID` 与 `X-Oneapi-Request-Id`，使 NewAPI 可以把风控 Request ID 记录为 upstream request ID。页面默认按完成时间展示，并同时提供开始、完成、入库三种时间。
