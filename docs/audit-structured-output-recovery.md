# 审计模型结构化输出恢复

## 根因

`invalid_json` 表示审计 HTTP 调用成功，但模型输出中没有可验证的策略 JSON。旧实现存在三个问题：

1. 三次重试发送完全相同的请求，模型重复同一种格式错误；
2. `max_tokens=128` 可能在六字段 JSON、原因和证据尚未闭合前截断；
3. 平台没有保存 `finish_reason`、响应字段、响应字节数或脱敏预览，无法区分解释性文本、截断、reasoning 字段输出和协议差异。

## 恢复顺序

Qwen 同一 Profile 的自动重试依次使用：

```text
1. response_format=json_schema，至少 256 output tokens
2. structured_outputs.json，至少 384 output tokens
3. response_format=json_object，至少 512 output tokens
4. legacy guided_json
5. prompt_only 兼容模式
```

默认重试两次，因此正常链路最多使用前三种。服务端明确拒绝某种结构化参数时，错误分类为 `structured_output_unsupported` 并进入下一模式；`finish_reason=length` 分类为 `output_truncated` 并增加下一次输出预算。

审计 Profile 的 Extra 可设置：

```json
{"_risk_structured_output_mode":"auto"}
```

也可明确设为 `json_schema`、`vllm_structured_json`、`json_object`、`guided_json` 或 `prompt_only`。所有 `_risk_*` 字段只由平台使用，不发送到模型。

## 解析兼容

平台可以从以下位置恢复最终策略对象：

- `choices[].message.content`；
- `choices[].message.reasoning_content` / `reasoning`；
- `choices[].text`；
- tool-call function arguments；
- content parts 数组；
- 直接 JSON、Markdown/思考文本中的平衡 JSON；
- 双重编码 JSON；
- `result`、`policy`、`output`、`response` 等嵌套对象。

## 追踪字段

每次尝试会记录：

```text
output_mode
output_max_tokens
finish_reason
response_content_bytes
response_source
response_id
response_preview
```

`response_preview` 只在失败时保存，经过凭据脱敏、空白折叠和长度限制；成功响应不保存完整策略 JSON。真实 API Key、Token 或 Authorization 不会写入 Trace。

所有结构化输出恢复和备用模型均失败后，仍遵循现有 fail-closed/fail-open 路由配置，不会因为格式错误静默绕过审计。
