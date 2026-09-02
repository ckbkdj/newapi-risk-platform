# 审计模型重试、备用链与超限 Token 诊断

## 执行顺序

每个审计模型都有 `retry_count`，表示**初次调用失败后额外重试的次数**。默认值为 `2`。

只有瞬时基础设施/响应错误会在同一个模型上重试，包括：连接失败、超时、429、5xx、响应读取失败、空响应、响应格式错误、非法 JSON 或非法 decision。

认证失败、模型/端点不存在、普通 4xx、凭据解密错误，以及已经完成分段仍无法容纳的上下文错误，不会浪费时间重复调用同一个模型，而是直接进入配置的备用模型链。

`block` 和 `review` 是有效的安全决策，**不会**触发重试或备用模型切换，避免通过“换模型”绕过风控。

## 备用模型链

审计模型页面可以按顺序加入最多 8 个备用模型，并通过“上移 / 下移 / 移除”调整顺序。

示例：

```text
主模型 A：retry_count=2
  ↓ A 第 1 次失败
  ↓ A 重试 1
  ↓ A 重试 2
备用 B：retry_count=1
  ↓ B 第 1 次失败
  ↓ B 重试 1
备用 C：retry_count=0
  ↓ C 成功
最终使用 C 的安全决策
```

全链路设置了 24 次模型调用的硬上限，避免错误配置造成无限循环或请求风暴。

## 上下文超限 Token

风控平台仍然先把完整请求发送给审计模型。只有模型明确返回 context-length 错误时才执行完整重叠分段审计。

如果模型错误中包含：

```text
maximum context length is 260000 tokens
request has 281432 input tokens
```

请求追踪会保存：

```text
audit_input_tokens=281432
audit_context_window_tokens=260000
audit_tokens_over_limit=21432
```

页面“请求追踪 → 详情”直接显示：

- 审计输入 Tokens
- 模型上下文上限
- 超出 Tokens
- 分段数量与大小
- 模型调用次数
- 同模型重试次数
- 备用模型切换次数
- 实际使用的模型
- 完整模型尝试记录

`audit_input_tokens` 是**审计模型自己报告的 prompt/input token 数**，因此包含平台系统提示词、聊天模板等开销；它比按字符估算更可靠，但不是仅计算用户原始正文的 tokenizer 数量。

## Qwen3.8

如果 vLLM 使用：

```text
--max-model-len 260000
```

那么模型的总上下文上限就是 260,000 tokens，而不是 272K。该总量需要同时容纳系统提示词、用户内容、聊天模板和模型输出。

Qwen 审计请求继续强制 no-thinking：

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
