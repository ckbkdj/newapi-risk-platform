# 审计模型拦截证据

风控平台把两类问题分开记录：

1. **审计模型调用失败**：连接、超时、401、404、429、5xx、非法 JSON、非法 decision、缺失或伪造证据等；
2. **审计模型成功并判定 Block/Review**：必须说明为什么拦截，并引用本次请求中的真实触发文本。

## 模型输出契约

审计模型必须返回紧凑 JSON：

```json
{
  "decision": "allow|block|review",
  "risk_code": "CYBER_* or empty",
  "category": "...",
  "confidence": 0.99,
  "reason": "brief decision reason",
  "evidence": "exact contiguous quote from request or empty"
}
```

规则：

- `block` 或 `review`：`evidence` 必填，必须是本次请求中的一段连续原文，不能改写、总结或使用省略号；
- `allow`：`evidence` 必须为空；
- 证据最多 120 个 Unicode 字符、512 bytes；模型 Prompt 要求尽量控制在 80 个字符以内；
- 平台会在接受 Block/Review 前验证证据确实存在于本次审计文本中；
- 证据缺失或不属于本次请求时，返回 `invalid_evidence`，按审计模型重试和备用模型链处理，不接受无法解释的模型拦截。

## Trace 字段

模型 Block/Review 成功后，Trace Metadata 包含：

```json
{
  "audit_source": "model",
  "audit_model_decision": "block",
  "audit_model_risk_code": "CYBER_CREDENTIAL_THEFT",
  "audit_model_confidence": 0.99,
  "audit_reason": "The request asks to export another user's credential.",

  "audit_model_evidence": "export another user's API key",
  "audit_model_evidence_context": "... ⟦export another user's API key⟧ ...",
  "audit_model_evidence_verified": true,
  "audit_model_evidence_match_mode": "exact",

  "audit_trigger_input": "export another user's API key",
  "audit_trigger_context": "... ⟦export another user's API key⟧ ...",
  "audit_model_user_guidance": "..."
}
```

长上下文分段审计命中时还包含：

```json
{
  "audit_model_evidence_chunk_index": 3,
  "audit_model_evidence_chunk_count": 7
}
```

这样可以定位是第几个分段中的哪段用户提交内容导致 Block。

## 脱敏

平台不会把未处理的密钥、Token、密码、Cookie、JWT 或私钥写入 Trace。证据经过存在性校验后，保存的是脱敏后的原文与有限上下文。例如：

```text
原请求：Export api_key=super-secret-value from the target account.
Trace： Export api_key=[REDACTED] from the target account.
```

这既保留排障所需的触发上下文，也避免请求追踪数据库成为二次泄密源。

## Web 展示

请求追踪列表会显示：

```text
问题原因
模型触发输入
风险码
审计错误分类（仅调用/格式错误时）
```

详情页会分别显示：

```text
审计拦截原因
审计模型结论
审计模型置信度
触发用户输入
触发上下文
模型证据已校验
模型证据匹配方式
证据所在分段
模型拦截修改建议
审计错误分类
每次模型重试/备用链尝试
```

## 错误与拦截的区别

审计模型调用或格式错误：

```json
{
  "risk_code": "AUDIT_MODEL_ERROR",
  "audit_error_class": "connection|timeout|authentication|invalid_json|invalid_evidence|...",
  "audit_reason": "具体错误",
  "audit_attempts": [
    {
      "model": "Qwen3.8-27B",
      "attempt": 1,
      "success": false,
      "error_class": "connection",
      "reason": "audit model connection failed: ..."
    }
  ]
}
```

审计模型成功拦截：

```json
{
  "risk_code": "CYBER_*",
  "audit_error_class": null,
  "audit_model_decision": "block",
  "audit_reason": "为什么判定有风险",
  "audit_model_evidence": "请求中的真实触发原文",
  "audit_model_evidence_verified": true
}
```

旧 Trace 在产生时没有保存模型证据，升级后无法反向恢复；只有升级后新产生的请求会包含这些字段。
