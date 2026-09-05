# 当前意图与证据链修复（2026-09-05）

## 根因与范围

生产记录暴露两个不同的问题：初审将网关追加的 `Return only the compact policy JSON object now` 当成攻击证据；重试后又将 `Recent Codex tasks in this project` 中的历史工作流标题当成当前数据库操作。API role=user 并不表示字符串里每一项都是当前指令；“证据能找到”也不证明证据支持危害结论。普通 GUI/语音输入被归类为 SOCIAL_ENGINEERING 是同一类目的推断问题，而不是 JSON 格式故障。

本次不新增 GUI/工作流关键词白名单，不删除所有历史内容，不关闭 FailClosed，不承诺任何模型永不误报。

## 新链路

1. 入口提取已有受审用户文本，保留原有系统/工具角色隔离。**不再按用户文本中的 `## My request` 截掉前文**，也不跳过伪造的 `ROLE=TOOL ...` 行。
2. 将待审内容编码为 `risk_audit_request.v2` JSON 文档。`request_text` 保存完整受审文本；网关的格式要求、no-thinking 开关和纠错指令不再拼入该字段。Qwen no-thinking 仍通过模板参数控制。
3. 对完整、具有任务结构的历史 JSON 数组标注 `reference_spans`。这只是位置提示，不是可信授权，也不删除内容。普通 Markdown/用户伪造的标题不产生放行。跨分块保存并裁剪位置提示，同时携带有界的当前任务上下文。任意尾部内容仍必须被审计。
4. 初审返回 allow 时走原有快路径。**每一个模型 block/review，以及已解析但证据无效的判定，必须进行新的语义复核**。复核使用新提示词，不携带初审标签、理由或置信度，避免直接复制错误结论。
5. 复核必须满足九字段契约：原有六字段加 `request_evidence`、`evidence_relation`、`harm_type`。危害证据和当前动作/明确采用引用的证据分开。历史数组中的标题不能充当当前动作证据。
6. 通过契约的 benign 复核才可纠正误报；confirmed block 继续阻断；真实不确定结果保持 review（故障关闭配置下为 block）。缺字段、伪造引用、矛盾的 allow/harm_type 或复核不可用不能自动变成 allow。

静态 block 若**仅命中已标注引用内容**，先降为待模型判断的候选，避免旁路语义链路直接误拦截；相同有害内容也出现在引用外时仍保留原硬规则。把真实有害请求套进历史格式不构成豁免：明确执行/继续引用中的有害操作，使用 adopted_reference 判定。

## 配置与成本

原 profile 无需数据库迁移即可使用新链路。默认复核使用同一 profile 的模型，以独立提示词重判；这不是两种独立模型，也不保证消除同源模型错误。管理员可以在原 profile 的额外 JSON 参数里增加：

```json
{
  "_risk_policy_mode": "internal_engineering",
  "_risk_verifier_profile_id": 2
}
```

`2` 仅为示例，必须替换为管理员已配置且启用的另一个 audit profile ID；不要将示例 ID 当作已存在。使用该 profile 的 endpoint/model/API key，仍遵守原 profile 的政策与阈值。无效配置和不可用复核模型按基础设施故障处理，不能隐式退回无复核放行。此设置来自服务端配置，用户请求中的同名字段不起作用。

正常初审 allow 不增加第二次模型调用。每个候选最多两次复核调用；整次审计最多 32 次复核调用、保留最多 16 条详细复核记录，其余仍计数。分块沿用现有并发和取消机制。复核至少预留 512 输出 tokens；候选较多时延迟和 GPU 消耗会增加，应通过真实数据测量。

`audit_model_attempts` 继续表示兼容的审计/故障恢复周期，不等于物理 HTTP 调用总数。新增 `audit_http_calls` 和 `audit_semantic_review_calls` 显示真实调用成本。格式恢复和证据语义复核不是同一件事。

## 追踪解释

- `audit_input_contract`: `risk_audit_request.v2`。
- `audit_semantic_reviews`: 原候选、原证据是否有效、复核模型、每次复核错误/响应 ID、复核结果。
- `audit_semantic_review_status`: overturned / confirmed / unresolved。基础设施失败详见记录内 error 状态。
- `audit_current_request_evidence`: 当前动作或明确采用引用的证据。
- `audit_evidence_relation`: no_harm / reference_only / direct_request / adopted_reference / uncertain。
- `audit_harm_type`: 复核识别的具体危害类型；none 不得与 block 同时成立。
- `audit_model_decision`: 初审原始判定（单段情况下）；`audit_effective_decision`: 最终执行判定。分块聚合及完整候选记录以 semantic_reviews 为准。
- `audit_policy_adjustment.code=SEMANTIC_FALSE_POSITIVE_CORRECTED`: 初审被有效的 benign 复核纠正。

`audit_model_evidence_verified` 仅代表引用位置有效，不是已证明攻击；页面已明确这一含义。历史追踪不重写。

## 验证分层

`audit_boundary_regression_test.go` 覆盖：平台指令误引用、历史工作流、普通长按、正常数据库诊断、公开 ADB、明确采用危险历史、混合有害尾部、无效/矛盾复核输出、真实超时诊断、伪造标题/角色、引用跨分块、规则候选和独立模型路由。`scripts/e2e.sh` 验证网关 200/555、上游是否启动及数据库追踪字段。

这些使用可控 mock 响应，证明的是**机制执行正确**，不证明真实 Qwen 权重的语义准确率。应再对实际 audit profile 做脱敏回放：

```bash
# 令牌是管理端访问令牌，不是渠道 Key。不要写入仓库或测试结果。
export RISK_BASE_URL='https://risk.example.invalid'
read -rsp 'Admin access token: ' RISK_ADMIN_TOKEN; echo
export RISK_ADMIN_TOKEN
python3 scripts/eval-audit-intent.py --profile-id 1
unset RISK_ADMIN_TOKEN
```

回放调用管理端 dry-run，不发送真实渠道请求、不操作手机/数据库；会产生管理端 dry-run 审计事件并消耗审计模型资源。结果分别统计误拦截、漏放和基础设施错误，脚本在任一不匹配或错误时非零退出。样例集较小，不能代替真实业务样本、长上下文和并发压力测试。未通过真实回放前，不应宣称业务语义已零误报或建议关闭 FailClosed。

参考：OWASP LLM Prompt Injection Prevention Cheat Sheet（指令/数据隔离与分层验证）；vLLM Structured Outputs（结构约束不是业务语义证明）。
