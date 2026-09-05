# 审计输出健壮性、融合复核与本地诊断

## P0：首要是输出不能崩溃

开发约束已写入根目录 `AGENTS.md`，用户指定的 `agent.MD` 是入口。
日志中的第三轮是合法 JSON 的 confidence 类型漂移，不是 JSON 语法错误。新的解析器规范化数字字符串、high/medium/low 定性标签和 allow 的 NONE 风险码；记录 confidence_kind/label 和 output_normalizations，不把 high 伪造成 0.95。数值范围和有限性仍校验；high 作为定性的高等级可满足不高于 0.90 的既有高等级门槛，但不能满足更严格的数值阈值；它不是校准概率。初审明确 allow 保持原有快路径。

未知字段类型、缺失 decision/confidence、矛盾 allow、重复键、多个判定、截断和深度/字节超限不猜测放行。合法 JSON 的字段问题使用 invalid_schema；语法错误使用 invalid_json。解析和恢复有界。最终 content 存在时不能以 reasoning 中的早期 allow 替代；finish_reason=length 即使出现完整 JSON 也不能当完整输出。保留既有 FailClosed/555 契约，不把解析失败当攻击实锤或自动放行。

前两轮出现旧版 `[MANDATORY AUDIT OUTPUT]`，并缺少 risk_audit_request.v2/语义复核字段，提示请求仍经过旧链路，但无法仅凭日志断言具体副本。现在 /healthz、管理端 runtime、每次审计追踪均记录 commit、随机进程 instance、输入/输出契约和 audit_engine=output-resilience-fusion.v1。deploy-local 在 git 工作区构建时注入实际 HEAD，并检查本地健康探针返回的运行提交与契约。不能仅凭仓库已更新声称生产已生效。健康探针不验证外部负载均衡的所有副本。

## Fusion：证据一致性 + 独立提示复核 + 可选裁决

默认仍使用已配置的单复核模型，不自动购买/调用额外服务。管理员可以先创建独立 audit profiles，再在主审计 profile 的 extra 中配置：

```json
{
  "_risk_policy_mode": "internal_engineering",
  "_risk_fusion_profile_ids": [2, 3],
  "_risk_fusion_adjudicator_profile_id": 4
}
```

上述 ID 全是示例，必须替换为真实已启用配置；不能照抄未知 ID。使用已有的 endpoint/model/加密 API key，并继承主 profile 的治理政策及阈值。配置存在时优先于旧 _risk_verifier_profile_id。允许 2–3 个并行复核成员、一个可选裁决成员；禁止重复 ID 和完全相同的 endpoint+model。不同别名/供应商不证明模型错误独立，更不能保证最优。

只对需要语义复核的候选启用面板，普通初审 allow 不增加多次请求。每份结果先通过九字段证据契约校验，再融合：

- 全部有效且一致 allow → allow；全部有效且 block 的危害类型、当前动作/能力证据兼容 → block。
- 成员有缺失、超时或契约错误 → fusion_incomplete；不能丢掉错误成员，把剩下的 allow 当完整通过。
- 有效结果分歧 → 可选裁决模型用新提示词重判，不给它初审/面板的标签、理由和置信度。只有裁决通过契约且与至少一份有效成员结论（block 还须证据兼容）一致，才产生 adjudicated。
- 未解决分歧保留 review / AUDIT_FUSION_DISAGREEMENT；FailClosed 路由仍会阻断，但标为 audit_uncertainty，不声称已证明攻击。

没有简单平均自报 confidence，没有任一 block 即视为攻击。保留每个 vote、错误、分歧与裁决。每个成员最多两次格式/证据修复，复核合计沿用每请求32次上限、最多16条详细记录和现有分块并发/取消；模型调用成本、GPU排队和延迟需真实测量。该实现不是经过业务标注验证的最优融合权重，不能宣称零误报/零漏报。

## 本地诊断（只生成文件，不自动上传）

在仓库目录运行：

```bash
bash scripts/collect-audit-diagnostics.sh
```

默认从本地 .env 只读取合法 HTTP_PORT，探测 loopback；不执行/source .env。缺 Docker/git 或服务不可达时记录收集限制，仍生成诊断包。只查询选择过的 Docker字段，不输出完整 inspect、Compose配置、容器环境或原始日志。

需要实际 profile 参数与指定事故的字段形状时：

```bash
# 将管理端导出的事故 JSON 放在本机 audit-error.json；它不会原样打包。
bash scripts/collect-audit-diagnostics.sh --prompt-token --trace-file ./audit-error.json
```

输入的是管理端 access_token，不是渠道 Key。提示输入不回显，不写文件；也支持已存在的 RISK_ADMIN_TOKEN 环境变量。远程实例可加 `--base-url https://你的风控域名`，HTTP仅允许回环地址，拒绝重定向，证书正常校验，不使用环境代理。脚本不注册用户、不操作手机/生产数据库、不更改 profile 或执行融合配置写入。

输出为 `audit-diagnostics-时间.zip`，权限0600，已在 .gitignore 排除。固定归档成员只有 diagnostics.json 和 README.txt。包括运行版本三次采样、仓库提交是否一致、可安全导出的运行/路由/profile参数、证据输出的字段类型、旧指令标记和失败分类。原始文本、原因、证据、endpoint、模型自定义名称、system prompt、密钥不导出；配置内容仅用不随报告导出的随机密钥产生关联指纹。诊断包不是匿名化保证，分享前仍需人工检查。三次采样不能覆盖所有负载均衡副本。

## 实际模型对照回放（显式执行才消耗审计资源）

```bash
# 单 profile 重复三遍，使用内置合成样例；不会发送真正的业务渠道请求。
bash scripts/collect-audit-diagnostics.sh --prompt-token --evaluate --profile-id 1 --repeats 3

# 比较已存在的多个主审计 profile，可分别配置单复核 / 融合面板。
# 数字仅为示例；用真实 ID，勿盲目填入。
bash scripts/collect-audit-diagnostics.sh --prompt-token --evaluate \
  --profile-id 1 --profile-id 5 --repeats 3
```

支持 `--cases 本地人工脱敏并标注的.jsonl`，每行包含 text 和 expected（allow/block）。输入仅发送到用户指定的风控 dry-run，不写入报告；报告通过 case_index 与用户本机样例逐项对应。最多5个配置、每配置1–5次重复、100条样例/600次dry-run上限，串行发送防止突然打满GPU。dry-run会消耗模型资源并可能产生管理审计事件。profile比较不修改服务端配置。

报告分别给出 false_blocks、false_allows、unresolved、infrastructure_errors、p50/p95、物理HTTP次数。重复同一批样例不是扩大独立样本量；小样本p95不能视为生产SLO。没有自动按最快/放行最多选优，也不自动关闭FailClosed。保留一组不参与调参的样例做复验；需要更多真阳性/正常任务、真实上下文和并发数据才能选择部署方案。

后续反馈：检查并发送生成的zip；语义误报需要复现时另外提供人工脱敏的对应case_index与预期结果。无需发送.env、完整数据库或整段原始聊天。

## 验证

Go回归/竞态测试覆盖本次confidence事故、重复冲突字段、截断、深度/大小限制、面板一致/分歧/裁决/错误和运行版本。新增解析器fuzz smoke、Python脱敏泄露哨兵测试；E2E验证正常请求实际到上游、追踪落库及融合dry-run路径。机制mock不是实际Qwen准确率测试。真实模型、GPU负载和生产升级必须另外验收。
