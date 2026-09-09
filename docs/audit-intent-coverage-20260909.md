# 2026-09-09 审计意图与输入覆盖修复

基线：`8ff2f41a596d74d5a9311f9226f7b9ee6709d1e9`。
引擎标识：`intent-coverage-guard.v2`。输入/输出契约仍为 `risk_audit_request.v2` / `risk_audit_output.v2`，新增追踪字段向后兼容。

## 修改的行为

### 凭据例外不再机械放行

防御性提醒只作用于其本地语句，不再为后续独立危险操作提供全局免责。更重要的是，命中凭据候选后，“内部调试”“用户提供密钥”本身不再抑制该候选，也不直接把 block 变成 allow；没有明确危险特征的工程候选转入 review，由完整语义复核决定最终结果。正常配置密钥、轮换、自有日志复现仍可通过复核放行。明确的危险凭据操作不会因为附带安全提醒或调试措辞而走机械放行。

`LOCAL_DEBUG_CREDENTIAL_REPRODUCTION` / `INTERNAL_SECRET_CONFIGURATION` 的旧自动放行路径改为 `LOCAL_DEBUG_CREDENTIAL_REVIEW_REQUIRED` / `INTERNAL_SECRET_CONFIGURATION_REVIEW_REQUIRED`。不能将这些调整代码当成最终 allow。

### 续写保留更多任务上下文与真实角色边界

“补齐剩余功能”“按前面讨论”“最终版本”等自然续写不再限于句首或很短的指令；同一连续用户回合中任一条续写都能激活历史。补取不再限制为两条用户消息，在 64 KiB 历史预算内保留此前用户消息，并保留当前用户回合之前最近的一条助手文本回复，以支持对助手方案的明确采纳。

历史用户内容和助手回复通过准确的 UTF-8 字节区间标为 `conversation_reference`。这些内容可作为采纳对象，但不能冒充“当前用户正在发出的指令”。分块保留边界及当前动作锚点。用户伪造 `ROLE=` 文本不产生真实角色边界。

超出历史预算或文本被截断时，标记覆盖不完整，不能将删掉任务目标后的内容当成完整安全输入。预算不是无限对话记忆；这是有界的启发式续写识别，不保证理解每一种隐含指代。未增加持久会话存储、提供商历史恢复或工具执行审计。

### 所有未消解的 review 候选都复核

即使 `audit_embedded_reference_count=0`，规则 review 也不能被第一次模型 allow 直接跳过。已激活上下文的续写同样要求复核。配置 Fusion 时，第一次 allow 也必须经过已配置的面板；无效 Fusion 配置不会因为第一次 allow 而被隐藏。

复核不会把主模型的结论当作证据。原有证据位置、当前动作、采纳关系、风险类型、置信度和有界调用预算仍生效。可配置独立 verifier / Fusion 模型；未配置独立模型时，复核是同一模型的一次新调用，并不等于独立模型投票。

主模型 allow、复核 block 的轨迹记为 `escalated`。复核超时、无效输出或预算耗尽仍按既有故障策略处理。

## 不支持的输入不再静默视为安全

新增字段：

| 字段 | 含义 |
|---|---|
| `audit_coverage_status` | `complete` 表示选定审计范围的文本完整；不是“整个应用安全”证明。`incomplete` 表示缺失或不支持的输入。 |
| `audit_conversation_reference_count` | 本次保留的历史用户/助手引用数；与原有 JSON 内嵌历史计数分开。 |
| `audit_coverage_issues` | 固定错误原因数组，见下文。 |
| `audit_semantic_review_status` | 增加 `escalated`；保留 confirmed / overturned / unresolved / error 等。 |

覆盖原因包括 `no_auditable_user_intent`、`unsupported_input_content`、`invalid_request_json`、`input_text_truncated`、`reference_context_limit`、`missing_continuation_context`、`unresolved_previous_response`。

图片/音频/文件及未知用户内容块（包括“文本+图片”混合输入）尚未接入真正的多模态审计；仅工具输出而没有可审用户意图的请求，也不能默认为安全。提供商 `previous_response_id` 无法在本服务内恢复和校验，因此非空 ID 明确记为未解析上下文，即使调用者同时提供了若干文本也不据此假定历史完整。要使用本版，调用方需发送不依赖该 ID 的完整必要文本历史；需要图片或仅 ID 的续接时，应先实现对应覆盖能力，不能靠调整提示词声称已支持。

路由或 profile 任一开启 fail-closed 时，覆盖失败在上游之前返回原有 HTTP/逻辑 555，风险码 `AUDIT_INPUT_COVERAGE_INCOMPLETE`，类别 `audit_infrastructure`，错误类 `input_coverage`，`audit_completed=false`，模型调用数 0。这是审计覆盖故障，不是对用户恶意的认定。

显式关闭路由与 profile 的 fail-closed 仍可按配置 fail-open，但必须记录 `source=fail_open`、`audit_coverage_status=incomplete` 和 `audit_completed=false`。本次不擅自修改数据库中的故障策略。强制保护场景必须开启 fail-closed。

## 测试与验收

原事故样例均为静态脱敏文本，不读取真实凭据、不访问外部目标。基线事故测试先复现失败，再修复；旧“只靠本地调试关键词直接 allow”的单元断言有意改为“进入 review”，最终正常放行另由完整审计流程测试证明。

```bash
go test -race -count=1 ./...
go vet ./...
go test ./internal/platform -run '^$' -fuzz '^FuzzAuditOutputDecode$' -fuzztime=10s -parallel=2
bash scripts/upgrade_test.sh
python3 scripts/test_collect_audit_diagnostics.py
```

`audit_coverage_guard_test.go` 覆盖主模型 allow 后的阻断升级、正常安全提醒放行、正常调试复核放行、复核异常、显式 fail-open、角色/采纳边界、历史预算、UTF-8 硬边界及 Fusion 的 allow 路径。`scripts/e2e-audit-coverage.py` 仅由 CI 的一次性 mock 栈执行，验证真实 HTTP 200/555、追踪状态和被阻断请求未进入上游。不得对生产执行这个会创建测试规则的脚本。

这些机制回归不能替代真实 Qwen 语义回放、误报/漏报测量、GPU 性能和并发验收。没有从汇总日志推断原始请求一定有害，也没有把某一次规则命中直接当成恶意证据。

## 升级

在修复合并到 main、CI/E2E 通过后，在原有部署的干净 Git 工作区执行：

```bash
bash scripts/upgrade.sh main
```

脚本沿用数据库备份、快速前进、重建/健康检查及失败回滚机制；本次没有数据库迁移或自动修改模型参数。不要只 `git pull` 后继续运行旧容器。

检查 `/healthz` 和新请求追踪中的 `gateway_build`：运行 commit 应对应实际部署提交，`audit_engine` 应为 `intent-coverage-guard.v2`。逐个确认负载均衡后面的副本，而不仅看一个本机探针。覆盖不完整的新错误可能暴露此前被静默跳过的客户端输入类型，需先在预发布验证客户端兼容性。为 review/续写新增的复核会增加调用次数和延迟；Fusion 面板现在同样覆盖初判 allow，应重新测量其预算和容量。
