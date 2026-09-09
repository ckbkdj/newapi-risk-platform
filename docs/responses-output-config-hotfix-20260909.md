# Responses 输出配置兼容修复（2026-09-09）

## 事故证据与定位

用户运行 `e467f3b` / `cyber-deny-qwen27b.v4` 后，日志包含：

```text
audit_coverage_issues = unsupported_input_content, ambiguous_input_fields
audit_error_class = input_coverage
audit_http_calls = 0
upstream_started = false
```

这是调用模型前的输入覆盖拒绝，不是 Qwen 判定 Cyber，也不是更新没有生效。原始请求正文未提供，因此不能将合成协议回归当作用户实际请求回放。

旧 `extractCyberAuditText` 遍历顶层 `messages/input/prompt/query/content/text`，不区分字段语义；它把 Responses 的 `text` 输出配置计为第二份正文，再把其中 `format` 对象当成无法识别的消息内容。下列正常请求即可复现相同的两项错误：

```json
{
  "model": "normal",
  "input": "Rename the button",
  "text": {"format": {"type": "text"}, "verbosity": "medium"}
}
```

依据：OpenAI Responses Create API 的 `text` 为输出配置（`format`、`verbosity`），与 `input` 合法共存：
https://developers.openai.com/api/reference/cli/resources/responses/methods/create

## 修复边界

- 仅在请求根级识别已知 `text` 输出配置结构：空对象、verbosity、text/json_object/json_schema 格式；可选空值不会被当成第二份用户输入。
- 传统字符串 `text` / `prompt` 仍作为正文送审，不是按字段名跳过所有 text。
- 正文中的嵌套对象不适用输出配置例外；未知格式、未知字段仍回到原有覆盖守卫。
- `input` 与真实 `messages`/字符串 `text` 并存仍算歧义；重复 JSON 键、未知消息类型、多模态覆盖缺口、未恢复的 previous_response_id 均保持 fail-closed。
- 输出配置被记入 `audit_ignored_roles: OUTPUT_TEXT_CONFIG`，不作为用户攻击证据。输入正文、历史和工具数据仍按已有政策检查。
- 正常请求仍须主审计与新调用复核；Cyber 命中仍终态 555、零模型调用、不得启动业务上游。没有新增工程豁免，没有关闭覆盖检查，没有修改 Qwen 参数。
- 不改写转发请求，不删除用户的输出格式配置；无数据库迁移、无数据重置。

## 回归

`internal/platform/audit_responses_config_test.go` 提供 7 种输出配置、null 别名、传统 text/prompt、原始请求不变、真实审计调用、Cyber 拒绝、12 种异常/歧义/未覆盖反例及输入保持性 fuzz 种子。

先在只加测试、未修改生产源码的提交 `2938ffa026e52c9e6bbbefb1b82dd990b0b90469` 上运行全量 race：GitHub CI `34359636621` 的 `TestResponsesOutputConfigCoverage` 对合法格式复现两项事故错误；null 别名也复现歧义错误。

扩展既有 `scripts/e2e-cyber-expanded.py`，通过实际 `/gateway/mock-main/v1/responses` 检查 5 种普通 JSON 请求、Cyber/歧义/图片 3 种拒绝，以及 SSE 正常转发。核对 trace 的模型调用次数、覆盖状态及 `upstream_started`，不把基础设施 555 算作 Cyber 正确识别。

最终验证结果以 PR #22 最终提交上的 CI/E2E 为准；不引用早期提交结果替代。Mock 只验证网关执行机制，本次未访问生产 Qwen 或生产数据库。

## main 升级与验证

PR #22 合并后，在原项目目录执行：

```bash
RESET_DATA=0 BACKUP_DATABASE=1 ALLOW_BRANCH_SWITCH=1 bash scripts/upgrade.sh main
git log -1 --format='%H %s'
```

升级会重建并重启服务。自动备份仅覆盖当前 Compose 中运行的 PostgreSQL；外置数据库需由运维单独备份。禁止删除数据卷或强行 reset 清理本地修改。

核对 `/healthz` 或新请求详情的 `gateway_build.commit` 与当前 Git HEAD 一致，并确认已包含 PR #22。审计策略没有变化，`audit_engine` 仍为 `cyber-deny-qwen27b.v4`，不能只靠 v4 标识判断是否已包含本修复。

普通文本加输出配置的请求不应再因该配置出现上述两项错误；正常完成主审计和复核后可见 `audit_http_calls=2`。带其他不支持的输入仍可能拒绝，不能通过关闭风控处理；需要检查其真实结构。排查时优先提供字段名、类型和脱敏结构，不提交真实密钥、隐私正文或生产数据库。
