# v9：CSV事故审查、正常开发与前处理故障

基线 main `47ab8bfbf70b66b9d0dd14d2b9c4c16fba16c85a` / v8。附件为100条历史追踪，不是100份完整原始请求，不能计算真实模型准确率。原始CSV及真实公司地址/凭据不提交仓库。审查计数：37条隐藏交互输入Token被规则阻断、23条JWT/Session认证设计被模型判绕过/外传、12条跨表格行拼接的提示词提取命中、1条配置不可用故障、17条入口大请求503过载、10条正常通过。这是出现次数，不是互相独立的样例。

## 修复范围

1. 内置凭据规则的动作关系检查：终端隐藏交互输入现成Token不作为提取秘密。只收窄该匹配的成立条件，继续检查同规则后续/重叠命中及其他规则，不给请求白名单。
2. 仅匹配未修改种子模式的系统提示词规则，拒绝把Markdown相邻行和否定提醒拼接成动作。直接及多行真实索取仍保留规则拒绝；自定义正则、contains和exact不改，不新增数据库迁移。
3. 相关认证/凭据类别只引用请求头设计时，使用已有一次操作校核；普通开发方案不等于已实施攻击；静态预期拒绝的表格示例不等于已经执行，相关候选同样需一次校核。原文、任务锚点、主审/复核、Fusion否决保留。重复弱证据/异常输出/超时仍555；真正操作拒绝仍终态。固定六字段策略和提示同步说明该边界。此前所有正常开发不是被整体免审。
4. 区分 `audit_profile_not_found`、`audit_profile_disabled`、`audit_profile_lookup_failed`、`audit_profile_lookup_timeout`、`audit_deadline_exceeded`、`audit_cancelled`。配置读取上限5秒且受120秒总期限约束；缓存命中也响应取消。错误不暴露数据库DSN，保留已有顶层错误码契约。
5. 新增 `audit_stage_timings_ms`（提取/上下文/规则/配置/模型）、`audit_failure_stage`、`audit_requested_profile_id`、`audit_input_partial`、`audit_capacity_text_limit_bytes`。摘要仅输出允许的字段和固定枚举，不含原文/端点。
6. 提取阶段、规则阶段加入取消检查，减少秘密替换的重复全量正则扫描。已有256 HTTP/128复核绝对预算要求每个分块至少两次调用；在16KiB分块下，2MiB是乐观的容量上界，重叠/边界/Fusion会使实际容量更低。超过上界或实际分块计划不可能完成时，以 `audit_capacity_exceeded` 快速拒绝，不伪装成“没有启用模型”、不截断后放行。全局120秒、模型并发和入口内存保护不变。
7. 对 `tool_search_output.tools` 的已知文字工具定义提取整份JSON并作为不可信工具数据审计，非请求根tools配置；未知类型/图片仍保留覆盖错误。参考官方工具搜索返回形态：https://developers.openai.com/api/docs/guides/tools-tool-search 。这不是支持图像审计的声明。
8. 503入口内存保护保留，增加 active/max/retryable/retry_after_seconds/security_violation=false，避免误当用户违规。没有封禁用户/IP，也没有给生产加免审开关。

## 验证与限制

先在v8加入事故回归，验证隐藏输入/认证设计/跨表格命中/取消分类的失败，再改实现。保留原有安全对照，新增原文一致、主审/复核校核、重复失败、有效拒绝、自定义规则、取消、配置分类、容量、秘密替换等价性、工具定义/图片覆盖及有界fuzz。现有完整E2E新增15项HTTP/SSE对照。真实Qwen3.8-27B与完整原始请求未回放，合成模型只用于验证机制。

`tests/fixtures/audit-csv-development-eval.jsonl` 提供10条脱敏真实模型评估输入，供现有 `scripts/eval-audit-intent.py` 使用；这里不声称已做生产回放。

独立未解决范围：图片仍未审计；原始31MB请求超出该预算仍被容量拒绝；无标签密码通用脱敏仍是此前独立缺口；未知完整历史可能有其他禁用操作。修正72条展示的阻断依据不等于承诺72条完整请求全可转发。历史CSV不回写。

## 部署

在 `/opt/newapi-risk-platform` 执行 `RESET_DATA=0 BACKUP_DATABASE=1 ALLOW_BRANCH_SWITCH=1 bash scripts/upgrade.sh main`，外置数据库另行备份，不删除卷。无新增迁移；以新请求的运行提交及 `cyber-deny-qwen27b.v9` 核验。关注上述阶段、容量和配置错误，不以Git目录版本代替容器构建版本。

## 本地验证记录

最终本地全量race、vet、两服务构建、升级脚本及9项诊断隐私测试通过（远端完整CI/E2E以合并前最终提交为准）。新增规则有界fuzz smoke运行5秒；此次只完成少量有效执行，不将其宣传为覆盖充分的安全证明。合成1.24MB文本提取/上下文基准由约551ms变为387ms，合成32MiB容量检查约239ms；这是此容器单次测量，不是用户服务器性能承诺，容量拒绝也不等于完成模型审计。
