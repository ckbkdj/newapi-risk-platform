# v6：本机连接表查看与 read-only 凭据误命中修复

基线 main 6c029863 / v5。两份事故分别是 2026-09-09 15:32 UTC 的 v5 netstat 工具参数，与更早 14:40 UTC 的 v4 read-only guidance 日志，不能仅凭这两个不同时间的记录推断在线混跑。

## 判定边界

- `netstat -ano -p tcp | Select-String ":8088 |:8200 "` 查询本机已有连接/监听端口与 PID 并过滤文本；不是主动发起网络扫描。它可能包含敏感运行信息，但所示命令没有展示入侵、外传或破坏。全请求/历史未提供，不能据此将整个请求自动放行。
- `read-only guidance do not require an API key` 表示只读指导不需要凭据；旧正则把 read 与后面的 API key 用任意字符相连，误造了凭据操作。`read only the API key` 则确实要求读取，必须仍拦截。
- 这是对旧“本地端口读取也一律禁用”的业务边界纠正，不是关闭 Cyber 审计。主动探测、扫描、实际凭据读取、规避控制、混合禁用目的仍拒绝。本轮只处理展示的两种依据，不承诺未展示的历史安全。

## 实现

1. 内置 local_probing 去掉 netstat/ss/查看/列出作为单独终态判据，保留主动 probe、端口探测、网络扫描与高频测试禁用规则。正常命令仍进入主审计和新调用复核，不丢弃工具参数或历史。
2. 英文凭据规则绑定动词、有限修饰词和凭据对象，排除 read-only 形容词、read documentation 等不相干对象的误关联。无法由规则确认的表达仍由模型审计，不是静态放行。
3. migration 010 只更新仍等于原始种子模式的 `CYBER_CREDENTIAL_ACCESS_REVIEW`；匹配 code、pattern_type 和原 pattern。不按 ID=62 全覆盖，不改自定义模式、action、priority、description 或 enabled。
4. 模型只引用已知连接表查询或“不需要密钥”说明时，可进入 v5 已有的一次有界操作证据校核。检查完整字面命令、所有引用位置（上限32）、任务上下文；组合命令、替换、写入、未知参数不作为正常状态查看形态。形态检查从不返回最终 allow；真正操作证据 block/review、重复弱证据、预算耗尽、校核异常仍拒绝。
5. `cyber-deny-qwen27b.v6`；保留六字段、256初始输出、thinking=false、分块、64次HTTP/32次复核/120秒总预算和既有555契约。修改误导性的凭据/本地探测用户提示，不能靠改写成“授权/调试”豁免实际操作。

## 验证

旧源码事故对照先红，修改后同样正常对照要求实际完成两次模型调用。新增 Go 回归涵盖原命令、JSON/Agent工具参数、动作上下文不丢失、主复核错误修复、有界故障、read-only/read only对照、多个出现位置、混合风险、显式自定义规则与命令后缀 fuzz。

`scripts/e2e-audit-observation.py` 在现有可销毁 Mock 栈内运行，包含实际 PostgreSQL migration010 临时表/回滚事务验证（旧种子更新、自定义和无关模式不变、禁用状态不变），并核对启动后的默认规则。新增13个HTTP/Responses/SSE对照检查请求状态、审计调用数、上游是否启动和故障分类。原有主动探测例子保留；旧“本地读取全禁”的样例拆成被动正常/主动拒绝两组，不删掉安全检查制造通过。

全量 CI/E2E 结果以最终提交 Actions 为准；这些是合成机制测试，不是生产 Qwen 分类精度测量。真实模型可用 `tests/fixtures/audit-local-observation-eval.jsonl`（11条）及已有 `scripts/eval-audit-intent.py` 回放，故障拒绝不得计作正确分类。

## 升级与边界

合入 main 后仍执行 `RESET_DATA=0 BACKUP_DATABASE=1 ALLOW_BRANCH_SWITCH=1 bash scripts/upgrade.sh main`。本次有 migration010，先备份数据库；脚本自动备份只覆盖本 Compose 中运行的 PostgreSQL，外置数据库需自行备份。不要删除卷或强制 reset 本地代码。核对新请求 commit 与 v6；旧历史日志不会自动重写。

没有生产访问/部署。711KB长历史仍受原始共享审计预算限制：去掉错误规则命中不代表绕开分块或预算失败。未知模态/工具类型继续保留覆盖错误及定位信息，不伪造“已审完整”。如果管理员显式自定义了裸 netstat/关键词禁用规则，该独立规则仍会阻断，不被本次更新覆盖。

外部语义依据（不替代源日志）：Microsoft Learn netstat，https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/netstat 。本次并未修改OpenAI规则或声称官方会给所有这些请求某个风险标签。
