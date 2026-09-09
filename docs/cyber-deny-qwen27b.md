# Cyber 禁用策略与 Qwen3.8-27B 审计规范

版本：`cyber-deny-qwen27b.v3`。本文取代旧“内部工程豁免 / 候选可被复核推翻”的运行策略。数据库变更为 migration 009；仍保留现有 HTTP 555、`risk_audit_request.v2` 和 `risk_audit_output.v2` 接口。

## 1. 决策规则（代码强制，不交给模型协商）

| 场景 | 结果 | 是否访问业务上游 |
|---|---|---|
| 命中任意启用的 Cyber 规则，包括旧 action=review/allow | block / 原规则码 | 否；不调用模型 |
| 模型输出合法 block，且证据存在于实际送审数据 | block / 模型风险码 | 否 |
| 模型输出合法 review，且证据有效 | block；保留原始 review，不声称已证实恶意 | 否 |
| 首次 allow；新调用复核也合法 allow、满足置信检查；所有分块完整 | allow | 是 |
| Fusion 任一有效 block/review | block；其他 allow 或裁决者不能翻转 | 否 |
| 无可用模型、缺字段、证据不存在、超时、预算耗尽、输入未覆盖 | 审计故障 / 555；不是攻击定性 | 否 |

自动化测试、QA、授权、CTF、本人设备、内部调试、轮换凭据均不豁免已经触发的 Cyber 请求。规则表是业务禁用列表，不是“仅召回后让模型自由推翻”的提示列表。即使规则命中的是 `Don’t ... extract hidden credentials`，也会按当前业务策略拒绝；这可能增加否定句、历史引用的拒绝量，不能把它描述为全部都是恶意攻击。

**并非封禁所有编程或自动化。** 普通界面/布局/文档/依赖构建、与 Cyber 无关的函数单元测试有放行对照用例。没有启用规则命中时，模型按实际操作识别禁止能力。禁用能力包括凭据提取/泄露、会话接管、漏洞利用、安全控制绕过、扫描侦察、恶意软件/持久化/C2、钓鱼欺骗，以及逆向/反编译/脱壳/Hook/反调试绕过。测试用途不改变这些能力的业务禁用属性。

## 2. 针对 27B 的执行设计

不要求一个 27B 模型在几十万 token 中同时判断动机、授权、引用来源、多层例外与复杂输出。运行时用固定短策略替代历史自定义/工程放行提示词；模型负责识别未被规则命中的操作，不负责撤销已生效的规则。

- 每次只需要六字段：`decision/risk_code/category/confidence/reason/evidence`。六字段存在性、类型、重复/冲突 JSON、截断和证据位置均由程序校验；少字段不是默认 allow。
- 审计数据与系统控制消息分离。只接受从真正送审数据复制的短证据；系统输出规范不能作为用户攻击证据。引用来源不会被当成可信授权。
- Qwen 本地 vLLM 调用强制 `chat_template_kwargs={"enable_thinking":false,"preserve_thinking":false}`。删除与审计预算冲突的 reasoning_effort、截断、工具和多结果参数。模型别名可用 `_risk_qwen_fast_mode:true` 标明实际为 Qwen。
- 初始输出预算 256 tokens；继承已有有界格式恢复（384/512，硬上限1024）。新一轮检查复用同 profile 已成功的格式，而不是重新触发同一格式故障。
- 主动将送审正文限制为每块 **16,384 UTF-8 字节**，保留重叠与有界当前任务锚点；这是工程初始保护值，不是 Qwen 官方上下文上限，也不是已测最优精度点。提示词、JSON、锚点另有开销，实际 token 不等于字节。
- 默认初判 allow 后增加一次新调用，不能把上一判定或解释喂给它；`_risk_verifier_profile_id` 可指定另一模型。相同模型的两次结果高度可能相关，不能称为统计独立的双模型保证。
- 配置 Fusion 后，初判 allow 再查询2–3个合法配置的评估模型；任一拒绝优先。旧 adjudicator 配置仍校验，但不用于推翻拒绝。主模型已拒绝时无需再花费用投票。
- 所有分块/备用/复核共享最多64次 HTTP 和32次复核预算，总审计墙钟120秒，并受更短的调用方/每次模型超时约束。耗尽预算拒绝并记录审计故障，不截断后放行。大请求必须先测容量与延迟。

`temperature=0` 是当前分类工程初值，不声称是官方推荐最优参数。官方模型卡的通用 non-thinking 建议不同，应在固定策略/样本下比较，再决定是否调整。不要把官方长上下文长度、一般基准成绩或 Mock 通过率解释成此业务场景的漏检率。

## 3. 配置与兼容性

migration 009 将启用的旧 Cyber 规则动作更新为 block；不启用原本 disabled 的规则。审计配置和路由更新为 fail-closed；新增/编辑配置同样不能通过旧 fail_open 或 engineering 参数放宽执行。数据库中的历史自定义系统提示保留作记录，运行时不使用它覆盖固定策略。管理界面显示不可豁免策略，旧豁免选项停用。

保留合法 confidence 数字、数字字符串和明确的 high/medium/low 标签，标签不伪造成概率。allow 要通过至少0.9的数值检查或 high 标签；这只是放行检查，不是模型概率已校准的证明。成功的 block/review 不靠调低阈值变成 allow。

只恢复真正的调用/格式故障。有效拒绝不是故障，不能通过重试直到 allow。备用模型继承主配置要求的复核/Fusion策略，不能漏掉复核后放行。

目前实现的是文本意图审计，而不是完整多模态/工具执行审计。Qwen3.8 本身支持多模态，但本平台未实现图片/音频/文件审计和 provider 侧 `previous_response_id` 历史恢复。未覆盖输入、仅工具输出、缺少必要续接历史、历史超出提取预算会明确拒绝，不能静默跳过；调用方应发送完整必要的文本历史。续写选择仍有启发式边界，没有宣称支持任意隐式指代或持久任务状态恢复。

## 4. 回归与真实模型验收

机制回归：`go test -race -count=1 ./...`、`go vet ./...`、服务构建、升级脚本、诊断隐私、输出解析 fuzz、容器与 E2E。包括：规则零模型调用、测试/否定句不豁免、正常双 allow、首个有效拒绝不被推翻、复核异常、字段缺失、conf 表示漂移、预算、角色边界、跨块、备用复核继承、Fusion否决优先、HTTP555无上游转发。

**Mock 检查只证明机制，不证明 Qwen 的理解准确率。** 在预发布选择实际 Qwen3.8-27B profile，使用下面的只审计脚本（不发送业务上游请求）：

```bash
export RISK_BASE_URL='https://your-staging-risk-gateway'
read -rsp 'Admin token: ' RISK_ADMIN_TOKEN; echo
export RISK_ADMIN_TOKEN
python3 scripts/eval-audit-intent.py --profile-id 1 \
  --cases tests/fixtures/audit-cyber-deny-eval.jsonl --repeat 3
unset RISK_ADMIN_TOKEN
```

使用合成样本，输出只保留 case ID、判定、来源/模型/构建、调用数和耗时，不打印原文或 token。分别统计规则阻断和模型审计；没有模型调用的样本不能算作模型能力验证。基础准入：禁止样本不能 allow，普通对照不能误阻，不能把基础设施失败算作正确分类。再补充真实脱敏事故、长文本关键句在首/中/尾、多轮续写、引号/否定/测试包装、中英文混合，记录漏拦/误拦/故障率与P95延迟。固定实际权重版本、量化、vLLM镜像/模板、配置、请求样本和网关commit，才能可重复比较。生产Qwen/GPU并发未执行时必须写“未实测”，不能许诺零错误。

升级仍走项目既有 `scripts/upgrade.sh` 流程，不删除数据库卷。确认新请求 `/healthz` 与 `gateway_build.audit_engine=cyber-deny-qwen27b.v3`、commit均为实际运行版本，并检查所有副本。先预发布验收；合并代码不等于容器已经升级。

## 5. 官方资料边界

- Qwen 官方模型卡：https://huggingface.co/Qwen/Qwen3.8-27B — 默认 thinking、局部关闭、模型架构/能力、通用采样建议；不提供本项目审计精度保证。
- vLLM reasoning：https://docs.vllm.ai/en/latest/features/reasoning_outputs/ — 返回或隐藏 reasoning 与关闭思考不是一回事，应使用模型模板控制。
- vLLM structured outputs：https://docs.vllm.ai/en/latest/features/structured_outputs/ — 输出约束只能帮助格式，不能证明分类或证据正确。
