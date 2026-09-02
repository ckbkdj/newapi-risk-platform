# Cyber 规则覆盖与自适应学习

本平台的 Cyber 风控不是单纯“敏感词命中即封禁”。数据面按照以下顺序执行：

1. **确定性规则**：只对高置信、目标明确的危害意图直接 `block`；双用途或上下文敏感行为使用 `review`。
2. **小模型语义审计**：规则未直接决策，或规则为 `review` 时，由路由配置的 OpenAI-compatible 审计模型判断意图。
3. **上游模型**：本地允许后才调用渠道。
4. **上游失败自适应学习**：仅对疑似政策/安全拒绝的失败做二次模型分析，形成窄范围候选规则。

## 固定规则覆盖

迁移 `003_cyber_coverage_and_adaptive_learning.sql` 将内置种子扩展为 54 个风险意图族，覆盖：

- 凭据窃取、会话劫持、MFA 绕过、撞库/密码喷洒；
- 钓鱼套件、欺骗性身份冒充；
- 恶意软件、勒索软件、Stealer、Keylogger、RAT、WebShell、Botnet；
- Reverse Shell、C2、持久化；
- 提权、安全控制规避、沙箱/反分析/反调试规避；
- 漏洞武器化、漏洞链、Web 注入、SSRF 云元数据凭据窃取；
- 恶意侦察/扫描、横向移动、AD/域环境接管；
- 数据外传、云 Secret 窃取、云账号接管；
- Kubernetes 接管、容器逃逸；
- 软件供应链投毒、CI/CD 入侵；
- 数据/磁盘破坏、Wiper、DDoS、非法挖矿、日志清除；
- LLM Jailbreak、Prompt Injection、System Prompt Extraction；
- RAG/训练数据/Agent Tool/Agent Memory 投毒；
- Agent Tool 凭据窃取、Agent 高影响工具滥用；
- Prompt/Agent Worm 自复制；
- AI 数据泄露、模型窃取、AI 供应链投毒；
- AI Cost Harvesting、AI DoS、可信输出操纵、Chaff/垃圾数据攻击。

规则包含英文与常见中文表达。规则重点匹配**动作 + 高风险对象/目标**的组合，而不是单个术语。

### Block 与 Review

高置信度危害行为使用 `block`，例如凭据窃取、恶意软件、C2、数据外传、破坏性操作、RAG 投毒等。

以下双用途行为默认使用 `review`：

- Reverse Shell；
- 提权；
- 漏洞链与 Web Injection；
- 主动侦察/扫描；
- Kubernetes/Container Escape；
- LLM Jailbreak / Prompt Injection / System Prompt Extraction；
- Agent Tool 高影响调用；
- Model Extraction；
- AI Output Manipulation。

Review 规则不会仅凭关键词直接拒绝，而是交给配置的小模型结合完整请求上下文复核。

## 上游失败自适应学习

### 不是什么错误都学习

以下错误**不会**生成 Cyber 候选规则：

- HTTP 401 认证失败；
- HTTP 404；
- HTTP 408/超时；
- HTTP 409；
- HTTP 429/配额或限流；
- HTTP 5xx；
- 网络连接失败；
- SSE 传输中断；
- 无可用模型、计费错误、上下文长度、请求 JSON 格式错误等基础设施/协议问题。

默认只对以下结果进入“是否为 Cyber 政策拒绝”的模型分析：

- HTTP 400；
- HTTP 403；
- HTTP 422；
- HTTP 451；
- HTTP 200 但返回明确错误包；
- HTTP 200 SSE 明确 `event:error`。

即使进入分析，也只有审计模型判断为 `is_cyber=true` 才会形成候选。

### 模型不能直接写正则

自适应模型只能返回：

```json
{
  "is_cyber": true,
  "category": "credential_access",
  "confidence": 0.997,
  "indicators": ["verbatim phrase A", "verbatim phrase B"],
  "reason": "brief"
}
```

平台随后执行硬校验：

- category 必须在服务端 allowlist；
- 至少两个 indicator；
- indicator 必须逐字出现在原始请求的审计文本中；
- 模型不能提交 regex、wildcard 或任意规则代码；
- 每个 indicator 使用 `regexp.QuoteMeta` 转义；
- 学习规则要求至少两个 indicator 在有限距离内共同出现；
- 新规则长度和正则语法再次由服务端验证。

因此，上游错误正文或 Prompt Injection 不能直接把任意正则注入生产规则库。

### 隐私保护

自适应规则不会保存完整 Prompt。进入规则生成前，还会拒绝下列 indicator：

- IPv4 / IPv6；
- URL；
- 邮箱；
- hostname/domain；
- UUID；
- 长 Hex/Base64/高熵标识；
- Bearer Token；
- API Key / Password / Secret / Cookie；
- 明显 ID 型数字串。

上游错误正文进入小模型前会截断，并对凭据/Secret 做脱敏。用于统计不同用户的标识是 HMAC digest，而不是原始用户 ID。

## 候选、Shadow 与自动晋级

数据库表：

```text
cyber_rule_candidates
cyber_rule_candidate_users
```

候选按照“风险类别 + 服务端验证后的原文 indicator 组合”生成 HMAC 指纹并聚合证据。

默认参数：

```text
cyber_adaptive_learning_enabled     = true
cyber_adaptive_auto_promote         = true
cyber_adaptive_min_confidence       = 0.99
cyber_adaptive_min_evidence         = 3
cyber_adaptive_min_distinct_users   = 2
cyber_adaptive_auto_block           = true
```

达到基础阈值后，候选会自动成为 `CYBER_ADAPTIVE_*` 规则。早期规则为 `review`，仍由本地审计模型复核。

要自动升级为硬 `block`，代码还有一个不可由模型降低的更高门槛：

```text
confidence >= 0.995
same candidate evidence >= 10
HMAC-distinct users >= 3
```

因此一次上游错误、一个用户反复重试、或者单次模型误判都不能直接生成硬拦截。

## 运行时行为

学习链路是异步、有界的，不阻塞主请求：

```text
New API request
  -> local rules
  -> small audit model
  -> upstream provider
       -> suspected policy failure
          -> bounded adaptive queue
          -> small-model failure classifier
          -> validated candidate
          -> evidence aggregation
          -> review rule
          -> stronger evidence
          -> optional hard block
```

规则晋级后调用 `ReloadRules` 热加载，不需要重启网关。

## 数据库升级

服务启动时自动执行 migration，不需要手工执行 SQL：

```text
internal/platform/migrations/003_cyber_coverage_and_adaptive_learning.sql
```

升级后可在 Web 管理台的 **Cyber 规则** 页面直接看到固定规则以及已经晋级的 `CYBER_ADAPTIVE_*` 规则。

## 重要边界

不存在一个有限的“所有 Cyber 恶意请求字符串全集”。固定规则负责高置信、低误报的常见风险族；小模型处理语义和双用途上下文；上游拒绝学习负责补充供应商实际发现的新模式。这三层组合比无限堆砌关键词更适合商业生产环境。
