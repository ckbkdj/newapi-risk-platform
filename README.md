# New API 风控平台

位于 **New API 与模型渠道之间** 的独立风控网关。它先执行可配置的 Cyber 规则，再调用默认小模型进行语义审计；通过审计后才转发到真实渠道。平台同时统一上游模型错误、提供请求追踪接口、可视化配置、PostgreSQL 七天检索窗口、Redis 分布式控制和 Kafka 长期事件流。

> 本仓库是独立 Go 服务，正式维护地址为 `ckbkdj/newapi-risk-platform`。

## 核心能力

- **双层审计**：高置信规则优先，未直接决策时调用 OpenAI 兼容小模型。
- **统一错误码 555**：Cyber 拦截、审计模型故障、上游连接/超时、上游 HTTP 错误、HTTP 200 错误包统一转换。
- **多协议渠道**：OpenAI、Anthropic、Gemini、Bearer、自定义 Header、Query Key、无鉴权及受约束的透传模式。
- **高并发保护**：连接复用、全局并发闸门、Redis Token Bucket、按路由分布式并发信号量、异步批量落库。
- **可视化控制台**：路由、模型、规则、试运行、追踪、存储策略和追踪客户端管理。
- **请求追踪**：网关自动追踪；New API 也可通过 HMAC 防重放接口主动上报。
- **分层存储**：PostgreSQL 默认七天按日分区；Redis Stream 作为故障队列；Kafka 作为长期事件流。
- **安全基线**：AES-256-GCM 密钥加密、JWT/RBAC、管理审计日志、SSRF/DNS 重绑定防护、CSP、非 root 容器。
- **可观测性**：JSON 日志、`/healthz`、`/readyz`、Prometheus `/metrics`。

## 架构

```mermaid
flowchart LR
    U[用户] --> N[New API]
    N -->|Bearer 路由 Key| G[Risk Gateway]
    G --> R[Cyber Rules]
    R -->|未直接决策| A[Small Audit Model]
    A -->|Allow| C[Provider Channel]
    R -->|Block| E[HTTP / Logical 555]
    A -->|Block / Failure + Fail-closed| E
    C -->|Provider Error| E
    C -->|Success| N

    G --> Q[Trace Queue]
    N -->|HMAC Tracking API| Q
    Q --> P[(PostgreSQL Daily Partitions)]
    Q --> K[(Kafka Long-term Events)]
    Q --> D[(Redis Stream DLQ)]
    X[Visual Admin] --> G
    X --> P
```

## 555 语义

以下情况返回实际 HTTP 状态 `555`，响应体中的 `error.code` 也为数字 `555`：

| 场景 | `risk_code` 示例 |
|---|---|
| Cyber 规则命中 | `CYBER_CREDENTIAL_THEFT` |
| 审计模型不可用，路由为 fail-closed | `AUDIT_MODEL_UNAVAILABLE` |
| 审计模型超时、非 2xx 或 JSON 不合法 | `AUDIT_MODEL_ERROR` |
| 上游连接失败 | `UPSTREAM_CONNECTION_ERROR` |
| 上游超时 | `UPSTREAM_TIMEOUT` |
| 上游返回非 2xx | `UPSTREAM_MODEL_ERROR` |
| 上游 HTTP 200 但正文是错误包 | `UPSTREAM_MODEL_ERROR` |
| 流式首事件前发现错误 | `UPSTREAM_STREAM_ERROR` |

示例：

```json
{
  "error": {
    "message": "request rejected by risk control",
    "type": "risk_control_error",
    "code": 555,
    "risk_code": "CYBER_CREDENTIAL_THEFT",
    "request_id": "8b36f5ec-e6a1-42ec-b0ee-6a81c10c9032"
  }
}
```

### SSE 限制

HTTP 响应头一旦发给客户端，协议上不能再把状态码从 `200` 改成 `555`。因此：

- 首个有意义 SSE 事件前发现错误：返回 **HTTP 555 + JSON 错误体**。
- 已开始流式传输后发现错误：保持已经发送的 HTTP 状态，并追加：

```text
event: error
data: {"error":{"code":555,"risk_code":"UPSTREAM_STREAM_ERROR",...}}
```

New API 的流式适配层应同时识别 HTTP 555 和 SSE `event:error` 中的逻辑码 555。

认证失败、普通限流和平台过载分别使用标准的 `401`、`429`、`503`，避免把基础网关错误与模型/风控错误混为一类。

## 快速启动

### 1. 首次部署

```bash
git clone https://github.com/ckbkdj/newapi-risk-platform.git
cd newapi-risk-platform
bash scripts/deploy-local.sh
```

`deploy-local.sh` 会基于 `.env.example` 创建或迁移 `.env`、生成缺失的随机密钥、校验 Compose、构建容器并等待 `/readyz`。不要把 `.env` 提交到 Git。

需要手工指定既有密钥时，可先编辑 `.env`，再重新执行：

```bash
bash scripts/deploy-local.sh
```

### 2. 启动 PostgreSQL、Redis 和平台

首次部署脚本已经完成启动。后续仅重新构建并检查就绪状态时仍执行：

```bash
bash scripts/deploy-local.sh
curl http://127.0.0.1:8080/readyz
```

控制台：`http://127.0.0.1:8080/admin`

管理员是 `.env` 中的：

```text
BOOTSTRAP_ADMIN_USERNAME
BOOTSTRAP_ADMIN_PASSWORD
```

初始化只在用户名不存在时创建账户，不会在每次启动时覆盖现有密码。

### 3. 可选启用 Kafka

```bash
# .env
KAFKA_ENABLED=true
KAFKA_BROKERS=kafka:9092

docker compose --profile longterm up -d --build
```

内置 Kafka 是单节点开发/验收环境。商业生产环境应使用至少三 Broker 的托管或独立 Kafka，预创建 Topic，并将副本因子、ISR、ACL、TLS/SASL 和磁盘保留策略纳入运维。


## Git 更新与安全升级

已有部署不要手工 `git pull && docker compose up`。使用仓库内升级脚本：

```bash
# 在当前分支做 fast-forward 更新、备份数据库、迁移 .env、重建并验证
bash scripts/upgrade.sh

# 明确升级 main
bash scripts/upgrade.sh main

# update.sh 是兼容入口
bash scripts/update.sh main
```

默认行为：

- 只接受 fast-forward，远端改写历史时停止，不强制覆盖本地代码；
- 工作区必须干净，避免把未提交修改卷入升级；
- `.env` 原样保留，并备份到 `.upgrade-backups/<UTC时间>-<旧提交>/`；
- PostgreSQL 正在运行时，默认先生成 `pg_dump -Fc` 备份；
- 不删除 PostgreSQL、Redis 或 Kafka Volume；
- 自动执行 `.env` 配置迁移、Compose 校验、镜像构建和 `/readyz` 检查；
- 部署失败时回退代码与容器到旧提交，但不会自动反向执行数据库迁移，避免破坏升级期间产生的数据。

可控开关：

```bash
BACKUP_DATABASE=0 bash scripts/upgrade.sh main       # 明确跳过数据库备份
ROLLBACK_ON_FAILURE=0 bash scripts/upgrade.sh main   # 禁止自动代码/容器回退
ALLOW_BRANCH_SWITCH=1 bash scripts/upgrade.sh main   # 允许从当前干净分支切换
```

升级失败时先查看脚本输出的备份目录，再运行：

```bash
docker compose ps -a
docker compose logs --tail=300 --no-color
bash scripts/doctor.sh
```

## 配置审计模型

控制台进入“审计模型”，配置 OpenAI Chat Completions 兼容接口：

```text
Endpoint: http://audit-model:8000/v1
Model:    Qwen3-4B-AWQ
Timeout:  8000 ms
Threshold: 0.65
Fail-closed: true
Default: true
```

模型必须返回单个 JSON 对象：

```json
{
  "decision": "allow",
  "risk_code": "",
  "category": "benign_security",
  "confidence": 0.96,
  "reason": "defensive request"
}
```

合法决策只有 `allow`、`block`、`review`。输出不可解析、请求超时或模型返回错误时，fail-closed 路由转为 555。

`Extra JSON` 可配置兼容服务所需的额外参数，例如：

```json
{
  "response_format": {"type": "json_object"},
  "top_p": 0.1
}
```

`model`、`messages`、`stream` 不允许由 Extra 覆盖。

## 配置路由并接入 New API

示例路由：

```text
Slug:                  openai-main
Upstream Base URL:     https://api.openai.com
Provider:              openai
Upstream Auth:         bearer
Upstream Secret:       sk-real-provider-key
New API Channel Key:   risk-route-random-secret
Audit Model:           default
Fail-closed:           true
Max concurrency:       256
Rate:                  100 RPS / burst 200
```

New API 渠道配置：

```text
Base URL: https://risk.example.com/gateway/openai-main
Key:      risk-route-random-secret
```

New API 通常会继续拼接 `/v1/chat/completions`、`/v1/responses` 或 `/v1/models`。平台将剩余路径拼接到真实渠道 Base URL。

入口 Key 可通过两种方式传递：

```http
Authorization: Bearer risk-route-random-secret
```

或：

```http
X-Risk-Gateway-Key: risk-route-random-secret
```

使用 `passthrough` 上游鉴权时必须使用 `X-Risk-Gateway-Key`，否则入口 Bearer Key 与需要透传的 Authorization 无法区分。

可选追踪头：

```http
X-Request-ID: req-unique-id
X-NewAPI-Request-ID: newapi-internal-id
X-NewAPI-User-ID: pseudonymous-user-id
```

请传匿名化/内部用户标识，不要传姓名、手机号、邮箱或证件号。

## New API 主动追踪接口

接口：

```text
POST /api/v1/track/events
```

请求头：

```text
X-Risk-Key-Id
X-Risk-Timestamp   Unix 秒
X-Risk-Nonce       每次请求唯一
X-Risk-Signature   HMAC-SHA256 十六进制
```

签名原文：

```text
timestamp + "\n" + nonce + "\n" + hex(sha256(raw_body))
```

单个事件或最多 1000 个事件的批量包均可。完整示例见 [`docs/newapi-integration.md`](docs/newapi-integration.md)。

## 数据治理

### PostgreSQL

- `request_traces` 按 UTC 日期分区。
- 默认保留最近 `7 × 24h`；页面可设置 1–365 天。
- 启动前创建当前及未来分区，多副本用 PostgreSQL Advisory Lock 串行维护。
- 过期分区直接删除，边界分区按精确时间清理。
- 幂等事件、Nonce、管理审计和 Outbox 分别有独立清理策略。

### 默认不保存原始提示词

平台只保存抽取文本的 HMAC 指纹：

```text
prompt_hmac = HMAC-SHA256(master_key, normalized_audit_text)
```

请求体、响应体、模型审计原文和上游错误正文均不写入追踪表。New API 上报的 `metadata` 会递归删除 `prompt`、`messages`、`content`、`input`、`authorization`、`password`、`secret`、Token、Cookie 等字段，并限制深度、数组长度和大小。

### Redis

- 分布式 Token Bucket。
- 按路由分布式并发信号量。
- 追踪签名 Nonce 防重放。
- PostgreSQL/本地队列故障时的 Redis Stream DLQ。
- Redis 不可用时，限流和并发保护降级到单进程；Nonce 降级到 PostgreSQL。

### Kafka

- 成功落 PostgreSQL 的追踪事件异步发布到 `risk.request.events.v1`。
- Kafka 写失败进入 PostgreSQL Outbox，后台指数退避重试。
- 页面可保存长期保留天数，并尝试修改 Topic `retention.ms`。
- Kafka 账户需要 `ALTER_CONFIGS` 权限；没有权限时页面会显示应用告警，但 PostgreSQL 设置仍会原子保存。

## 管理 API

| 方法 | 路径 | 作用 |
|---|---|---|
| `POST` | `/api/admin/v1/login` | 管理员登录 |
| `GET` | `/api/admin/v1/dashboard` | 24 小时指标 |
| `GET/POST` | `/api/admin/v1/routes` | 路由查询/保存 |
| `GET/POST` | `/api/admin/v1/audit-profiles` | 审计模型查询/保存 |
| `GET/POST` | `/api/admin/v1/cyber-rules` | Cyber 规则查询/保存 |
| `POST` | `/api/admin/v1/audit/dry-run` | 审计试运行 |
| `GET` | `/api/admin/v1/traces` | 追踪查询 |
| `PUT` | `/api/admin/v1/settings/storage` | 存储保留策略 |
| `GET/POST` | `/api/admin/v1/tracking-clients` | 追踪签名客户端 |

`viewer` 只读，`operator` 可修改路由/模型/规则并试运行，`admin` 还可删除资源和修改存储、追踪客户端。

## 高并发与容量规划

网关本身是无状态多副本服务；配置与事件状态在 PostgreSQL/Redis/Kafka 中共享。建议：

1. 从 3 副本起步，通过 HPA 扩展；负载均衡必须支持长时间 SSE。
2. 每个实例的 `POSTGRES_MAX_CONNS × 最大副本数` 不得超过数据库可用连接数；大规模部署前加入 PgBouncer。
3. Redis 使用 Sentinel/Cluster 或托管高可用实例；关闭会导致跨副本限流精度下降。
4. 审计小模型通常是吞吐瓶颈，应独立扩容、批量压测并限制最大上下文。
5. Kafka Topic 以 `request_id` 为 Key，可按 Key 保序；生产环境预设足够分区和副本。
6. 对 `gateway_requests_total`、P95/P99、追踪队列深度、丢弃计数、Outbox 积压、Redis 降级和审计超时建立告警。

## Kubernetes

先替换 `deploy/kubernetes.yaml` 中镜像、Secret 和外部服务地址，再使用 Kustomize：

```bash
kubectl apply -k deploy/
```

Kustomize 补丁会移除基础清单中依赖 shell 的 `preStop`，因为运行镜像是 distroless。生产 Ingress/LB 应在 Pod 进入 Terminating 后立即停止新流量，并保留至少 45 秒终止宽限期。

默认 NetworkPolicy 只允许同命名空间的 PostgreSQL/Redis/Kafka和公网 `443`。如果数据库、Redis、Kafka 位于其他命名空间或私网地址，必须按实际 CIDR/Pod Selector 修改策略后再部署。

## 开发与验证

```bash
make fmt
make test
make race
make vet
make build
```

GitHub Actions 还会：

- 运行竞态检测；
- 执行 `go vet`；
- 构建静态二进制；
- 构建非 root 容器；
- 启动真实 PostgreSQL、Redis 与服务；
- 验证 `/readyz` 和管理员登录。

## 安全与上线检查

- 在受信任的 TLS Ingress 后暴露服务，不要直接公开明文 HTTP。
- 管理端最好通过 VPN、零信任访问代理或管理网段限制。
- 路由入口 Key、上游 Key、追踪 Secret、JWT Secret、Master Key 必须由密钥管理系统托管。
- **不要直接更换 `MASTER_KEY_B64`**：现有密文、路由 Key HMAC 和提示词指纹依赖该 Key。轮换前应先编写重加密迁移并保留旧 Key 读取窗口。
- 默认禁止私网/回环/链路本地/云元数据地址及 DNS 重绑定。只有确实要调用内网模型时才设置 `ALLOW_PRIVATE_UPSTREAMS=true`，同时限制出站目的地。
- Cyber 规则应保持高置信，宽泛规则使用 `review`，避免仅凭关键词误杀防御性内容。
- 小模型审计不是唯一安全边界；保留规则、身份、额度、租户隔离、内容治理和人工复核。
- 对生产规则和模型提示词建立变更评审、回滚与灰度流程。

## 当前边界

- 审计模型接口当前采用 OpenAI Chat Completions 兼容格式。
- 多模态二进制本身不落库；文本字段和工具 Schema 会进入审计文本。
- 管理用户初始化、角色读取已实现，批量用户生命周期和企业 SSO/OIDC 建议在下一阶段接入。
- Master Key 自动在线轮换尚未实现，必须按上述重加密流程操作。
- Kafka 页面修改保留策略依赖 Broker ACL；无权限时仅保存期望值并返回告警。


## 独立仓库来源

本仓库于 2026-09-02 从 `ckbkdj/proxy` 的临时功能分支迁移而来，源提交为
`650a61815639bae568d9c1e1ed487aaf2c163f43`。项目现在以独立仓库维护；
`ckbkdj/proxy` 不再作为本项目的发布或部署来源。


## Web 查询请求

管理台的“请求追踪”页面支持：

- 15 分钟、1 小时、24 小时、7 天快捷时间范围，以及自定义浏览器本地时间；
- 用户标识精确、前缀或包含匹配；
- 网关 Request ID、New API Request ID、路由、模型、接口、来源和租户标识；
- Allow、Block、Error、Review、风险码、HTTP 状态及上游状态；
- 匹配结果统计、分页、当前页 CSV 导出和单条请求详情。

用户查询依赖 New API 在代理请求中传入 `X-NewAPI-User-ID`，或者通过
`POST /api/v1/track/events` 上报 `external_user_id`。建议传内部数字 ID、UUID 或不可逆匿名标识，
不要传姓名、手机号、邮箱或证件号码。`metadata.tenant_id` 可用于租户级精确过滤。

精确用户过滤会使用索引，适合高并发日常查询；前缀和包含搜索用于排障，其中包含搜索在大数据窗口下成本更高，页面默认仍使用精确匹配。
