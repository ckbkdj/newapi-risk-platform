# 本地 Docker 部署与排障

`docker compose up -d --build` 返回成功，只说明 Docker 已接受创建/启动任务；应用进程仍可能因配置校验、PostgreSQL 连接或迁移错误立即退出。生产和本地部署应使用带就绪检查的脚本。

## 首次部署

```bash
git clone https://github.com/ckbkdj/newapi-risk-platform.git
cd newapi-risk-platform

bash scripts/init-env.sh
# 立即保存脚本首次输出的管理员密码

bash scripts/deploy-local.sh
```

成功时脚本会明确输出：

```text
Deployment is ready.
Admin UI: http://127.0.0.1:8080/admin
Readiness: http://127.0.0.1:8080/readyz
```

也可以使用：

```bash
make deploy
```

## 已执行 `docker compose up`，但 8080 拒绝连接

先执行：

```bash
bash scripts/doctor.sh
```

重点看：

```text
containers
published risk-platform port
risk-platform state
risk-platform logs
PostgreSQL logs
```

常见结果：

### 实际端口不是 8080

```bash
docker compose port risk-platform 8080
```

例如输出：

```text
0.0.0.0:18080
```

则访问：

```text
http://127.0.0.1:18080/admin
```

`.env` 中的 `HTTP_PORT` 控制宿主机端口；容器内部始终监听 8080。

### `configuration validation failed`

缺少或错误的配置通常包括：

```text
MASTER_KEY_B64
JWT_SECRET
BOOTSTRAP_ADMIN_PASSWORD
POSTGRES_PASSWORD
```

执行：

```bash
bash scripts/init-env.sh
bash scripts/deploy-local.sh
```

脚本不会打印已有秘密，也不会覆盖看起来有效的现有密钥。示例占位值会被替换为安全随机值。

### PostgreSQL 密码不匹配

如果日志包含：

```text
password authentication failed
```

说明当前 `.env` 的 `POSTGRES_PASSWORD` 与已初始化的 PostgreSQL 命名卷不一致。

对于确认没有业务数据的首次部署，可清空本项目的命名卷并重新生成密码：

```bash
RESET_DATA=1 bash scripts/deploy-local.sh
```

`RESET_DATA=1` 会删除本项目的 PostgreSQL、Redis 和 Kafka 命名卷。已有业务数据时禁止使用，应恢复原密码或在数据库内完成密码轮换。

### 容器处于 Restarting 或 Exited

```bash
docker compose ps -a
docker inspect --format 'status={{.State.Status}} exit={{.State.ExitCode}} restart={{.RestartCount}} error={{.State.Error}}' newapi-risk-platform
docker compose logs --tail=250 risk-platform
```

容器镜像构建成功不代表进程持续运行。只有 `/readyz` 返回 HTTP 200，平台才算真正启动成功。

## 远程访问

默认配置：

```env
BIND_ADDRESS=0.0.0.0
HTTP_PORT=8080
```

服务器本机验证：

```bash
curl --noproxy '*' -f http://127.0.0.1:8080/readyz
```

局域网或公网客户端使用服务器实际 IP，而不是客户端自己的 `127.0.0.1`：

```text
http://服务器IP:8080/admin
```

生产环境建议仅让反向代理访问该端口，并通过 HTTPS、访问控制和防火墙限制管理端入口。
