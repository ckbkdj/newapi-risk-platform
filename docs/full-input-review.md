# 完整请求输入复盘

本功能保存风险网关实际收到并完整读取的 HTTP 请求体，不是摘要、HMAC、命中片段，也不是审核模型重新生成的解释。放行、拦截、审计不确定后放行、上游失败都使用同一入口留存。未知字段、工具记录和正文中的凭据不被静默删除；HTTP Authorization/Cookie 等认证头不保存。

## 使用

管理员登录 `/admin` → 请求追踪 → 每条记录右侧「完整输入」，或使用「完整输入复盘」按 Request ID 查询。选择开始时间和路由对应的尝试，再点「查看完整输入」。相同 Request ID 的重试分别保留，不互相覆盖，可翻页查看较早尝试。

完整原文按 32768 个 UTF-16 字符分页显示，分页不影响保存内容。也可切换到 user 角色消息视图；其他角色、工具数据和未知输入类型仍在完整原文中。下载接口输出原始字节，不经过 JSON 重序列化。读取和下载均写入独立访问审计，退出账号或关闭窗口会清理本功能持有的浏览器正文。

**旧记录无法补回**：启用前只有 HMAC/摘要的请求不能还原。无原文不代表输入为空，也不代表请求被风控拦截。队列未完成、捕获容量不足、存储异常和已过期同样可能导致查不到原文；「留存状态」显示当前进程的排队、已存、未捕获与存储失败计数。计数在进程重启后重置，不是历史完整率。

## 安全和范围

- 仅 admin 可读取完整原文；operator/viewer 和未登录请求分别返回 403/401。读取时还检查数据库中的实时角色与启用状态，旧 JWT 不会绕过撤权。
- 完整原文可能包含敏感用户信息，应仅提供给必要的审计人员，并按业务的数据告知与管理流程启用。本次按项目需求默认开启，环境变量可关闭。
- 单独 PostgreSQL 表 `trace_input_archives` 保存 gzip + AES-256-GCM 密文；原文不加入普通 TraceEvent、metadata、Kafka 或 Redis DLQ。原文访问记录在 `trace_input_accesses`。
- 从现有 MASTER_KEY_B64 派生专用加密密钥；AAD 绑定记录 ID、Request ID、路由、开始时间、到期时间和完整字节数。备份数据库时妥善保管 MASTER_KEY_B64，不要直接换掉它，否则已有密文不能解密。备份副本的清理仍由备份系统负责。
- 默认保留 7 天，不超过应用初始保留设置；读取和清理还遵循数据库中更短的存储保留期。读取立即检查到期，后台每分钟分批物理清理；数据库中断时物理删除可能延后。
- 只捕获完成网关认证后由网关实际完整读取的请求体。认证前拒绝、未读完、超过接收上限或只有 New API 追踪回调而未经过网关的请求不会被伪装成完整原文。
- 不自动下载正文中的链接，不自动执行/重放请求，不保证链接所指外部文件仍然可访问。

## 部署参数

正常升级与 migration 015 会自动建表；本机 Compose 已传递这些环境变量。独立/外部编排环境请在 risk-platform 容器中传递同名变量：

```env
TRACE_INPUT_CAPTURE_ENABLED=true
TRACE_INPUT_RETENTION_DAYS=7
TRACE_INPUT_QUEUE_SIZE=64
TRACE_INPUT_MEMORY_BUDGET_BYTES=536870912
```

关闭新留存用 `TRACE_INPUT_CAPTURE_ENABLED=false`，已有记录保留到各自到期。修改 Compose 环境变量需要重建容器，不是单纯 restart。

捕获上限跟随 REQUEST_HARD_MAX_BYTES，不能保存截断前缀并称其完整。每个 64 KiB 捕获块按 4 倍字节记账，为压缩扩容与密文留空间；默认 512 MiB 是捕获工作内存预算，另有队列条数限制和两个写入工作线程。网关原本的请求缓冲与审核内存不计入此预算。数据库慢、队列满或内存预算不足时正常请求不会因为留存而变成 555；缺失会记录固定诊断和计数，不会向普通日志写入原文。进程被强杀时尚未落库的队列仍可能丢失，因此本功能不是强一致合规录制系统。

## 接口

所有接口均须 admin Bearer token：

- GET `/api/admin/v1/trace-inputs/status`：启用状态、有效保留期和本进程计数。
- GET `/api/admin/v1/trace-inputs?request_id=...&offset=0`：最多 50 个尝试的元数据，不含原文。通过 offset 翻页。
- GET `/api/admin/v1/trace-inputs/{id}/body`：完整原始请求字节，以 text/plain 返回。
- GET `/api/admin/v1/trace-inputs/{id}/body?download=1`：按附件下载；访问独立记录。

原文仅在解密和完整性校验成功后返回 `X-Trace-Input-Complete: true` 与 `X-Trace-Input-Bytes`；浏览器另外校验收到的字节数。不存在返回 404，到期返回 410，存储/访问审计不可用返回 503，完整性异常返回 500，不输出伪造前缀。

## 2026-09-22 日志中的耗时

示例 commit 87583818 的总耗时 51.876 秒：抽取 0.104 秒、规则 4.425 秒、模型阶段 34.271 秒、上游响应头 12.901 秒。模型阶段包含所有分块与等待，不等于一次实际推理耗时。

本次日志已经没有重复 verifier：9 次调用全部是 primary。`chunked_for_audit_budget` 和固定 16384 字节来自 cyberDenyChunkBytes 的主动分块，并非模型报上下文超限。后续分块约 7.3–7.8 秒的 queue_wait_ms 说明平台并发槽位确有等待；这些等待相互重叠，不能简单相加为总耗时。只增大 AUDIT_FALLBACK_CHUNK_BYTES 不能改变这个主动分块分支。

本功能不修改分块、并发、模型、审核决策或用户之前要求的 555 契约，也不把未实测的并发调整当作性能修复。原始输入留存一次，与九次模型分块调用分离。

## 验证

纯标准库回归可独立运行：

```sh
cd internal/platform
GO111MODULE=off go test -race trace_input_codec.go trace_input_recorder.go trace_input_codec_test.go
```

`Input archive verification` 工作流编译完整服务，并对一次性 PostgreSQL 跑完整字节往返、admin/operator/viewer 权限、撤权、访问审计、到期删除和 UI 接入测试。不要把测试数据库变量指向生产。原仓库 CI/E2E 的既有失败应单独列出，不因新增功能检查通过而声称全仓库全绿。
