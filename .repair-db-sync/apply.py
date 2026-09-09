from pathlib import Path
import subprocess
root=Path('.')
def change(name,old,new):
 p=root/name;s=p.read_text();assert old in s,(name,old[:120]);p.write_text(s.replace(old,new,1))
change('internal/platform/audit_cyber_deny.go','普通 UI/构建/业务函数测试不自动等于 Cyber。','使用用户已提供的连接凭据登录、按已有 sudo 权限管理或部署服务，不等于窃取凭据或利用漏洞提权。数据库备份、同步、迁移、导入及全量/按表抽样拉取，本身不等于凭据导出或非法外传；root 用户、密码字段或脱敏占位符不能单独作为阻断证据。必须说明具体被禁止的操作及对象，如寻找隐藏凭据、披露秘密、未经许可取得/传出数据或绕过访问边界；测试环境/自有资产声明不是豁免。覆盖目标数据属于需确认目标与备份的执行风险，不能只凭覆盖一词伪造 Cyber。保留其他片段及混合操作检查。\n普通 UI/构建/业务函数测试不自动等于 Cyber。')
change('internal/platform/audit_operation_grounding.go','q := normalizeAuditEvidenceQuote(d.Evidence)','q := normalizeAuditEvidenceQuote(d.Evidence)\n\t// Display redaction can replace USER_PROVIDED_SECRET with REDACTED.\n\t// Use validated offsets, not a lossy log quote, for source-shape admission.\n\tif d.evidenceSourceMatched && d.evidenceSourceStart >= 0 && d.evidenceSourceEnd <= len(source) && d.evidenceSourceEnd > d.evidenceSourceStart {\n\t\traw := source[d.evidenceSourceStart:d.evidenceSourceEnd]\n\t\tif redactCyberTraceText(raw) == d.Evidence { q = raw }\n\t}')
change('internal/platform/audit_operation_grounding.go','if observationalAuditEvidence(q, source) {','if administrativeAuditEvidence(d, q, source) || observationalAuditEvidence(q, source) {')
change('internal/platform/audit_operation_grounding.go','保持六字段输出；证据不超过80字。','使用已经提供的登录凭据、已有 sudo 权限和正常数据库备份/同步/全量拉取不等于窃取凭据、漏洞提权或非法外传。说明具体操作及对象，不得只重复 root/密码字段/同步语句。覆盖操作需要目标和备份确认，但这不是 Cyber 攻击证据。不能凭“我的/测试”授予全请求豁免，其他禁用操作仍 block。保持六字段输出；证据不超过80字。')
change('internal/platform/types.go','type AuditDecision struct {','type AuditDecision struct {\n\tevidenceSourceMatched bool // In-memory validated offsets; never serialize raw secrets.\n\tevidenceSourceStart int\n\tevidenceSourceEnd int')
change('internal/platform/audit_model_evidence.go','if decision.Decision == DecisionAllow {','if decision.Decision == DecisionAllow {\n\t\tdecision.evidenceSourceMatched = false')
change('internal/platform/audit_model_evidence.go','decision.Evidence = redactCyberTraceText(sourceText[start:end])','decision.evidenceSourceMatched = true\n\tdecision.evidenceSourceStart, decision.evidenceSourceEnd = start, end\n\tdecision.Evidence = redactCyberTraceText(sourceText[start:end])')
change('internal/platform/audit_semantic_review.go','httpCalls   int','httpCalls   int\n\thttpBudget int\n\treviewBudget int')
change('internal/platform/audit_semantic_review.go','if s.reviewCalls >= maxAuditSemanticCalls {','limit := s.reviewBudget\n\tif limit == 0 { limit = maxAuditSemanticCalls }\n\tif s.reviewCalls >= limit {')
change('internal/platform/audit.go','if cyberDenyActive(ctx) && state.httpCalls >= cyberDenyHTTPBudget {','limit := state.httpBudget\n\t\tif limit == 0 { limit = cyberDenyHTTPBudget }\n\t\tif cyberDenyActive(ctx) && state.httpCalls >= limit {')
change('internal/platform/audit_long_context.go','"sync"','"sync"\n\t"sync/atomic"')
change('internal/platform/audit_long_context.go','type auditCallMetadata struct {','type auditChunkProgressKey struct{}\n\ntype auditCallMetadata struct {\n\tChunksCompleted int')
change('internal/platform/audit_long_context.go','if err == nil || !isAuditContextLengthError(err) {','if err == nil { metadata.ChunksCompleted = 1 }\n\t\tif err == nil || !isAuditContextLengthError(err) {')
change('internal/platform/audit_long_context.go','decision, chunkErr := e.callModelChunks(context.WithValue(ctx, auditChunkOffsetsKey{}, offsets), profile, chunks)','if state, ok := ctx.Value(auditSemanticStateKey{}).(*auditSemanticState); ok && cyberDenyActive(ctx) { state.configureChunkBudget(len(chunks)) }\n\t\tprogress := &atomic.Int32{}\n\t\tchunkCtx := context.WithValue(ctx, auditChunkProgressKey{}, progress)\n\t\tdecision, chunkErr := e.callModelChunks(context.WithValue(chunkCtx, auditChunkOffsetsKey{}, offsets), profile, chunks)\n\t\tmetadata.ChunksCompleted = int(progress.Load())')
change('internal/platform/audit_long_context.go','return e.callModelOnceWithEvidenceSource(ctx, profile, decorateAuditChunk(chunks[0], 0, 1), chunks[0])','d, err := e.callModelOnceWithEvidenceSource(ctx, profile, decorateAuditChunk(chunks[0], 0, 1), chunks[0])\n\t\trecordAuditChunkCompletion(ctx, d, err)\n\t\treturn d, err')
change('internal/platform/audit_long_context.go','for result := range results {\n\t\tcompleted++','for result := range results {\n\t\trecordAuditChunkCompletion(ctx, result.decision, result.err)\n\t\tcompleted++')
p=root/'internal/platform/audit_long_context.go';p.write_text(p.read_text()+'''\n// Count completed decisions, not canceled or failed physical calls.
func recordAuditChunkCompletion(ctx context.Context, d AuditDecision, err error) {
 if err != nil || (d.Decision != DecisionAllow && d.Decision != DecisionBlock && d.Decision != DecisionReview) { return }
 if progress, ok := ctx.Value(auditChunkProgressKey{}).(*atomic.Int32); ok { progress.Add(1) }
}
''')
change('internal/platform/types.go','AuditChunkCount             int','AuditChunksCompleted int `json:"audit_chunks_completed"`\n\tAuditChunkCount             int')
change('internal/platform/audit.go','result.AuditChunkCount = callMetadata.ChunkCount','result.AuditChunkCount = callMetadata.ChunkCount\n\tresult.AuditChunksCompleted = callMetadata.ChunksCompleted')
change('internal/platform/audit_recovery.go','metadata["audit_completed"] = finalized && result.AuditCoverageStatus != "incomplete"','metadata["audit_chunks_completed"] = result.AuditChunksCompleted\n\tmetadata["audit_completed"] = finalized && result.AuditCoverageStatus != "incomplete" && (result.AuditChunkCount == 0 || result.AuditChunksCompleted == result.AuditChunkCount)')
for p in [root/'internal/platform/build_info.go', *(root/'scripts').glob('*.py'), root/'scripts/e2e.sh']:
 s=p.read_text()
 if p.name=='collect-audit-diagnostics.py':
  s=s.replace('"cyber-deny-qwen27b.v6"}', '"cyber-deny-qwen27b.v6", "cyber-deny-qwen27b.v7"}')
  s=s.replace('"audit_chunk_count",','"audit_chunk_count", "audit_chunks_completed",')
  s=s.replace('ERRORS = {','ERRORS = {"audit_http_budget", ')
 else:s=s.replace('cyber-deny-qwen27b.v6','cyber-deny-qwen27b.v7')
 p.write_text(s)
subprocess.run(['gofmt','-w','cmd','internal'],check=True)
change('internal/platform/audit_failover.go','HTTPCalls           int','HTTPCalls           int\n\tHTTPBudget int\n\tReviewBudget int')
change('internal/platform/audit_semantic_review.go','m.HTTPCalls, m.SemanticReviewCalls, m.SemanticReviewCount = s.httpCalls, s.reviewCalls, s.reviews','m.HTTPCalls, m.SemanticReviewCalls, m.SemanticReviewCount = s.httpCalls, s.reviewCalls, s.reviews\n\tm.HTTPBudget = max(cyberDenyHTTPBudget, s.httpBudget)\n\tm.ReviewBudget = max(maxAuditSemanticCalls, s.reviewBudget)')
change('internal/platform/types.go','AuditChunksCompleted','AuditHTTPBudget int `json:"audit_http_budget"`\n\tAuditReviewBudget int `json:"audit_review_budget"`\n\tAuditChunksCompleted')
change('internal/platform/audit.go','result.AuditHTTPCalls = failoverMetadata.HTTPCalls','result.AuditHTTPCalls = failoverMetadata.HTTPCalls\n\tresult.AuditHTTPBudget = failoverMetadata.HTTPBudget\n\tresult.AuditReviewBudget = failoverMetadata.ReviewBudget')
change('internal/platform/audit_recovery.go','metadata["audit_http_calls"] = result.AuditHTTPCalls','metadata["audit_http_calls"] = result.AuditHTTPCalls\n\tmetadata["audit_http_budget"] = result.AuditHTTPBudget\n\tmetadata["audit_review_budget"] = result.AuditReviewBudget')
change('scripts/collect-audit-diagnostics.py','"audit_http_calls",','"audit_http_calls", "audit_http_budget", "audit_review_budget",')
change('cmd/mockprovider/accuracy.go','control := messageText(request)','control := messageText(request)\n\tif strings.Contains(text, "db-sync-mechanism") {\n\t\tmockDBSyncVerification(w, text, control)\n\t\treturn true\n\t}')
change('scripts/e2e.sh','echo "New API risk platform end-to-end checks passed."','BASE_URL="${BASE_URL}" RISK_ADMIN_TOKEN="${TOKEN}" ROUTE_KEY="${ROUTE_KEY}" python3 scripts/e2e-audit-db-sync.py\n\necho "New API risk platform end-to-end checks passed."')
p=root/'AGENTS.md';p.write_text('''# 数据库同步与已提供凭据（v7 / 2026-09-10）

区分使用现成登录凭据与提取/披露秘密，区分已有 sudo 管理与漏洞提权，区分数据库备份/同步/迁移与非法外传。root、密码字段或全量拉取不能单独证明禁用操作；测试/自有声明同样不能豁免真实禁用操作。仅符合有限弱证据形态的相关类别候选在终态锁定前进行一次校核，保留全部原送审数据/任务锚点，重复弱证据和失败仍拒绝。所有真实规则否决和有效操作拒绝保留。禁止无脑给 SSH/sudo/数据库设置请求白名单。

审计完成必须结合已完成分块计数，不得将输入可提取或提前阻断冒充全部分块审完。小请求保留64 HTTP/32复核基础预算；长请求按分块数分配有限余量，绝对上限256 HTTP/128复核，跨重试共享已花费调用，不变更120秒期限或并发。必须测试60分块双审计、超限故障关闭和中途取消。

'''+p.read_text())
p=root/'docs/database-sync-evidence-20260910.md';p.write_text('''# v7：数据库同步误判、分块预算和完成语义

基线 main `0b8d6a9d00c675610f0fa89bc275be45e675bd50` / v6。用户提供的是审计日志，不是完整711657字节原请求。本轮用测试库说明、已提供且遮蔽的连接凭据、全量或每表抽样同步重建事故；不包含真实公司名、数据库地址和密码。

## 判定

仅凭提供数据库连接密码并要求同步业务数据，不足以判定 `CYBER_CREDENTIAL_EXFIL`。密码用于认证，不等于请求取得/披露密码；业务数据库迁移不等于未授权外传。覆盖目标是应确认目标、备份及授权的执行风险，不伪造为网络攻击。完整历史仍审计，其他禁用操作仍可阻断。MySQL官方将跨服务器复制数据库列为备份/恢复场景：https://dev.mysql.com/doc/refman/8.0/en/mysqldump-copying-to-other-server.html 。本项目自己的严格禁用范围不是对OpenAI政策的定义。

## 修复

- 固定短六字段策略明确上述动作/对象区别，并同样区分已有sudo管理与漏洞提权。不启用旧全局工程、授权或凭据豁免。
- 相关凭据/外传/权限类别若只引用连接配置或普通同步描述，进入已有一次操作证据校核；检查整条包含证据的行及所有出现位置（最多32），不因正常首个匹配覆盖后面的操作。完整数据、任务锚点、双审计/Fusion否决保留。模型仍给弱依据、格式错误或超时则555审计故障；有效操作拒绝继续不可撤销。
- 证据显示脱敏会把送审的 USER_PROVIDED_SECRET 变成 REDACTED，造成形态校核找不到原引用。保留仅内存的已验证位置，核对显示脱敏结果后再定位；不序列化秘密或私有位置。
- 新增 `audit_chunks_completed`、`audit_http_budget`、`audit_review_budget`。`audit_completed` 要求最后一轮全部分块有有效决定；提前阻断仍 finalized，但不能声称所有分块完成。分块取消/失败不计作完成。
- 原60分块最少需120 HTTP/60复核，v6固定64/32不能完成正常审计。现在 n 个分块额外余量为 `2*min(n,16)`；HTTP预算 `min(256,max(64,2*n+余量))`，复核预算 `min(128,max(32,n+余量))`。60分块为152/92。预算只增不重置已花费次数，120秒期限和并发不变；更多分块或Fusion可仍耗尽预算，此时必须审计故障拒绝，不截断历史或少审放行。新增预算可能增加长请求最坏调用成本，需监测真实模型延迟。

## 验证

先在v6源码上新增事故回归，实际复现主审/复核误拒、有界校核未触发、提前阻断却标记完整、60块第64调用预算终止。修改后相同正常/禁用对照通过。新增HTTP/SSE测试使用可销毁Mock栈，故意制造模型误判，检查调用数、错误分类、上游访问和日志秘密脱敏。既有CI/E2E和部署/隐私测试保留，不删除安全断言来制造通过。

这些是机制回归，不是Qwen3.8-27B真实分类精度或本机GPU并发测试；未访问用户数据库、SSH或生产模型，没有执行同步/覆盖或线上升级。未展示历史的最终结果不能保证。此前无标签账号/密码脱敏属于不同格式缺口，本轮不宣称通用明文密码检测已解决。

## 部署

本次不新增数据库迁移。先备份，在既有项目根目录运行 `RESET_DATA=0 BACKUP_DATABASE=1 ALLOW_BRANCH_SWITCH=1 bash scripts/upgrade.sh main`。外置数据库需独立备份；核验健康及新请求中的真实commit和 `cyber-deny-qwen27b.v7`。不要删除数据卷。旧审计日志不会被重写。
''')
change('.github/workflows/ci.yml',"go test ./internal/platform -run '^$' -fuzz '^FuzzAuditOutputDecode$' -fuzztime=10s -parallel=2","go test ./internal/platform -run '^$' -fuzz '^FuzzAuditOutputDecode$' -fuzztime=10s -parallel=2\n          go test ./internal/platform -run '^$' -fuzz '^FuzzDBSyncAdmissionBounded$' -fuzztime=5s -parallel=2")
subprocess.run(['gofmt','-w','cmd','internal'],check=True)
