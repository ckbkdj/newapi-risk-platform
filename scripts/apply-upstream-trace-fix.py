from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def replace_once(path: Path, old: str, new: str, label: str) -> None:
    text = path.read_text(encoding="utf-8")
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected exactly one match, found {count}")
    path.write_text(text.replace(old, new, 1), encoding="utf-8")


# ---------------------------------------------------------------------------
# Failure reason precedence: audit_reason only explains AUDIT_/CYBER failures.
# It must never mask a later upstream or client failure.
# ---------------------------------------------------------------------------
diag = ROOT / "internal/platform/audit_diagnostics.go"
replace_once(
    diag,
    '''func traceFailureReason(riskCode string, upstreamStatus int, metadata map[string]any) string {
\tif metadata != nil {
\t\tif reason, ok := metadata["audit_reason"].(string); ok && strings.TrimSpace(reason) != "" {
\t\t\treturn truncateString(reason, auditDiagnosticTextLimit)
\t\t}
\t\tif reason, ok := metadata["error_reason"].(string); ok && strings.TrimSpace(reason) != "" {
\t\t\treturn truncateString(reason, auditDiagnosticTextLimit)
\t\t}
\t}
''',
    '''func traceFailureReason(riskCode string, upstreamStatus int, metadata map[string]any) string {
\tif metadata != nil {
\t\t// Explicit stage-specific diagnostics always win. REQUEST_TOO_LARGE and
\t\t// body-read paths may populate this before finish() runs.
\t\tif reason, ok := metadata["error_reason"].(string); ok && strings.TrimSpace(reason) != "" {
\t\t\treturn truncateString(reason, auditDiagnosticTextLimit)
\t\t}
\t\t// An audit reason describes only the audit stage. A benign audit result
\t\t// must never become the final error reason when the real failure happens
\t\t// later in the upstream/SSE path.
\t\tif strings.HasPrefix(riskCode, "AUDIT_") || strings.HasPrefix(riskCode, "CYBER_") {
\t\t\tif reason, ok := metadata["audit_reason"].(string); ok && strings.TrimSpace(reason) != "" {
\t\t\t\treturn truncateString(reason, auditDiagnosticTextLimit)
\t\t\t}
\t\t}
\t\tif reason, ok := metadata["upstream_error_reason"].(string); ok && strings.TrimSpace(reason) != "" {
\t\t\treturn truncateString(reason, auditDiagnosticTextLimit)
\t\t}
\t}
''',
    "trace failure reason precedence",
)
replace_once(
    diag,
    '''\tcase "UPSTREAM_STREAM_ERROR":
\t\treturn "真实上游流式响应中断或返回错误事件"
\t}
''',
    '''\tcase "UPSTREAM_STREAM_ERROR":
\t\treturn "真实上游流式响应返回错误事件"
\tcase "UPSTREAM_STREAM_INTERRUPTED":
\t\treturn "真实上游流式连接在完成前中断"
\tcase "UPSTREAM_READ_ERROR":
\t\treturn "读取真实上游响应失败"
\tcase "CLIENT_DISCONNECT":
\t\treturn "客户端在响应传输完成前断开连接"
\t}
''',
    "stream failure reason cases",
)

# ---------------------------------------------------------------------------
# Gateway: preserve the exact final failure stage and sanitized upstream detail.
# ---------------------------------------------------------------------------
gateway = ROOT / "internal/platform/gateway.go"
replace_once(
    gateway,
    '''\tresponse, err := g.client.Do(upstreamRequest)
\tif err != nil {
\t\triskCode := "UPSTREAM_CONNECTION_ERROR"
\t\tif errors.Is(err, context.DeadlineExceeded) || errors.Is(requestContext.Err(), context.DeadlineExceeded) {
\t\t\triskCode = "UPSTREAM_TIMEOUT"
\t\t}
\t\ttrace.Metadata["error_class"] = riskCode
''',
    '''\tresponse, err := g.client.Do(upstreamRequest)
\tif err != nil {
\t\triskCode := "UPSTREAM_CONNECTION_ERROR"
\t\tif errors.Is(err, context.DeadlineExceeded) || errors.Is(requestContext.Err(), context.DeadlineExceeded) {
\t\t\triskCode = "UPSTREAM_TIMEOUT"
\t\t}
\t\ttrace.Metadata["failure_stage"] = "upstream_connect"
\t\ttrace.Metadata["error_class"] = riskCode
''',
    "upstream connect failure stage",
)
replace_once(
    gateway,
    '''\t\ttrace.Metadata["error_class"] = "upstream_http_error"
\t\tfinish("error", "UPSTREAM_MODEL_ERROR", g.cfg.ErrorHTTPStatus, response.StatusCode, 0)
''',
    '''\t\ttrace.Metadata["error_class"] = "upstream_http_error"
\t\trecordUpstreamFailureMetadata(&trace, "UPSTREAM_MODEL_ERROR", response.StatusCode, failureBody, "upstream_http")
\t\tfinish("error", "UPSTREAM_MODEL_ERROR", g.cfg.ErrorHTTPStatus, response.StatusCode, 0)
''',
    "upstream HTTP detail",
)
replace_once(
    gateway,
    '''\tif strings.Contains(strings.ToLower(response.Header.Get("Content-Type")), "text/event-stream") {
\t\tbytesWritten, riskCode, status, failureEvidence := g.proxySSE(w, response, requestID)
\t\tif riskCode != "" {
\t\t\tif riskCode == "UPSTREAM_STREAM_ERROR" {
\t\t\t\tg.audit.ObserveUpstreamFailure(route, requestID, clientIdentity, body, response.StatusCode, riskCode, failureEvidence)
\t\t\t}
\t\t\ttrace.Metadata["stream_error_semantics"] = "logical_555_after_headers"
\t\t\tfinish("error", riskCode, status, response.StatusCode, bytesWritten)
\t\t\treturn
\t\t}
\t\tfinish(DecisionAllow, "", status, response.StatusCode, bytesWritten)
\t\treturn
\t}
''',
    '''\tif strings.Contains(strings.ToLower(response.Header.Get("Content-Type")), "text/event-stream") {
\t\tbytesWritten, riskCode, status, failureEvidence, streamCommitted := g.proxySSE(w, response, requestID)
\t\tif riskCode != "" {
\t\t\tif riskCode == "UPSTREAM_STREAM_ERROR" {
\t\t\t\tg.audit.ObserveUpstreamFailure(route, requestID, clientIdentity, body, response.StatusCode, riskCode, failureEvidence)
\t\t\t}
\t\t\tstage := "upstream_stream"
\t\t\tif riskCode == "CLIENT_DISCONNECT" {
\t\t\t\tstage = "client_disconnect"
\t\t\t}
\t\t\trecordUpstreamFailureMetadata(&trace, riskCode, response.StatusCode, failureEvidence, stage)
\t\t\tif streamCommitted && (riskCode == "UPSTREAM_STREAM_ERROR" || riskCode == "UPSTREAM_STREAM_INTERRUPTED") {
\t\t\t\ttrace.Metadata["stream_error_semantics"] = "logical_555_after_headers"
\t\t\t}
\t\t\tfinish("error", riskCode, status, response.StatusCode, bytesWritten)
\t\t\treturn
\t\t}
\t\tfinish(DecisionAllow, "", status, response.StatusCode, bytesWritten)
\t\treturn
\t}
''',
    "SSE failure stage",
)
replace_once(
    gateway,
    '''\tbytesWritten, riskCode, status, failureEvidence := g.proxyBuffered(w, response, requestID)
\tif riskCode != "" {
\t\tif riskCode == "UPSTREAM_MODEL_ERROR" {
\t\t\tg.audit.ObserveUpstreamFailure(route, requestID, clientIdentity, body, response.StatusCode, riskCode, failureEvidence)
\t\t}
\t\tfinish("error", riskCode, status, response.StatusCode, bytesWritten)
''',
    '''\tbytesWritten, riskCode, status, failureEvidence := g.proxyBuffered(w, response, requestID)
\tif riskCode != "" {
\t\tif riskCode == "UPSTREAM_MODEL_ERROR" {
\t\t\tg.audit.ObserveUpstreamFailure(route, requestID, clientIdentity, body, response.StatusCode, riskCode, failureEvidence)
\t\t}
\t\tstage := "upstream_response"
\t\tif riskCode == "CLIENT_DISCONNECT" {
\t\t\tstage = "client_disconnect"
\t\t}
\t\trecordUpstreamFailureMetadata(&trace, riskCode, response.StatusCode, failureEvidence, stage)
\t\tfinish("error", riskCode, status, response.StatusCode, bytesWritten)
''',
    "buffered upstream failure stage",
)
replace_once(
    gateway,
    '''func (g *Gateway) proxySSE(
\tw http.ResponseWriter,
\tresponse *http.Response,
\trequestID string,
) (int64, string, int, []byte) {
''',
    '''func (g *Gateway) proxySSE(
\tw http.ResponseWriter,
\tresponse *http.Response,
\trequestID string,
) (int64, string, int, []byte, bool) {
''',
    "proxySSE signature",
)
# Before headers are committed.
for old, new, label in [
    ('return 0, "UPSTREAM_STREAM_ERROR", g.cfg.ErrorHTTPStatus, nil', 'return 0, "UPSTREAM_STREAM_ERROR", g.cfg.ErrorHTTPStatus, nil, false', 'pre-header stream read'),
    ('return 0, "UPSTREAM_STREAM_ERROR", g.cfg.ErrorHTTPStatus, sseEventEvidence(event)', 'return 0, "UPSTREAM_STREAM_ERROR", g.cfg.ErrorHTTPStatus, sseEventEvidence(event), false', 'pre-header stream event'),
]:
    replace_once(gateway, old, new, label)
# Every return below w.WriteHeader has committed the SSE response.
for old, new, label in [
    ('return total, "CLIENT_DISCONNECT", response.StatusCode, nil', 'return total, "CLIENT_DISCONNECT", response.StatusCode, nil, true', 'buffered client disconnect'),
    ('return total, "UPSTREAM_STREAM_INTERRUPTED", response.StatusCode, nil', 'return total, "UPSTREAM_STREAM_INTERRUPTED", response.StatusCode, nil, true', 'stream interrupted'),
    ('return total, "UPSTREAM_STREAM_ERROR", response.StatusCode, sseEventEvidence(event)', 'return total, "UPSTREAM_STREAM_ERROR", response.StatusCode, sseEventEvidence(event), true', 'late stream event'),
    ('return total, "", response.StatusCode, nil', 'return total, "", response.StatusCode, nil, true', 'stream success'),
]:
    # CLIENT_DISCONNECT appears twice after commit; replace all of those explicitly.
    text = gateway.read_text(encoding="utf-8")
    if label == 'buffered client disconnect':
        count = text.count(old)
        if count != 2:
            raise SystemExit(f"{label}: expected two matches, found {count}")
        gateway.write_text(text.replace(old, new), encoding="utf-8")
    else:
        replace_once(gateway, old, new, label)

# ---------------------------------------------------------------------------
# Web: for non-allow results, the final error reason must beat benign audit_reason.
# Also expose the final failure stage and upstream diagnostic separately.
# ---------------------------------------------------------------------------
web = ROOT / "internal/platform/web/index.html"
replace_once(
    web,
    '''      function traceReason(item) {
        const metadata=item.metadata||{};
        if(metadata.audit_reason)return String(metadata.audit_reason);
        if(metadata.error_reason)return String(metadata.error_reason);
        if(item.decision==='allow')return '正常放行';
''',
    '''      function traceReason(item) {
        const metadata=item.metadata||{};
        if(item.decision!=='allow'&&metadata.error_reason)return String(metadata.error_reason);
        if(metadata.audit_reason)return String(metadata.audit_reason);
        if(metadata.error_reason)return String(metadata.error_reason);
        if(item.decision==='allow')return '正常放行';
''',
    "web trace reason precedence",
)
replace_once(
    web,
    '''          ['问题原因',traceReason(item)], ['审计错误分类',item.metadata?.audit_error_class||'-'], ['审计模型 HTTP',item.metadata?.audit_http_status||'-'],
          ['HTTP 状态',item.http_status||'-'], ['上游状态',item.upstream_status||'-'], ['总延迟',`${number(item.latency_ms)} ms`],
''',
    '''          ['问题原因',traceReason(item)], ['最终失败阶段',item.metadata?.failure_stage||'-'], ['上游错误原因',item.metadata?.upstream_error_reason||'-'],
          ['审计阶段',(item.metadata?.audit_attempts||[]).length?((item.metadata.audit_attempts[item.metadata.audit_attempts.length-1]?.success===true)?'成功':'失败'):'-'], ['审计错误分类',item.metadata?.audit_error_class||'-'], ['审计模型 HTTP',item.metadata?.audit_http_status||'-'],
          ['HTTP 状态',item.http_status||'-'], ['上游状态',item.upstream_status||'-'], ['总延迟',`${number(item.latency_ms)} ms`],
''',
    "web trace failure fields",
)

# ---------------------------------------------------------------------------
# E2E: give stream cases stable request IDs and verify the trace semantics.
# ---------------------------------------------------------------------------
e2e = ROOT / "scripts/e2e.sh"
replace_once(
    e2e,
    '''  "${gateway}" "${gateway_auth[@]}" \\
  --data-binary '{"model":"stream-late-error","stream":true,"messages":[{"role":"user","content":"safe stream request"}]}' )'''.replace("}' )", "}'"),
    '''  "${gateway}" "${gateway_auth[@]}" \\
  -H 'X-Request-ID: e2e-stream-late' \\
  --data-binary '{"model":"stream-late-error","stream":true,"messages":[{"role":"user","content":"safe stream request"}]}' ''',
    "late stream request id",
)
replace_once(
    e2e,
    '''  "${gateway}" "${gateway_auth[@]}" \\
  --data-binary '{"model":"stream-normal","stream":true,"messages":[{"role":"user","content":"safe normal stream request"}]}' ''',
    '''  "${gateway}" "${gateway_auth[@]}" \\
  -H 'X-Request-ID: e2e-stream-normal' \\
  --data-binary '{"model":"stream-normal","stream":true,"messages":[{"role":"user","content":"safe normal stream request"}]}' ''',
    "normal stream request id",
)
replace_once(
    e2e,
    '''attempts = fm.get("audit_attempts", [])
if len(attempts) != 6 or not attempts[-1].get("success"):
    raise RuntimeError(f"attempt diagnostics missing: {attempts}")
PY
''',
    '''attempts = fm.get("audit_attempts", [])
if len(attempts) != 6 or not attempts[-1].get("success"):
    raise RuntimeError(f"attempt diagnostics missing: {attempts}")

stream_late = next((item for item in items if item.get("request_id") == "e2e-stream-late"), None)
if not stream_late:
    raise RuntimeError("late-stream trace missing")
sm = stream_late.get("metadata", {})
if sm.get("failure_stage") != "upstream_stream":
    raise RuntimeError(f"late-stream failure stage is wrong: {sm}")
if sm.get("upstream_error_reason") != "late stream failure":
    raise RuntimeError(f"late-stream upstream reason missing: {sm}")
if sm.get("error_reason") != "late stream failure":
    raise RuntimeError(f"final error reason was contaminated by benign audit reason: {sm}")
if sm.get("audit_reason") == sm.get("error_reason"):
    raise RuntimeError(f"benign audit reason incorrectly became final stream error: {sm}")
if sm.get("stream_error_semantics") != "logical_555_after_headers":
    raise RuntimeError(f"late-stream logical 555 semantics missing: {sm}")

stream_normal = next((item for item in items if item.get("request_id") == "e2e-stream-normal"), None)
if not stream_normal:
    raise RuntimeError("normal-stream trace missing")
nm = stream_normal.get("metadata", {})
if nm.get("error_reason") or nm.get("failure_stage") or nm.get("stream_error_semantics"):
    raise RuntimeError(f"normal stream was polluted with failure diagnostics: {nm}")
PY
''',
    "stream trace assertions",
)

print("upstream trace fix applied")
