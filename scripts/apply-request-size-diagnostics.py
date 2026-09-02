from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

def replace_once(path: str, old: str, new: str, label: str) -> None:
    p = ROOT / path
    text = p.read_text(encoding="utf-8")
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected one match in {path}, found {count}")
    p.write_text(text.replace(old, new, 1), encoding="utf-8")

# ---------------------------------------------------------------------------
# Remove the fixed 260K platform target. 0 means derive the usable target from
# the model's actual context-length response; explicit non-zero overrides remain
# supported for operators who need them.
# ---------------------------------------------------------------------------
replace_once(
    "internal/platform/config.go",
    'AuditContextTargetTokens:       envInt("AUDIT_CONTEXT_TARGET_TOKENS", envInt("AUDIT_PROMPT_TRUNCATE_TOKENS", 260000)),',
    'AuditContextTargetTokens:       envInt("AUDIT_CONTEXT_TARGET_TOKENS", 0),',
    "automatic context target default",
)
replace_once(
    "internal/platform/config.go",
    'if c.AuditContextTargetTokens < 1024 || c.AuditContextTargetTokens > 1000000 {\n\t\tproblems = append(problems, "AUDIT_CONTEXT_TARGET_TOKENS must be between 1024 and 1000000")\n\t}',
    'if c.AuditContextTargetTokens != 0 && (c.AuditContextTargetTokens < 1024 || c.AuditContextTargetTokens > 1000000) {\n\t\tproblems = append(problems, "AUDIT_CONTEXT_TARGET_TOKENS must be 0 for automatic model-derived sizing or between 1024 and 1000000")\n\t}',
    "automatic context target validation",
)

# Existing .env installations created by the previous release normally contain
# exactly 260000. Migrate only that historical default; preserve custom values.
replace_once(
    "scripts/init-env.sh",
    '"AUDIT_CONTEXT_TARGET_TOKENS": values.get("AUDIT_PROMPT_TRUNCATE_TOKENS", "260000"),',
    '"AUDIT_CONTEXT_TARGET_TOKENS": "0",',
    "init env automatic context target",
)
replace_once(
    "scripts/init-env.sh",
    '    if key == "AUDIT_TEXT_MAX_BYTES" and current in {"262144", "2097152"}:\n        should_set = True\n        warnings.append(\n            "AUDIT_TEXT_MAX_BYTES was upgraded to 8 MiB so the request layer can segment and audit the complete prompt."\n        )\n    if should_set:',
    '    if key == "AUDIT_TEXT_MAX_BYTES" and current in {"262144", "2097152"}:\n        should_set = True\n        warnings.append(\n            "AUDIT_TEXT_MAX_BYTES was upgraded to 8 MiB so the request layer can segment and audit the complete prompt."\n        )\n    if key == "AUDIT_CONTEXT_TARGET_TOKENS" and current == "260000":\n        should_set = True\n        warnings.append(\n            "AUDIT_CONTEXT_TARGET_TOKENS was changed from the historical fixed 260000 value to 0 (automatic model-derived sizing)."\n        )\n    if should_set:',
    "migrate historical 260K target",
)

replace_once(
    ".env.example",
    'AUDIT_CONTEXT_TARGET_TOKENS=260000',
    '# 0 = do not impose a platform token ceiling; use the audit model\'s reported context limit after an actual context-length error.\nAUDIT_CONTEXT_TARGET_TOKENS=0',
    "env example automatic context target",
)

# ---------------------------------------------------------------------------
# Gateway request-body diagnostics.
# ---------------------------------------------------------------------------
replace_once(
    "internal/platform/gateway.go",
    '''\tbodyReader := http.MaxBytesReader(w, r.Body, g.cfg.RequestMaxBytes)\n\tbody, err := io.ReadAll(bodyReader)\n\tif err != nil {\n\t\tfinish("error", "REQUEST_TOO_LARGE", g.cfg.ErrorHTTPStatus, 0, 0)\n\t\twriteRiskError(w, g.cfg.ErrorHTTPStatus, requestID, "REQUEST_TOO_LARGE", "request body exceeds the configured limit")\n\t\treturn\n\t}\n\ttrace.RequestBytes = int64(len(body))\n''',
    '''\t// If Content-Length is present we know the exact size before reading. This\n\t// avoids buffering an oversized body and lets the trace show the real value.\n\tif r.ContentLength > g.cfg.RequestMaxBytes {\n\t\treason := markRequestTooLarge(&trace, r.ContentLength, g.cfg.RequestMaxBytes, true)\n\t\tw.Header().Set("X-Risk-Request-Bytes", fmt.Sprintf("%d", trace.RequestBytes))\n\t\tw.Header().Set("X-Risk-Request-Limit-Bytes", fmt.Sprintf("%d", g.cfg.RequestMaxBytes))\n\t\tw.Header().Set("X-Risk-Request-Size-Exact", "true")\n\t\tfinish("error", "REQUEST_TOO_LARGE", g.cfg.ErrorHTTPStatus, 0, 0)\n\t\twriteRiskError(w, g.cfg.ErrorHTTPStatus, requestID, "REQUEST_TOO_LARGE", reason)\n\t\treturn\n\t}\n\n\tbodyReader := http.MaxBytesReader(w, r.Body, g.cfg.RequestMaxBytes)\n\tbody, err := io.ReadAll(bodyReader)\n\tif err != nil {\n\t\tvar maxBytesError *http.MaxBytesError\n\t\tif errors.As(err, &maxBytesError) {\n\t\t\t// Chunked/unknown-length requests cannot be read to EOF without\n\t\t\t// defeating the DoS limit. Record the strongest safe lower bound.\n\t\t\tobserved := g.cfg.RequestMaxBytes + 1\n\t\t\tif int64(len(body)) > observed {\n\t\t\t\tobserved = int64(len(body))\n\t\t\t}\n\t\t\treason := markRequestTooLarge(&trace, observed, g.cfg.RequestMaxBytes, false)\n\t\t\tw.Header().Set("X-Risk-Request-Bytes", fmt.Sprintf("%d", trace.RequestBytes))\n\t\t\tw.Header().Set("X-Risk-Request-Limit-Bytes", fmt.Sprintf("%d", g.cfg.RequestMaxBytes))\n\t\t\tw.Header().Set("X-Risk-Request-Size-Exact", "false")\n\t\t\tfinish("error", "REQUEST_TOO_LARGE", g.cfg.ErrorHTTPStatus, 0, 0)\n\t\t\twriteRiskError(w, g.cfg.ErrorHTTPStatus, requestID, "REQUEST_TOO_LARGE", reason)\n\t\t\treturn\n\t\t}\n\t\ttrace.RequestBytes = int64(len(body))\n\t\ttrace.Metadata["error_class"] = "request_body_read"\n\t\ttrace.Metadata["error_reason"] = truncateString("failed to read request body: "+err.Error(), auditDiagnosticTextLimit)\n\t\tfinish("error", "REQUEST_READ_ERROR", g.cfg.ErrorHTTPStatus, 0, 0)\n\t\twriteRiskError(w, g.cfg.ErrorHTTPStatus, requestID, "REQUEST_READ_ERROR", "gateway could not read the request body")\n\t\treturn\n\t}\n\ttrace.RequestBytes = int64(len(body))\n''',
    "gateway oversized request diagnostics",
)

# Add a helper next to the gateway request code. Keep it in gateway.go so the
# semantics stay close to the trace fields it populates.
replace_once(
    "internal/platform/gateway.go",
    '''func (g *Gateway) buildUpstreamRequest(\n''',
    '''func markRequestTooLarge(trace *TraceEvent, requestBytes int64, limitBytes int64, exact bool) string {\n\tif limitBytes < 1 {\n\t\tlimitBytes = 1\n\t}\n\tif requestBytes <= limitBytes {\n\t\trequestBytes = limitBytes + 1\n\t}\n\toverBytes := requestBytes - limitBytes\n\ttrace.RequestBytes = requestBytes\n\ttrace.Metadata["error_class"] = "request_body_too_large"\n\ttrace.Metadata["request_body_bytes"] = requestBytes\n\ttrace.Metadata["request_body_limit_bytes"] = limitBytes\n\ttrace.Metadata["request_body_over_limit_bytes"] = overBytes\n\ttrace.Metadata["request_body_size_exact"] = exact\n\n\tqualifier := ""\n\tif !exact {\n\t\tqualifier = "at least "\n\t}\n\treason := fmt.Sprintf(\n\t\t"request body is %s%d bytes; gateway limit is %d bytes; over limit by %s%d bytes",\n\t\tqualifier, requestBytes, limitBytes, qualifier, overBytes,\n\t)\n\ttrace.Metadata["error_reason"] = reason\n\treturn reason\n}\n\nfunc (g *Gateway) buildUpstreamRequest(\n''',
    "request size helper",
)

replace_once(
    "internal/platform/audit_diagnostics.go",
    '''\tcase "REQUEST_TOO_LARGE":\n\t\treturn "请求体超过网关限制"\n''',
    '''\tcase "REQUEST_TOO_LARGE":\n\t\treturn "请求体超过网关字节安全上限；查看请求体大小、平台上限和超出量"\n\tcase "REQUEST_READ_ERROR":\n\t\treturn "网关读取请求体失败"\n''',
    "trace reason request read/size",
)

# ---------------------------------------------------------------------------
# Admin UI: make byte-limit and token-limit diagnostics visible without opening
# raw metadata.
# ---------------------------------------------------------------------------
replace_once(
    "internal/platform/web/index.html",
    '''      const number = value => new Intl.NumberFormat().format(Number(value || 0));\n''',
    '''      const number = value => new Intl.NumberFormat().format(Number(value || 0));\n      const byteText = value => { const bytes=Number(value||0); if(!Number.isFinite(bytes)||bytes<=0)return '-'; if(bytes>=1024*1024)return `${number(bytes)} B (${(bytes/1024/1024).toFixed(2)} MiB)`; if(bytes>=1024)return `${number(bytes)} B (${(bytes/1024).toFixed(2)} KiB)`; return `${number(bytes)} B`; };\n      const requestBodyDiagnostic = item => { const metadata=item?.metadata||{}; const bytes=Number(metadata.request_body_bytes||item?.request_bytes||0); const limit=Number(metadata.request_body_limit_bytes||0); if(!limit)return ''; const over=Number(metadata.request_body_over_limit_bytes||Math.max(0,bytes-limit)); const exact=metadata.request_body_size_exact===true; return `${exact?'':'至少 '}${byteText(bytes)} / 上限 ${byteText(limit)} / 超出 ${exact?'':'至少 '}${byteText(over)}`; };\n''',
    "web byte helpers",
)
replace_once(
    "internal/platform/web/index.html",
    '''          const errorClass=item.metadata?.audit_error_class||'';\n          return `<tr><td><strong>${escapeHTML(detailedDateText(item.created_at))}</strong><span class="trace-subline">浏览器本地时间</span></td><td><span class="mono trace-request-id">${escapeHTML(item.request_id)}</span><span class="trace-subline mono">New API: ${escapeHTML(item.newapi_request_id||'-')}</span></td><td>${user}<span class="trace-subline">租户：${escapeHTML(tenant)}</span></td><td>${escapeHTML(item.source||'-')}<span class="trace-subline mono">${escapeHTML(item.route_slug||'-')}</span></td><td>${escapeHTML(item.model||'-')}<span class="trace-subline mono">${escapeHTML(item.endpoint||'-')}</span></td><td>${badge(item.decision||'unknown')}<span class="trace-subline mono">${escapeHTML(item.risk_code||'-')}</span></td><td><span class="trace-reason">${escapeHTML(reason)}</span>${errorClass?`<span class="trace-error-class">${escapeHTML(errorClass)}${item.metadata?.audit_http_status?` · HTTP ${escapeHTML(item.metadata.audit_http_status)}`:''}</span>`:''}</td><td>HTTP ${item.http_status||'-'} / 上游 ${item.upstream_status||'-'}<span class="trace-subline">总计 ${number(item.latency_ms)} ms · 审计 ${number(item.audit_latency_ms)} ms</span></td><td><button class="btn btn-small btn-secondary" type="button" data-trace-detail-index="${index}">详情</button></td></tr>`;\n''',
    '''          const errorClass=item.metadata?.audit_error_class||'';\n          const requestSize=requestBodyDiagnostic(item);\n          return `<tr><td><strong>${escapeHTML(detailedDateText(item.created_at))}</strong><span class="trace-subline">浏览器本地时间</span></td><td><span class="mono trace-request-id">${escapeHTML(item.request_id)}</span><span class="trace-subline mono">New API: ${escapeHTML(item.newapi_request_id||'-')}</span></td><td>${user}<span class="trace-subline">租户：${escapeHTML(tenant)}</span></td><td>${escapeHTML(item.source||'-')}<span class="trace-subline mono">${escapeHTML(item.route_slug||'-')}</span></td><td>${escapeHTML(item.model||'-')}<span class="trace-subline mono">${escapeHTML(item.endpoint||'-')}</span></td><td>${badge(item.decision||'unknown')}<span class="trace-subline mono">${escapeHTML(item.risk_code||'-')}</span></td><td><span class="trace-reason">${escapeHTML(reason)}</span>${requestSize?`<span class="trace-error-class">请求体：${escapeHTML(requestSize)}</span>`:''}${errorClass?`<span class="trace-error-class">${escapeHTML(errorClass)}${item.metadata?.audit_http_status?` · HTTP ${escapeHTML(item.metadata.audit_http_status)}`:''}</span>`:''}</td><td>HTTP ${item.http_status||'-'} / 上游 ${item.upstream_status||'-'}<span class="trace-subline">总计 ${number(item.latency_ms)} ms · 审计 ${number(item.audit_latency_ms)} ms</span></td><td><button class="btn btn-small btn-secondary" type="button" data-trace-detail-index="${index}">详情</button></td></tr>`;\n''',
    "trace table request size",
)
replace_once(
    "internal/platform/web/index.html",
    '''          ['审计延迟',`${number(item.audit_latency_ms)} ms`], ['请求字节',number(item.request_bytes)], ['响应字节',number(item.response_bytes)],\n          ['Prompt HMAC',item.prompt_hmac||'-']\n''',
    '''          ['审计延迟',`${number(item.audit_latency_ms)} ms`], ['请求字节',byteText(item.request_bytes)], ['响应字节',byteText(item.response_bytes)],\n          ['请求体大小',item.metadata?.request_body_bytes?`${item.metadata.request_body_size_exact===true?'':'至少 '}${byteText(item.metadata.request_body_bytes)}`:'-'],\n          ['平台请求体上限',byteText(item.metadata?.request_body_limit_bytes)], ['超出请求体上限',item.metadata?.request_body_over_limit_bytes?`${item.metadata.request_body_size_exact===true?'':'至少 '}${byteText(item.metadata.request_body_over_limit_bytes)}`:'-'],\n          ['请求体大小是否精确',item.metadata?.request_body_limit_bytes?(item.metadata.request_body_size_exact===true?'是（Content-Length）':'否（安全下界）'):'-'],\n          ['Prompt HMAC',item.prompt_hmac||'-']\n''',
    "trace detail request sizes",
)
replace_once(
    "internal/platform/web/index.html",
    '''        const header = ['created_at','request_id','newapi_request_id','external_event_id','external_user_id','tenant_id','source','route_slug','model','endpoint','decision','risk_code','reason','audit_error_class','audit_http_status','http_status','upstream_status','latency_ms','audit_latency_ms','request_bytes','response_bytes','prompt_hmac','metadata'];\n        const rows = state.traceItems.map(item => [item.created_at,item.request_id,item.newapi_request_id,item.external_event_id,item.external_user_id,item.metadata?.tenant_id,item.source,item.route_slug,item.model,item.endpoint,item.decision,item.risk_code,traceReason(item),item.metadata?.audit_error_class,item.metadata?.audit_http_status,item.http_status,item.upstream_status,item.latency_ms,item.audit_latency_ms,item.request_bytes,item.response_bytes,item.prompt_hmac,JSON.stringify(item.metadata||{})]);\n''',
    '''        const header = ['created_at','request_id','newapi_request_id','external_event_id','external_user_id','tenant_id','source','route_slug','model','endpoint','decision','risk_code','reason','audit_error_class','audit_http_status','http_status','upstream_status','latency_ms','audit_latency_ms','request_bytes','request_body_limit_bytes','request_body_over_limit_bytes','request_body_size_exact','response_bytes','prompt_hmac','metadata'];\n        const rows = state.traceItems.map(item => [item.created_at,item.request_id,item.newapi_request_id,item.external_event_id,item.external_user_id,item.metadata?.tenant_id,item.source,item.route_slug,item.model,item.endpoint,item.decision,item.risk_code,traceReason(item),item.metadata?.audit_error_class,item.metadata?.audit_http_status,item.http_status,item.upstream_status,item.latency_ms,item.audit_latency_ms,item.request_bytes,item.metadata?.request_body_limit_bytes,item.metadata?.request_body_over_limit_bytes,item.metadata?.request_body_size_exact,item.response_bytes,item.prompt_hmac,JSON.stringify(item.metadata||{})]);\n''',
    "trace csv request sizes",
)

# ---------------------------------------------------------------------------
# Docs: explain that Qwen's 260K is model configuration, not a risk-platform cap.
# ---------------------------------------------------------------------------
doc = ROOT / "docs/request-size-and-context-limits.md"
doc.write_text('''# 请求体大小与模型上下文限制\n\n平台现在区分两个完全不同的限制：\n\n1. `REQUEST_TOO_LARGE`：HTTP 请求体超过网关的字节安全上限 `REQUEST_MAX_BYTES`。这是防 DoS 限制，不是模型 token 限制。\n2. `AUDIT_CONTEXT_TOO_LARGE`：审计模型自己报告 prompt/input tokens 超过模型上下文。\n\n## REQUEST_TOO_LARGE\n\n如果客户端携带可靠 `Content-Length`，Trace 会记录精确：\n\n```text\nrequest_body_bytes\nrequest_body_limit_bytes\nrequest_body_over_limit_bytes\nrequest_body_size_exact=true\n```\n\n对于 HTTP chunked 或没有 Content-Length 的请求，为了不通过“读完整个超大请求”绕过防 DoS 上限，平台只读取到安全边界并记录：\n\n```text\nrequest_body_size_exact=false\nrequest_body_bytes=至少 REQUEST_MAX_BYTES+1\n```\n\nWeb 会明确显示“至少”，不会把下界伪装成精确大小。\n\n## 审计模型 Token 上下文\n\n`AUDIT_CONTEXT_TARGET_TOKENS=0` 为默认值，表示平台不设置固定 token 天花板。平台先发送完整审计请求；只有审计模型明确返回 context-length 错误后，才使用模型报告的最大上下文和实际 input tokens 动态计算重叠分段。\n\n例如 Qwen vLLM 使用：\n\n```text\n--max-model-len 260000\n```\n\n则 260,000 是这个 Qwen 实例的模型上下文上限，不是风控平台硬编码的限制。\n''', encoding="utf-8")

print("request-size diagnostics patch applied")
