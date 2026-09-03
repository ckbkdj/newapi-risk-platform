from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def replace_once(text: str, old: str, new: str, label: str) -> str:
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected one match, found {count}")
    return text.replace(old, new, 1)


# ---------------------------------------------------------------------------
# Gateway: correlate with NewAPI's native request ID, expose body admission,
# and record exactly whether audit/upstream started.
# ---------------------------------------------------------------------------
gateway_path = ROOT / "internal/platform/gateway.go"
gateway = gateway_path.read_text(encoding="utf-8")
gateway = replace_once(
    gateway,
    "\tstartedAt := started.UTC()\n"
    "\tinboundRequestID := normalizeRequestID(r.Header.Get(\"X-Request-ID\"))\n"
    "\trequestID := inboundRequestID\n"
    "\trequestIDSource := \"x_request_id\"\n"
    "\tif requestID == \"\" {\n"
    "\t\trequestID = NewRequestID()\n"
    "\t\trequestIDSource = \"generated\"\n"
    "\t}\n",
    "\tstartedAt := started.UTC()\n"
    "\txRequestID := normalizeRequestID(r.Header.Get(\"X-Request-ID\"))\n"
    "\toneAPIRequestID := normalizeRequestID(r.Header.Get(\"X-Oneapi-Request-Id\"))\n"
    "\tinboundRequestID := firstNonEmpty(xRequestID, oneAPIRequestID)\n"
    "\trequestID := inboundRequestID\n"
    "\trequestIDSource := \"x_request_id\"\n"
    "\tif xRequestID == \"\" && oneAPIRequestID != \"\" {\n"
    "\t\trequestIDSource = \"x_oneapi_request_id\"\n"
    "\t}\n"
    "\tif requestID == \"\" {\n"
    "\t\trequestID = NewRequestID()\n"
    "\t\trequestIDSource = \"generated\"\n"
    "\t}\n",
    "gateway NewAPI request ID selection",
)
gateway = gateway.replace(
    '\tw.Header().Set("X-Risk-Request-ID", requestID)\n',
    '\tw.Header().Set("X-Risk-Request-ID", requestID)\n\tw.Header().Set("X-Oneapi-Request-Id", requestID)\n',
)
gateway = replace_once(
    gateway,
    "\t\tNewAPIRequestID: firstNonEmpty(normalizeRequestID(r.Header.Get(\"X-NewAPI-Request-ID\")), inboundRequestID),\n",
    "\t\tNewAPIRequestID: firstNonEmpty(normalizeRequestID(r.Header.Get(\"X-NewAPI-Request-ID\")), oneAPIRequestID, inboundRequestID),\n",
    "gateway NewAPI trace request ID",
)
gateway = replace_once(
    gateway,
    "\t\tMetadata: map[string]any{\n"
    "\t\t\t\"request_id_source\":  requestIDSource,\n"
    "\t\t\t\"gateway_started_at\": startedAt.Format(time.RFC3339Nano),\n"
    "\t\t},\n",
    "\t\tMetadata: map[string]any{\n"
    "\t\t\t\"request_id_source\":  requestIDSource,\n"
    "\t\t\t\"gateway_started_at\": startedAt.Format(time.RFC3339Nano),\n"
    "\t\t\t\"audit_started\":      false,\n"
    "\t\t\t\"upstream_started\":   false,\n"
    "\t\t},\n",
    "gateway stage flags initialization",
)
gateway = replace_once(
    gateway,
    "\tif bodyPolicy.ConfiguredLimitBytes > 0 {\n"
    "\t\ttrace.Metadata[\"request_body_configured_limit_bytes\"] = bodyPolicy.ConfiguredLimitBytes\n"
    "\t}\n\n"
    "\t// In automatic mode",
    "\tif bodyPolicy.ConfiguredLimitBytes > 0 {\n"
    "\t\ttrace.Metadata[\"request_body_configured_limit_bytes\"] = bodyPolicy.ConfiguredLimitBytes\n"
    "\t}\n"
    "\tw.Header().Set(\"X-Risk-Request-Limit-Mode\", bodyPolicy.Mode)\n"
    "\tw.Header().Set(\"X-Risk-Request-Limit-Bytes\", fmt.Sprintf(\"%d\", bodyPolicy.EffectiveLimitBytes))\n"
    "\tw.Header().Set(\"X-Risk-Request-Hard-Limit-Bytes\", fmt.Sprintf(\"%d\", bodyPolicy.HardLimitBytes))\n\n"
    "\t// In automatic mode",
    "gateway body admission response headers",
)
gateway = replace_once(
    gateway,
    "\ttrace.Model = ExtractRequestedModel(body)\n\n"
    "\tauditResult := g.audit.Audit(r.Context(), route, body)\n",
    "\ttrace.Model = ExtractRequestedModel(body)\n\n"
    "\ttrace.Metadata[\"audit_started\"] = true\n"
    "\tauditResult := g.audit.Audit(r.Context(), route, body)\n",
    "gateway audit start flag",
)
gateway = replace_once(
    gateway,
    "\tupstreamStarted := time.Now()\n"
    "\tresponse, err := g.client.Do(upstreamRequest)\n",
    "\tupstreamStarted := time.Now()\n"
    "\ttrace.Metadata[\"upstream_started\"] = true\n"
    "\tresponse, err := g.client.Do(upstreamRequest)\n",
    "gateway upstream start flag",
)
gateway_path.write_text(gateway, encoding="utf-8")

# ---------------------------------------------------------------------------
# Runtime diagnostics and Web trace presentation.
# ---------------------------------------------------------------------------
admin_path = ROOT / "internal/platform/admin.go"
admin = admin_path.read_text(encoding="utf-8")
admin = replace_once(
    admin,
    "\t\t\"error_http_status\":          s.cfg.ErrorHTTPStatus,\n"
    "\t\t\"allow_private_upstreams\":    s.cfg.AllowPrivateUpstreams,\n",
    "\t\t\"error_http_status\":                   s.cfg.ErrorHTTPStatus,\n"
    "\t\t\"server_time\":                         time.Now().UTC(),\n"
    "\t\t\"request_body_limit_mode\":             map[bool]string{true: \"automatic\", false: \"configured\"}[s.cfg.RequestMaxBytes == 0],\n"
    "\t\t\"request_max_bytes\":                   s.cfg.RequestMaxBytes,\n"
    "\t\t\"request_hard_max_bytes\":              s.cfg.RequestHardMaxBytes,\n"
    "\t\t\"request_large_body_threshold_bytes\":  s.cfg.LargeRequestThresholdBytes,\n"
    "\t\t\"request_large_body_max_concurrency\":  s.cfg.LargeRequestMaxConcurrency,\n"
    "\t\t\"allow_private_upstreams\":             s.cfg.AllowPrivateUpstreams,\n",
    "runtime request body diagnostics",
)
admin_path.write_text(admin, encoding="utf-8")

web_path = ROOT / "internal/platform/web/index.html"
web = web_path.read_text(encoding="utf-8")
web = replace_once(
    web,
    "          const requestLimitSource=item.metadata?.limit_config==='REQUEST_MAX_BYTES'?`<span class=\"trace-error-class\">超限来源：Risk Gateway 入口 REQUEST_MAX_BYTES · 审计模型未调用 · 真实上游未调用</span>`:'';\n",
    "          const requestLimitSource=item.metadata?.failure_component==='request_body_guard'?`<span class=\"trace-error-class\">超限来源：Risk Gateway 入口 ${escapeHTML(item.metadata?.limit_config||'请求体门禁')} · 审计模型未调用 · 真实上游未调用</span>`:'';\n",
    "Web dynamic request limit source",
)
web = replace_once(
    web,
    "        $('trace-results-meta').textContent = `共 ${number(total)} 条 · 当前 ${number(start)}-${number(end)} · 时间口径：${basisLabel} · 浏览器时区：${browserTimeZone} · ${dateText(data.from)} 至 ${dateText(data.to)}`;\n",
    "        $('trace-results-meta').textContent = `共 ${number(total)} 条 · 当前 ${number(start)}-${number(end)} · 时间口径：${basisLabel} · 浏览器时区：${browserTimeZone} · 平台 UTC：${data.server_time||'-'} · ${dateText(data.from)} 至 ${dateText(data.to)}`;\n",
    "Web trace server time",
)
web = replace_once(
    web,
    "          ['请求开始时间',detailedDateText(traceStartedAt(item))], ['请求完成时间',detailedDateText(traceCompletedAt(item))], ['平台入库时间',detailedDateText(traceIngestedAt(item))],\n"
    "          ['浏览器时区',browserTimeZone], ['网关 Request ID',item.request_id], ['New API Request ID',item.newapi_request_id||'-'],\n",
    "          ['请求开始时间',detailedDateText(traceStartedAt(item))], ['请求完成时间',detailedDateText(traceCompletedAt(item))], ['平台入库时间',detailedDateText(traceIngestedAt(item))],\n"
    "          ['请求开始 UTC',traceStartedAt(item)||'-'], ['请求完成 UTC',traceCompletedAt(item)||'-'], ['平台入库 UTC',traceIngestedAt(item)||'-'],\n"
    "          ['浏览器时区',browserTimeZone], ['网关 Request ID',item.request_id], ['New API Request ID',item.newapi_request_id||'-'],\n",
    "Web trace raw UTC timeline",
)
web = replace_once(
    web,
    "          ['请求体大小',item.metadata?.request_body_bytes?`${item.metadata.request_body_size_exact===true?'':'至少 '}${byteText(item.metadata.request_body_bytes)}`:'-'], ['平台请求体上限',byteText(item.metadata?.request_body_limit_bytes)], ['超出请求体上限',item.metadata?.request_body_over_limit_bytes?`${item.metadata.request_body_size_exact===true?'':'至少 '}${byteText(item.metadata.request_body_over_limit_bytes)}`:'-'], ['请求体大小是否精确',item.metadata?.request_body_limit_bytes?(item.metadata.request_body_size_exact===true?'是（Content-Length）':'否（安全下界）'):'-'],\n",
    "          ['请求体大小',item.metadata?.request_body_bytes?`${item.metadata.request_body_size_exact===true?'':'至少 '}${byteText(item.metadata.request_body_bytes)}`:byteText(item.request_bytes)], ['请求体放行模式',item.metadata?.request_body_limit_mode||'-'], ['本次有效读取上限',byteText(item.metadata?.request_body_effective_limit_bytes||item.metadata?.request_body_limit_bytes)], ['硬安全上限',byteText(item.metadata?.request_body_hard_limit_bytes)],\n"
    "          ['平台请求体上限',byteText(item.metadata?.request_body_limit_bytes)], ['超出请求体上限',item.metadata?.request_body_over_limit_bytes?`${item.metadata.request_body_size_exact===true?'':'至少 '}${byteText(item.metadata.request_body_over_limit_bytes)}`:'-'], ['请求体大小是否精确',item.metadata?.request_body_limit_bytes?(item.metadata.request_body_size_exact===true?'是（Content-Length）':'否（安全下界）'):'-'], ['大请求内存槽',item.metadata?.large_request_slot?`是（最多 ${number(item.metadata?.large_request_max_concurrency||0)} 并发`:'否'],\n",
    "Web body admission detail fields",
)
# Correct the missing closing parenthesis in the human-readable memory slot.
web = web.replace("?`是（最多 ${number(item.metadata?.large_request_max_concurrency||0)} 并发`:'否'", "?`是（最多 ${number(item.metadata?.large_request_max_concurrency||0)} 并发）`:'否'", 1)
web = replace_once(
    web,
    "        const header = ['started_at','completed_at','ingested_at','created_at','request_id','newapi_request_id','external_event_id','external_user_id','tenant_id','source','route_slug','model','endpoint','decision','risk_code','reason'",
    "        const header = ['started_at','completed_at','ingested_at','created_at','request_id','newapi_request_id','external_event_id','external_user_id','tenant_id','source','route_slug','model','endpoint','decision','risk_code','reason','request_body_limit_mode','request_body_effective_limit_bytes','request_body_hard_limit_bytes','audit_input_scope','audit_intent_bytes','audit_ignored_context_bytes'",
    "Web CSV diagnostics header",
)
web = replace_once(
    web,
    "        const rows = state.traceItems.map(item => [item.started_at,item.completed_at,item.ingested_at,item.created_at,item.request_id,item.newapi_request_id,item.external_event_id,item.external_user_id,item.metadata?.tenant_id,item.source,item.route_slug,item.model,item.endpoint,item.decision,item.risk_code,traceReason(item),item.metadata?.audit_model_decision",
    "        const rows = state.traceItems.map(item => [item.started_at,item.completed_at,item.ingested_at,item.created_at,item.request_id,item.newapi_request_id,item.external_event_id,item.external_user_id,item.metadata?.tenant_id,item.source,item.route_slug,item.model,item.endpoint,item.decision,item.risk_code,traceReason(item),item.metadata?.request_body_limit_mode,item.metadata?.request_body_effective_limit_bytes,item.metadata?.request_body_hard_limit_bytes,item.metadata?.audit_input_scope,item.metadata?.audit_intent_bytes,item.metadata?.audit_ignored_context_bytes,item.metadata?.audit_model_decision",
    "Web CSV diagnostics rows",
)
web_path.write_text(web, encoding="utf-8")

# ---------------------------------------------------------------------------
# Production Kubernetes manifest parity.
# ---------------------------------------------------------------------------
k8s_path = ROOT / "deploy/kubernetes.yaml"
k8s = k8s_path.read_text(encoding="utf-8")
k8s = replace_once(
    k8s,
    "  REQUEST_MAX_BYTES: \"8388608\"\n"
    "  RESPONSE_INSPECT_MAX_BYTES: \"2097152\"\n"
    "  AUDIT_TEXT_MAX_BYTES: \"262144\"\n",
    "  REQUEST_MAX_BYTES: \"0\"\n"
    "  REQUEST_HARD_MAX_BYTES: \"67108864\"\n"
    "  REQUEST_LARGE_BODY_THRESHOLD_BYTES: \"8388608\"\n"
    "  REQUEST_LARGE_BODY_MAX_CONCURRENCY: \"4\"\n"
    "  RESPONSE_INSPECT_MAX_BYTES: \"2097152\"\n"
    "  AUDIT_TEXT_MAX_BYTES: \"8388608\"\n"
    "  AUDIT_OUTPUT_MAX_TOKENS: \"128\"\n"
    "  AUDIT_DISABLE_THINKING: \"true\"\n"
    "  AUDIT_LONG_CONTEXT_THRESHOLD_BYTES: \"131072\"\n"
    "  AUDIT_LONG_CONTEXT_TIMEOUT: 120s\n"
    "  AUDIT_CONTEXT_TARGET_TOKENS: \"0\"\n"
    "  AUDIT_FALLBACK_CHUNK_BYTES: \"196608\"\n"
    "  AUDIT_CHUNK_OVERLAP_BYTES: \"4096\"\n"
    "  AUDIT_CHUNK_CONCURRENCY: \"2\"\n"
    "  AUDIT_MAX_CHUNKS: \"64\"\n",
    "Kubernetes request and audit settings",
)
k8s_path.write_text(k8s, encoding="utf-8")

# ---------------------------------------------------------------------------
# OpenAPI timeline and native NewAPI request-ID documentation.
# ---------------------------------------------------------------------------
openapi_path = ROOT / "docs/openapi.yaml"
openapi = openapi_path.read_text(encoding="utf-8")
openapi = replace_once(
    openapi,
    "        - name: X-NewAPI-Request-ID\n"
    "          in: header\n"
    "          schema: {type: string, maxLength: 128}\n",
    "        - name: X-NewAPI-Request-ID\n"
    "          in: header\n"
    "          schema: {type: string, maxLength: 128}\n"
    "        - name: X-Oneapi-Request-Id\n"
    "          in: header\n"
    "          description: Native NewAPI request identifier when forwarded by the channel.\n"
    "          schema: {type: string, maxLength: 128}\n",
    "OpenAPI NewAPI request ID header",
)
openapi = replace_once(
    openapi,
    "        - {name: upstream_status, in: query, schema: {type: integer, minimum: 0, maximum: 999}}\n"
    "        - {name: from, in: query, schema: {type: string, format: date-time}}\n",
    "        - {name: upstream_status, in: query, schema: {type: integer, minimum: 0, maximum: 999}}\n"
    "        - {name: time_basis, in: query, description: Time column used for filtering and ordering. Defaults to request completion time to align with NewAPI logs., schema: {type: string, enum: [completed, started, ingested], default: completed}}\n"
    "        - {name: from, in: query, schema: {type: string, format: date-time}}\n",
    "OpenAPI trace time basis",
)
openapi = replace_once(
    openapi,
    "                required: [items, total, limit, offset, has_more, from, to, summary]\n",
    "                required: [items, total, limit, offset, has_more, from, to, time_basis, server_time, summary]\n",
    "OpenAPI trace response required timeline",
)
openapi = replace_once(
    openapi,
    "                  to: {type: string, format: date-time}\n"
    "                  summary:\n",
    "                  to: {type: string, format: date-time}\n"
    "                  time_basis: {type: string, enum: [completed, started, ingested]}\n"
    "                  server_time: {type: string, format: date-time}\n"
    "                  summary:\n",
    "OpenAPI trace response timeline properties",
)
openapi = replace_once(
    openapi,
    "        occurred_at: {type: string, format: date-time}\n"
    "        metadata:\n",
    "        started_at: {type: string, format: date-time}\n"
    "        completed_at: {type: string, format: date-time}\n"
    "        occurred_at: {type: string, format: date-time, description: Backward-compatible completion/event time.}\n"
    "        metadata:\n",
    "OpenAPI tracking event timeline fields",
)
openapi = replace_once(
    openapi,
    "            source: {type: string}\n"
    "            created_at: {type: string, format: date-time}\n",
    "            source: {type: string}\n"
    "            started_at: {type: string, format: date-time}\n"
    "            completed_at: {type: string, format: date-time}\n"
    "            ingested_at: {type: string, format: date-time}\n"
    "            created_at: {type: string, format: date-time, description: PostgreSQL partition timestamp.}\n",
    "OpenAPI trace timeline fields",
)
openapi_path.write_text(openapi, encoding="utf-8")

# ---------------------------------------------------------------------------
# E2E executes automatic admission, hard ceiling, stage flags, and NewAPI ID.
# ---------------------------------------------------------------------------
test_compose_path = ROOT / "docker-compose.test.yml"
test_compose = test_compose_path.read_text(encoding="utf-8")
test_compose = replace_once(
    test_compose,
    "      REQUEST_MAX_BYTES: \"65536\"\n",
    "      REQUEST_MAX_BYTES: \"0\"\n"
    "      REQUEST_HARD_MAX_BYTES: \"1048576\"\n"
    "      REQUEST_LARGE_BODY_THRESHOLD_BYTES: \"131072\"\n"
    "      REQUEST_LARGE_BODY_MAX_CONCURRENCY: \"2\"\n",
    "test automatic body settings",
)
test_compose_path.write_text(test_compose, encoding="utf-8")

e2e_path = ROOT / "scripts/e2e.sh"
e2e = e2e_path.read_text(encoding="utf-8")
e2e = replace_once(
    e2e,
    '    json.dump({"model":"normal","messages":[{"role":"user","content":"x" * 70000}]}, handle)\n',
    '    json.dump({"model":"normal","messages":[{"role":"user","content":"x" * 1100000}]}, handle)\n',
    "E2E hard ceiling body size",
)
e2e = replace_once(
    e2e,
    "contains \"${WORKDIR}/too-large.headers\" 'X-Risk-Request-Limit-Bytes: 65536'\n"
    "contains \"${WORKDIR}/too-large.headers\" 'X-Risk-Request-Size-Exact: true'\n\n",
    "contains \"${WORKDIR}/too-large.headers\" 'X-Risk-Request-Limit-Bytes: 1048576'\n"
    "contains \"${WORKDIR}/too-large.headers\" 'X-Risk-Request-Hard-Limit-Bytes: 1048576'\n"
    "contains \"${WORKDIR}/too-large.headers\" 'X-Risk-Request-Limit-Mode: auto_hard_ceiling'\n"
    "contains \"${WORKDIR}/too-large.headers\" 'X-Risk-Request-Size-Exact: true'\n\n"
    "python3 - \"${WORKDIR}/auto-large.json\" <<'PY'\n"
    "import json\n"
    "import sys\n"
    "with open(sys.argv[1], \"w\", encoding=\"utf-8\") as handle:\n"
    "    json.dump({\"model\":\"normal\",\"messages\":[{\"role\":\"user\",\"content\":\"Explain normal project build verification.\"}],\"padding\":\"x\" * 700000}, handle)\n"
    "PY\n"
    "status=\"$(curl --silent --show-error -D \"${WORKDIR}/auto-large.headers\" -o \"${WORKDIR}/auto-large-response.json\" -w '%{http_code}' \\\n"
    "  \"${gateway}\" \"${gateway_auth[@]}\" \\\n"
    "  -H 'X-Oneapi-Request-Id: e2e-newapi-auto-large' \\\n"
    "  --data-binary @\"${WORKDIR}/auto-large.json\")\"\n"
    "assert_status 200 \"${status}\" \"${WORKDIR}/auto-large-response.json\"\n"
    "contains \"${WORKDIR}/auto-large-response.json\" 'mock provider success'\n"
    "contains \"${WORKDIR}/auto-large.headers\" 'X-Risk-Request-Limit-Mode: auto_actual_size'\n"
    "contains \"${WORKDIR}/auto-large.headers\" 'X-Risk-Request-Hard-Limit-Bytes: 1048576'\n"
    "contains \"${WORKDIR}/auto-large.headers\" 'X-Oneapi-Request-Id: e2e-newapi-auto-large'\n\n",
    "E2E automatic actual-size request",
)
e2e = replace_once(
    e2e,
    "     grep -Fq 'e2e-system-context-allow' \"${WORKDIR}/traces.json\" && \\\n",
    "     grep -Fq 'e2e-system-context-allow' \"${WORKDIR}/traces.json\" && \\\n"
    "     grep -Fq 'e2e-newapi-auto-large' \"${WORKDIR}/traces.json\" && \\\n",
    "E2E wait for automatic large request trace",
)
e2e = replace_once(
    e2e,
    "if int(metadata.get(\"request_body_limit_bytes\", 0)) != 65536:\n"
    "    raise RuntimeError(f\"oversized request limit missing: {metadata}\")\n",
    "if int(metadata.get(\"request_body_limit_bytes\", 0)) != 1048576:\n"
    "    raise RuntimeError(f\"oversized request hard limit missing: {metadata}\")\n"
    "if metadata.get(\"request_body_limit_mode\") != \"auto_hard_ceiling\" or metadata.get(\"limit_config\") != \"REQUEST_HARD_MAX_BYTES\":\n"
    "    raise RuntimeError(f\"oversized request source/mode missing: {metadata}\")\n",
    "E2E hard limit trace assertion",
)
e2e = replace_once(
    e2e,
    "if metadata.get(\"request_body_size_exact\") is not True:\n"
    "    raise RuntimeError(f\"Content-Length request should have exact size: {metadata}\")\n\n"
    "rule_item = next",
    "if metadata.get(\"request_body_size_exact\") is not True:\n"
    "    raise RuntimeError(f\"Content-Length request should have exact size: {metadata}\")\n"
    "if metadata.get(\"audit_started\") is not False or metadata.get(\"upstream_started\") is not False:\n"
    "    raise RuntimeError(f\"oversized request incorrectly reached audit/upstream: {metadata}\")\n\n"
    "auto_large = next((item for item in items if item.get(\"request_id\") == \"e2e-newapi-auto-large\"), None)\n"
    "if not auto_large:\n"
    "    raise RuntimeError(\"automatic actual-size request trace is missing\")\n"
    "alm = auto_large.get(\"metadata\", {})\n"
    "if auto_large.get(\"decision\") != \"allow\" or int(auto_large.get(\"http_status\", 0)) != 200:\n"
    "    raise RuntimeError(f\"automatic actual-size request was not allowed: {auto_large}\")\n"
    "if auto_large.get(\"newapi_request_id\") != \"e2e-newapi-auto-large\" or alm.get(\"request_id_source\") != \"x_oneapi_request_id\":\n"
    "    raise RuntimeError(f\"native NewAPI request ID correlation missing: {auto_large}\")\n"
    "if alm.get(\"request_body_limit_mode\") != \"auto_actual_size\" or int(alm.get(\"request_body_effective_limit_bytes\", 0)) <= 131072:\n"
    "    raise RuntimeError(f\"automatic request body admission metadata missing: {alm}\")\n"
    "if alm.get(\"large_request_slot\") is not True or alm.get(\"audit_started\") is not True or alm.get(\"upstream_started\") is not True:\n"
    "    raise RuntimeError(f\"large request stage diagnostics missing: {alm}\")\n\n"
    "rule_item = next",
    "E2E automatic large request trace assertions",
)
e2e_path.write_text(e2e, encoding="utf-8")

# Extend the implementation guide with native NewAPI correlation.
doc_path = ROOT / "docs/automatic-body-timeline-and-role-aware-audit.md"
doc = doc_path.read_text(encoding="utf-8")
doc += "\n## NewAPI 请求关联\n\nRisk Gateway 识别 `X-NewAPI-Request-ID`、`X-Oneapi-Request-Id` 和 `X-Request-ID`。响应同时返回 `X-Risk-Request-ID` 与 `X-Oneapi-Request-Id`，使 NewAPI 可以把风控 Request ID 记录为 upstream request ID。页面默认按完成时间展示，并同时提供开始、完成、入库三种时间。\n"
doc_path.write_text(doc, encoding="utf-8")

print("final request correlation and deployment parity patch applied")
