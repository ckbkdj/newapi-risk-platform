from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def replace_once(path: Path, old: str, new: str, label: str) -> None:
    text = path.read_text(encoding="utf-8")
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected exactly one match, found {count}")
    path.write_text(text.replace(old, new, 1), encoding="utf-8")


# ---------------------------------------------------------------------------
# Public audit result fields. Values stored here have already been verified
# against request text and redacted by audit_model_evidence.go.
# ---------------------------------------------------------------------------
types = ROOT / "internal/platform/types.go"
replace_once(
    types,
    '''type AuditDecision struct {
\tDecision   string  `json:"decision"`
\tRiskCode   string  `json:"risk_code,omitempty"`
\tCategory   string  `json:"category,omitempty"`
\tConfidence float64 `json:"confidence"`
\tReason     string  `json:"reason,omitempty"`
\tSource     string  `json:"source"`
\tRuleID     int64   `json:"rule_id,omitempty"`
}
''',
    '''type AuditDecision struct {
\tDecision          string  `json:"decision"`
\tRiskCode          string  `json:"risk_code,omitempty"`
\tCategory          string  `json:"category,omitempty"`
\tConfidence        float64 `json:"confidence"`
\tReason            string  `json:"reason,omitempty"`
\tSource            string  `json:"source"`
\tRuleID            int64   `json:"rule_id,omitempty"`
\tEvidence          string  `json:"evidence,omitempty"`
\tEvidenceContext   string  `json:"evidence_context,omitempty"`
\tEvidenceVerified  bool    `json:"evidence_verified,omitempty"`
\tEvidenceMatchMode string  `json:"evidence_match_mode,omitempty"`
\tEvidenceChunkIndex int    `json:"evidence_chunk_index,omitempty"`
\tEvidenceChunkCount int    `json:"evidence_chunk_count,omitempty"`
}
''',
    "audit decision evidence fields",
)

# ---------------------------------------------------------------------------
# Model contract and evidence validation.
# ---------------------------------------------------------------------------
audit = ROOT / "internal/platform/audit.go"
replace_once(
    audit,
    '''operational capability against real systems or victims. Do not reveal chain-of-thought and do not emit <think>
blocks, Markdown, or explanatory prose. Return the final compact JSON object immediately. Keep reason under 120
characters:
{"decision":"allow|block|review","risk_code":"CYBER_* or empty","category":"...","confidence":0.0,"reason":"brief"}`''',
    '''operational capability against real systems or victims. Do not reveal chain-of-thought and do not emit <think>
blocks, Markdown, or explanatory prose. For block or review, evidence is mandatory and must be one exact contiguous
quote copied from the supplied request text, without ellipsis or paraphrase; keep it under 80 characters. For allow,
evidence must be empty. Return the final compact JSON object immediately. Keep reason under 120 characters:
{"decision":"allow|block|review","risk_code":"CYBER_* or empty","category":"...","confidence":0.0,"reason":"brief","evidence":"exact request quote or empty"}`''',
    "default audit evidence contract",
)
replace_once(
    audit,
    '''type modelAuditResponse struct {
\tDecision   string  `json:"decision"`
\tRiskCode   string  `json:"risk_code"`
\tCategory   string  `json:"category"`
\tConfidence float64 `json:"confidence"`
\tReason     string  `json:"reason"`
}
''',
    '''type modelAuditResponse struct {
\tDecision   string  `json:"decision"`
\tRiskCode   string  `json:"risk_code"`
\tCategory   string  `json:"category"`
\tConfidence float64 `json:"confidence"`
\tReason     string  `json:"reason"`
\tEvidence   string  `json:"evidence"`
}
''',
    "model response evidence field",
)
replace_once(
    audit,
    '''func (e *AuditEngine) callModelOnce(
\tctx context.Context,
\tprofile AuditProfile,
\ttext string,
) (AuditDecision, error) {
''',
    '''func (e *AuditEngine) callModelOnce(
\tctx context.Context,
\tprofile AuditProfile,
\ttext string,
) (AuditDecision, error) {
\treturn e.callModelOnceWithEvidenceSource(ctx, profile, text, text)
}

func (e *AuditEngine) callModelOnceWithEvidenceSource(
\tctx context.Context,
\tprofile AuditProfile,
\ttext string,
\tevidenceSource string,
) (AuditDecision, error) {
''',
    "evidence-aware model call wrapper",
)
replace_once(
    audit,
    '''\treturn AuditDecision{
\t\tDecision:   modelResult.Decision,
\t\tRiskCode:   strings.TrimSpace(modelResult.RiskCode),
\t\tCategory:   strings.TrimSpace(modelResult.Category),
\t\tConfidence: modelResult.Confidence,
\t\tReason:     modelResult.Reason,
\t\tSource:     "model",
\t}, nil
}
''',
    '''\tdecision := AuditDecision{
\t\tDecision:   modelResult.Decision,
\t\tRiskCode:   strings.TrimSpace(modelResult.RiskCode),
\t\tCategory:   strings.TrimSpace(modelResult.Category),
\t\tConfidence: modelResult.Confidence,
\t\tReason:     modelResult.Reason,
\t\tSource:     "model",
\t\tEvidence:   modelResult.Evidence,
\t}
\treturn validateAuditDecisionEvidence(decision, evidenceSource)
}
''',
    "validate model evidence before accepting decision",
)

# Mandatory guard applies even when the operator supplies a custom prompt.
fast = ROOT / "internal/platform/audit_fast_mode.go"
replace_once(
    fast,
    '''- Return one compact policy JSON object immediately.
- Keep the reason field under 120 characters.
- When a long request is split, classify only the supplied chunk and never assume other chunks are safe.`''',
    '''- Return one compact policy JSON object immediately.
- Keep the reason field under 120 characters.
- For block or review, evidence is mandatory: copy one exact contiguous quote from the request, under 80 characters, with no ellipsis or paraphrase.
- For allow, evidence must be an empty string.
- When a long request is split, classify only the supplied chunk and never assume other chunks are safe.`''',
    "mandatory model evidence directive",
)

# Validate chunk evidence against the raw request chunk, not the decoration
# header that the gateway adds for the model.
long_context = ROOT / "internal/platform/audit_long_context.go"
replace_once(
    long_context,
    '''\tif len(chunks) == 1 {
\t\treturn e.callModelOnce(ctx, profile, decorateAuditChunk(chunks[0], 0, 1))
\t}
''',
    '''\tif len(chunks) == 1 {
\t\treturn e.callModelOnceWithEvidenceSource(ctx, profile, decorateAuditChunk(chunks[0], 0, 1), chunks[0])
\t}
''',
    "single chunk evidence source",
)
replace_once(
    long_context,
    '''\t\t\t\t\tdecision, err := e.callModelOnce(
\t\t\t\t\t\tworkerContext,
\t\t\t\t\t\tprofile,
\t\t\t\t\t\tdecorateAuditChunk(chunks[index], index, len(chunks)),
\t\t\t\t\t)
''',
    '''\t\t\t\t\tdecision, err := e.callModelOnceWithEvidenceSource(
\t\t\t\t\t\tworkerContext,
\t\t\t\t\t\tprofile,
\t\t\t\t\t\tdecorateAuditChunk(chunks[index], index, len(chunks)),
\t\t\t\t\t\tchunks[index],
\t\t\t\t\t)
''',
    "parallel chunk evidence source",
)
replace_once(
    long_context,
    '''func decorateChunkDecision(decision AuditDecision, index int, total int) AuditDecision {
\tdecision.Source = "model_chunked"
\treason := strings.TrimSpace(decision.Reason)
''',
    '''func decorateChunkDecision(decision AuditDecision, index int, total int) AuditDecision {
\tdecision.Source = "model_chunked"
\tif decision.EvidenceVerified {
\t\tdecision.EvidenceChunkIndex = index + 1
\t\tdecision.EvidenceChunkCount = total
\t}
\treason := strings.TrimSpace(decision.Reason)
''',
    "chunk evidence location",
)

# A malformed/missing block quote is usually a transient model-format failure.
# Retry the same profile, then use the configured fallback chain.
failover = ROOT / "internal/platform/audit_failover.go"
replace_once(
    failover,
    '''\t\t"empty_response",
\t\t"invalid_json",
\t\t"invalid_decision":
''',
    '''\t\t"empty_response",
\t\t"invalid_json",
\t\t"invalid_decision",
\t\t"invalid_evidence":
''',
    "invalid evidence retry policy",
)

# ---------------------------------------------------------------------------
# Trace: persist final model decision and the verified/redacted trigger input.
# ---------------------------------------------------------------------------
gateway = ROOT / "internal/platform/gateway.go"
replace_once(
    gateway,
    '''\tif auditResult.Reason != "" {
\t\ttrace.Metadata["audit_reason"] = truncateString(auditResult.Reason, auditDiagnosticTextLimit)
\t}
\tif auditResult.ErrorClass != "" {
''',
    '''\tif auditResult.Reason != "" {
\t\ttrace.Metadata["audit_reason"] = truncateString(auditResult.Reason, auditDiagnosticTextLimit)
\t}
\tif strings.HasPrefix(auditResult.Source, "model") {
\t\ttrace.Metadata["audit_model_decision"] = auditResult.Decision
\t\ttrace.Metadata["audit_model_risk_code"] = auditResult.RiskCode
\t\ttrace.Metadata["audit_model_confidence"] = auditResult.Confidence
\t}
\tif auditResult.EvidenceVerified {
\t\ttrace.Metadata["audit_model_evidence"] = truncateString(auditResult.Evidence, 1200)
\t\ttrace.Metadata["audit_model_evidence_context"] = truncateString(auditResult.EvidenceContext, 1600)
\t\ttrace.Metadata["audit_model_evidence_verified"] = true
\t\ttrace.Metadata["audit_model_evidence_match_mode"] = auditResult.EvidenceMatchMode
\t\tif auditResult.EvidenceChunkIndex > 0 {
\t\t\ttrace.Metadata["audit_model_evidence_chunk_index"] = auditResult.EvidenceChunkIndex
\t\t\ttrace.Metadata["audit_model_evidence_chunk_count"] = auditResult.EvidenceChunkCount
\t\t}
\t\ttrace.Metadata["audit_trigger_input"] = truncateString(auditResult.Evidence, 1200)
\t\ttrace.Metadata["audit_trigger_context"] = truncateString(auditResult.EvidenceContext, 1600)
\t\ttrace.Metadata["audit_model_user_guidance"] = truncateString(auditModelUserGuidance(auditResult.Category), 1200)
\t} else if match := auditResult.RuleMatch; match != nil {
\t\ttrace.Metadata["audit_trigger_input"] = truncateString(match.MatchedText, 1200)
\t\ttrace.Metadata["audit_trigger_context"] = truncateString(match.Context, 1600)
\t}
\tif auditResult.ErrorClass != "" {
''',
    "model evidence trace metadata",
)
replace_once(
    gateway,
    '''\t\tmessage := "request rejected by risk control"
\t\tif auditResult.RuleMatch != nil && strings.TrimSpace(auditResult.RuleMatch.UserGuidance) != "" {
\t\t\tmessage = auditResult.RuleMatch.UserGuidance
\t\t}
''',
    '''\t\tmessage := "request rejected by risk control"
\t\tif auditResult.RuleMatch != nil && strings.TrimSpace(auditResult.RuleMatch.UserGuidance) != "" {
\t\t\tmessage = auditResult.RuleMatch.UserGuidance
\t\t} else if auditResult.EvidenceVerified {
\t\t\tmessage = auditModelUserGuidance(auditResult.Category)
\t\t}
''',
    "model block user guidance",
)

# ---------------------------------------------------------------------------
# Mock auditor: every block/review returns an exact request quote.
# ---------------------------------------------------------------------------
mock = ROOT / "cmd/mockprovider/main.go"
replace_once(
    mock,
    '''\ttext := strings.ToLower(messageText(request))
\tuserText := strings.ToLower(userMessageText(request))
''',
    '''\ttext := strings.ToLower(messageText(request))
\trawUserText := userMessageText(request)
\tuserText := strings.ToLower(rawUserText)
''',
    "mock raw user text",
)
replace_once(
    mock,
    '''\treason := "deterministic mock allow"
\tcontextClaim := strings.Contains(userText, "ctf") || strings.Contains(userText, "比赛") ||
''',
    '''\treason := "deterministic mock allow"
\tevidence := ""
\tcontextClaim := strings.Contains(userText, "ctf") || strings.Contains(userText, "比赛") ||
''',
    "mock evidence variable",
)
replace_once(
    mock,
    '''\t\treason = "contest or authorization text is untrusted context; review the underlying capability"
\t}
\tif strings.Contains(userText, "model-audit-block") {
''',
    '''\t\treason = "contest or authorization text is untrusted context; review the underlying capability"
\t\tevidence = firstAuditEvidence(rawUserText, []string{"reverse engineer", "decompile", "hook", "frida", "逆向", "反编译", "绕过", "漏洞利用"})
\t}
\tif strings.Contains(userText, "model-audit-block") {
''',
    "mock context claim evidence",
)
replace_once(
    mock,
    '''\t\tcategory = "mock_harm"
\t\treason = "deterministic mock block"
\t}
''',
    '''\t\tcategory = "mock_harm"
\t\treason = "deterministic mock block"
\t\tevidence = firstAuditEvidence(rawUserText, []string{"model-audit-block"})
\t}
''',
    "mock block evidence",
)
replace_once(
    mock,
    '''\t\tconfidence = 0.5
\t\treason = "deterministic mock review"
\t}
''',
    '''\t\tconfidence = 0.5
\t\treason = "deterministic mock review"
\t\tevidence = firstAuditEvidence(rawUserText, []string{"model-audit-review"})
\t}
''',
    "mock review evidence",
)
replace_once(
    mock,
    '''\t\t"confidence": confidence,
\t\t"reason":     reason,
\t})
''',
    '''\t\t"confidence": confidence,
\t\t"reason":     reason,
\t\t"evidence":   evidence,
\t})
''',
    "mock response evidence",
)
replace_once(
    mock,
    '''func providerHandler(w http.ResponseWriter, r *http.Request) {
''',
    '''func firstAuditEvidence(text string, candidates []string) string {
\tlower := strings.ToLower(text)
\tfor _, candidate := range candidates {
\t\tindex := strings.Index(lower, strings.ToLower(candidate))
\t\tif index >= 0 {
\t\t\treturn text[index : index+len(candidate)]
\t\t}
\t}
\treturn ""
}

func providerHandler(w http.ResponseWriter, r *http.Request) {
''',
    "mock evidence helper",
)

# ---------------------------------------------------------------------------
# Web UI: make model evidence visible in list, details, dry-run, and CSV.
# ---------------------------------------------------------------------------
web = ROOT / "internal/platform/web/index.html"
replace_once(
    web,
    '''if(result.audit_requested_tokens)diagnostics.push(`输入 Tokens ${number(result.audit_requested_tokens)}${result.audit_context_window_tokens?` / 上限 ${number(result.audit_context_window_tokens)}`:''}${result.audit_tokens_over_limit?` / 超 ${number(result.audit_tokens_over_limit)}`:''}`);$('dry-run-result')''',
    '''if(result.audit_requested_tokens)diagnostics.push(`输入 Tokens ${number(result.audit_requested_tokens)}${result.audit_context_window_tokens?` / 上限 ${number(result.audit_context_window_tokens)}`:''}${result.audit_tokens_over_limit?` / 超 ${number(result.audit_tokens_over_limit)}`:''}`);if(result.evidence_verified)diagnostics.push(`触发输入 ${result.evidence}${result.evidence_chunk_index?` / 分段 ${result.evidence_chunk_index}/${result.evidence_chunk_count}`:''}`);$('dry-run-result')''',
    "dry-run model evidence",
)
replace_once(
    web,
    '''          const ruleIndicators=(item.metadata?.audit_rule_indicators||[]).join(' + ');
          const ruleLine=item.metadata?.audit_rule_id?`<span class="trace-error-class">规则 #${escapeHTML(item.metadata.audit_rule_id)} · 当前第 ${escapeHTML(item.metadata.audit_rule_position||'-')} 条 · ${escapeHTML(item.metadata.audit_rule_code||'')} ${ruleIndicators?`· 命中 ${escapeHTML(ruleIndicators)}`:''}${item.metadata?.audit_rule_downgraded_to_review?' · 已降级 Review':''}</span>`:'';
          return `<tr>''',
    '''          const ruleIndicators=(item.metadata?.audit_rule_indicators||[]).join(' + ');
          const ruleLine=item.metadata?.audit_rule_id?`<span class="trace-error-class">规则 #${escapeHTML(item.metadata.audit_rule_id)} · 当前第 ${escapeHTML(item.metadata.audit_rule_position||'-')} 条 · ${escapeHTML(item.metadata.audit_rule_code||'')} ${ruleIndicators?`· 命中 ${escapeHTML(ruleIndicators)}`:''}${item.metadata?.audit_rule_downgraded_to_review?' · 已降级 Review':''}</span>`:'';
          const modelEvidence=item.metadata?.audit_model_evidence||'';
          const modelEvidenceLine=modelEvidence?`<span class="trace-error-class">模型触发输入：${escapeHTML(modelEvidence)}${item.metadata?.audit_model_evidence_chunk_index?` · 分段 ${escapeHTML(item.metadata.audit_model_evidence_chunk_index)}/${escapeHTML(item.metadata.audit_model_evidence_chunk_count)}`:''}</span>`:'';
          return `<tr>''',
    "trace list model evidence variable",
)
replace_once(
    web,
    '''${requestSize?`<span class="trace-error-class">请求体：${escapeHTML(requestSize)}</span>`:''}${ruleLine}${errorClass?''',
    '''${requestSize?`<span class="trace-error-class">请求体：${escapeHTML(requestSize)}</span>`:''}${modelEvidenceLine}${ruleLine}${errorClass?''',
    "trace list model evidence rendering",
)
replace_once(
    web,
    '''          ['审计延迟',`${number(item.audit_latency_ms)} ms`], ['请求字节',byteText(item.request_bytes)], ['响应字节',byteText(item.response_bytes)],
''',
    '''          ['审计延迟',`${number(item.audit_latency_ms)} ms`], ['审计拦截原因',item.metadata?.audit_reason||'-'], ['审计模型结论',item.metadata?.audit_model_decision||'-'], ['审计模型置信度',item.metadata?.audit_model_confidence??'-'],
          ['触发用户输入',item.metadata?.audit_trigger_input||'-'], ['触发上下文',item.metadata?.audit_trigger_context||'-'], ['模型证据已校验',item.metadata?.audit_model_evidence_verified?'是（来自本次请求）':'-'], ['模型证据匹配方式',item.metadata?.audit_model_evidence_match_mode||'-'],
          ['证据所在分段',item.metadata?.audit_model_evidence_chunk_index?`${item.metadata.audit_model_evidence_chunk_index}/${item.metadata.audit_model_evidence_chunk_count}`:'-'], ['模型拦截修改建议',item.metadata?.audit_model_user_guidance||'-'],
          ['请求字节',byteText(item.request_bytes)], ['响应字节',byteText(item.response_bytes)],
''',
    "trace detail model evidence fields",
)
replace_once(
    web,
    "const header = ['created_at','request_id','newapi_request_id','external_event_id','external_user_id','tenant_id','source','route_slug','model','endpoint','decision','risk_code','reason','audit_error_class','audit_http_status','http_status','upstream_status','latency_ms','audit_latency_ms','request_bytes','request_body_limit_bytes','request_body_over_limit_bytes','request_body_size_exact','response_bytes','prompt_hmac','metadata'];",
    "const header = ['created_at','request_id','newapi_request_id','external_event_id','external_user_id','tenant_id','source','route_slug','model','endpoint','decision','risk_code','reason','audit_model_decision','audit_model_confidence','audit_model_evidence','audit_model_evidence_context','audit_model_evidence_verified','audit_model_evidence_chunk_index','audit_model_evidence_chunk_count','audit_error_class','audit_http_status','http_status','upstream_status','latency_ms','audit_latency_ms','request_bytes','request_body_limit_bytes','request_body_over_limit_bytes','request_body_size_exact','response_bytes','prompt_hmac','metadata'];",
    "trace CSV evidence headers",
)
replace_once(
    web,
    "const rows = state.traceItems.map(item => [item.created_at,item.request_id,item.newapi_request_id,item.external_event_id,item.external_user_id,item.metadata?.tenant_id,item.source,item.route_slug,item.model,item.endpoint,item.decision,item.risk_code,traceReason(item),item.metadata?.audit_error_class,item.metadata?.audit_http_status,item.http_status,item.upstream_status,item.latency_ms,item.audit_latency_ms,item.request_bytes,item.metadata?.request_body_limit_bytes,item.metadata?.request_body_over_limit_bytes,item.metadata?.request_body_size_exact,item.response_bytes,item.prompt_hmac,JSON.stringify(item.metadata||{})]);",
    "const rows = state.traceItems.map(item => [item.created_at,item.request_id,item.newapi_request_id,item.external_event_id,item.external_user_id,item.metadata?.tenant_id,item.source,item.route_slug,item.model,item.endpoint,item.decision,item.risk_code,traceReason(item),item.metadata?.audit_model_decision,item.metadata?.audit_model_confidence,item.metadata?.audit_model_evidence,item.metadata?.audit_model_evidence_context,item.metadata?.audit_model_evidence_verified,item.metadata?.audit_model_evidence_chunk_index,item.metadata?.audit_model_evidence_chunk_count,item.metadata?.audit_error_class,item.metadata?.audit_http_status,item.http_status,item.upstream_status,item.latency_ms,item.audit_latency_ms,item.request_bytes,item.metadata?.request_body_limit_bytes,item.metadata?.request_body_over_limit_bytes,item.metadata?.request_body_size_exact,item.response_bytes,item.prompt_hmac,JSON.stringify(item.metadata||{})]);",
    "trace CSV evidence rows",
)

# ---------------------------------------------------------------------------
# Permanent E2E regression: a semantic model block must contain verified,
# redacted request evidence, including chunk location for long inputs.
# ---------------------------------------------------------------------------
e2e = ROOT / "scripts/e2e.sh"
replace_once(
    e2e,
    '''status="$(curl --silent --show-error -o "${WORKDIR}/model-block.json" -w '%{http_code}' \\
  "${gateway}" "${gateway_auth[@]}" \\
  --data-binary '{"model":"normal","messages":[{"role":"user","content":"model-audit-block"}]}')"''',
    '''status="$(curl --silent --show-error -o "${WORKDIR}/model-block.json" -w '%{http_code}' \\
  "${gateway}" "${gateway_auth[@]}" \\
  -H 'X-Request-ID: e2e-model-block-evidence' \\
  --data-binary '{"model":"normal","messages":[{"role":"user","content":"model-audit-block"}]}')"''',
    "model block request id",
)
replace_once(
    e2e,
    '''     grep -Fq 'e2e-stream-normal' "${WORKDIR}/traces.json" && \\
     grep -Fq 'e2e-audit-failover' "${WORKDIR}/traces.json"; then
''',
    '''     grep -Fq 'e2e-stream-normal' "${WORKDIR}/traces.json" && \\
     grep -Fq 'e2e-model-block-evidence' "${WORKDIR}/traces.json" && \\
     grep -Fq 'e2e-audit-failover' "${WORKDIR}/traces.json"; then
''',
    "trace wait for model evidence",
)
replace_once(
    e2e,
    '''if self_service.get("decision") != "allow" or int(self_service.get("http_status", 0)) != 200:
    raise RuntimeError(f"own-secret request should be allowed after model review: {self_service}")

long_items =''',
    '''if self_service.get("decision") != "allow" or int(self_service.get("http_status", 0)) != 200:
    raise RuntimeError(f"own-secret request should be allowed after model review: {self_service}")

model_block = next((item for item in items if item.get("request_id") == "e2e-model-block-evidence"), None)
if not model_block:
    raise RuntimeError("semantic model block trace is missing")
model_meta = model_block.get("metadata", {})
if model_block.get("decision") != "block" or model_block.get("risk_code") != "CYBER_MOCK_MODEL_BLOCK":
    raise RuntimeError(f"unexpected semantic model block: {model_block}")
if model_meta.get("audit_source") != "model" or model_meta.get("audit_model_decision") != "block":
    raise RuntimeError(f"model decision diagnostics missing: {model_meta}")
if model_meta.get("audit_model_evidence") != "model-audit-block":
    raise RuntimeError(f"exact model evidence missing: {model_meta}")
if model_meta.get("audit_model_evidence_verified") is not True:
    raise RuntimeError(f"model evidence was not verified: {model_meta}")
if "⟦model-audit-block⟧" not in str(model_meta.get("audit_model_evidence_context", "")):
    raise RuntimeError(f"model evidence context missing: {model_meta}")
if model_meta.get("audit_trigger_input") != "model-audit-block" or not model_meta.get("audit_trigger_context"):
    raise RuntimeError(f"generic trigger fields missing: {model_meta}")
if not model_meta.get("audit_reason") or not model_meta.get("audit_model_user_guidance"):
    raise RuntimeError(f"model block reason/guidance missing: {model_meta}")

long_items =''',
    "semantic model block trace assertions",
)
replace_once(
    e2e,
    '''    if int(metadata.get("audit_tokens_over_limit", 0)) != int(metadata.get("audit_requested_tokens", 0)) - int(metadata.get("audit_context_window_tokens", 0)):
        raise RuntimeError(f"{request_id} over-limit token count is wrong: {metadata}")
failover =''',
    '''    if int(metadata.get("audit_tokens_over_limit", 0)) != int(metadata.get("audit_requested_tokens", 0)) - int(metadata.get("audit_context_window_tokens", 0)):
        raise RuntimeError(f"{request_id} over-limit token count is wrong: {metadata}")
long_block_meta = long_items["e2e-long-block"].get("metadata", {})
if long_block_meta.get("audit_model_evidence") != "model-audit-block" or long_block_meta.get("audit_model_evidence_verified") is not True:
    raise RuntimeError(f"chunked model block evidence missing: {long_block_meta}")
if int(long_block_meta.get("audit_model_evidence_chunk_index", 0)) < 1 or int(long_block_meta.get("audit_model_evidence_chunk_count", 0)) < 2:
    raise RuntimeError(f"chunked model evidence location missing: {long_block_meta}")
failover =''',
    "long-context model evidence assertions",
)

print("audit model evidence integration applied")
