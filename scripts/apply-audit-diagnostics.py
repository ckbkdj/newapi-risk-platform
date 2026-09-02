from pathlib import Path


def replace_once(text: str, old: str, new: str, label: str) -> str:
    count = text.count(old)
    if count != 1:
        raise RuntimeError(f"{label}: expected one anchor, found {count}")
    return text.replace(old, new, 1)


# ---------------------------------------------------------------------------
# Structured AuditResult diagnostics.
# ---------------------------------------------------------------------------
path = Path("internal/platform/types.go")
text = path.read_text(encoding="utf-8")
old = '''type AuditResult struct {
\tAuditDecision
\tPromptHMAC string        `json:"prompt_hmac"`
\tTextBytes  int           `json:"text_bytes"`
\tLatency    time.Duration `json:"-"`
\tModel      string        `json:"model,omitempty"`
}'''
new = '''type AuditResult struct {
\tAuditDecision
\tPromptHMAC      string        `json:"prompt_hmac"`
\tTextBytes       int           `json:"text_bytes"`
\tLatency         time.Duration `json:"-"`
\tModel           string        `json:"model,omitempty"`
\tErrorClass      string        `json:"error_class,omitempty"`
\tAuditHTTPStatus int           `json:"audit_http_status,omitempty"`
}'''
text = replace_once(text, old, new, "AuditResult diagnostics")
path.write_text(text, encoding="utf-8")


# ---------------------------------------------------------------------------
# Audit client: classify call failures, expose provider error details, and
# tolerate reasoning / Markdown wrappers around the final JSON object.
# ---------------------------------------------------------------------------
path = Path("internal/platform/audit.go")
text = path.read_text(encoding="utf-8")
old = '''\tdecision, err := e.callModel(ctx, profile, text)
\tresult.Model = profile.Model
\tif err != nil {
\t\tif route.FailClosed || profile.FailClosed {
\t\t\tresult.AuditDecision = AuditDecision{
\t\t\t\tDecision:   DecisionBlock,
\t\t\t\tRiskCode:   "AUDIT_MODEL_ERROR",
\t\t\t\tCategory:   "audit_infrastructure",
\t\t\t\tConfidence: 1,
\t\t\t\tReason:     err.Error(),
\t\t\t\tSource:     "platform",
\t\t\t}
\t\t} else if matched != nil {
\t\t\tresult.AuditDecision = *matched
\t\t} else {
\t\t\tresult.AuditDecision = AuditDecision{
\t\t\t\tDecision: DecisionAllow,
\t\t\t\tSource:   "fail_open",
\t\t\t}
\t\t}
\t\treturn result
\t}'''
new = '''\tdecision, err := e.callModel(ctx, profile, text)
\tresult.Model = profile.Model
\tif err != nil {
\t\terrorClass, auditHTTPStatus, reason := auditModelErrorDetails(err)
\t\tresult.ErrorClass = errorClass
\t\tresult.AuditHTTPStatus = auditHTTPStatus
\t\tif route.FailClosed || profile.FailClosed {
\t\t\tresult.AuditDecision = AuditDecision{
\t\t\t\tDecision:   DecisionBlock,
\t\t\t\tRiskCode:   "AUDIT_MODEL_ERROR",
\t\t\t\tCategory:   "audit_infrastructure",
\t\t\t\tConfidence: 1,
\t\t\t\tReason:     reason,
\t\t\t\tSource:     "platform",
\t\t\t}
\t\t} else if matched != nil {
\t\t\tresult.AuditDecision = *matched
\t\t} else {
\t\t\tresult.AuditDecision = AuditDecision{
\t\t\t\tDecision: DecisionAllow,
\t\t\t\tReason:   reason,
\t\t\t\tSource:   "fail_open",
\t\t\t}
\t\t}
\t\treturn result
\t}'''
text = replace_once(text, old, new, "Audit() call error diagnostics")

text = replace_once(
    text,
    '''\tencoded, err := json.Marshal(payload)
\tif err != nil {
\t\treturn AuditDecision{}, err
\t}''',
    '''\tencoded, err := json.Marshal(payload)
\tif err != nil {
\t\treturn AuditDecision{}, newAuditModelCallError("request_encode", 0, "encode audit model request", err)
\t}''',
    "audit request encode",
)
text = replace_once(
    text,
    '''\tif err != nil {
\t\treturn AuditDecision{}, err
\t}
\trequest.Header.Set("Content-Type", "application/json")''',
    '''\tif err != nil {
\t\treturn AuditDecision{}, newAuditModelCallError("request_build", 0, "build audit model request", err)
\t}
\trequest.Header.Set("Content-Type", "application/json")''',
    "audit request build",
)
text = replace_once(
    text,
    '''\t\tif err != nil {
\t\t\treturn AuditDecision{}, fmt.Errorf("decrypt audit API key: %w", err)
\t\t}''',
    '''\t\tif err != nil {
\t\t\treturn AuditDecision{}, newAuditModelCallError("credential_decrypt", 0, "decrypt audit API key", err)
\t\t}''',
    "audit credential decrypt",
)
text = replace_once(
    text,
    '''\tresponse, err := e.client.Do(request)
\tif err != nil {
\t\treturn AuditDecision{}, fmt.Errorf("audit model request failed: %w", err)
\t}''',
    '''\tresponse, err := e.client.Do(request)
\tif err != nil {
\t\treturn AuditDecision{}, classifyAuditTransportError(err)
\t}''',
    "audit transport diagnostics",
)
text = replace_once(
    text,
    '''\tresponseBody, err := io.ReadAll(io.LimitReader(response.Body, 1024*1024))
\tif err != nil {
\t\treturn AuditDecision{}, fmt.Errorf("read audit model response: %w", err)
\t}
\tif response.StatusCode < 200 || response.StatusCode >= 300 {
\t\treturn AuditDecision{}, fmt.Errorf("audit model returned HTTP %d", response.StatusCode)
\t}''',
    '''\tresponseBody, err := io.ReadAll(io.LimitReader(response.Body, 1024*1024))
\tif err != nil {
\t\treturn AuditDecision{}, newAuditModelCallError("response_read", 0, "read audit model response", err)
\t}
\tif response.StatusCode < 200 || response.StatusCode >= 300 {
\t\treturn AuditDecision{}, auditHTTPStatusError(response.StatusCode, responseBody)
\t}''',
    "audit HTTP diagnostics",
)
text = replace_once(
    text,
    '''\tcontent, err := extractChatCompletionContent(responseBody)
\tif err != nil {
\t\treturn AuditDecision{}, err
\t}
\tcontent = strings.TrimSpace(content)
\tcontent = strings.TrimPrefix(content, "```json")
\tcontent = strings.TrimPrefix(content, "```")
\tcontent = strings.TrimSuffix(content, "```")
\tcontent = strings.TrimSpace(content)
\tvar modelResult modelAuditResponse
\tif err := json.Unmarshal([]byte(content), &modelResult); err != nil {
\t\treturn AuditDecision{}, fmt.Errorf("audit model did not return valid JSON: %w", err)
\t}
\tmodelResult.Decision = strings.ToLower(strings.TrimSpace(modelResult.Decision))
\tswitch modelResult.Decision {
\tcase DecisionAllow, DecisionBlock, DecisionReview:
\tdefault:
\t\treturn AuditDecision{}, fmt.Errorf(
\t\t\t"audit model returned invalid decision %q",
\t\t\tmodelResult.Decision,
\t\t)
\t}
\tif modelResult.Confidence < 0 {
\t\tmodelResult.Confidence = 0
\t}
\tif modelResult.Confidence > 1 {
\t\tmodelResult.Confidence = 1
\t}
\tif len(modelResult.Reason) > 500 {
\t\tmodelResult.Reason = modelResult.Reason[:500]
\t}''',
    '''\tcontent, err := extractChatCompletionContent(responseBody)
\tif err != nil {
\t\treturn AuditDecision{}, newAuditModelCallError("response_format", 0, err.Error(), nil)
\t}
\tmodelResult, err := parseAuditModelResponseContent(content)
\tif err != nil {
\t\treturn AuditDecision{}, err
\t}''',
    "audit tolerant JSON parse",
)

old_extract = '''func extractChatCompletionContent(body []byte) (string, error) {
\tvar envelope struct {
\t\tChoices []struct {
\t\t\tMessage struct {
\t\t\t\tContent json.RawMessage `json:"content"`
\t\t\t} `json:"message"`
\t\t} `json:"choices"`
\t}
\tif err := json.Unmarshal(body, &envelope); err != nil {
\t\treturn "", fmt.Errorf("decode audit model response: %w", err)
\t}
\tif len(envelope.Choices) == 0 {
\t\treturn "", errors.New("audit model response has no choices")
\t}
\tvar text string
\tif json.Unmarshal(envelope.Choices[0].Message.Content, &text) == nil {
\t\treturn text, nil
\t}
\tvar parts []map[string]any
\tif json.Unmarshal(envelope.Choices[0].Message.Content, &parts) == nil {
\t\tvar builder strings.Builder
\t\tfor _, part := range parts {
\t\t\tif value, ok := part["text"].(string); ok {
\t\t\t\tbuilder.WriteString(value)
\t\t\t}
\t\t}
\t\tif builder.Len() > 0 {
\t\t\treturn builder.String(), nil
\t\t}
\t}
\treturn "", errors.New("audit model response content is not text")
}'''
new_extract = '''func extractChatCompletionContent(body []byte) (string, error) {
\tvar direct modelAuditResponse
\tif json.Unmarshal(body, &direct) == nil && strings.TrimSpace(direct.Decision) != "" {
\t\treturn string(body), nil
\t}
\tvar envelope struct {
\t\tChoices []struct {
\t\t\tText    json.RawMessage `json:"text"`
\t\t\tMessage struct {
\t\t\t\tContent json.RawMessage `json:"content"`
\t\t\t} `json:"message"`
\t\t} `json:"choices"`
\t}
\tif err := json.Unmarshal(body, &envelope); err != nil {
\t\treturn "", fmt.Errorf("decode audit model response: %w", err)
\t}
\tif len(envelope.Choices) == 0 {
\t\treturn "", errors.New("audit model response has no choices")
\t}
\tdecodeText := func(raw json.RawMessage) string {
\t\tif len(raw) == 0 || string(raw) == "null" {
\t\t\treturn ""
\t\t}
\t\tvar text string
\t\tif json.Unmarshal(raw, &text) == nil {
\t\t\treturn text
\t\t}
\t\tvar parts []map[string]any
\t\tif json.Unmarshal(raw, &parts) == nil {
\t\t\tvar builder strings.Builder
\t\t\tfor _, part := range parts {
\t\t\t\tif value, ok := part["text"].(string); ok {
\t\t\t\t\tbuilder.WriteString(value)
\t\t\t\t}
\t\t\t}
\t\t\treturn builder.String()
\t\t}
\t\treturn ""
\t}
\tif text := decodeText(envelope.Choices[0].Message.Content); strings.TrimSpace(text) != "" {
\t\treturn text, nil
\t}
\tif text := decodeText(envelope.Choices[0].Text); strings.TrimSpace(text) != "" {
\t\treturn text, nil
\t}
\treturn "", errors.New("audit model response content is not text")
}'''
text = replace_once(text, old_extract, new_extract, "chat completion content compatibility")
path.write_text(text, encoding="utf-8")


# ---------------------------------------------------------------------------
# Trace metadata: persist audit reason/error class and a readable default
# reason for every failed request.
# ---------------------------------------------------------------------------
path = Path("internal/platform/gateway.go")
text = path.read_text(encoding="utf-8")
old = '''\tfinish := func(decision string, riskCode string, status int, upstreamStatus int, responseBytes int64) {
\t\tif finished {
\t\t\treturn
\t\t}
\t\tfinished = true
\t\ttrace.Decision = decision
\t\ttrace.RiskCode = riskCode
\t\ttrace.HTTPStatus = status
\t\ttrace.UpstreamStatus = upstreamStatus
\t\ttrace.ResponseBytes = responseBytes
\t\ttrace.LatencyMS = time.Since(started).Milliseconds()
\t\tg.traces.Submit(trace)'''
new = '''\tfinish := func(decision string, riskCode string, status int, upstreamStatus int, responseBytes int64) {
\t\tif finished {
\t\t\treturn
\t\t}
\t\tfinished = true
\t\ttrace.Decision = decision
\t\ttrace.RiskCode = riskCode
\t\ttrace.HTTPStatus = status
\t\ttrace.UpstreamStatus = upstreamStatus
\t\ttrace.ResponseBytes = responseBytes
\t\ttrace.LatencyMS = time.Since(started).Milliseconds()
\t\tif riskCode != "" {
\t\t\ttrace.Metadata["error_reason"] = traceFailureReason(riskCode, upstreamStatus, trace.Metadata)
\t\t}
\t\tg.traces.Submit(trace)'''
text = replace_once(text, old, new, "trace failure reason persistence")
old = '''\ttrace.Metadata["audit_source"] = auditResult.Source
\ttrace.Metadata["audit_category"] = auditResult.Category
\tif auditResult.Model != "" {
\t\ttrace.Metadata["audit_model"] = auditResult.Model
\t}'''
new = '''\ttrace.Metadata["audit_source"] = auditResult.Source
\ttrace.Metadata["audit_category"] = auditResult.Category
\tif auditResult.Model != "" {
\t\ttrace.Metadata["audit_model"] = auditResult.Model
\t}
\tif auditResult.Reason != "" {
\t\ttrace.Metadata["audit_reason"] = truncateString(auditResult.Reason, auditDiagnosticTextLimit)
\t}
\tif auditResult.ErrorClass != "" {
\t\ttrace.Metadata["audit_error_class"] = auditResult.ErrorClass
\t}
\tif auditResult.AuditHTTPStatus > 0 {
\t\ttrace.Metadata["audit_http_status"] = auditResult.AuditHTTPStatus
\t}'''
text = replace_once(text, old, new, "audit trace diagnostics")
path.write_text(text, encoding="utf-8")


# ---------------------------------------------------------------------------
# Global trace search should find diagnostic text as well.
# ---------------------------------------------------------------------------
path = Path("internal/platform/trace_search.go")
text = path.read_text(encoding="utf-8")
old = '''\t\tcolumns := []string{
\t\t\t"request_id",
\t\t\t"newapi_request_id",
\t\t\t"external_event_id",
\t\t\t"external_user_id",
\t\t\t"model",
\t\t\t"endpoint",
\t\t\t"route_slug",
\t\t\t"risk_code",
\t\t\t"source",
\t\t\t"COALESCE(metadata ->> 'tenant_id','')",
\t\t}'''
new = '''\t\tcolumns := []string{
\t\t\t"request_id",
\t\t\t"newapi_request_id",
\t\t\t"external_event_id",
\t\t\t"external_user_id",
\t\t\t"model",
\t\t\t"endpoint",
\t\t\t"route_slug",
\t\t\t"risk_code",
\t\t\t"source",
\t\t\t"COALESCE(metadata ->> 'tenant_id','')",
\t\t\t"COALESCE(metadata ->> 'error_reason','')",
\t\t\t"COALESCE(metadata ->> 'audit_reason','')",
\t\t\t"COALESCE(metadata ->> 'audit_error_class','')",
\t\t}'''
text = replace_once(text, old, new, "trace diagnostic full-text search")
path.write_text(text, encoding="utf-8")


# ---------------------------------------------------------------------------
# Mock audit endpoint: reasoning-wrapped valid JSON + explicit HTTP auth error.
# ---------------------------------------------------------------------------
path = Path("cmd/mockprovider/main.go")
text = path.read_text(encoding="utf-8")
anchor = '''\tdecision := "allow"
\triskCode := ""
\tcategory := "benign"
\tconfidence := 0.99
\treason := "deterministic mock allow"
'''
replacement = '''\tif strings.Contains(text, "model-audit-http-401") {
\t\twriteJSON(w, http.StatusUnauthorized, map[string]any{
\t\t\t"error": map[string]any{"message": "mock audit API key rejected", "type": "authentication_error"},
\t\t})
\t\treturn
\t}
\tif strings.Contains(text, "model-audit-thinking-json") {
\t\tcontent := "<think>checking policy context before the final answer</think>\\n```json\\n{\\\"decision\\\":\\\"allow\\\",\\\"risk_code\\\":\\\"\\\",\\\"category\\\":\\\"benign\\\",\\\"confidence\\\":0.99,\\\"reason\\\":\\\"reasoning wrapper accepted\\\"}\\n```"
\t\twriteJSON(w, http.StatusOK, map[string]any{
\t\t\t"id": "audit-thinking-mock",
\t\t\t"choices": []any{map[string]any{
\t\t\t\t"message": map[string]any{"role": "assistant", "content": content},
\t\t\t}},
\t\t})
\t\treturn
\t}
\tdecision := "allow"
\triskCode := ""
\tcategory := "benign"
\tconfidence := 0.99
\treason := "deterministic mock allow"
'''
text = replace_once(text, anchor, replacement, "mock audit diagnostics")
path.write_text(text, encoding="utf-8")


# ---------------------------------------------------------------------------
# Web: detailed request timestamp, visible failure reason, audit error class,
# one-click profile test and richer CSV/detail output.
# ---------------------------------------------------------------------------
path = Path("internal/platform/web/index.html")
text = path.read_text(encoding="utf-8")
text = replace_once(
    text,
    '''      const dateText = value => value ? new Date(value).toLocaleString() : '-';''',
    '''      const dateText = value => value ? new Date(value).toLocaleString() : '-';
      const detailedDateText = value => { if (!value) return '-'; const date=new Date(value); return `${date.toLocaleString('zh-CN',{hour12:false})}.${String(date.getMilliseconds()).padStart(3,'0')}`; };''',
    "detailed request timestamp",
)
text = replace_once(
    text,
    '''            <div class="panel-head"><div><h3>匹配请求</h3><div id="trace-results-meta" class="trace-result-meta">尚未查询</div></div><button id="trace-export" class="btn btn-secondary" type="button">导出当前页 CSV</button></div>''',
    '''            <div class="panel-head"><div><h3>请求时间与问题明细</h3><div id="trace-results-meta" class="trace-result-meta">尚未查询</div></div><button id="trace-export" class="btn btn-secondary" type="button">导出当前页 CSV</button></div>''',
    "trace list heading",
)
text = replace_once(
    text,
    '''    .trace-presets{display:flex;align-items:center;gap:8px;flex-wrap:wrap;margin-bottom:15px}.trace-presets>span{font-size:13px;font-weight:700;color:#475467}.trace-summary{grid-template-columns:repeat(5,minmax(0,1fr))}.trace-summary .metric-value{font-size:24px}.trace-result-meta{font-size:13px;color:#667085}.trace-pagination{display:flex;align-items:center;justify-content:flex-end;gap:9px;margin-top:14px}.trace-table table{min-width:1220px}.trace-user-button{border:0;background:transparent;padding:0;color:#175cd3;text-align:left;font-weight:700}.trace-user-button:hover{text-decoration:underline}.trace-subline{display:block;margin-top:3px;color:#667085;font-size:12px}.trace-request-id{display:block;max-width:290px;word-break:break-all}''',
    '''    .trace-presets{display:flex;align-items:center;gap:8px;flex-wrap:wrap;margin-bottom:15px}.trace-presets>span{font-size:13px;font-weight:700;color:#475467}.trace-summary{grid-template-columns:repeat(5,minmax(0,1fr))}.trace-summary .metric-value{font-size:24px}.trace-result-meta{font-size:13px;color:#667085}.trace-pagination{display:flex;align-items:center;justify-content:flex-end;gap:9px;margin-top:14px}.trace-table table{min-width:1450px}.trace-user-button{border:0;background:transparent;padding:0;color:#175cd3;text-align:left;font-weight:700}.trace-user-button:hover{text-decoration:underline}.trace-subline{display:block;margin-top:3px;color:#667085;font-size:12px}.trace-request-id{display:block;max-width:290px;word-break:break-all}.trace-reason{display:block;max-width:360px;white-space:normal;word-break:break-word}.trace-error-class{display:block;margin-top:4px;font-size:11px;color:#b54708;font-family:ui-monospace,SFMono-Regular,Consolas,monospace}''',
    "trace reason styles",
)
old_load_profiles = '''      async function loadProfiles() { await ensureProfiles(); $('profiles-table').innerHTML=state.profiles.length?`<div class="table-wrap"><table><thead><tr><th>名称</th><th>模型</th><th>策略</th><th>状态</th><th>操作</th></tr></thead><tbody>${state.profiles.map(profile=>`<tr><td><strong>${escapeHTML(profile.name)}</strong><br><span class="muted">${escapeHTML(profile.endpoint)}</span></td><td>${escapeHTML(profile.model)}<br>${profile.api_key_configured?'已配置 Key':'无 Key'}</td><td>阈值 ${profile.block_threshold}<br>${profile.fail_closed?badge('fail-closed'):badge('fail-open')}</td><td>${profile.is_default?badge('default'):badge(profile.enabled?'enabled':'disabled')}</td><td><button class="btn btn-small btn-secondary" data-profile-edit="${profile.id}">编辑</button> <button class="btn btn-small btn-danger" data-profile-delete="${profile.id}" ${profile.is_default?'disabled':''}>删除</button></td></tr>`).join('')}</tbody></table></div>`:'<div class="empty">尚未配置审计模型</div>'; }'''
new_load_profiles = '''      async function loadProfiles() { await ensureProfiles(); $('profiles-table').innerHTML=state.profiles.length?`<div class="table-wrap"><table><thead><tr><th>名称</th><th>模型</th><th>策略</th><th>状态</th><th>操作</th></tr></thead><tbody>${state.profiles.map(profile=>`<tr><td><strong>${escapeHTML(profile.name)}</strong><br><span class="muted">${escapeHTML(profile.endpoint)}</span></td><td>${escapeHTML(profile.model)}<br>${profile.api_key_configured?'已配置 Key':'无 Key'}</td><td>阈值 ${profile.block_threshold}<br>${profile.fail_closed?badge('fail-closed'):badge('fail-open')}</td><td>${profile.is_default?badge('default'):badge(profile.enabled?'enabled':'disabled')}</td><td><button class="btn btn-small btn-secondary" data-profile-test="${profile.id}">测试</button> <button class="btn btn-small btn-secondary" data-profile-edit="${profile.id}">编辑</button> <button class="btn btn-small btn-danger" data-profile-delete="${profile.id}" ${profile.is_default?'disabled':''}>删除</button></td></tr>`).join('')}</tbody></table></div>`:'<div class="empty">尚未配置审计模型</div>'; }'''
text = replace_once(text, old_load_profiles, new_load_profiles, "audit profile test button")
text = replace_once(
    text,
    '''      function editProfile(id) { const profile=state.profiles.find(item=>item.id===Number(id));if(!profile)return;$('profile-id').value=profile.id;$('profile-name').value=profile.name;$('profile-endpoint').value=profile.endpoint;$('profile-model').value=profile.model;$('profile-api-key').value='';$('profile-system-prompt').value=profile.system_prompt||'';$('profile-timeout').value=profile.timeout_ms;$('profile-threshold').value=profile.block_threshold;$('profile-extra').value=JSON.stringify(profile.extra||{},null,2);$('profile-enabled').checked=profile.enabled;$('profile-fail-closed').checked=profile.fail_closed;$('profile-default').checked=profile.is_default;$('profile-form-title').textContent=`编辑模型 #${profile.id}`;$('profile-form').scrollIntoView({behavior:'smooth',block:'start'}); }''',
    '''      function editProfile(id) { const profile=state.profiles.find(item=>item.id===Number(id));if(!profile)return;$('profile-id').value=profile.id;$('profile-name').value=profile.name;$('profile-endpoint').value=profile.endpoint;$('profile-model').value=profile.model;$('profile-api-key').value='';$('profile-system-prompt').value=profile.system_prompt||'';$('profile-timeout').value=profile.timeout_ms;$('profile-threshold').value=profile.block_threshold;$('profile-extra').value=JSON.stringify(profile.extra||{},null,2);$('profile-enabled').checked=profile.enabled;$('profile-fail-closed').checked=profile.fail_closed;$('profile-default').checked=profile.is_default;$('profile-form-title').textContent=`编辑模型 #${profile.id}`;$('profile-form').scrollIntoView({behavior:'smooth',block:'start'}); }
      function testProfile(id) { $('dry-run-profile').value=String(id); if(!$('dry-run-text').value.trim()) $('dry-run-text').value='这是一条普通的产品功能说明，请判断是否安全。'; $('dry-run-form').scrollIntoView({behavior:'smooth',block:'center'}); $('dry-run-form').requestSubmit(); }''',
    "audit profile test action",
)
old_dry = '''      async function dryRun(event) { event.preventDefault();$('dry-run-result').hidden=true;try{const data=await api('/api/admin/v1/audit/dry-run',{method:'POST',body:JSON.stringify({text:$('dry-run-text').value,profile_id:$('dry-run-profile').value?Number($('dry-run-profile').value):null})});const result=data.result;$('dry-run-result').className=`notice ${result.decision==='block'?'warning':''}`;$('dry-run-result').textContent=`${result.decision.toUpperCase()} · ${result.risk_code||'无风险码'} · 置信度 ${result.confidence} · ${data.latency_ms} ms · ${result.reason||''}`;$('dry-run-result').hidden=false;}catch(error){toast(error.message,'error');} }'''
new_dry = '''      async function dryRun(event) { event.preventDefault();$('dry-run-result').hidden=true;try{const data=await api('/api/admin/v1/audit/dry-run',{method:'POST',body:JSON.stringify({text:$('dry-run-text').value,profile_id:$('dry-run-profile').value?Number($('dry-run-profile').value):null})});const result=data.result;const diagnostics=[];if(result.error_class)diagnostics.push(`错误分类 ${result.error_class}`);if(result.audit_http_status)diagnostics.push(`审计 HTTP ${result.audit_http_status}`);$('dry-run-result').className=`notice ${(result.decision==='block'||result.error_class)?'warning':''}`;$('dry-run-result').textContent=`${result.decision.toUpperCase()} · ${result.risk_code||'无风险码'} · 置信度 ${result.confidence} · ${data.latency_ms} ms${diagnostics.length?' · '+diagnostics.join(' · '):''} · ${result.reason||''}`;$('dry-run-result').hidden=false;}catch(error){toast(error.message,'error');} }'''
text = replace_once(text, old_dry, new_dry, "dry-run detailed diagnostics")

old_render = '''      function renderTraceTable(items) {
        if (!items.length) {
          $('traces-table').innerHTML = '<div class="empty">没有匹配的追踪记录</div>';
          return;
        }
        $('traces-table').innerHTML = `<div class="table-wrap trace-table"><table><thead><tr><th>时间 / Request ID</th><th>用户 / 租户</th><th>来源 / 路由</th><th>模型 / 接口</th><th>决策 / 风险</th><th>状态 / 延迟</th><th>操作</th></tr></thead><tbody>${items.map((item,index) => {
          const tenant = item.metadata?.tenant_id || '-';
          const user = item.external_user_id ? `<button class="trace-user-button" type="button" data-trace-user-index="${index}">${escapeHTML(item.external_user_id)}</button>` : '-';
          return `<tr><td>${escapeHTML(dateText(item.created_at))}<span class="mono trace-request-id">${escapeHTML(item.request_id)}</span><span class="trace-subline mono">New API: ${escapeHTML(item.newapi_request_id||'-')}</span></td><td>${user}<span class="trace-subline">租户：${escapeHTML(tenant)}</span></td><td>${escapeHTML(item.source||'-')}<span class="trace-subline mono">${escapeHTML(item.route_slug||'-')}</span></td><td>${escapeHTML(item.model||'-')}<span class="trace-subline mono">${escapeHTML(item.endpoint||'-')}</span></td><td>${badge(item.decision||'unknown')}<span class="trace-subline mono">${escapeHTML(item.risk_code||'-')}</span></td><td>HTTP ${item.http_status||'-'} / 上游 ${item.upstream_status||'-'}<span class="trace-subline">总计 ${number(item.latency_ms)} ms · 审计 ${number(item.audit_latency_ms)} ms</span></td><td><button class="btn btn-small btn-secondary" type="button" data-trace-detail-index="${index}">详情</button></td></tr>`;
        }).join('')}</tbody></table></div>`;
      }'''
new_render = '''      function traceReason(item) {
        const metadata=item.metadata||{};
        if(metadata.audit_reason)return String(metadata.audit_reason);
        if(metadata.error_reason)return String(metadata.error_reason);
        if(item.decision==='allow')return '正常放行';
        if(item.risk_code)return String(item.risk_code);
        return '-';
      }
      function renderTraceTable(items) {
        if (!items.length) {
          $('traces-table').innerHTML = '<div class="empty">没有匹配的追踪记录</div>';
          return;
        }
        $('traces-table').innerHTML = `<div class="table-wrap trace-table"><table><thead><tr><th>请求时间</th><th>Request ID</th><th>用户 / 租户</th><th>来源 / 路由</th><th>模型 / 接口</th><th>决策 / 风险</th><th>问题原因 / 诊断</th><th>状态 / 延迟</th><th>操作</th></tr></thead><tbody>${items.map((item,index) => {
          const tenant = item.metadata?.tenant_id || '-';
          const user = item.external_user_id ? `<button class="trace-user-button" type="button" data-trace-user-index="${index}">${escapeHTML(item.external_user_id)}</button>` : '-';
          const reason=traceReason(item);
          const errorClass=item.metadata?.audit_error_class||'';
          return `<tr><td><strong>${escapeHTML(detailedDateText(item.created_at))}</strong><span class="trace-subline">浏览器本地时间</span></td><td><span class="mono trace-request-id">${escapeHTML(item.request_id)}</span><span class="trace-subline mono">New API: ${escapeHTML(item.newapi_request_id||'-')}</span></td><td>${user}<span class="trace-subline">租户：${escapeHTML(tenant)}</span></td><td>${escapeHTML(item.source||'-')}<span class="trace-subline mono">${escapeHTML(item.route_slug||'-')}</span></td><td>${escapeHTML(item.model||'-')}<span class="trace-subline mono">${escapeHTML(item.endpoint||'-')}</span></td><td>${badge(item.decision||'unknown')}<span class="trace-subline mono">${escapeHTML(item.risk_code||'-')}</span></td><td><span class="trace-reason">${escapeHTML(reason)}</span>${errorClass?`<span class="trace-error-class">${escapeHTML(errorClass)}${item.metadata?.audit_http_status?` · HTTP ${escapeHTML(item.metadata.audit_http_status)}`:''}</span>`:''}</td><td>HTTP ${item.http_status||'-'} / 上游 ${item.upstream_status||'-'}<span class="trace-subline">总计 ${number(item.latency_ms)} ms · 审计 ${number(item.audit_latency_ms)} ms</span></td><td><button class="btn btn-small btn-secondary" type="button" data-trace-detail-index="${index}">详情</button></td></tr>`;
        }).join('')}</tbody></table></div>`;
      }'''
text = replace_once(text, old_render, new_render, "trace diagnostic table")
text = replace_once(
    text,
    '''          ['接口',item.endpoint||'-'], ['决策',item.decision||'-'], ['风险码',item.risk_code||'-'],
          ['HTTP 状态',item.http_status||'-'], ['上游状态',item.upstream_status||'-'], ['总延迟',`${number(item.latency_ms)} ms`],''',
    '''          ['接口',item.endpoint||'-'], ['决策',item.decision||'-'], ['风险码',item.risk_code||'-'],
          ['问题原因',traceReason(item)], ['审计错误分类',item.metadata?.audit_error_class||'-'], ['审计模型 HTTP',item.metadata?.audit_http_status||'-'],
          ['HTTP 状态',item.http_status||'-'], ['上游状态',item.upstream_status||'-'], ['总延迟',`${number(item.latency_ms)} ms`],''',
    "trace detail diagnostics",
)
text = replace_once(
    text,
    '''        const header = ['created_at','request_id','newapi_request_id','external_event_id','external_user_id','tenant_id','source','route_slug','model','endpoint','decision','risk_code','http_status','upstream_status','latency_ms','audit_latency_ms','request_bytes','response_bytes','prompt_hmac','metadata'];
        const rows = state.traceItems.map(item => [item.created_at,item.request_id,item.newapi_request_id,item.external_event_id,item.external_user_id,item.metadata?.tenant_id,item.source,item.route_slug,item.model,item.endpoint,item.decision,item.risk_code,item.http_status,item.upstream_status,item.latency_ms,item.audit_latency_ms,item.request_bytes,item.response_bytes,item.prompt_hmac,JSON.stringify(item.metadata||{})]);''',
    '''        const header = ['created_at','request_id','newapi_request_id','external_event_id','external_user_id','tenant_id','source','route_slug','model','endpoint','decision','risk_code','reason','audit_error_class','audit_http_status','http_status','upstream_status','latency_ms','audit_latency_ms','request_bytes','response_bytes','prompt_hmac','metadata'];
        const rows = state.traceItems.map(item => [item.created_at,item.request_id,item.newapi_request_id,item.external_event_id,item.external_user_id,item.metadata?.tenant_id,item.source,item.route_slug,item.model,item.endpoint,item.decision,item.risk_code,traceReason(item),item.metadata?.audit_error_class,item.metadata?.audit_http_status,item.http_status,item.upstream_status,item.latency_ms,item.audit_latency_ms,item.request_bytes,item.response_bytes,item.prompt_hmac,JSON.stringify(item.metadata||{})]);''',
    "trace CSV diagnostics",
)
text = replace_once(
    text,
    '''$('profiles-table').addEventListener('click',event=>{const edit=event.target.closest('[data-profile-edit]');const remove=event.target.closest('[data-profile-delete]');if(edit)editProfile(edit.dataset.profileEdit);if(remove&&!remove.disabled)deleteProfile(remove.dataset.profileDelete);});$('dry-run-form').addEventListener('submit',dryRun);''',
    '''$('profiles-table').addEventListener('click',event=>{const test=event.target.closest('[data-profile-test]');const edit=event.target.closest('[data-profile-edit]');const remove=event.target.closest('[data-profile-delete]');if(test)testProfile(test.dataset.profileTest);if(edit)editProfile(edit.dataset.profileEdit);if(remove&&!remove.disabled)deleteProfile(remove.dataset.profileDelete);});$('dry-run-form').addEventListener('submit',dryRun);''',
    "profile test event handler",
)
path.write_text(text, encoding="utf-8")


# ---------------------------------------------------------------------------
# E2E: prove reasoning wrappers are accepted and diagnostics reach traces.
# ---------------------------------------------------------------------------
path = Path("scripts/e2e.sh")
text = path.read_text(encoding="utf-8")
anchor = '''contains "${WORKDIR}/model-block.json" 'CYBER_MOCK_MODEL_BLOCK'

status="$(curl --silent --show-error -o "${WORKDIR}/audit-invalid.json" -w '%{http_code}' \\
'''
replacement = '''contains "${WORKDIR}/model-block.json" 'CYBER_MOCK_MODEL_BLOCK'

status="$(curl --silent --show-error -o "${WORKDIR}/audit-thinking.json" -w '%{http_code}' \\
  "${gateway}" "${gateway_auth[@]}" \\
  --data-binary '{"model":"normal","messages":[{"role":"user","content":"model-audit-thinking-json"}]}')"
assert_status 200 "${status}" "${WORKDIR}/audit-thinking.json"
contains "${WORKDIR}/audit-thinking.json" 'mock provider success'

status="$(curl --silent --show-error -o "${WORKDIR}/audit-http-401.json" -w '%{http_code}' \\
  "${gateway}" "${gateway_auth[@]}" \\
  --data-binary '{"model":"normal","messages":[{"role":"user","content":"model-audit-http-401"}]}')"
assert_status 555 "${status}" "${WORKDIR}/audit-http-401.json"
contains "${WORKDIR}/audit-http-401.json" 'AUDIT_MODEL_ERROR'

status="$(curl --silent --show-error -o "${WORKDIR}/audit-invalid.json" -w '%{http_code}' \\
'''
text = replace_once(text, anchor, replacement, "E2E audit diagnostics requests")
anchor = '''[[ "${trace_ok}" == 1 ]] || fail "expected gateway and New API traces were not persisted"


trace_from="$(date -u -d '10 minutes ago' '+%Y-%m-%dT%H:%M:%SZ')"'''
replacement = '''[[ "${trace_ok}" == 1 ]] || fail "expected gateway and New API traces were not persisted"

TRACE_FILE="${WORKDIR}/traces.json" python3 - <<'PY'
import json
import os

with open(os.environ["TRACE_FILE"], encoding="utf-8") as handle:
    items = json.load(handle).get("items", [])
errors = [item for item in items if item.get("risk_code") == "AUDIT_MODEL_ERROR"]
if not errors:
    raise RuntimeError("AUDIT_MODEL_ERROR trace is missing")
classes = {item.get("metadata", {}).get("audit_error_class") for item in errors}
if "invalid_json" not in classes:
    raise RuntimeError(f"invalid_json audit diagnostic missing: {classes}")
if "authentication" not in classes:
    raise RuntimeError(f"authentication audit diagnostic missing: {classes}")
for item in errors:
    metadata = item.get("metadata", {})
    if not metadata.get("audit_reason") or not metadata.get("error_reason"):
        raise RuntimeError(f"audit error trace is missing readable reason: {item}")
if not any(item.get("metadata", {}).get("audit_http_status") == 401 for item in errors):
    raise RuntimeError("audit HTTP status 401 was not persisted")
PY


trace_from="$(date -u -d '10 minutes ago' '+%Y-%m-%dT%H:%M:%SZ')"'''
text = replace_once(text, anchor, replacement, "E2E trace diagnostic persistence")
path.write_text(text, encoding="utf-8")

print("audit diagnostics integration patch applied")
