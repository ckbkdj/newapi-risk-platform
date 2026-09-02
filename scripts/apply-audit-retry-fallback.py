from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def replace_once(path: str, old: str, new: str, label: str):
    p = ROOT / path
    text = p.read_text(encoding="utf-8")
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected 1 match, found {count}")
    p.write_text(text.replace(old, new, 1), encoding="utf-8")


# ---------------------------------------------------------------------------
# Types
# ---------------------------------------------------------------------------
replace_once(
    "internal/platform/types.go",
    '''\tIsDefault        bool            `json:"is_default"`\n\tExtra            json.RawMessage `json:"extra,omitempty"`\n''',
    '''\tIsDefault          bool            `json:"is_default"`\n\tRetryCount         int             `json:"retry_count"`\n\tFallbackProfileIDs []int64         `json:"fallback_profile_ids"`\n\tExtra              json.RawMessage `json:"extra,omitempty"`\n''',
    "AuditProfile fields",
)
replace_once(
    "internal/platform/types.go",
    '''\tIsDefault      bool            `json:"is_default"`\n\tExtra          json.RawMessage `json:"extra"`\n''',
    '''\tIsDefault          bool            `json:"is_default"`\n\tRetryCount         int             `json:"retry_count"`\n\tFallbackProfileIDs []int64         `json:"fallback_profile_ids"`\n\tExtra              json.RawMessage `json:"extra"`\n''',
    "AuditProfileInput fields",
)
replace_once(
    "internal/platform/types.go",
    '''type AuditResult struct {\n\tAuditDecision\n''',
    '''type AuditAttempt struct {\n\tProfileID   int64  `json:"profile_id"`\n\tProfileName string `json:"profile_name"`\n\tModel       string `json:"model"`\n\tAttempt     int    `json:"attempt"`\n\tSuccess     bool   `json:"success"`\n\tErrorClass  string `json:"error_class,omitempty"`\n\tHTTPStatus  int    `json:"http_status,omitempty"`\n\tReason      string `json:"reason,omitempty"`\n}\n\ntype AuditResult struct {\n\tAuditDecision\n''',
    "AuditAttempt type",
)
replace_once(
    "internal/platform/types.go",
    '''\tAuditRetryCount          int           `json:"audit_retry_count,omitempty"`\n}\n''',
    '''\tAuditRetryCount          int           `json:"audit_retry_count,omitempty"`\n\tAuditProfileID           int64         `json:"audit_profile_id,omitempty"`\n\tAuditProfileName         string        `json:"audit_profile_name,omitempty"`\n\tAuditModelAttempts       int           `json:"audit_model_attempts,omitempty"`\n\tAuditModelRetries        int           `json:"audit_model_retries,omitempty"`\n\tAuditFallbackCount       int           `json:"audit_fallback_count,omitempty"`\n\tAuditModelsTried         []string      `json:"audit_models_tried,omitempty"`\n\tAuditTokensOverLimit     int           `json:"audit_tokens_over_limit,omitempty"`\n\tAuditAttempts            []AuditAttempt `json:"audit_attempts,omitempty"`\n}\n''',
    "AuditResult failover fields",
)

# ---------------------------------------------------------------------------
# Store persistence
# ---------------------------------------------------------------------------
replace_once(
    "internal/platform/store.go",
    '''const profileColumns = `id,name,endpoint,model,system_prompt,timeout_ms,block_threshold,enabled,\n\tfail_closed,is_default,extra,api_key_ciphertext,created_at,updated_at`\n''',
    '''const profileColumns = `id,name,endpoint,model,system_prompt,timeout_ms,block_threshold,enabled,\n\tfail_closed,is_default,retry_count,fallback_profile_ids,extra,api_key_ciphertext,created_at,updated_at`\n''',
    "profileColumns",
)
replace_once(
    "internal/platform/store.go",
    '''\t\t&profile.TimeoutMS, &profile.BlockThreshold, &profile.Enabled, &profile.FailClosed,\n\t\t&profile.IsDefault, &extra, &profile.APIKeyCiphertext, &profile.CreatedAt, &profile.UpdatedAt,\n''',
    '''\t\t&profile.TimeoutMS, &profile.BlockThreshold, &profile.Enabled, &profile.FailClosed,\n\t\t&profile.IsDefault, &profile.RetryCount, &profile.FallbackProfileIDs, &extra,\n\t\t&profile.APIKeyCiphertext, &profile.CreatedAt, &profile.UpdatedAt,\n''',
    "scanProfile",
)
replace_once(
    "internal/platform/store.go",
    '''\tif len(input.Extra) == 0 {\n\t\tinput.Extra = json.RawMessage(`{}`)\n\t}\n''',
    '''\tif len(input.Extra) == 0 {\n\t\tinput.Extra = json.RawMessage(`{}`)\n\t}\n\tif input.FallbackProfileIDs == nil {\n\t\tinput.FallbackProfileIDs = []int64{}\n\t}\n''',
    "SaveAuditProfile defaults",
)
replace_once(
    "internal/platform/store.go",
    '''\t\tprofile, err = scanProfile(transaction.QueryRow(ctx, `INSERT INTO audit_profiles\n\t\t\t(name,endpoint,model,api_key_ciphertext,system_prompt,timeout_ms,block_threshold,\n\t\t\tenabled,fail_closed,is_default,extra)\n\t\t\tVALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) RETURNING `+profileColumns,\n\t\t\tinput.Name, input.Endpoint, input.Model, ciphertext, input.SystemPrompt, input.TimeoutMS,\n\t\t\tinput.BlockThreshold, input.Enabled, input.FailClosed, input.IsDefault, input.Extra))\n''',
    '''\t\tprofile, err = scanProfile(transaction.QueryRow(ctx, `INSERT INTO audit_profiles\n\t\t\t(name,endpoint,model,api_key_ciphertext,system_prompt,timeout_ms,block_threshold,\n\t\t\tenabled,fail_closed,is_default,retry_count,fallback_profile_ids,extra)\n\t\t\tVALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13) RETURNING `+profileColumns,\n\t\t\tinput.Name, input.Endpoint, input.Model, ciphertext, input.SystemPrompt, input.TimeoutMS,\n\t\t\tinput.BlockThreshold, input.Enabled, input.FailClosed, input.IsDefault, input.RetryCount,\n\t\t\tinput.FallbackProfileIDs, input.Extra))\n''',
    "insert audit profile",
)
replace_once(
    "internal/platform/store.go",
    '''\t\tprofile, err = scanProfile(transaction.QueryRow(ctx, `UPDATE audit_profiles SET name=$2,\n\t\t\tendpoint=$3,model=$4,api_key_ciphertext=$5,system_prompt=$6,timeout_ms=$7,\n\t\t\tblock_threshold=$8,enabled=$9,fail_closed=$10,is_default=$11,extra=$12,updated_at=now()\n\t\t\tWHERE id=$1 RETURNING `+profileColumns,\n\t\t\tinput.ID, input.Name, input.Endpoint, input.Model, ciphertext, input.SystemPrompt, input.TimeoutMS,\n\t\t\tinput.BlockThreshold, input.Enabled, input.FailClosed, input.IsDefault, input.Extra))\n''',
    '''\t\tprofile, err = scanProfile(transaction.QueryRow(ctx, `UPDATE audit_profiles SET name=$2,\n\t\t\tendpoint=$3,model=$4,api_key_ciphertext=$5,system_prompt=$6,timeout_ms=$7,\n\t\t\tblock_threshold=$8,enabled=$9,fail_closed=$10,is_default=$11,retry_count=$12,\n\t\t\tfallback_profile_ids=$13,extra=$14,updated_at=now()\n\t\t\tWHERE id=$1 RETURNING `+profileColumns,\n\t\t\tinput.ID, input.Name, input.Endpoint, input.Model, ciphertext, input.SystemPrompt, input.TimeoutMS,\n\t\t\tinput.BlockThreshold, input.Enabled, input.FailClosed, input.IsDefault, input.RetryCount,\n\t\t\tinput.FallbackProfileIDs, input.Extra))\n''',
    "update audit profile",
)
replace_once(
    "internal/platform/store.go",
    '''func (s *Store) DeleteAuditProfile(ctx context.Context, id int64) error {\n\tcommand, err := s.pool.Exec(ctx,\n\t\t"DELETE FROM audit_profiles WHERE id=$1 AND is_default=FALSE", id)\n''',
    '''func (s *Store) DeleteAuditProfile(ctx context.Context, id int64) error {\n\t_, _ = s.pool.Exec(ctx, `UPDATE audit_profiles SET fallback_profile_ids=array_remove(fallback_profile_ids,$1),updated_at=now()\n\t\tWHERE $1=ANY(fallback_profile_ids)`, id)\n\tcommand, err := s.pool.Exec(ctx,\n\t\t"DELETE FROM audit_profiles WHERE id=$1 AND is_default=FALSE", id)\n''',
    "delete fallback cleanup",
)

# ---------------------------------------------------------------------------
# Audit execution
# ---------------------------------------------------------------------------
replace_once(
    "internal/platform/audit.go",
    '''\tdecision, callMetadata, err := e.callModel(ctx, profile, text)\n\tresult.Model = profile.Model\n\tresult.AuditMode = callMetadata.Mode\n\tresult.AuditChunkCount = callMetadata.ChunkCount\n\tresult.AuditChunkBytes = callMetadata.ChunkBytes\n\tresult.AuditRequestedTokens = callMetadata.RequestedTokens\n\tresult.AuditContextWindowTokens = callMetadata.ContextWindowTokens\n\tresult.AuditRetryCount = callMetadata.RetryCount\n''',
    '''\tdecision, usedProfile, failoverMetadata, err := e.callModelWithFailover(ctx, profile, text)\n\tcallMetadata := failoverMetadata.CallMetadata\n\tresult.Model = usedProfile.Model\n\tresult.AuditProfileID = usedProfile.ID\n\tresult.AuditProfileName = usedProfile.Name\n\tresult.AuditMode = callMetadata.Mode\n\tresult.AuditChunkCount = callMetadata.ChunkCount\n\tresult.AuditChunkBytes = callMetadata.ChunkBytes\n\tresult.AuditRequestedTokens = callMetadata.RequestedTokens\n\tresult.AuditContextWindowTokens = callMetadata.ContextWindowTokens\n\tresult.AuditRetryCount = callMetadata.RetryCount\n\tresult.AuditModelAttempts = failoverMetadata.AttemptCount\n\tresult.AuditModelRetries = failoverMetadata.ModelRetryCount\n\tresult.AuditFallbackCount = failoverMetadata.FallbackCount\n\tresult.AuditAttempts = append([]AuditAttempt(nil), failoverMetadata.Attempts...)\n\tresult.AuditModelsTried = auditAttemptModelNames(failoverMetadata.Attempts)\n\tif result.AuditRequestedTokens > result.AuditContextWindowTokens && result.AuditContextWindowTokens > 0 {\n\t\tresult.AuditTokensOverLimit = result.AuditRequestedTokens - result.AuditContextWindowTokens\n\t}\n''',
    "Audit call failover",
)
replace_once(
    "internal/platform/audit.go",
    '''\tif decision.Decision == DecisionBlock && decision.Confidence < profile.BlockThreshold {\n''',
    '''\tif decision.Decision == DecisionBlock && decision.Confidence < usedProfile.BlockThreshold {\n''',
    "selected profile block threshold",
)
replace_once(
    "internal/platform/audit.go",
    '''\tif decision.Decision == DecisionReview && (route.FailClosed || profile.FailClosed) {\n''',
    '''\tif decision.Decision == DecisionReview && (route.FailClosed || usedProfile.FailClosed) {\n''',
    "selected profile review fail closed",
)

# ---------------------------------------------------------------------------
# Admin validation and trace metadata
# ---------------------------------------------------------------------------
replace_once(
    "internal/platform/admin.go",
    '''\tif input.TimeoutMS != 0 && (input.TimeoutMS < 250 || input.TimeoutMS > 120000) {\n\t\twriteAPIError(w, http.StatusBadRequest, "invalid_profile", "audit timeout is invalid")\n\t\treturn\n\t}\n''',
    '''\tif input.TimeoutMS != 0 && (input.TimeoutMS < 250 || input.TimeoutMS > 120000) {\n\t\twriteAPIError(w, http.StatusBadRequest, "invalid_profile", "audit timeout is invalid")\n\t\treturn\n\t}\n\tif input.RetryCount < 0 || input.RetryCount > maxAuditRetryCount {\n\t\twriteAPIError(w, http.StatusBadRequest, "invalid_profile", "audit retry count must be between 0 and 5")\n\t\treturn\n\t}\n\tif err := s.store.ValidateAuditFallbackProfiles(r.Context(), input.ID, input.FallbackProfileIDs); err != nil {\n\t\twriteAPIError(w, http.StatusBadRequest, "invalid_fallback_chain", err.Error())\n\t\treturn\n\t}\n''',
    "admin retry/fallback validation",
)
replace_once(
    "internal/platform/admin.go",
    '''\ts.auditAdmin(r, "save", "audit_profile", strconv.FormatInt(profile.ID, 10), map[string]any{\n\t\t"name":  profile.Name,\n\t\t"model": profile.Model,\n\t})\n''',
    '''\ts.auditAdmin(r, "save", "audit_profile", strconv.FormatInt(profile.ID, 10), map[string]any{\n\t\t"name":             profile.Name,\n\t\t"model":            profile.Model,\n\t\t"retry_count":      profile.RetryCount,\n\t\t"fallback_profiles": profile.FallbackProfileIDs,\n\t})\n''',
    "audit admin fields",
)
replace_once(
    "internal/platform/gateway.go",
    '''\tif auditResult.AuditRetryCount > 0 {\n\t\ttrace.Metadata["audit_retry_count"] = auditResult.AuditRetryCount\n\t}\n''',
    '''\tif auditResult.AuditRetryCount > 0 {\n\t\ttrace.Metadata["audit_retry_count"] = auditResult.AuditRetryCount\n\t\ttrace.Metadata["audit_chunk_retry_count"] = auditResult.AuditRetryCount\n\t}\n\tif auditResult.AuditRequestedTokens > 0 {\n\t\ttrace.Metadata["audit_input_tokens"] = auditResult.AuditRequestedTokens\n\t}\n\tif auditResult.AuditTokensOverLimit > 0 {\n\t\ttrace.Metadata["audit_tokens_over_limit"] = auditResult.AuditTokensOverLimit\n\t}\n\tif auditResult.AuditProfileID > 0 {\n\t\ttrace.Metadata["audit_profile_id"] = auditResult.AuditProfileID\n\t}\n\tif auditResult.AuditProfileName != "" {\n\t\ttrace.Metadata["audit_profile_name"] = auditResult.AuditProfileName\n\t}\n\tif auditResult.AuditModelAttempts > 0 {\n\t\ttrace.Metadata["audit_model_attempts"] = auditResult.AuditModelAttempts\n\t}\n\tif auditResult.AuditModelRetries > 0 {\n\t\ttrace.Metadata["audit_model_retries"] = auditResult.AuditModelRetries\n\t}\n\tif auditResult.AuditFallbackCount > 0 {\n\t\ttrace.Metadata["audit_fallback_count"] = auditResult.AuditFallbackCount\n\t}\n\tif len(auditResult.AuditModelsTried) > 0 {\n\t\ttrace.Metadata["audit_models_tried"] = auditResult.AuditModelsTried\n\t}\n\tif len(auditResult.AuditAttempts) > 0 {\n\t\ttrace.Metadata["audit_attempts"] = auditResult.AuditAttempts\n\t}\n''',
    "gateway failover trace metadata",
)

# ---------------------------------------------------------------------------
# Mock provider: deterministic failed audit model for E2E fallback chain.
# ---------------------------------------------------------------------------
replace_once(
    "cmd/mockprovider/main.go",
    '''\ttext := strings.ToLower(messageText(request))\n\tuserText := strings.ToLower(userMessageText(request))\n''',
    '''\ttext := strings.ToLower(messageText(request))\n\tuserText := strings.ToLower(userMessageText(request))\n\tif strings.EqualFold(request.Model, "audit-always-503") {\n\t\twriteJSON(w, http.StatusServiceUnavailable, map[string]any{\n\t\t\t"error": map[string]any{"message": "mock transient audit service failure", "type": "server_error"},\n\t\t})\n\t\treturn\n\t}\n''',
    "mock audit failure model",
)

# ---------------------------------------------------------------------------
# Web UI
# ---------------------------------------------------------------------------
replace_once(
    "internal/platform/web/index.html",
    '''                <div class=\"field\"><label for=\"profile-timeout\">超时（毫秒）</label><input id=\"profile-timeout\" type=\"number\" min=\"250\" value=\"8000\"></div>\n                <div class=\"field\"><label for=\"profile-threshold\">拦截阈值</label><input id=\"profile-threshold\" type=\"number\" min=\"0\" max=\"1\" step=\"0.01\" value=\"0.65\"></div>\n''',
    '''                <div class=\"field\"><label for=\"profile-timeout\">超时（毫秒）</label><input id=\"profile-timeout\" type=\"number\" min=\"250\" value=\"8000\"></div>\n                <div class=\"field\"><label for=\"profile-threshold\">拦截阈值</label><input id=\"profile-threshold\" type=\"number\" min=\"0\" max=\"1\" step=\"0.01\" value=\"0.65\"></div>\n                <div class=\"field\"><label for=\"profile-retry-count\">模型失败重试次数</label><input id=\"profile-retry-count\" type=\"number\" min=\"0\" max=\"5\" value=\"2\"><small>初次调用失败后，连接/超时/429/5xx 等瞬时错误最多再试 N 次。</small></div>\n                <div class=\"field wide\"><label>备用审计模型链</label><div class=\"actions\"><select id=\"profile-fallback-add\"><option value=\"\">选择备用模型</option></select><button id=\"profile-fallback-add-button\" class=\"btn btn-secondary\" type=\"button\">加入备用链</button></div><div id=\"profile-fallback-chain\" class=\"grid\"></div><small>主模型重试耗尽或出现确定性配置/上下文错误后，按这里的顺序切换。block/review 不会触发切换。</small></div>\n''',
    "profile retry/fallback form",
)
replace_once(
    "internal/platform/web/index.html",
    '''      const state = { token: sessionStorage.getItem('risk_token') || '', user: null, view: 'dashboard', routes: [], profiles: [], rules: [], clients: [], traceItems: [], traceTotal: 0, traceOffset: 0, traceLimit: 100 };\n''',
    '''      const state = { token: sessionStorage.getItem('risk_token') || '', user: null, view: 'dashboard', routes: [], profiles: [], profileFallbackChain: [], rules: [], clients: [], traceItems: [], traceTotal: 0, traceOffset: 0, traceLimit: 100 };\n''',
    "web state fallback chain",
)
replace_once(
    "internal/platform/web/index.html",
    '''      function fillProfileOptions() {\n        const options=state.profiles.map(profile=>`<option value=\"${profile.id}\">${escapeHTML(profile.name)}${profile.is_default?'（默认）':''}</option>`).join('');\n        $('route-profile').innerHTML=`<option value=\"\">默认模型</option>${options}`; $('dry-run-profile').innerHTML=`<option value=\"\">默认模型</option>${options}`;\n      }\n''',
    '''      function fillProfileOptions() {\n        const options=state.profiles.map(profile=>`<option value=\"${profile.id}\">${escapeHTML(profile.name)}${profile.is_default?'（默认）':''}</option>`).join('');\n        $('route-profile').innerHTML=`<option value=\"\">默认模型</option>${options}`; $('dry-run-profile').innerHTML=`<option value=\"\">默认模型</option>${options}`;\n        fillFallbackProfileOptions();\n      }\n      function fillFallbackProfileOptions() {\n        const select=$('profile-fallback-add'); if(!select)return;\n        const current=Number($('profile-id').value||0); const selected=new Set(state.profileFallbackChain.map(Number));\n        const options=state.profiles.filter(profile=>profile.id!==current&&!selected.has(Number(profile.id))).map(profile=>`<option value=\"${profile.id}\">${escapeHTML(profile.name)} · ${escapeHTML(profile.model)}</option>`).join('');\n        select.innerHTML=`<option value=\"\">选择备用模型</option>${options}`; renderFallbackChain();\n      }\n      function renderFallbackChain() {\n        const container=$('profile-fallback-chain'); if(!container)return;\n        if(!state.profileFallbackChain.length){container.innerHTML='<div class=\"muted\">未配置备用模型</div>';return;}\n        container.innerHTML=state.profileFallbackChain.map((id,index)=>{const profile=state.profiles.find(item=>Number(item.id)===Number(id));const label=profile?`${profile.name} · ${profile.model}`:`#${id}`;return `<div class=\"notice\"><strong>${index+1}. ${escapeHTML(label)}</strong><div class=\"actions\"><button class=\"btn btn-small btn-secondary\" type=\"button\" data-fallback-up=\"${index}\" ${index===0?'disabled':''}>上移</button><button class=\"btn btn-small btn-secondary\" type=\"button\" data-fallback-down=\"${index}\" ${index===state.profileFallbackChain.length-1?'disabled':''}>下移</button><button class=\"btn btn-small btn-danger\" type=\"button\" data-fallback-remove=\"${index}\">移除</button></div></div>`;}).join('');\n      }\n      function addFallbackProfile(){const id=Number($('profile-fallback-add').value||0);if(!id||state.profileFallbackChain.includes(id))return;state.profileFallbackChain.push(id);fillFallbackProfileOptions();}\n      function moveFallbackProfile(index,direction){const next=index+direction;if(index<0||next<0||index>=state.profileFallbackChain.length||next>=state.profileFallbackChain.length)return;[state.profileFallbackChain[index],state.profileFallbackChain[next]]=[state.profileFallbackChain[next],state.profileFallbackChain[index]];fillFallbackProfileOptions();}\n      function removeFallbackProfile(index){if(index<0||index>=state.profileFallbackChain.length)return;state.profileFallbackChain.splice(index,1);fillFallbackProfileOptions();}\n''',
    "fallback chain UI helpers",
)
replace_once(
    "internal/platform/web/index.html",
    '''      async function loadProfiles() { await ensureProfiles(); $('profiles-table').innerHTML=state.profiles.length?`<div class=\"table-wrap\"><table><thead><tr><th>名称</th><th>模型</th><th>策略</th><th>状态</th><th>操作</th></tr></thead><tbody>${state.profiles.map(profile=>`<tr><td><strong>${escapeHTML(profile.name)}</strong><br><span class=\"muted\">${escapeHTML(profile.endpoint)}</span></td><td>${escapeHTML(profile.model)}<br>${profile.api_key_configured?'已配置 Key':'无 Key'}</td><td>阈值 ${profile.block_threshold}<br>${profile.fail_closed?badge('fail-closed'):badge('fail-open')}</td><td>${profile.is_default?badge('default'):badge(profile.enabled?'enabled':'disabled')}</td><td><button class=\"btn btn-small btn-secondary\" data-profile-test=\"${profile.id}\">测试</button> <button class=\"btn btn-small btn-secondary\" data-profile-edit=\"${profile.id}\">编辑</button> <button class=\"btn btn-small btn-danger\" data-profile-delete=\"${profile.id}\" ${profile.is_default?'disabled':''}>删除</button></td></tr>`).join('')}</tbody></table></div>`:'<div class=\"empty\">尚未配置审计模型</div>'; }\n      function resetProfile() { $('profile-form').reset(); $('profile-id').value=''; $('profile-form-title').textContent='新增模型'; $('profile-timeout').value='8000'; $('profile-threshold').value='0.65'; $('profile-extra').value='{}'; $('profile-enabled').checked=true; $('profile-fail-closed').checked=true; $('profile-default').checked=false; }\n      function editProfile(id) { const profile=state.profiles.find(item=>item.id===Number(id));if(!profile)return;$('profile-id').value=profile.id;$('profile-name').value=profile.name;$('profile-endpoint').value=profile.endpoint;$('profile-model').value=profile.model;$('profile-api-key').value='';$('profile-system-prompt').value=profile.system_prompt||'';$('profile-timeout').value=profile.timeout_ms;$('profile-threshold').value=profile.block_threshold;$('profile-extra').value=JSON.stringify(profile.extra||{},null,2);$('profile-enabled').checked=profile.enabled;$('profile-fail-closed').checked=profile.fail_closed;$('profile-default').checked=profile.is_default;$('profile-form-title').textContent=`编辑模型 #${profile.id}`;$('profile-form').scrollIntoView({behavior:'smooth',block:'start'}); }\n''',
    '''      async function loadProfiles() { await ensureProfiles(); $('profiles-table').innerHTML=state.profiles.length?`<div class=\"table-wrap\"><table><thead><tr><th>名称</th><th>模型</th><th>策略</th><th>状态</th><th>操作</th></tr></thead><tbody>${state.profiles.map(profile=>`<tr><td><strong>${escapeHTML(profile.name)}</strong><br><span class=\"muted\">${escapeHTML(profile.endpoint)}</span></td><td>${escapeHTML(profile.model)}<br>${profile.api_key_configured?'已配置 Key':'无 Key'}</td><td>阈值 ${profile.block_threshold}<br>失败重试 ${number(profile.retry_count||0)} 次 · 备用 ${number((profile.fallback_profile_ids||[]).length)} 个<br>${profile.fail_closed?badge('fail-closed'):badge('fail-open')}</td><td>${profile.is_default?badge('default'):badge(profile.enabled?'enabled':'disabled')}</td><td><button class=\"btn btn-small btn-secondary\" data-profile-test=\"${profile.id}\">测试</button> <button class=\"btn btn-small btn-secondary\" data-profile-edit=\"${profile.id}\">编辑</button> <button class=\"btn btn-small btn-danger\" data-profile-delete=\"${profile.id}\" ${profile.is_default?'disabled':''}>删除</button></td></tr>`).join('')}</tbody></table></div>`:'<div class=\"empty\">尚未配置审计模型</div>'; fillFallbackProfileOptions(); }\n      function resetProfile() { $('profile-form').reset(); $('profile-id').value=''; $('profile-form-title').textContent='新增模型'; $('profile-timeout').value='8000'; $('profile-threshold').value='0.65'; $('profile-retry-count').value='2'; $('profile-extra').value='{}'; state.profileFallbackChain=[]; $('profile-enabled').checked=true; $('profile-fail-closed').checked=true; $('profile-default').checked=false; fillFallbackProfileOptions(); }\n      function editProfile(id) { const profile=state.profiles.find(item=>item.id===Number(id));if(!profile)return;$('profile-id').value=profile.id;$('profile-name').value=profile.name;$('profile-endpoint').value=profile.endpoint;$('profile-model').value=profile.model;$('profile-api-key').value='';$('profile-system-prompt').value=profile.system_prompt||'';$('profile-timeout').value=profile.timeout_ms;$('profile-threshold').value=profile.block_threshold;$('profile-retry-count').value=profile.retry_count??2;$('profile-extra').value=JSON.stringify(profile.extra||{},null,2);state.profileFallbackChain=(profile.fallback_profile_ids||[]).map(Number);$('profile-enabled').checked=profile.enabled;$('profile-fail-closed').checked=profile.fail_closed;$('profile-default').checked=profile.is_default;$('profile-form-title').textContent=`编辑模型 #${profile.id}`;fillFallbackProfileOptions();$('profile-form').scrollIntoView({behavior:'smooth',block:'start'}); }\n''',
    "profile table/reset/edit",
)
replace_once(
    "internal/platform/web/index.html",
    '''      async function saveProfile(event) { event.preventDefault();let extra;try{extra=JSON.parse($('profile-extra').value||'{}');}catch{toast('额外参数不是合法 JSON','error');return;}const payload={id:Number($('profile-id').value||0),name:$('profile-name').value,endpoint:$('profile-endpoint').value,model:$('profile-model').value,api_key:$('profile-api-key').value,system_prompt:$('profile-system-prompt').value,timeout_ms:Number($('profile-timeout').value),block_threshold:Number($('profile-threshold').value),enabled:$('profile-enabled').checked,fail_closed:$('profile-fail-closed').checked,is_default:$('profile-default').checked,extra};try{await api('/api/admin/v1/audit-profiles',{method:'POST',body:JSON.stringify(payload)});toast('审计模型已保存');resetProfile();await loadProfiles();}catch(error){toast(error.message,'error');} }\n''',
    '''      async function saveProfile(event) { event.preventDefault();let extra;try{extra=JSON.parse($('profile-extra').value||'{}');}catch{toast('额外参数不是合法 JSON','error');return;}const payload={id:Number($('profile-id').value||0),name:$('profile-name').value,endpoint:$('profile-endpoint').value,model:$('profile-model').value,api_key:$('profile-api-key').value,system_prompt:$('profile-system-prompt').value,timeout_ms:Number($('profile-timeout').value),block_threshold:Number($('profile-threshold').value),retry_count:Number($('profile-retry-count').value||0),fallback_profile_ids:[...state.profileFallbackChain],enabled:$('profile-enabled').checked,fail_closed:$('profile-fail-closed').checked,is_default:$('profile-default').checked,extra};try{await api('/api/admin/v1/audit-profiles',{method:'POST',body:JSON.stringify(payload)});toast('审计模型已保存');resetProfile();await loadProfiles();}catch(error){toast(error.message,'error');} }\n''',
    "save profile retry/fallback",
)
replace_once(
    "internal/platform/web/index.html",
    '''          const errorClass=item.metadata?.audit_error_class||'';\n          return `<tr><td><strong>${escapeHTML(detailedDateText(item.created_at))}</strong><span class=\"trace-subline\">浏览器本地时间</span></td><td><span class=\"mono trace-request-id\">${escapeHTML(item.request_id)}</span><span class=\"trace-subline mono\">New API: ${escapeHTML(item.newapi_request_id||'-')}</span></td><td>${user}<span class=\"trace-subline\">租户：${escapeHTML(tenant)}</span></td><td>${escapeHTML(item.source||'-')}<span class=\"trace-subline mono\">${escapeHTML(item.route_slug||'-')}</span></td><td>${escapeHTML(item.model||'-')}<span class=\"trace-subline mono\">${escapeHTML(item.endpoint||'-')}</span></td><td>${badge(item.decision||'unknown')}<span class=\"trace-subline mono\">${escapeHTML(item.risk_code||'-')}</span></td><td><span class=\"trace-reason\">${escapeHTML(reason)}</span>${errorClass?`<span class=\"trace-error-class\">${escapeHTML(errorClass)}${item.metadata?.audit_http_status?` · HTTP ${escapeHTML(item.metadata.audit_http_status)}`:''}</span>`:''}</td><td>HTTP ${item.http_status||'-'} / 上游 ${item.upstream_status||'-'}<span class=\"trace-subline\">总计 ${number(item.latency_ms)} ms · 审计 ${number(item.audit_latency_ms)} ms</span></td><td><button class=\"btn btn-small btn-secondary\" type=\"button\" data-trace-detail-index=\"${index}\">详情</button></td></tr>`;\n''',
    '''          const errorClass=item.metadata?.audit_error_class||'';\n          const inputTokens=Number(item.metadata?.audit_input_tokens||item.metadata?.audit_requested_tokens||0);const contextTokens=Number(item.metadata?.audit_context_window_tokens||0);const overTokens=Number(item.metadata?.audit_tokens_over_limit||0);const tokenLine=inputTokens?`<span class=\"trace-subline mono\">Tokens ${number(inputTokens)}${contextTokens?` / ${number(contextTokens)}`:''}${overTokens?` · 超 ${number(overTokens)}`:''}</span>`:'';\n          return `<tr><td><strong>${escapeHTML(detailedDateText(item.created_at))}</strong><span class=\"trace-subline\">浏览器本地时间</span></td><td><span class=\"mono trace-request-id\">${escapeHTML(item.request_id)}</span><span class=\"trace-subline mono\">New API: ${escapeHTML(item.newapi_request_id||'-')}</span></td><td>${user}<span class=\"trace-subline\">租户：${escapeHTML(tenant)}</span></td><td>${escapeHTML(item.source||'-')}<span class=\"trace-subline mono\">${escapeHTML(item.route_slug||'-')}</span></td><td>${escapeHTML(item.model||'-')}<span class=\"trace-subline mono\">${escapeHTML(item.endpoint||'-')}</span></td><td>${badge(item.decision||'unknown')}<span class=\"trace-subline mono\">${escapeHTML(item.risk_code||'-')}</span></td><td><span class=\"trace-reason\">${escapeHTML(reason)}</span>${errorClass?`<span class=\"trace-error-class\">${escapeHTML(errorClass)}${item.metadata?.audit_http_status?` · HTTP ${escapeHTML(item.metadata.audit_http_status)}`:''}</span>`:''}${tokenLine}</td><td>HTTP ${item.http_status||'-'} / 上游 ${item.upstream_status||'-'}<span class=\"trace-subline\">总计 ${number(item.latency_ms)} ms · 审计 ${number(item.audit_latency_ms)} ms</span><span class=\"trace-subline\">模型调用 ${number(item.metadata?.audit_model_attempts||0)} · 重试 ${number(item.metadata?.audit_model_retries||0)} · 切换 ${number(item.metadata?.audit_fallback_count||0)}</span></td><td><button class=\"btn btn-small btn-secondary\" type=\"button\" data-trace-detail-index=\"${index}\">详情</button></td></tr>`;\n''',
    "trace table token/failover diagnostics",
)
replace_once(
    "internal/platform/web/index.html",
    '''          ['审计延迟',`${number(item.audit_latency_ms)} ms`], ['请求字节',number(item.request_bytes)], ['响应字节',number(item.response_bytes)],\n          ['Prompt HMAC',item.prompt_hmac||'-']\n''',
    '''          ['审计延迟',`${number(item.audit_latency_ms)} ms`], ['请求字节',number(item.request_bytes)], ['响应字节',number(item.response_bytes)],\n          ['审计输入 Tokens',item.metadata?.audit_input_tokens||item.metadata?.audit_requested_tokens||'-'], ['模型上下文上限',item.metadata?.audit_context_window_tokens||'-'], ['超出 Tokens',item.metadata?.audit_tokens_over_limit||'-'],\n          ['实际审计模型',item.metadata?.audit_profile_name||item.metadata?.audit_model||'-'], ['模型调用次数',item.metadata?.audit_model_attempts||'-'], ['模型重试次数',item.metadata?.audit_model_retries||0], ['备用模型切换',item.metadata?.audit_fallback_count||0], ['模型链',(item.metadata?.audit_models_tried||[]).join(' → ')||'-'],\n          ['Prompt HMAC',item.prompt_hmac||'-']\n''',
    "trace detail token/failover fields",
)
replace_once(
    "internal/platform/web/index.html",
    '''      async function dryRun(event) { event.preventDefault();$('dry-run-result').hidden=true;try{const data=await api('/api/admin/v1/audit/dry-run',{method:'POST',body:JSON.stringify({text:$('dry-run-text').value,profile_id:$('dry-run-profile').value?Number($('dry-run-profile').value):null})});const result=data.result;const diagnostics=[];if(result.error_class)diagnostics.push(`错误分类 ${result.error_class}`);if(result.audit_http_status)diagnostics.push(`审计 HTTP ${result.audit_http_status}`);$('dry-run-result').className=`notice ${(result.decision==='block'||result.error_class)?'warning':''}`;$('dry-run-result').textContent=`${result.decision.toUpperCase()} · ${result.risk_code||'无风险码'} · 置信度 ${result.confidence} · ${data.latency_ms} ms${diagnostics.length?' · '+diagnostics.join(' · '):''} · ${result.reason||''}`;$('dry-run-result').hidden=false;}catch(error){toast(error.message,'error');} }\n''',
    '''      async function dryRun(event) { event.preventDefault();$('dry-run-result').hidden=true;try{const data=await api('/api/admin/v1/audit/dry-run',{method:'POST',body:JSON.stringify({text:$('dry-run-text').value,profile_id:$('dry-run-profile').value?Number($('dry-run-profile').value):null})});const result=data.result;const diagnostics=[];if(result.error_class)diagnostics.push(`错误分类 ${result.error_class}`);if(result.audit_http_status)diagnostics.push(`审计 HTTP ${result.audit_http_status}`);if(result.audit_model_attempts)diagnostics.push(`模型调用 ${result.audit_model_attempts}`);if(result.audit_model_retries)diagnostics.push(`重试 ${result.audit_model_retries}`);if(result.audit_fallback_count)diagnostics.push(`切换备用 ${result.audit_fallback_count}`);if(result.audit_requested_tokens)diagnostics.push(`输入 Tokens ${number(result.audit_requested_tokens)}${result.audit_context_window_tokens?` / 上限 ${number(result.audit_context_window_tokens)}`:''}${result.audit_tokens_over_limit?` / 超 ${number(result.audit_tokens_over_limit)}`:''}`);$('dry-run-result').className=`notice ${(result.decision==='block'||result.error_class)?'warning':''}`;$('dry-run-result').textContent=`${result.decision.toUpperCase()} · ${result.risk_code||'无风险码'} · 置信度 ${result.confidence} · ${data.latency_ms} ms${diagnostics.length?' · '+diagnostics.join(' · '):''} · ${result.reason||''}`;$('dry-run-result').hidden=false;}catch(error){toast(error.message,'error');} }\n''',
    "dry run diagnostics",
)
replace_once(
    "internal/platform/web/index.html",
    '''      $('new-profile-button').addEventListener('click',resetProfile);$('profile-reset').addEventListener('click',resetProfile);$('profile-form').addEventListener('submit',saveProfile);$('profiles-table').addEventListener('click',event=>{const test=event.target.closest('[data-profile-test]');const edit=event.target.closest('[data-profile-edit]');const remove=event.target.closest('[data-profile-delete]');if(test)testProfile(test.dataset.profileTest);if(edit)editProfile(edit.dataset.profileEdit);if(remove&&!remove.disabled)deleteProfile(remove.dataset.profileDelete);});$('dry-run-form').addEventListener('submit',dryRun);\n''',
    '''      $('new-profile-button').addEventListener('click',resetProfile);$('profile-reset').addEventListener('click',resetProfile);$('profile-form').addEventListener('submit',saveProfile);$('profile-fallback-add-button').addEventListener('click',addFallbackProfile);$('profile-fallback-chain').addEventListener('click',event=>{const up=event.target.closest('[data-fallback-up]');const down=event.target.closest('[data-fallback-down]');const removeFallback=event.target.closest('[data-fallback-remove]');if(up&&!up.disabled)moveFallbackProfile(Number(up.dataset.fallbackUp),-1);if(down&&!down.disabled)moveFallbackProfile(Number(down.dataset.fallbackDown),1);if(removeFallback)removeFallbackProfile(Number(removeFallback.dataset.fallbackRemove));});$('profiles-table').addEventListener('click',event=>{const test=event.target.closest('[data-profile-test]');const edit=event.target.closest('[data-profile-edit]');const remove=event.target.closest('[data-profile-delete]');if(test)testProfile(test.dataset.profileTest);if(edit)editProfile(edit.dataset.profileEdit);if(remove&&!remove.disabled)deleteProfile(remove.dataset.profileDelete);});$('dry-run-form').addEventListener('submit',dryRun);\n''',
    "fallback UI event listeners",
)

# ---------------------------------------------------------------------------
# E2E: ordered N-model fallback + default two retries + token visibility.
# ---------------------------------------------------------------------------
replace_once(
    "scripts/e2e.sh",
    '''contains "${WORKDIR}/audit-invalid.json" 'AUDIT_MODEL_ERROR'\n\nstatus="$(curl --silent --show-error -o "${WORKDIR}/upstream-http.json" -w '%{http_code}' \\\n''',
    '''contains "${WORKDIR}/audit-invalid.json" 'AUDIT_MODEL_ERROR'\n\n# Build a 3-model ordered audit chain. The primary retries twice, then the first\n# fallback retries once, then the final Qwen audit model succeeds.\ncreate_profile() {\n  local name="$1" model="$2" retry_count="$3" fallbacks_json="$4" output="$5"\n  local payload\n  payload="$(python3 - <<PY\nimport json\nprint(json.dumps({\n  "id": 0, "name": ${name@Q}, "endpoint": "http://mock-provider:18081/audit/v1",\n  "model": ${model@Q}, "api_key": "", "system_prompt": "", "timeout_ms": 5000,\n  "block_threshold": 0.65, "retry_count": int(${retry_count}),\n  "fallback_profile_ids": json.loads(${fallbacks_json@Q}),\n  "enabled": True, "fail_closed": True, "is_default": False, "extra": {}\n}, separators=(",", ":")))\nPY\n)"\n  curl --fail --silent --show-error "${BASE_URL}/api/admin/v1/audit-profiles" "${auth[@]}" -H 'Content-Type: application/json' --data-binary "${payload}" >"${output}"\n}\n\ncreate_profile "E2E final audit" "qwen3.8-audit-mock" 0 '[]' "${WORKDIR}/profile-final.json"\nFINAL_AUDIT_ID="$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["id"])' "${WORKDIR}/profile-final.json")"\ncreate_profile "E2E middle failing audit" "audit-always-503" 1 '[]' "${WORKDIR}/profile-middle.json"\nMIDDLE_AUDIT_ID="$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["id"])' "${WORKDIR}/profile-middle.json")"\ncreate_profile "E2E primary failing audit" "audit-always-503" 2 "[${MIDDLE_AUDIT_ID},${FINAL_AUDIT_ID}]" "${WORKDIR}/profile-primary.json"\nPRIMARY_AUDIT_ID="$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["id"])' "${WORKDIR}/profile-primary.json")"\n\nFAILOVER_KEY='e2e-failover-route-key-with-sufficient-randomness'\nfailover_route_payload="$(python3 - <<PY\nimport json\nprint(json.dumps({\n  "id":0,"slug":"mock-failover","name":"E2E audit failover route","base_url":"http://mock-provider:18081",\n  "provider":"generic","auth_mode":"none","secret_header":"","upstream_secret":"","inbound_key":"${FAILOVER_KEY}",\n  "audit_profile_id":int("${PRIMARY_AUDIT_ID}"),"enabled":True,"fail_closed":True,"request_timeout_ms":10000,\n  "max_concurrency":50,"rate_limit_rps":1000,"rate_limit_burst":1000\n}, separators=(",", ":")))\nPY\n)"\ncurl --fail --silent --show-error "${BASE_URL}/api/admin/v1/routes" "${auth[@]}" -H 'Content-Type: application/json' --data-binary "${failover_route_payload}" >"${WORKDIR}/failover-route.json"\nstatus="$(curl --silent --show-error -o "${WORKDIR}/failover-response.json" -w '%{http_code}' \\\n  "${BASE_URL}/gateway/mock-failover/v1/chat/completions" \\\n  -H "Authorization: Bearer ${FAILOVER_KEY}" -H 'Content-Type: application/json' -H 'X-Request-ID: e2e-audit-failover' \\\n  --data-binary '{"model":"normal","messages":[{"role":"user","content":"safe failover request"}]}')"\nassert_status 200 "${status}" "${WORKDIR}/failover-response.json"\ncontains "${WORKDIR}/failover-response.json" 'mock provider success'\n\nstatus="$(curl --silent --show-error -o "${WORKDIR}/upstream-http.json" -w '%{http_code}' \\\n''',
    "e2e fallback setup",
)
replace_once(
    "scripts/e2e.sh",
    '''     grep -Fq 'e2e-newapi-request-1' "${WORKDIR}/traces.json"; then\n''',
    '''     grep -Fq 'e2e-newapi-request-1' "${WORKDIR}/traces.json" && \\\n     grep -Fq 'e2e-audit-failover' "${WORKDIR}/traces.json"; then\n''',
    "trace polling fallback",
)
replace_once(
    "scripts/e2e.sh",
    '''    if int(metadata.get("audit_requested_tokens", 0)) <= int(metadata.get("audit_context_window_tokens", 0)):\n        raise RuntimeError(f"{request_id} lacks parsed context-limit counts: {metadata}")\nPY\n''',
    '''    if int(metadata.get("audit_requested_tokens", 0)) <= int(metadata.get("audit_context_window_tokens", 0)):\n        raise RuntimeError(f"{request_id} lacks parsed context-limit counts: {metadata}")\n    if int(metadata.get("audit_input_tokens", 0)) != int(metadata.get("audit_requested_tokens", 0)):\n        raise RuntimeError(f"{request_id} user-facing input token count missing: {metadata}")\n    if int(metadata.get("audit_tokens_over_limit", 0)) != int(metadata.get("audit_requested_tokens", 0)) - int(metadata.get("audit_context_window_tokens", 0)):\n        raise RuntimeError(f"{request_id} over-limit token count is wrong: {metadata}")\nfailover = next((item for item in items if item.get("request_id") == "e2e-audit-failover"), None)\nif not failover:\n    raise RuntimeError("audit failover trace missing")\nfm = failover.get("metadata", {})\nif int(fm.get("audit_model_attempts", 0)) != 6:\n    raise RuntimeError(f"expected six model calls (3 primary + 2 middle + 1 final): {fm}")\nif int(fm.get("audit_model_retries", 0)) != 3:\n    raise RuntimeError(f"expected three same-model retries: {fm}")\nif int(fm.get("audit_fallback_count", 0)) != 2:\n    raise RuntimeError(f"expected two ordered fallback switches: {fm}")\nmodels = fm.get("audit_models_tried", [])\nif models != ["audit-always-503", "qwen3.8-audit-mock"]:\n    raise RuntimeError(f"unexpected model chain: {models}")\nattempts = fm.get("audit_attempts", [])\nif len(attempts) != 6 or not attempts[-1].get("success"):\n    raise RuntimeError(f"attempt diagnostics missing: {attempts}")\nPY\n''',
    "e2e token/fallback assertions",
)

print("audit retry/fallback patch applied")
