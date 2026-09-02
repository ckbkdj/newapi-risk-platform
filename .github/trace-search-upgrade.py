from pathlib import Path
import re


def replace_once(path: Path, old: str, new: str) -> None:
    text = path.read_text(encoding="utf-8")
    count = text.count(old)
    if count != 1:
        raise RuntimeError(f"expected one match in {path}, found {count}: {old[:80]!r}")
    path.write_text(text.replace(old, new, 1), encoding="utf-8")


# Route the existing public endpoint to the richer, backward-compatible search handler.
http_path = Path("internal/platform/http.go")
http_text = http_path.read_text(encoding="utf-8")
old_route = 'admin.Get("/api/admin/v1/traces", s.adminListTraces)'
new_route = 'admin.Get("/api/admin/v1/traces", s.adminSearchTraces)'
if old_route in http_text:
    http_path.write_text(http_text.replace(old_route, new_route, 1), encoding="utf-8")
elif new_route not in http_text:
    raise RuntimeError("trace API route was not found")


ui_path = Path("internal/platform/web/index.html")
ui = ui_path.read_text(encoding="utf-8")

if ".trace-filter-grid" not in ui:
    trace_css = r'''
    .trace-filter-grid{display:grid;grid-template-columns:repeat(4,minmax(160px,1fr));gap:12px;align-items:end}.trace-filter-grid .field{margin-bottom:0}.trace-filter-grid .span-2{grid-column:span 2}.trace-filter-grid .span-3{grid-column:span 3}.trace-actions{display:flex;justify-content:flex-end;gap:8px;flex-wrap:wrap}
    .trace-presets{display:flex;align-items:center;gap:8px;flex-wrap:wrap;margin-bottom:15px}.trace-presets>span{font-size:13px;font-weight:700;color:#475467}.trace-summary{grid-template-columns:repeat(5,minmax(0,1fr))}.trace-summary .metric-value{font-size:24px}.trace-result-meta{font-size:13px;color:#667085}.trace-pagination{display:flex;align-items:center;justify-content:flex-end;gap:9px;margin-top:14px}.trace-table table{min-width:1220px}.trace-user-button{border:0;background:transparent;padding:0;color:#175cd3;text-align:left;font-weight:700}.trace-user-button:hover{text-decoration:underline}.trace-subline{display:block;margin-top:3px;color:#667085;font-size:12px}.trace-request-id{display:block;max-width:290px;word-break:break-all}
    .trace-modal{position:fixed;inset:0;z-index:40;background:rgba(16,24,40,.58);display:grid;place-items:center;padding:20px}.trace-modal-card{width:min(1050px,100%);max-height:90vh;overflow:auto;background:#fff;border-radius:16px;padding:20px;box-shadow:0 24px 80px rgba(0,0,0,.28)}.trace-detail-grid{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:10px;margin-bottom:18px}.trace-detail-grid>div{border:1px solid #e0e7f0;border-radius:9px;padding:10px;min-width:0}.trace-detail-grid span{display:block;color:#667085;font-size:12px;margin-bottom:4px}.trace-detail-grid strong{display:block;word-break:break-all;font-size:13px}.modal-open{overflow:hidden}
    @media(max-width:1100px){.trace-filter-grid{grid-template-columns:repeat(2,minmax(0,1fr))}.trace-filter-grid .span-3{grid-column:span 2}.trace-summary{grid-template-columns:repeat(3,1fr)}.trace-detail-grid{grid-template-columns:repeat(2,1fr)}}
    @media(max-width:760px){.trace-filter-grid,.trace-summary,.trace-detail-grid{grid-template-columns:1fr}.trace-filter-grid .span-2,.trace-filter-grid .span-3{grid-column:auto}.trace-actions,.trace-pagination{justify-content:stretch}.trace-actions .btn,.trace-pagination .btn{flex:1}}
'''
    ui = ui.replace("  </style>", trace_css + "\n  </style>", 1)

if 'id="trace-query"' not in ui:
    trace_section = r'''        <section id="view-traces" class="view" hidden>
          <div class="view-head">
            <div><h2>请求追踪</h2><p>按浏览器本地时间、用户、请求 ID、模型、渠道和风险结果组合查询。默认展示最近 24 小时。</p></div>
          </div>
          <div class="card">
            <div id="trace-presets" class="trace-presets">
              <span>快捷时间</span>
              <button class="btn btn-small btn-secondary" type="button" data-trace-hours="0.25">15 分钟</button>
              <button class="btn btn-small btn-secondary" type="button" data-trace-hours="1">1 小时</button>
              <button class="btn btn-small btn-secondary" type="button" data-trace-hours="24">24 小时</button>
              <button class="btn btn-small btn-secondary" type="button" data-trace-hours="168">7 天</button>
            </div>
            <form id="trace-filter" class="trace-filter-grid" autocomplete="off">
              <div class="field span-2"><label for="trace-query">全局模糊搜索</label><input id="trace-query" placeholder="请求 ID、用户、模型、路由、风险码或租户（至少 3 个字符）"></div>
              <div class="field"><label for="trace-from">开始时间</label><input id="trace-from" type="datetime-local" step="1"></div>
              <div class="field"><label for="trace-to">结束时间</label><input id="trace-to" type="datetime-local" step="1"></div>

              <div class="field"><label for="trace-user">用户标识</label><input id="trace-user" placeholder="X-NewAPI-User-ID / external_user_id"></div>
              <div class="field"><label for="trace-user-match">用户匹配方式</label><select id="trace-user-match"><option value="exact">精确（推荐）</option><option value="prefix">前缀</option><option value="contains">包含（较慢）</option></select></div>
              <div class="field"><label for="trace-request-id">网关 Request ID</label><input id="trace-request-id"></div>
              <div class="field"><label for="trace-newapi-request-id">New API Request ID</label><input id="trace-newapi-request-id"></div>

              <div class="field"><label for="trace-route">路由</label><input id="trace-route" list="trace-route-options" placeholder="openai-main"><datalist id="trace-route-options"></datalist></div>
              <div class="field"><label for="trace-model">模型</label><input id="trace-model" placeholder="支持部分匹配"></div>
              <div class="field"><label for="trace-source">来源</label><select id="trace-source"><option value="">全部</option><option value="gateway">Gateway 自动追踪</option><option value="newapi">New API 主动上报</option></select></div>
              <div class="field"><label for="trace-tenant">租户标识</label><input id="trace-tenant" placeholder="metadata.tenant_id"></div>

              <div class="field"><label for="trace-decision">决策</label><select id="trace-decision"><option value="">全部</option><option value="allow">Allow</option><option value="block">Block</option><option value="error">Error</option><option value="review">Review</option><option value="unknown">Unknown</option></select></div>
              <div class="field"><label for="trace-risk">风险码</label><input id="trace-risk" placeholder="CYBER_* / UPSTREAM_*"></div>
              <div class="field"><label for="trace-http-status">HTTP 状态</label><input id="trace-http-status" type="number" min="0" max="999" placeholder="200 / 555"></div>
              <div class="field"><label for="trace-upstream-status">上游状态</label><input id="trace-upstream-status" type="number" min="0" max="999" placeholder="200 / 429 / 500"></div>

              <div class="field span-2"><label for="trace-endpoint">接口路径</label><input id="trace-endpoint" placeholder="/v1/chat/completions 或 /v1/responses"></div>
              <div class="field"><label for="trace-limit">每页条数</label><select id="trace-limit"><option>50</option><option selected>100</option><option>200</option><option>500</option></select></div>
              <div class="trace-actions"><button id="trace-filter-reset" class="btn btn-secondary" type="button">重置</button><button class="btn btn-primary" type="submit">查询</button></div>
            </form>
          </div>

          <div id="trace-summary" class="grid trace-summary"></div>
          <div class="card">
            <div class="panel-head"><div><h3>匹配请求</h3><div id="trace-results-meta" class="trace-result-meta">尚未查询</div></div><button id="trace-export" class="btn btn-secondary" type="button">导出当前页 CSV</button></div>
            <div id="traces-table"></div>
            <div class="trace-pagination"><button id="trace-prev" class="btn btn-secondary" type="button">上一页</button><span id="trace-page-info" class="muted">第 1 页</span><button id="trace-next" class="btn btn-secondary" type="button">下一页</button></div>
          </div>

          <div id="trace-detail" class="trace-modal" hidden>
            <div class="trace-modal-card" role="dialog" aria-modal="true" aria-labelledby="trace-detail-title">
              <div class="panel-head"><h3 id="trace-detail-title">请求详情</h3><button id="trace-detail-close" class="btn btn-secondary" type="button">关闭</button></div>
              <div id="trace-detail-fields" class="trace-detail-grid"></div>
              <h3>清洗后的元数据</h3>
              <pre id="trace-detail-metadata" class="code"></pre>
            </div>
          </div>
        </section>

        <section id="view-storage"'''
    pattern = re.compile(r'        <section id="view-traces".*?        <section id="view-storage"', re.S)
    ui, replacements = pattern.subn(trace_section, ui, count=1)
    if replacements != 1:
        raise RuntimeError(f"trace section replacement count was {replacements}")

old_state = "const state = { token: sessionStorage.getItem('risk_token') || '', user: null, view: 'dashboard', routes: [], profiles: [], rules: [], clients: [] };"
new_state = "const state = { token: sessionStorage.getItem('risk_token') || '', user: null, view: 'dashboard', routes: [], profiles: [], rules: [], clients: [], traceItems: [], traceTotal: 0, traceOffset: 0, traceLimit: 100 };"
if old_state in ui:
    ui = ui.replace(old_state, new_state, 1)
elif new_state not in ui:
    raise RuntimeError("UI state declaration was not found")

helper_anchor = "      const number = value => new Intl.NumberFormat().format(Number(value || 0));\n"
if "const toLocalInputValue" not in ui:
    helpers = r'''      const number = value => new Intl.NumberFormat().format(Number(value || 0));
      const toLocalInputValue = value => { const date = new Date(value); const local = new Date(date.getTime() - date.getTimezoneOffset() * 60000); return local.toISOString().slice(0,19); };
      const localInputToISO = value => value ? new Date(value).toISOString() : '';
      const csvCell = value => `"${String(value ?? '').replace(/"/g,'""')}"`;
'''
    if helper_anchor not in ui:
        raise RuntimeError("JavaScript helper anchor was not found")
    ui = ui.replace(helper_anchor, helpers, 1)

if "function setTraceRange" not in ui:
    trace_js = r'''      function setTraceRange(hours, refresh=false) {
        const to = new Date();
        const from = new Date(to.getTime() - Number(hours) * 60 * 60 * 1000);
        $('trace-from').value = toLocalInputValue(from);
        $('trace-to').value = toLocalInputValue(to);
        state.traceOffset = 0;
        if (refresh) loadTraces(true).catch(error => toast(error.message,'error'));
      }
      function ensureTraceRange() {
        if (!$('trace-from').value || !$('trace-to').value) setTraceRange(24, false);
      }
      async function ensureTraceRouteOptions() {
        if (!state.routes.length) {
          const data = await api('/api/admin/v1/routes');
          state.routes = data.items || [];
        }
        $('trace-route-options').innerHTML = state.routes.map(route => `<option value="${escapeHTML(route.slug)}">${escapeHTML(route.name)}</option>`).join('');
      }
      function buildTraceParameters() {
        const parameters = new URLSearchParams();
        const fields = [
          ['trace-query','q'], ['trace-request-id','request_id'], ['trace-newapi-request-id','newapi_request_id'],
          ['trace-route','route_slug'], ['trace-user','user_id'], ['trace-tenant','tenant_id'],
          ['trace-model','model'], ['trace-endpoint','endpoint'], ['trace-source','source'],
          ['trace-decision','decision'], ['trace-risk','risk_code'], ['trace-http-status','http_status'],
          ['trace-upstream-status','upstream_status']
        ];
        fields.forEach(([id,name]) => { const value = $(id).value.trim(); if (value) parameters.set(name,value); });
        if ($('trace-user').value.trim()) parameters.set('user_match',$('trace-user-match').value || 'exact');
        const from = localInputToISO($('trace-from').value);
        const to = localInputToISO($('trace-to').value);
        if (from) parameters.set('from',from);
        if (to) parameters.set('to',to);
        parameters.set('limit',String(state.traceLimit));
        parameters.set('offset',String(state.traceOffset));
        return parameters;
      }
      function renderTraceSummary(data) {
        const summary = data.summary || {};
        const cards = [
          ['匹配总数',number(data.total),'当前组合条件'],
          ['已放行',number(summary.allowed_requests),'Allow'],
          ['已拦截',number(summary.blocked_requests),'Block'],
          ['错误',number(summary.error_requests),'Error'],
          ['平均延迟',`${Number(summary.average_latency_ms||0).toFixed(0)} ms`,'匹配结果']
        ];
        $('trace-summary').innerHTML = cards.map(item => `<div class="card"><div class="metric-label">${item[0]}</div><div class="metric-value">${item[1]}</div><div class="metric-sub">${item[2]}</div></div>`).join('');
      }
      function renderTraceTable(items) {
        if (!items.length) {
          $('traces-table').innerHTML = '<div class="empty">没有匹配的追踪记录</div>';
          return;
        }
        $('traces-table').innerHTML = `<div class="table-wrap trace-table"><table><thead><tr><th>时间 / Request ID</th><th>用户 / 租户</th><th>来源 / 路由</th><th>模型 / 接口</th><th>决策 / 风险</th><th>状态 / 延迟</th><th>操作</th></tr></thead><tbody>${items.map((item,index) => {
          const tenant = item.metadata?.tenant_id || '-';
          const user = item.external_user_id ? `<button class="trace-user-button" type="button" data-trace-user-index="${index}">${escapeHTML(item.external_user_id)}</button>` : '-';
          return `<tr><td>${escapeHTML(dateText(item.created_at))}<span class="mono trace-request-id">${escapeHTML(item.request_id)}</span><span class="trace-subline mono">New API: ${escapeHTML(item.newapi_request_id||'-')}</span></td><td>${user}<span class="trace-subline">租户：${escapeHTML(tenant)}</span></td><td>${escapeHTML(item.source||'-')}<span class="trace-subline mono">${escapeHTML(item.route_slug||'-')}</span></td><td>${escapeHTML(item.model||'-')}<span class="trace-subline mono">${escapeHTML(item.endpoint||'-')}</span></td><td>${badge(item.decision||'unknown')}<span class="trace-subline mono">${escapeHTML(item.risk_code||'-')}</span></td><td>HTTP ${item.http_status||'-'} / 上游 ${item.upstream_status||'-'}<span class="trace-subline">总计 ${number(item.latency_ms)} ms · 审计 ${number(item.audit_latency_ms)} ms</span></td><td><button class="btn btn-small btn-secondary" type="button" data-trace-detail-index="${index}">详情</button></td></tr>`;
        }).join('')}</tbody></table></div>`;
      }
      function renderTracePagination(data) {
        const limit = Number(data.limit || state.traceLimit || 100);
        const offset = Number(data.offset || 0);
        const total = Number(data.total || 0);
        const page = Math.floor(offset / limit) + 1;
        const pages = Math.max(1, Math.ceil(total / limit));
        const start = total ? offset + 1 : 0;
        const end = Math.min(offset + state.traceItems.length,total);
        $('trace-page-info').textContent = `第 ${page} / ${pages} 页`;
        $('trace-prev').disabled = offset <= 0;
        $('trace-next').disabled = !data.has_more;
        $('trace-results-meta').textContent = `共 ${number(total)} 条 · 当前 ${number(start)}-${number(end)} · ${dateText(data.from)} 至 ${dateText(data.to)}`;
      }
      async function loadTraces(resetOffset=false) {
        if (resetOffset) state.traceOffset = 0;
        ensureTraceRange();
        await ensureTraceRouteOptions();
        state.traceLimit = Number($('trace-limit').value || 100);
        $('traces-table').innerHTML = '<div class="empty">正在查询…</div>';
        const data = await api(`/api/admin/v1/traces?${buildTraceParameters()}`);
        state.traceItems = data.items || [];
        state.traceTotal = Number(data.total || 0);
        state.traceOffset = Number(data.offset || 0);
        renderTraceSummary(data);
        renderTraceTable(state.traceItems);
        renderTracePagination(data);
      }
      function openTraceDetail(index) {
        const item = state.traceItems[Number(index)];
        if (!item) return;
        const fields = [
          ['时间',dateText(item.created_at)], ['网关 Request ID',item.request_id], ['New API Request ID',item.newapi_request_id||'-'],
          ['外部事件 ID',item.external_event_id||'-'], ['用户标识',item.external_user_id||'-'], ['租户标识',item.metadata?.tenant_id||'-'],
          ['来源',item.source||'-'], ['路由',item.route_slug||'-'], ['模型',item.model||'-'],
          ['接口',item.endpoint||'-'], ['决策',item.decision||'-'], ['风险码',item.risk_code||'-'],
          ['HTTP 状态',item.http_status||'-'], ['上游状态',item.upstream_status||'-'], ['总延迟',`${number(item.latency_ms)} ms`],
          ['审计延迟',`${number(item.audit_latency_ms)} ms`], ['请求字节',number(item.request_bytes)], ['响应字节',number(item.response_bytes)],
          ['Prompt HMAC',item.prompt_hmac||'-']
        ];
        $('trace-detail-fields').innerHTML = fields.map(([label,value]) => `<div><span>${escapeHTML(label)}</span><strong>${escapeHTML(value)}</strong></div>`).join('');
        $('trace-detail-metadata').textContent = JSON.stringify(item.metadata || {},null,2);
        $('trace-detail').hidden = false;
        document.body.classList.add('modal-open');
      }
      function closeTraceDetail() {
        $('trace-detail').hidden = true;
        document.body.classList.remove('modal-open');
      }
      function filterByTraceUser(index) {
        const item = state.traceItems[Number(index)];
        if (!item?.external_user_id) return;
        $('trace-user').value = item.external_user_id;
        $('trace-user-match').value = 'exact';
        loadTraces(true).catch(error => toast(error.message,'error'));
      }
      function changeTracePage(direction) {
        const next = state.traceOffset + Number(direction) * state.traceLimit;
        state.traceOffset = Math.max(0,next);
        loadTraces(false).catch(error => toast(error.message,'error'));
      }
      function resetTraceFilters() {
        $('trace-filter').reset();
        $('trace-user-match').value = 'exact';
        $('trace-limit').value = '100';
        state.traceOffset = 0;
        state.traceLimit = 100;
        setTraceRange(24,false);
        loadTraces(true).catch(error => toast(error.message,'error'));
      }
      function exportTraceCSV() {
        if (!state.traceItems.length) { toast('当前页没有可导出的记录','error'); return; }
        const header = ['created_at','request_id','newapi_request_id','external_event_id','external_user_id','tenant_id','source','route_slug','model','endpoint','decision','risk_code','http_status','upstream_status','latency_ms','audit_latency_ms','request_bytes','response_bytes','prompt_hmac','metadata'];
        const rows = state.traceItems.map(item => [item.created_at,item.request_id,item.newapi_request_id,item.external_event_id,item.external_user_id,item.metadata?.tenant_id,item.source,item.route_slug,item.model,item.endpoint,item.decision,item.risk_code,item.http_status,item.upstream_status,item.latency_ms,item.audit_latency_ms,item.request_bytes,item.response_bytes,item.prompt_hmac,JSON.stringify(item.metadata||{})]);
        const csv = [header,...rows].map(row => row.map(csvCell).join(',')).join('\r\n');
        const blob = new Blob(['\ufeff'+csv],{type:'text/csv;charset=utf-8'});
        const link = document.createElement('a');
        link.href = URL.createObjectURL(blob);
        link.download = `newapi-risk-traces-${new Date().toISOString().replace(/[:.]/g,'-')}.csv`;
        document.body.appendChild(link); link.click(); link.remove(); URL.revokeObjectURL(link.href);
      }

'''
    pattern = re.compile(r"      async function loadTraces\(\) \{.*?\n\n      async function loadStorage", re.S)
    ui, replacements = pattern.subn(trace_js + "      async function loadStorage", ui, count=1)
    if replacements != 1:
        raise RuntimeError(f"loadTraces replacement count was {replacements}")

old_events = "      $('trace-filter').addEventListener('submit',event=>{event.preventDefault();loadTraces().catch(error=>toast(error.message,'error'));});$('storage-form').addEventListener('submit',saveStorage);$('client-form').addEventListener('submit',saveClient);$('clients-table').addEventListener('click',event=>{const edit=event.target.closest('[data-client-edit]');if(edit)editClient(edit.dataset.clientEdit);});"
if old_events in ui:
    new_events = r'''      $('trace-filter').addEventListener('submit',event=>{event.preventDefault();loadTraces(true).catch(error=>toast(error.message,'error'));});
      $('trace-filter-reset').addEventListener('click',resetTraceFilters);
      $('trace-presets').addEventListener('click',event=>{const button=event.target.closest('[data-trace-hours]');if(button)setTraceRange(Number(button.dataset.traceHours),true);});
      $('trace-prev').addEventListener('click',()=>changeTracePage(-1));$('trace-next').addEventListener('click',()=>changeTracePage(1));$('trace-export').addEventListener('click',exportTraceCSV);
      $('traces-table').addEventListener('click',event=>{const detail=event.target.closest('[data-trace-detail-index]');const user=event.target.closest('[data-trace-user-index]');if(detail)openTraceDetail(detail.dataset.traceDetailIndex);if(user)filterByTraceUser(user.dataset.traceUserIndex);});
      $('trace-detail-close').addEventListener('click',closeTraceDetail);$('trace-detail').addEventListener('click',event=>{if(event.target===$('trace-detail'))closeTraceDetail();});document.addEventListener('keydown',event=>{if(event.key==='Escape'&&!$('trace-detail').hidden)closeTraceDetail();});
      $('storage-form').addEventListener('submit',saveStorage);$('client-form').addEventListener('submit',saveClient);$('clients-table').addEventListener('click',event=>{const edit=event.target.closest('[data-client-edit]');if(edit)editClient(edit.dataset.clientEdit);});'''
    ui = ui.replace(old_events, new_events, 1)
elif "trace-filter-reset" not in ui:
    raise RuntimeError("trace event binding anchor was not found")

old_bootstrap = "      resetRoute();resetProfile();resetRule();restoreSession();"
new_bootstrap = "      resetRoute();resetProfile();resetRule();setTraceRange(24,false);restoreSession();"
if old_bootstrap in ui:
    ui = ui.replace(old_bootstrap, new_bootstrap, 1)
elif new_bootstrap not in ui:
    raise RuntimeError("UI bootstrap anchor was not found")

ui_path.write_text(ui, encoding="utf-8")


# Extend the E2E test with exact user, request, time-range, summary, and fuzzy search assertions.
e2e_path = Path("scripts/e2e.sh")
e2e = e2e_path.read_text(encoding="utf-8")
if "trace-search-by-user.json" not in e2e:
    anchor = '[[ "${trace_ok}" == 1 ]] || fail "expected gateway and New API traces were not persisted"\n'
    addition = r'''

trace_from="$(date -u -d '10 minutes ago' '+%Y-%m-%dT%H:%M:%SZ')"
trace_to="$(date -u -d '2 minutes' '+%Y-%m-%dT%H:%M:%SZ')"
curl --fail --silent --show-error --get \
  "${BASE_URL}/api/admin/v1/traces" \
  "${auth[@]}" \
  --data-urlencode "from=${trace_from}" \
  --data-urlencode "to=${trace_to}" \
  --data-urlencode "request_id=e2e-newapi-request-1" \
  --data-urlencode "user_id=anonymous-e2e-user" \
  --data-urlencode "user_match=exact" \
  --data-urlencode "tenant_id=e2e-tenant" \
  --data-urlencode "limit=20" >"${WORKDIR}/trace-search-by-user.json"

TRACE_FILE="${WORKDIR}/trace-search-by-user.json" python3 - <<'PY'
import json
import os

with open(os.environ["TRACE_FILE"], encoding="utf-8") as handle:
    payload = json.load(handle)
if payload.get("total") != 1:
    raise RuntimeError(f"expected one exact trace result: {payload}")
item = payload["items"][0]
if item.get("request_id") != "e2e-newapi-request-1" or item.get("external_user_id") != "anonymous-e2e-user":
    raise RuntimeError(f"unexpected exact trace item: {item}")
if item.get("metadata", {}).get("tenant_id") != "e2e-tenant":
    raise RuntimeError(f"tenant search metadata missing: {item}")
if payload.get("summary", {}).get("allowed_requests") != 1:
    raise RuntimeError(f"unexpected trace summary: {payload}")
if payload.get("has_more") is not False:
    raise RuntimeError(f"unexpected pagination state: {payload}")
PY

curl --fail --silent --show-error --get \
  "${BASE_URL}/api/admin/v1/traces" \
  "${auth[@]}" \
  --data-urlencode "from=${trace_from}" \
  --data-urlencode "to=${trace_to}" \
  --data-urlencode "q=newapi-e2e-1" \
  --data-urlencode "limit=20" >"${WORKDIR}/trace-search-global.json"
contains "${WORKDIR}/trace-search-global.json" '"newapi_request_id":"newapi-e2e-1"'
'''
    if anchor not in e2e:
        raise RuntimeError("E2E trace persistence anchor was not found")
    e2e = e2e.replace(anchor, anchor + addition, 1)
e2e_path.write_text(e2e, encoding="utf-8")


# Update the OpenAPI contract while keeping the same endpoint for backward compatibility.
openapi_path = Path("docs/openapi.yaml")
openapi = openapi_path.read_text(encoding="utf-8")
if "user_match" not in openapi:
    trace_openapi = r'''  /api/admin/v1/traces:
    get:
      operationId: searchTraces
      summary: Search request traces by time, user, request identifiers, model, route, status, and risk result.
      security:
        - AdminBearer: []
      parameters:
        - {name: q, in: query, description: Case-insensitive contains search across identifiers, user, model, endpoint, route, risk code, source, and tenant. Minimum 3 characters., schema: {type: string, minLength: 3, maxLength: 300}}
        - {name: request_id, in: query, schema: {type: string, maxLength: 128}}
        - {name: newapi_request_id, in: query, schema: {type: string, maxLength: 128}}
        - {name: external_event_id, in: query, schema: {type: string, maxLength: 200}}
        - {name: route_slug, in: query, schema: {type: string, maxLength: 100}}
        - {name: source, in: query, schema: {type: string, enum: [gateway, newapi]}}
        - {name: user_id, in: query, schema: {type: string, maxLength: 200}}
        - {name: user_match, in: query, schema: {type: string, enum: [exact, prefix, contains], default: exact}}
        - {name: tenant_id, in: query, description: Exact match against metadata.tenant_id., schema: {type: string, maxLength: 200}}
        - {name: model, in: query, description: Case-insensitive contains match., schema: {type: string, maxLength: 200}}
        - {name: endpoint, in: query, description: Case-insensitive contains match., schema: {type: string, maxLength: 300}}
        - {name: decision, in: query, schema: {type: string, enum: [allow, block, review, error, unknown]}}
        - {name: risk_code, in: query, schema: {type: string, maxLength: 200}}
        - {name: http_status, in: query, schema: {type: integer, minimum: 0, maximum: 999}}
        - {name: upstream_status, in: query, schema: {type: integer, minimum: 0, maximum: 999}}
        - {name: from, in: query, schema: {type: string, format: date-time}}
        - {name: to, in: query, schema: {type: string, format: date-time}}
        - {name: limit, in: query, schema: {type: integer, minimum: 1, maximum: 1000, default: 200}}
        - {name: offset, in: query, schema: {type: integer, minimum: 0, maximum: 1000000, default: 0}}
      responses:
        "200":
          description: Filtered request traces and aggregate counts for the selected range.
          content:
            application/json:
              schema:
                type: object
                required: [items, total, limit, offset, has_more, from, to, summary]
                properties:
                  items:
                    type: array
                    items: {$ref: "#/components/schemas/TraceEvent"}
                  total: {type: integer, format: int64}
                  limit: {type: integer}
                  offset: {type: integer}
                  has_more: {type: boolean}
                  from: {type: string, format: date-time}
                  to: {type: string, format: date-time}
                  summary:
                    type: object
                    required: [allowed_requests, blocked_requests, error_requests, review_requests, average_latency_ms]
                    properties:
                      allowed_requests: {type: integer, format: int64}
                      blocked_requests: {type: integer, format: int64}
                      error_requests: {type: integer, format: int64}
                      review_requests: {type: integer, format: int64}
                      average_latency_ms: {type: number, format: double}
        "400": {description: Invalid time range, pagination value, status, or overly broad fuzzy query.}
        "401": {description: Administrator authentication required.}
components:'''
    pattern = re.compile(r'  /api/admin/v1/traces:\n.*?\ncomponents:', re.S)
    openapi, replacements = pattern.subn(trace_openapi, openapi, count=1)
    if replacements != 1:
        raise RuntimeError(f"OpenAPI trace block replacement count was {replacements}")
openapi_path.write_text(openapi, encoding="utf-8")


readme_path = Path("README.md")
readme = readme_path.read_text(encoding="utf-8")
if "## Web 查询请求" not in readme:
    readme += r'''

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
'''
readme_path.write_text(readme, encoding="utf-8")


integration_path = Path("docs/newapi-integration.md")
integration = integration_path.read_text(encoding="utf-8")
if "## Web 可视化追踪查询" not in integration:
    integration += r'''

## Web 可视化追踪查询

要让管理台按用户查到一次请求，New API 至少需要在代理请求中附带：

```http
X-NewAPI-User-ID: 18492
X-NewAPI-Request-ID: req-newapi-01J...
```

也可以在签名追踪事件中上报：

```json
{
  "request_id": "req-gateway-01J...",
  "newapi_request_id": "req-newapi-01J...",
  "external_user_id": "18492",
  "metadata": {
    "tenant_id": "tenant-a"
  }
}
```

随后在 Web 管理台进入“请求追踪”，选择时间范围并使用用户、租户、请求 ID、模型、路由、状态码或风险码组合查询。用户精确匹配走数据库索引；“包含”模式只建议在较小时间范围内排障使用。
'''
integration_path.write_text(integration, encoding="utf-8")
