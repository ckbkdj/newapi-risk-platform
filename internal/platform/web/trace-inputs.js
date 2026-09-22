/* Full input review: never execute, HTML-render, auto-open URLs or persist user bodies in browser storage. */
(() => {
  'use strict';
  const byId = id => document.getElementById(id);
  const node = (tag, text, cls) => {
    const el = document.createElement(tag);
    if (text !== undefined) el.textContent = text;
    if (cls) el.className = cls;
    return el;
  };
  const button = (label, action) => {
    const el = node('button', label, 'btn btn-small btn-secondary');
    el.type = 'button'; el.addEventListener('click', action); return el;
  };
  const admin = () => byId('sidebar-role')?.textContent.trim() === 'admin' && !byId('app')?.hidden;
  const PAGE = 32768;
  let dialog = null, controller = null, generation = 0;
  let raw = '', display = '', selected = null, page = 0;
  let status, content, pages, options, recordsBox;
  async function request(path, signal) {
    const token = sessionStorage.getItem('risk_token');
    const response = await fetch(path, {signal, cache:'no-store', headers:{Authorization:`Bearer ${token || ''}`}});
    if (!response.ok) {
      let detail; try { detail = await response.json(); } catch { /* No raw error body shown. */ }
      throw new Error(detail?.error?.message || `原文请求失败：HTTP ${response.status}`);
    }
    return response;
  }
  function close() {
    generation++; controller?.abort(); controller = null;
    dialog?.remove(); dialog = null; raw = ''; display = ''; selected = null;
  }
  function renderPage() {
    const count = Math.max(1, Math.ceil(display.length/PAGE));
    page = Math.max(0, Math.min(page, count-1));
    content.value = display.slice(page*PAGE, (page+1)*PAGE);
    pages.textContent = `第 ${page+1} / ${count} 页；共 ${display.length.toLocaleString()} 个 UTF-16 字符。分页仅影响显示，下载保留全部原始字节。`;
  }
  function setMode(mode) {
    page = 0; display = raw;
    if (mode === 'user') {
      try {
        const doc = JSON.parse(raw);
        const units = [];
        if (typeof doc.input === 'string') units.push({path:'$.input', content:doc.input});
        for (const name of ['messages','input']) {
          if (Array.isArray(doc[name])) doc[name].forEach((item,index) => {
            if (item && String(item.role || '').toLowerCase() === 'user') units.push({path:`$.${name}[${index}]`, message:item});
          });
        }
        if (!units.length) display = '没有可按 user 角色展示的消息。请查看完整原文；不代表输入为空。';
        else display = JSON.stringify(units, null, 2);
      } catch { display = '请求体不是可解析的 JSON。请查看完整原文或下载原始字节。'; }
    }
    renderPage();
  }
  async function readBody(record) {
    const own = ++generation;
    controller?.abort(); controller = new AbortController();
    raw = ''; display = ''; selected = null; content.value = ''; pages.textContent = '';
    status.textContent = '正在按权限读取原文，并校验完整字节数…';
    try {
      const response = await request(`/api/admin/v1/trace-inputs/${encodeURIComponent(record.id)}/body`, controller.signal);
      const bytes = await response.arrayBuffer();
      if (own !== generation || !dialog) return;
      if (bytes.byteLength !== record.body_bytes || response.headers.get('X-Trace-Input-Complete') !== 'true') throw new Error('原文传输不完整，未标记为完整。');
      try { raw = new TextDecoder('utf-8',{fatal:true}).decode(bytes); }
      catch { throw new Error('原始字节不是有效 UTF-8；请使用下载原始请求按钮，不进行文本替换。'); }
      selected = record;
      status.textContent = `完整请求体：${bytes.byteLength.toLocaleString()} 字节；路由 ${record.route_slug}；开始 ${record.started_at}；保留至 ${new Date(record.expires_unix*1000).toLocaleString()}。这是网关收到的请求体，不是模型摘要，也不包含 HTTP 认证头。`;
      options.value = 'raw'; setMode('raw');
    } catch (error) { if (own === generation && dialog && error.name !== 'AbortError') status.textContent = error.message; }
  }
  async function download(record) {
    if (!record) return;
    const own = generation;
    try {
      // Download is separately authorized and access-audited, not a token in a URL.
      const response = await request(`/api/admin/v1/trace-inputs/${encodeURIComponent(record.id)}/body?download=1`, controller?.signal);
      const blob = await response.blob();
      if (own !== generation || !dialog) return;
      if (blob.size !== record.body_bytes) throw new Error('下载字节数不匹配，已停止。');
      const url = URL.createObjectURL(blob);
      const link = node('a'); link.href = url; link.download = `request-${record.id}.json`;
      link.click(); setTimeout(() => URL.revokeObjectURL(url), 1000);
    } catch (error) { if (dialog && error.name !== 'AbortError') status.textContent = error.message; }
  }
  async function search(id, offset = 0) {
    const own = ++generation;
    controller?.abort(); controller = new AbortController();
    selected = null; raw = ''; display = ''; content.value = ''; recordsBox.replaceChildren();
    status.textContent = '正在查询已保存的完整原文…';
    try {
      const response = await request(`/api/admin/v1/trace-inputs?request_id=${encodeURIComponent(id.trim())}&offset=${offset}`, controller.signal);
      const payload = await response.json();
      if (own !== generation || !dialog) return;
      status.textContent = payload.items?.length ? '选择与追踪开始时间、路由相同的记录。相同 Request ID 的重试不会互相覆盖。' : payload.missing_explanation;
      if (!payload.capture_enabled) status.textContent += ' 当前实例已关闭新请求原文留存。';
      if (offset > 0) recordsBox.append(button('较新一批记录', () => search(id, Math.max(0, offset-50))));
      for (const record of payload.items || []) {
        const row = node('div', undefined, 'notice');
        row.append(node('p', `${record.started_at} · ${record.route_slug} · ${record.body_bytes.toLocaleString()} 字节`));
        row.append(button('查看完整输入', () => readBody(record)), button('下载原始请求', () => download(record)));
        recordsBox.append(row);
      }
      if (payload.has_more) recordsBox.append(button('更早一批记录', () => search(id, offset+50)));
    } catch (error) { if (own === generation && dialog && error.name !== 'AbortError') status.textContent = error.message; }
  }
  function open(id = '') {
    if (!admin()) return;
    close();
    dialog = node('div', undefined, 'trace-modal');
    dialog.setAttribute('role','dialog'); dialog.setAttribute('aria-modal','true'); dialog.setAttribute('aria-label','完整输入复盘');
    const panel = node('div', undefined, 'trace-modal-card');
    panel.append(node('h3','完整输入复盘（仅管理员）'));
    panel.append(node('p','原文可能包含个人信息、代码和正文中的凭据。每次读取与下载均记录访问审计；不会执行内容，也不会自动访问其中的链接。','notice warning'));
    const form = node('form');
    const field = node('input'); field.placeholder = '输入 Request ID'; field.value = id; field.required = true; field.autocomplete = 'off';
    const actions = node('div', undefined, 'actions');
    actions.append(button('查询', () => search(field.value)), button('留存状态', async () => {
      const own = generation;
      try {
        const response = await request('/api/admin/v1/trace-inputs/status', controller?.signal);
        const data = await response.json();
        if (own === generation && dialog) status.textContent = `新请求留存：${data.capture_enabled ? '已启用' : '已关闭'}；保留 ${data.retention_days} 天；本进程已存 ${data.stored}，未捕获 ${data.not_captured}，存储失败 ${data.store_failed}，队列 ${data.queue_depth}。放行状态与原文是否成功保存是两件事。`;
      } catch (error) { if (dialog && error.name !== 'AbortError') status.textContent = error.message; }
    }), button('关闭并清除', close));
    form.append(field,actions); form.addEventListener('submit', event => { event.preventDefault(); search(field.value); }); panel.append(form);
    status = node('p',''); panel.append(status);
    recordsBox = node('div', undefined, 'grid'); panel.append(recordsBox);
    options = node('select');
    for (const [value,label] of [['raw','完整原文（不裁剪，可翻页）'],['user','user 角色消息（完整请求中仍保留其他角色与工具数据）']]) {
      const option = node('option', label); option.value = value; options.append(option);
    }
    options.addEventListener('change', () => setMode(options.value)); panel.append(options);
    content = node('textarea'); content.readOnly = true; content.rows = 18; content.className = 'mono'; content.spellcheck = false; content.setAttribute('aria-label','请求正文'); panel.append(content);
    pages = node('p',''); panel.append(pages);
    const paging = node('div', undefined, 'actions');
    paging.append(button('上一页', () => { page--; renderPage(); }), button('下一页', () => { page++; renderPage(); }), button('下载完整原始字节', () => download(selected)));
    panel.append(paging); dialog.append(panel); document.body.append(dialog);
    dialog.addEventListener('click', event => { if (event.target === dialog) close(); });
    field.focus(); if (id) search(id);
  }
  function decorate() {
    const canRead = admin();
    if (!canRead && dialog) close();
    const view = byId('view-traces'); if (!view) return;
    let launch = byId('trace-input-review-launch');
    if (!launch) {
      launch = button('完整输入复盘', () => open(byId('trace-request-id')?.value || ''));
      launch.id = 'trace-input-review-launch'; (view.querySelector('.view-head') || view).append(launch);
    }
    if (launch.hidden !== !canRead) launch.hidden = !canRead;
    for (const row of view.querySelectorAll('#traces-table tbody tr')) {
      const id = row.querySelector('.trace-request-id')?.textContent?.trim();
      if (!id) continue;
      let launch = row.querySelector('[data-input-review]');
      if (!launch) { launch = button('完整输入', () => open(id)); launch.dataset.inputReview = '1'; row.lastElementChild.append(launch); }
      if (launch.hidden !== !canRead) launch.hidden = !canRead;
    }
  }
  let scheduled = false;
  const schedule = () => { if (!scheduled) { scheduled = true; requestAnimationFrame(() => { scheduled = false; decorate(); }); } };
  const observer = new MutationObserver(schedule);
  const root = byId('app');
  if (root) observer.observe(root,{childList:true,subtree:true,attributes:true,attributeFilter:['hidden']});
  document.addEventListener('keydown', event => { if (event.key === 'Escape') close(); });
  byId('logout-button')?.addEventListener('click', close);
  decorate();
})();
