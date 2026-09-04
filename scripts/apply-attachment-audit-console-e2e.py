from __future__ import annotations

from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]


def read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def write(path: str, content: str) -> None:
    target = ROOT / path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content, encoding="utf-8")


def replace_once(path: str, old: str, new: str, label: str) -> None:
    content = read(path)
    if new in content:
        return
    count = content.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected one match in {path}, found {count}")
    write(path, content.replace(old, new, 1))


write(
    "internal/platform/attachment_admin.go",
    r'''package platform

import (
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"strconv"
	"strings"
)

func (s *HTTPService) adminDryRunAttachmentAudit(w http.ResponseWriter, r *http.Request) {
	maximumBody := s.audit.attachmentTotalMaxBytes + int64(s.audit.attachmentMaxCount)*64*1024
	r.Body = http.MaxBytesReader(w, r.Body, maximumBody)
	if err := r.ParseMultipartForm(minInt64(maximumBody, 32*1024*1024)); err != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid_multipart", "could not parse attachment upload: "+sanitizeAuditDiagnostic(err.Error()))
		return
	}
	if r.MultipartForm != nil {
		defer r.MultipartForm.RemoveAll()
	}

	var profileID *int64
	if raw := strings.TrimSpace(r.FormValue("profile_id")); raw != "" {
		parsed, err := strconv.ParseInt(raw, 10, 64)
		if err != nil || parsed <= 0 {
			writeAPIError(w, http.StatusBadRequest, "invalid_profile_id", "profile_id must be a positive integer")
			return
		}
		profileID = &parsed
	}
	failClosed := false
	if raw := strings.TrimSpace(r.FormValue("fail_closed")); raw != "" {
		parsed, err := strconv.ParseBool(raw)
		if err != nil {
			writeAPIError(w, http.StatusBadRequest, "invalid_fail_closed", "fail_closed must be true or false")
			return
		}
		failClosed = parsed
	}

	files := collectMultipartFiles(r.MultipartForm)
	if len(files) == 0 {
		writeAPIError(w, http.StatusBadRequest, "files_required", "upload at least one file using the files field")
		return
	}
	if len(files) > s.audit.attachmentMaxCount {
		writeAPIError(w, http.StatusRequestEntityTooLarge, "too_many_attachments", fmt.Sprintf("received %d files; maximum is %d", len(files), s.audit.attachmentMaxCount))
		return
	}
	candidates := make([]attachmentCandidate, 0, len(files))
	for index, header := range files {
		candidate, err := multipartAttachmentCandidate(header, index+1, s.audit.attachmentFetchMaxBytes)
		if err != nil {
			writeAPIError(w, http.StatusBadRequest, "attachment_read_failed", fmt.Sprintf("file %q: %s", sanitizeAttachmentName(header.Filename), sanitizeAuditDiagnostic(err.Error())))
			return
		}
		candidates = append(candidates, candidate)
	}

	report := s.audit.auditAttachments(
		r.Context(),
		Route{AuditProfileID: profileID, FailClosed: failClosed},
		candidates,
		0,
		nil,
	)
	s.auditAdmin(r, "dry_run", "attachment_audit", "multipart", map[string]any{
		"profile_id": profileID,
		"file_count": len(candidates),
		"blocked":    report.Blocked,
		"reviewed":   report.Reviewed,
		"errors":     report.Errors,
	})
	writeJSON(w, http.StatusOK, report)
}

func collectMultipartFiles(form *multipart.Form) []*multipart.FileHeader {
	if form == nil {
		return nil
	}
	keys := make([]string, 0, len(form.File))
	for key := range form.File {
		keys = append(keys, key)
	}
	// Put the documented field first; keep deterministic support for clients
	// that use attachment/file/upload as field names.
	ordered := []string{"files", "file", "attachments", "attachment", "upload"}
	seen := make(map[string]struct{})
	result := make([]*multipart.FileHeader, 0)
	for _, key := range append(ordered, keys...) {
		if _, duplicate := seen[key]; duplicate {
			continue
		}
		seen[key] = struct{}{}
		result = append(result, form.File[key]...)
	}
	return result
}

func multipartAttachmentCandidate(header *multipart.FileHeader, index int, maximum int64) (attachmentCandidate, error) {
	if header == nil {
		return attachmentCandidate{}, errors.New("empty multipart file header")
	}
	stream, err := header.Open()
	if err != nil {
		return attachmentCandidate{}, err
	}
	defer stream.Close()
	data, err := io.ReadAll(io.LimitReader(stream, maximum+1))
	if err != nil {
		return attachmentCandidate{}, err
	}
	if int64(len(data)) > maximum {
		return attachmentCandidate{}, fmt.Errorf("file exceeds %d-byte materialization limit", maximum)
	}
	return attachmentCandidate{
		Index:        index,
		Name:         sanitizeAttachmentName(header.Filename),
		DeclaredMIME: normalizeAttachmentMIME(header.Header.Get("Content-Type")),
		Source:       "uploaded_file",
		Data:         data,
	}, nil
}
''',
)

# Direct uploaded bytes are materialized without any URL/base64 round trip.
replace_once(
    "internal/platform/attachment_audit.go",
    '''\tif candidate.Source == "archive_entry" {
\t\tmaterial = materializeArchiveEntry(candidate)
\t} else {
''',
    '''\tif candidate.Source == "archive_entry" || candidate.Source == "uploaded_file" {
\t\tmaterial = materializeArchiveEntry(candidate)
\t} else {
''',
    "uploaded attachment materialization",
)

# Avoid delegating a large URL to the vision model, which would re-resolve it
# outside the gateway's SSRF-safe transport. Operators can raise the bounded
# fetch limit up to 256 MiB if they need larger images.
fetch_path = "internal/platform/attachment_fetch.go"
fetch_text = read(fetch_path)
unsafe_block = '''\tif contentLength > maximum && strings.HasPrefix(provisionalMIME, "image/") {
\t\t// The URL has already passed the SSRF-safe transport. Let the configured
\t\t// multimodal model retrieve/downsample a large public image rather than
\t\t// buffering it in the gateway.
\t\tmaterial.RemoteVisionURL = parsed.String()
\t\tmaterial.MIMEType = provisionalMIME
\t\tmaterial.Kind = attachmentKindImage
\t\tmaterial.MaterializedBytes = 0
\t\tmaterial.ExtractionHint = "remote_image_reference"
\t\treturn material, nil
\t}
'''
safe_block = '''\tif contentLength > maximum && strings.HasPrefix(provisionalMIME, "image/") {
\t\treturn material, fmt.Errorf("remote image is %d bytes; bounded fetch limit is %d", contentLength, maximum)
\t}
'''
if unsafe_block in fetch_text:
    fetch_text = fetch_text.replace(unsafe_block, safe_block, 1)
elif safe_block not in fetch_text:
    raise SystemExit("remote image SSRF-safe replacement anchor not found")
write(fetch_path, fetch_text)

# HTTP route.
replace_once(
    "internal/platform/http.go",
    '''\t\tadmin.Get("/api/admin/v1/cyber-rule-candidates", s.adminListCyberRuleCandidates)
''',
    '''\t\tadmin.Get("/api/admin/v1/cyber-rule-candidates", s.adminListCyberRuleCandidates)
\t\tadmin.With(s.requireRole("operator")).Post("/api/admin/v1/attachment-audits/dry-run", s.adminDryRunAttachmentAudit)
''',
    "attachment dry-run route",
)

# Runtime diagnostics.
replace_once(
    "internal/platform/admin.go",
    '''\t\t"request_large_body_max_concurrency": s.cfg.LargeRequestMaxConcurrency,
''',
    '''\t\t"request_large_body_max_concurrency": s.cfg.LargeRequestMaxConcurrency,
\t\t"attachment_audit_enabled":              s.cfg.AttachmentAuditEnabled,
\t\t"attachment_max_count":                  s.cfg.AttachmentMaxCount,
\t\t"attachment_fetch_max_bytes":            s.cfg.AttachmentFetchMaxBytes,
\t\t"attachment_total_max_bytes":            s.cfg.AttachmentTotalMaxBytes,
\t\t"attachment_extract_max_bytes":          s.cfg.AttachmentExtractMaxBytes,
\t\t"attachment_sample_max_bytes":           s.cfg.AttachmentSampleMaxBytes,
\t\t"attachment_segment_bytes":              s.cfg.AttachmentSegmentBytes,
\t\t"attachment_image_max_bytes":            s.cfg.AttachmentImageMaxBytes,
\t\t"attachment_image_max_pixels":           s.cfg.AttachmentImageMaxPixels,
\t\t"attachment_per_request_concurrency":    s.cfg.AttachmentPerRequestConcurrency,
\t\t"attachment_global_concurrency":         s.cfg.AttachmentGlobalConcurrency,
\t\t"attachment_archive_max_entries":        s.cfg.AttachmentArchiveMaxEntries,
\t\t"attachment_archive_max_depth":          s.cfg.AttachmentArchiveMaxDepth,
\t\t"attachment_allow_remote_urls":          s.cfg.AttachmentAllowRemoteURLs,
\t\t"attachment_allow_private_urls":         s.cfg.AttachmentAllowPrivateURLs,
''',
    "runtime attachment diagnostics",
)

# Admin console: nav, view, functions, trace summary and events.
web_path = "internal/platform/web/index.html"
web = read(web_path)
if 'data-view="attachment-audit"' not in web:
    nav_pattern = re.compile(r'(data-view="rules"[^>]*>.*?</button>)', re.S)
    web, count = nav_pattern.subn(r'\1\n        <button class="nav-item" data-view="attachment-audit">附件审计</button>', web, count=1)
    if count != 1:
        raise SystemExit("attachment audit nav anchor not found")

if 'id="view-attachment-audit"' not in web:
    marker = '<section id="view-storage"'
    position = web.find(marker)
    if position < 0:
        raise SystemExit("storage view marker not found")
    section = '''        <section id="view-attachment-audit" class="view" hidden>
          <div class="view-head"><div><h2>附件审计</h2><p>图片、PDF、Office、文本、日志、源码、邮件、压缩包和其他二进制文件逐个审计。原始文件不会写入 Trace；只保存哈希、抽样范围和审计结论。</p></div><button id="attachment-refresh-profiles" class="btn btn-secondary">刷新模型</button></div>
          <div class="grid split">
            <div class="card">
              <h3>上传并独立审核</h3>
              <form id="attachment-audit-form" class="form-grid">
                <label>附件审计模型<select id="attachment-profile"><option value="">默认审计模型</option></select></label>
                <label>失败策略<select id="attachment-fail-closed"><option value="false">测试模式：错误不转 Block</option><option value="true">严格模式：错误视为 Block</option></select></label>
                <label class="full">选择文件<input id="attachment-files" type="file" name="files" multiple required></label>
                <div class="full muted">单次最多按 ATTACHMENT_MAX_COUNT 处理；大文本采用头部、尾部、均匀区间和安全信号窗口抽样。压缩包内文件也会分别列出。</div>
                <div class="full actions"><button class="btn btn-primary" type="submit">开始附件审计</button></div>
              </form>
            </div>
            <div class="card">
              <h3>审计摘要</h3>
              <div id="attachment-audit-summary" class="empty">尚未运行</div>
            </div>
          </div>
          <div class="card"><h3>逐个文件结果</h3><div id="attachment-audit-results"><div class="empty">上传文件后显示每个文件、压缩包子文件和分段结果</div></div></div>
          <div class="card"><h3>完整脱敏结果</h3><pre id="attachment-audit-json" class="code-block">{}</pre></div>
        </section>

'''
    web = web[:position] + section + web[position:]

if 'function renderAttachmentAuditReport' not in web:
    marker = '      function setTraceRange('
    position = web.find(marker)
    if position < 0:
        raise SystemExit("trace function marker not found")
    functions = r'''      async function loadAttachmentAuditProfiles() {
        if(!state.profiles.length){const data=await api('/api/admin/v1/audit-profiles');state.profiles=data.items||[];}
        $('attachment-profile').innerHTML='<option value="">默认审计模型</option>'+state.profiles.filter(profile=>profile.enabled).map(profile=>`<option value="${profile.id}">${escapeHTML(profile.name)} · ${escapeHTML(profile.model)}</option>`).join('');
      }
      function renderAttachmentAuditReport(report) {
        const cards=[['发现附件',number(report.discovered||0),'请求根附件'],['已审计',number(report.audited||0),'含压缩包子文件'],['Allow',number(report.allowed||0),'正常'],['Review',number(report.reviewed||0),'需要复核'],['Block',number(report.blocked||0),'命中风险'],['错误',number(report.errors||0),report.fail_closed?'严格模式':'测试模式'],['抽样',number(report.sampled||0),'大文件或缩放图片'],['处理字节',byteText(report.total_bytes||0),'受全局上限保护']];
        $('attachment-audit-summary').className='metrics';
        $('attachment-audit-summary').innerHTML=cards.map(item=>`<div class="metric"><span>${item[0]}</span><strong>${item[1]}</strong><small>${item[2]}</small></div>`).join('');
        const items=report.items||[];
        $('attachment-audit-results').innerHTML=items.length?`<div class="table-wrap"><table><thead><tr><th>文件</th><th>类型 / 大小</th><th>提取 / 抽样</th><th>决策</th><th>原因 / 证据</th><th>模型</th></tr></thead><tbody>${items.map(item=>`<tr><td><strong>${escapeHTML(item.name||'attachment')}</strong><br><span class="mono">#${number(item.index)}${item.parent_index?` · 父 #${number(item.parent_index)}`:''}</span><br><span class="muted">${escapeHTML(item.sha256||'-')}</span></td><td>${escapeHTML(item.kind||'-')}<br>${escapeHTML(item.mime_type||'-')}<br><span class="muted">原始 ${byteText(item.original_bytes||0)} · 读取 ${byteText(item.materialized_bytes||0)}</span></td><td>${escapeHTML(item.extraction_method||'-')}<br><span class="muted">提取 ${byteText(item.extracted_text_bytes||0)} · 审计 ${byteText(item.audited_text_bytes||0)}</span><br><span class="muted">分段 ${number(item.segments_audited||0)}/${number(item.segment_count||0)}${item.sampled?' · 已抽样':''}${item.truncated?' · 已截取':''}</span></td><td>${badge(item.decision||'unknown')}<br><span class="mono">${escapeHTML(item.risk_code||'-')}</span></td><td>${escapeHTML(item.reason||item.error_reason||'-')}<br>${item.evidence?`<span class="trace-error-class">证据：${escapeHTML(item.evidence)}</span>`:''}${item.error_class?`<span class="trace-error-class">${escapeHTML(item.error_class)}</span>`:''}</td><td>${escapeHTML(item.profile_name||'-')}<br><span class="mono">${escapeHTML(item.model||'-')}</span><br><span class="muted">调用 ${number(item.model_attempts||0)} · 重试 ${number(item.model_retries||0)} · ${number(item.latency_ms||0)} ms</span></td></tr>`).join('')}</tbody></table></div>`:'<div class="empty">没有可展示的附件</div>';
        $('attachment-audit-json').textContent=JSON.stringify(report,null,2);
      }
      async function runAttachmentAudit(event) {
        event.preventDefault();
        const files=Array.from($('attachment-files').files||[]);
        if(!files.length){toast('请选择至少一个文件','error');return;}
        const form=new FormData();files.forEach(file=>form.append('files',file,file.name));
        if($('attachment-profile').value)form.set('profile_id',$('attachment-profile').value);
        form.set('fail_closed',$('attachment-fail-closed').value||'false');
        const button=event.submitter||$('attachment-audit-form').querySelector('button[type="submit"]');const old=button.textContent;button.disabled=true;button.textContent='审计中…';
        try{
          const response=await fetch('/api/admin/v1/attachment-audits/dry-run',{method:'POST',headers:{Authorization:`Bearer ${state.token}`},body:form});
          const payload=await response.json().catch(()=>({}));
          if(!response.ok)throw new Error(payload?.error?.message||`HTTP ${response.status}`);
          renderAttachmentAuditReport(payload);toast('附件审计完成');
        }catch(error){toast(error.message,'error');$('attachment-audit-json').textContent=String(error.stack||error);}
        finally{button.disabled=false;button.textContent=old;}
      }

'''
    web = web[:position] + functions + web[position:]

# Trace table attachment summary.
if 'const attachmentLine=' not in web:
    old = "          const auditOutputLine=(item.metadata?.audit_output_mode||item.metadata?.audit_finish_reason)?"
    pos = web.find(old)
    if pos < 0:
        raise SystemExit("trace audit output line anchor not found")
    line_end = web.find('\n', pos)
    addition = "\n          const attachmentLine=Number(item.metadata?.attachment_count||0)?`<span class=\"trace-error-class\">附件 ${number(item.metadata.attachment_count)} · 审计 ${number(item.metadata?.attachment_audited_count||0)} · Block ${number(item.metadata?.attachment_blocked_count||0)} · Error ${number(item.metadata?.attachment_error_count||0)}${item.metadata?.attachment_sampled_count?` · 抽样 ${number(item.metadata.attachment_sampled_count)}`:''}</span>`:'';"
    web = web[:line_end] + addition + web[line_end:]
    target = '${auditOutputLine}${tokenLine}</td>'
    if target not in web:
        raise SystemExit("trace attachment render target not found")
    web = web.replace(target, '${auditOutputLine}${attachmentLine}${tokenLine}</td>', 1)

if "['附件数量',item.metadata?.attachment_count" not in web:
    marker = "          ['审计延迟',`${number(item.audit_latency_ms)} ms`],"
    if marker not in web:
        raise SystemExit("trace detail attachment field marker not found")
    addition = "          ['附件数量',item.metadata?.attachment_count??0], ['附件已审计',item.metadata?.attachment_audited_count??0], ['附件 Allow',item.metadata?.attachment_allowed_count??0], ['附件 Review',item.metadata?.attachment_review_count??0], ['附件 Block',item.metadata?.attachment_blocked_count??0], ['附件错误',item.metadata?.attachment_error_count??0], ['附件抽样',item.metadata?.attachment_sampled_count??0], ['附件处理字节',byteText(item.metadata?.attachment_total_bytes||0)], ['附件审计延迟',item.metadata?.attachment_audit_latency_ms!=null?`${number(item.metadata.attachment_audit_latency_ms)} ms`:'-'], ['附件名称',(item.metadata?.attachment_names||[]).join(' | ')||'-'], ['逐项附件结果',JSON.stringify(item.metadata?.attachment_audits||[])],\n"
    web = web.replace(marker, addition + marker, 1)

if "$('attachment-audit-form').addEventListener" not in web:
    marker = "      $('new-rule-button').addEventListener"
    pos = web.find(marker)
    if pos < 0:
        raise SystemExit("admin event marker not found")
    line_end = web.find('\n', pos)
    events = "\n      $('attachment-audit-form').addEventListener('submit',runAttachmentAudit);$('attachment-refresh-profiles').addEventListener('click',()=>loadAttachmentAuditProfiles().catch(error=>toast(error.message,'error')));document.querySelector('[data-view=\"attachment-audit\"]').addEventListener('click',()=>loadAttachmentAuditProfiles().catch(error=>toast(error.message,'error')));"
    web = web[:line_end] + events + web[line_end:]
write(web_path, web)

# Mock model behavior for harmful file evidence.
replace_once(
    "cmd/mockprovider/main.go",
    '''\tif strings.Contains(userText, "model-audit-block") {
''',
    '''\tif strings.Contains(userText, "attachment-file-malware-marker") {
\t\tdecision = "block"
\t\triskCode = "CYBER_ATTACHMENT_FILE_MALWARE"
\t\tcategory = "malware"
\t\tconfidence = 0.999
\t\treason = "file contains an explicit malicious capability marker"
\t\tevidence = firstAuditEvidence(rawUserText, []string{"attachment-file-malware-marker"})
\t}
\tif strings.Contains(userText, "model-audit-block") {
''',
    "mock harmful attachment",
)

# Test-stack limits make deterministic sampling observable without a huge CI body.
compose_test = read("docker-compose.test.yml")
if "ATTACHMENT_SAMPLE_MAX_BYTES" not in compose_test:
    match = re.search(r'(?m)^(\s+REQUEST_HARD_MAX_BYTES:\s*[^\n]+\n)', compose_test)
    if not match:
        raise SystemExit("docker-compose.test request hard limit anchor not found")
    insertion = match.group(1) + "      ATTACHMENT_SAMPLE_MAX_BYTES: 32768\n      ATTACHMENT_SEGMENT_BYTES: 8192\n      ATTACHMENT_MAX_COUNT: 24\n      ATTACHMENT_GLOBAL_CONCURRENCY: 8\n      ATTACHMENT_PER_REQUEST_CONCURRENCY: 2\n"
    compose_test = compose_test[:match.start()] + insertion + compose_test[match.end():]
write("docker-compose.test.yml", compose_test)

# E2E requests and assertions.
e2e = read("scripts/e2e.sh")
if "e2e-attachment-safe-files" not in e2e:
    marker = '''status="$(curl --silent --show-error -o "${WORKDIR}/rule-block.json" -w '%{http_code}' \\
'''
    pos = e2e.find(marker)
    if pos < 0:
        raise SystemExit("E2E attachment insertion marker not found")
    block = r'''python3 - "${WORKDIR}/attachment-safe.json" "${WORKDIR}/attachment-large.json" "${WORKDIR}/attachment-image.json" "${WORKDIR}/attachment-archive.json" <<'PY'
import base64
import io
import json
import sys
import zipfile

safe = {
    "model": "normal",
    "messages": [{"role": "user", "content": [
        {"type": "text", "text": "Audit these two internal project files independently."},
        {"type": "input_file", "filename": "notes.txt", "file_data": "data:text/plain;base64," + base64.b64encode(b"normal deployment notes").decode()},
        {"type": "input_file", "filename": "config.json", "file_data": "data:application/json;base64," + base64.b64encode(b'{"mode":"safe"}').decode()},
    ]}],
}
large_text = "HEAD_ATTACHMENT_MARKER\n" + ("normal project log line\n" * 6000) + "TAIL_ATTACHMENT_MARKER\n"
large = {
    "model": "normal",
    "messages": [{"role": "user", "content": [
        {"type": "text", "text": "Audit the attached large log using bounded sampling."},
        {"type": "input_file", "filename": "large.log", "file_data": "data:text/plain;base64," + base64.b64encode(large_text.encode()).decode()},
    ]}],
}
png = base64.b64decode("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAusB9Y9Z3E8AAAAASUVORK5CYII=")
image_payload = {
    "model": "normal",
    "messages": [{"role": "user", "content": [
        {"type": "text", "text": "Audit the attached screenshot independently."},
        {"type": "image_url", "image_url": {"url": "data:image/png;base64," + base64.b64encode(png).decode()}},
    ]}],
}
archive_buffer = io.BytesIO()
with zipfile.ZipFile(archive_buffer, "w", zipfile.ZIP_DEFLATED) as archive:
    archive.writestr("first.txt", "normal archive child one")
    archive.writestr("folder/second.txt", "normal archive child two")
archive_payload = {
    "model": "normal",
    "messages": [{"role": "user", "content": [
        {"type": "text", "text": "Audit every file inside this archive separately."},
        {"type": "input_file", "filename": "bundle.zip", "file_data": "data:application/zip;base64," + base64.b64encode(archive_buffer.getvalue()).decode()},
    ]}],
}
for path, payload in zip(sys.argv[1:], [safe, large, image_payload, archive_payload]):
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, separators=(",", ":"))
PY

status="$(curl --silent --show-error -o "${WORKDIR}/attachment-safe-response.json" -w '%{http_code}' \
  "${gateway}" "${gateway_auth[@]}" -H 'X-Request-ID: e2e-attachment-safe-files' \
  --data-binary @"${WORKDIR}/attachment-safe.json")"
assert_status 200 "${status}" "${WORKDIR}/attachment-safe-response.json"
contains "${WORKDIR}/attachment-safe-response.json" 'mock provider success'

status="$(curl --silent --show-error -o "${WORKDIR}/attachment-large-response.json" -w '%{http_code}' \
  "${gateway}" "${gateway_auth[@]}" -H 'X-Request-ID: e2e-attachment-large-sampled' \
  --data-binary @"${WORKDIR}/attachment-large.json")"
assert_status 200 "${status}" "${WORKDIR}/attachment-large-response.json"

status="$(curl --silent --show-error -o "${WORKDIR}/attachment-image-response.json" -w '%{http_code}' \
  "${gateway}" "${gateway_auth[@]}" -H 'X-Request-ID: e2e-attachment-image' \
  --data-binary @"${WORKDIR}/attachment-image.json")"
assert_status 200 "${status}" "${WORKDIR}/attachment-image-response.json"

status="$(curl --silent --show-error -o "${WORKDIR}/attachment-archive-response.json" -w '%{http_code}' \
  "${gateway}" "${gateway_auth[@]}" -H 'X-Request-ID: e2e-attachment-archive' \
  --data-binary @"${WORKDIR}/attachment-archive.json")"
assert_status 200 "${status}" "${WORKDIR}/attachment-archive-response.json"

status="$(curl --silent --show-error -o "${WORKDIR}/attachment-malicious-response.json" -w '%{http_code}' \
  "${gateway}" "${gateway_auth[@]}" -H 'X-Request-ID: e2e-attachment-malicious' \
  --data-binary '{"model":"normal","messages":[{"role":"user","content":[{"type":"text","text":"Review this project attachment."},{"type":"input_file","filename":"payload.txt","file_data":"data:text/plain;base64,YXR0YWNobWVudC1maWxlLW1hbHdhcmUtbWFya2Vy"}]}]}')"
assert_status 555 "${status}" "${WORKDIR}/attachment-malicious-response.json"
contains "${WORKDIR}/attachment-malicious-response.json" 'CYBER_ATTACHMENT_FILE_MALWARE'

printf 'normal uploaded file for dry run\n' >"${WORKDIR}/dry-run.txt"
curl --fail --silent --show-error \
  "${BASE_URL}/api/admin/v1/attachment-audits/dry-run" "${auth[@]}" \
  -F "files=@${WORKDIR}/dry-run.txt;type=text/plain" \
  -F 'fail_closed=false' >"${WORKDIR}/attachment-dry-run.json"
contains "${WORKDIR}/attachment-dry-run.json" '"audited":1'
contains "${WORKDIR}/attachment-dry-run.json" '"name":"dry-run.txt"'

'''
    e2e = e2e[:pos] + block + e2e[pos:]

    wait_old = "     grep -Fq 'e2e-audit-structured-recovery' \"${WORKDIR}/traces.json\"; then"
    wait_new = "     grep -Fq 'e2e-audit-structured-recovery' \"${WORKDIR}/traces.json\" && \\\n     grep -Fq 'e2e-attachment-safe-files' \"${WORKDIR}/traces.json\" && \\\n     grep -Fq 'e2e-attachment-large-sampled' \"${WORKDIR}/traces.json\" && \\\n     grep -Fq 'e2e-attachment-image' \"${WORKDIR}/traces.json\" && \\\n     grep -Fq 'e2e-attachment-archive' \"${WORKDIR}/traces.json\" && \\\n     grep -Fq 'e2e-attachment-malicious' \"${WORKDIR}/traces.json\"; then"
    if wait_old not in e2e:
        raise SystemExit("E2E trace wait anchor not found")
    e2e = e2e.replace(wait_old, wait_new, 1)

    assert_marker = 'too_large = next((item for item in items if item.get("request_id") == "e2e-request-too-large"), None)\n'
    if assert_marker not in e2e:
        raise SystemExit("E2E attachment assertion marker not found")
    assertions = r'''attachment_safe = next((item for item in items if item.get("request_id") == "e2e-attachment-safe-files"), None)
if not attachment_safe:
    raise RuntimeError("safe attachment trace is missing")
asm = attachment_safe.get("metadata", {})
if int(asm.get("attachment_count", 0)) != 2 or int(asm.get("attachment_audited_count", 0)) != 2:
    raise RuntimeError(f"safe attachments were not audited independently: {asm}")
if int(asm.get("attachment_blocked_count", 0)) != 0 or int(asm.get("attachment_error_count", 0)) != 0:
    raise RuntimeError(f"safe attachments unexpectedly failed: {asm}")
names = {entry.get("name") for entry in asm.get("attachment_audits", [])}
if not {"notes.txt", "config.json"}.issubset(names):
    raise RuntimeError(f"safe attachment names are missing: {names}")

attachment_large = next((item for item in items if item.get("request_id") == "e2e-attachment-large-sampled"), None)
if not attachment_large:
    raise RuntimeError("large attachment trace is missing")
alm = attachment_large.get("metadata", {})
large_item = next((entry for entry in alm.get("attachment_audits", []) if entry.get("name") == "large.log"), None)
if not large_item or large_item.get("sampled") is not True or not large_item.get("sample_ranges"):
    raise RuntimeError(f"large attachment was not deterministically sampled: {alm}")
if int(large_item.get("audited_text_bytes", 0)) > 40000:
    raise RuntimeError(f"large attachment exceeded configured sample budget: {large_item}")

attachment_image = next((item for item in items if item.get("request_id") == "e2e-attachment-image"), None)
if not attachment_image:
    raise RuntimeError("image attachment trace is missing")
aim = attachment_image.get("metadata", {})
image_item = next((entry for entry in aim.get("attachment_audits", []) if entry.get("kind") == "image"), None)
if not image_item or image_item.get("extraction_method") != "multimodal_pixels" or image_item.get("decision") != "allow":
    raise RuntimeError(f"image pixels were not audited by the multimodal path: {aim}")

attachment_archive = next((item for item in items if item.get("request_id") == "e2e-attachment-archive"), None)
if not attachment_archive:
    raise RuntimeError("archive attachment trace is missing")
aam = attachment_archive.get("metadata", {})
archive_items = aam.get("attachment_audits", [])
if len(archive_items) < 3 or not any(entry.get("parent_index") for entry in archive_items):
    raise RuntimeError(f"archive children were not audited individually: {aam}")
if any(entry.get("decision") == "error" for entry in archive_items):
    raise RuntimeError(f"archive child audit failed: {aam}")

attachment_malicious = next((item for item in items if item.get("request_id") == "e2e-attachment-malicious"), None)
if not attachment_malicious:
    raise RuntimeError("malicious attachment trace is missing")
amm = attachment_malicious.get("metadata", {})
if attachment_malicious.get("decision") != "block" or attachment_malicious.get("risk_code") != "CYBER_ATTACHMENT_FILE_MALWARE":
    raise RuntimeError(f"malicious file did not block the request: {attachment_malicious}")
if int(amm.get("attachment_blocked_count", 0)) != 1 or amm.get("upstream_started") is True:
    raise RuntimeError(f"malicious attachment reached the real upstream: {amm}")

'''
    e2e = e2e.replace(assert_marker, assertions + assert_marker, 1)
write("scripts/e2e.sh", e2e)

# OpenAPI endpoint.
openapi = read("docs/openapi.yaml")
if "/api/admin/v1/attachment-audits/dry-run:" not in openapi:
    marker = "  /api/admin/v1/cyber-rule-candidates:\n"
    if marker not in openapi:
        raise SystemExit("OpenAPI candidate marker not found")
    path_doc = '''  /api/admin/v1/attachment-audits/dry-run:
    post:
      operationId: dryRunAttachmentAudit
      summary: Audit uploaded images and files independently without forwarding them upstream.
      description: Supports multiple multipart files. Archives are expanded within configured entry, depth, decompression-ratio, and total-byte limits. Raw file bytes are never returned or persisted.
      security:
        - AdminBearer: []
      requestBody:
        required: true
        content:
          multipart/form-data:
            schema:
              type: object
              required: [files]
              properties:
                profile_id: {type: integer, format: int64, minimum: 1}
                fail_closed: {type: boolean, default: false}
                files:
                  type: array
                  items: {type: string, format: binary}
      responses:
        "200": {description: Per-file attachment audit report.}
        "400": {description: Invalid multipart input, profile, or attachment.}
        "401": {description: Administrator authentication required.}
        "403": {description: Operator role required.}
        "413": {description: Upload or file count exceeds configured limits.}
'''
    openapi = openapi.replace(marker, path_doc + marker, 1)
write("docs/openapi.yaml", openapi)

# README and operational documentation.
readme = read("README.md")
if "## 图片与文件逐项审计" not in readme:
    marker = "## Git 更新与安全升级\n"
    if marker not in readme:
        raise SystemExit("README upgrade marker not found")
    section = '''## 图片与文件逐项审计

Gateway 会从 Chat Completions 和 Responses API 的最终用户输入中识别 `image_url`、`input_image`、`input_file`、`file_data`、`file_url` 和常见 attachment 结构。原始请求保持不变并只在全部审计通过后转发；每个图片、文件以及压缩包子文件分别产生审计结果。

支持范围：

```text
图片：PNG / JPEG / GIF，以及受大小限制的 WebP、AVIF 等模型可识别格式
文档：PDF / DOCX / PPTX / XLSX / ODT / ODS / ODP
文本：Markdown / JSON / YAML / XML / CSV / 日志 / 源码 / 配置 / 邮件
压缩：ZIP / TAR / TAR.GZ / GZIP（受条目数、深度、解压比例和总字节限制）
其他二进制：提取可打印字符串后进行有限审计
```

大文本不是简单截断开头，而是选择：头部、尾部、均匀分布区间和安全信号附近窗口，再按段逐项审计。图片超过模型输入预算时会在网关内缩放并转成受限 JPEG。远程 URL 使用独立 SSRF-safe 客户端，禁止重定向和私网地址；超出远程图片硬读取上限时拒绝，不把 URL 转交模型重新解析。

审计 Profile Extra 示例：

```json
{
  "_risk_policy_mode": "internal_engineering",
  "_risk_supports_vision": true,
  "_risk_attachment_profile_id": 2,
  "_risk_attachment_fail_closed": true,
  "_risk_image_detail": "auto",
  "_risk_structured_output_mode": "auto"
}
```

`_risk_attachment_profile_id` 可指定独立的图片/文件模型；未配置时复用当前文本审计模型。图片模型必须支持 OpenAI-compatible `image_url` 内容。管理后台的“附件审计”页面可以直接多文件上传测试，Trace 会保存文件名、MIME、SHA-256、抽样范围、分段数量、模型尝试和结论，但不会保存原始文件或 Data URL。

'''
    readme = readme.replace(marker, section + marker, 1)
write("README.md", readme)

write(
    "docs/attachment-media-audit.md",
    '''# 图片与文件审计链路

## 处理顺序

```text
结构化请求解析
→ 只发现最终用户角色中的附件
→ 每个根附件独立编号和去重
→ data/base64 解码或 SSRF-safe URL 拉取
→ MIME 嗅探与文件类型判定
→ 图片缩放 / 文档文本提取 / 压缩包受限展开
→ 大文本分层抽样
→ 每个文件、子文件、抽样段分别执行规则和模型审计
→ Block > Review > Allow 聚合
→ 全部通过后才调用真实上游
```

## 文件过大时的策略

文本和日志超过 `ATTACHMENT_SAMPLE_MAX_BYTES` 后，平台组合以下窗口：

1. 文件头；
2. 文件尾；
3. 四个均匀分布的中间窗口；
4. 凭据、恶意软件、C2、持久化、绕过和外传等高信号附近窗口。

窗口去重、合并并严格压缩到预算，再按 `ATTACHMENT_SEGMENT_BYTES` 切分。远程超大文本使用 HTTP Range 获取头、中、尾三个区间。PDF、Office 和压缩包必须在 `ATTACHMENT_FETCH_MAX_BYTES` 内完整读取才能可靠解析；上限可配置到 256 MiB。

## 图片

图片以 OpenAI-compatible `image_url` 内容部件送给支持视觉的审计 Profile。PNG/JPEG/GIF 超过 `ATTACHMENT_IMAGE_MAX_BYTES` 或像素预算时在本地解码、缩放并压缩为 JPEG；原图仍保留在原始用户请求中，审计副本不会覆盖上游请求。

图片 Block/Review 的 evidence 是经过脱敏的视觉观察，标记为 `visual_observation`。文档 evidence 仍必须是抽取文本中的连续原文。

## 安全边界

- 不读取请求中声称的本地文件路径；
- 默认禁止私网、环回、链路本地和云元数据 URL；
- URL 禁止重定向；
- 原始附件、Data URL、Base64 和远程 URL 不写入 Trace；
- API Key、Bearer Token 和密码在抽取文本进入规则/模型前替换为占位符；
- ZIP/TAR 限制条目数、递归深度、单项/总解压字节和解压比；
- 全局与单请求并发信号量限制模型调用和内存放大；
- opaque `file_id` 若没有 `file_data` 或安全 `file_url`，明确报 `file_id_unresolved`，绝不假装已审计。

## 主要配置

```env
ATTACHMENT_AUDIT_ENABLED=true
ATTACHMENT_MAX_COUNT=16
ATTACHMENT_FETCH_MAX_BYTES=67108864
ATTACHMENT_TOTAL_MAX_BYTES=134217728
ATTACHMENT_EXTRACT_MAX_BYTES=33554432
ATTACHMENT_SAMPLE_MAX_BYTES=1048576
ATTACHMENT_SEGMENT_BYTES=196608
ATTACHMENT_IMAGE_MAX_BYTES=8388608
ATTACHMENT_IMAGE_MAX_PIXELS=20000000
ATTACHMENT_PER_REQUEST_CONCURRENCY=2
ATTACHMENT_GLOBAL_CONCURRENCY=16
ATTACHMENT_FETCH_TIMEOUT=15s
ATTACHMENT_ARCHIVE_MAX_ENTRIES=128
ATTACHMENT_ARCHIVE_MAX_DEPTH=2
ATTACHMENT_ARCHIVE_MAX_BYTES=134217728
ATTACHMENT_ALLOW_REMOTE_URLS=true
ATTACHMENT_ALLOW_PRIVATE_URLS=false
```

生产环境开启私网附件 URL 时，还必须显式设置 `ACK_ATTACHMENT_PRIVATE_URL_SSRF_RISK=true`，并通过网络策略限制出口。
''',
)

print("attachment audit console, API, docs and E2E applied")
