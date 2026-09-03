from __future__ import annotations

from pathlib import Path

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
    if old not in content:
        raise SystemExit(f"{label}: anchor not found in {path}")
    write(path, content.replace(old, new, 1))


# ---------------------------------------------------------------------------
# Manual approval path for Shadow-first adaptive candidates.
# ---------------------------------------------------------------------------
write(
    "internal/platform/adaptive_admin.go",
    r'''package platform

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5"
)

func normalizeManualCandidateAction(value string) (string, error) {
	action := strings.ToLower(strings.TrimSpace(value))
	switch action {
	case DecisionReview, DecisionBlock:
		return action, nil
	default:
		return "", errors.New("action must be review or block")
	}
}

func normalizeCandidateWorkflowStatus(value string) (string, error) {
	status := strings.ToLower(strings.TrimSpace(value))
	switch status {
	case "shadow", "rejected":
		return status, nil
	default:
		return "", errors.New("status must be shadow or rejected")
	}
}

func (s *Store) PromoteCyberRuleCandidateManual(
	ctx context.Context,
	id int64,
	requestedAction string,
) (CyberRuleCandidate, CyberRule, error) {
	action, err := normalizeManualCandidateAction(requestedAction)
	if err != nil {
		return CyberRuleCandidate{}, CyberRule{}, err
	}

	transaction, err := s.pool.Begin(ctx)
	if err != nil {
		return CyberRuleCandidate{}, CyberRule{}, err
	}
	defer transaction.Rollback(ctx)

	candidate, err := scanCyberRuleCandidate(transaction.QueryRow(ctx,
		`SELECT `+cyberRuleCandidateColumns+`
		 FROM cyber_rule_candidates
		 WHERE id=$1
		 FOR UPDATE`,
		id,
	))
	if errors.Is(err, pgx.ErrNoRows) {
		return CyberRuleCandidate{}, CyberRule{}, ErrNotFound
	}
	if err != nil {
		return CyberRuleCandidate{}, CyberRule{}, err
	}
	if candidate.Status != "candidate" && candidate.Status != "shadow" {
		return CyberRuleCandidate{}, CyberRule{}, fmt.Errorf(
			"candidate cannot be promoted from status %q",
			candidate.Status,
		)
	}

	ruleInput := CyberRule{
		Code:        candidate.ProposedCode,
		Name:        truncateString("Adaptive approved: "+candidate.Category, 200),
		Description: truncateString("Manually approved through the Shadow-first workflow. "+candidate.Reason, 2000),
		Category:    candidate.Category,
		Pattern:     candidate.Pattern,
		PatternType: candidate.PatternType,
		Action:      action,
		Priority:    1200,
		Enabled:     true,
	}
	if err := ValidateCyberRule(ruleInput); err != nil {
		return CyberRuleCandidate{}, CyberRule{}, fmt.Errorf("candidate rule is invalid: %w", err)
	}

	const ruleColumns = `id,code,name,description,category,pattern,pattern_type,action,priority,enabled,created_at,updated_at`
	rule, err := scanCyberRule(transaction.QueryRow(ctx, `INSERT INTO cyber_rules
		(code,name,description,category,pattern,pattern_type,action,priority,enabled)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8,TRUE)
		ON CONFLICT(code) DO UPDATE SET
			name=EXCLUDED.name,
			description=EXCLUDED.description,
			category=EXCLUDED.category,
			pattern=EXCLUDED.pattern,
			pattern_type=EXCLUDED.pattern_type,
			action=EXCLUDED.action,
			priority=EXCLUDED.priority,
			enabled=TRUE,
			updated_at=now()
		RETURNING `+ruleColumns,
		ruleInput.Code,
		ruleInput.Name,
		ruleInput.Description,
		ruleInput.Category,
		ruleInput.Pattern,
		ruleInput.PatternType,
		ruleInput.Action,
		ruleInput.Priority,
	))
	if err != nil {
		return CyberRuleCandidate{}, CyberRule{}, err
	}

	command, err := transaction.Exec(ctx, `UPDATE cyber_rule_candidates
		SET status='promoted',
			proposed_action=$3,
			promoted_rule_id=$2,
			updated_at=now()
		WHERE id=$1 AND status IN ('candidate','shadow')`,
		candidate.ID,
		rule.ID,
		action,
	)
	if err != nil {
		return CyberRuleCandidate{}, CyberRule{}, err
	}
	if command.RowsAffected() != 1 {
		return CyberRuleCandidate{}, CyberRule{}, errors.New("candidate status changed during promotion")
	}
	if err := transaction.Commit(ctx); err != nil {
		return CyberRuleCandidate{}, CyberRule{}, err
	}

	candidate.Status = "promoted"
	candidate.ProposedAction = action
	candidate.PromotedRuleID = &rule.ID
	return candidate, rule, nil
}

func (s *HTTPService) adminListCyberRuleCandidates(w http.ResponseWriter, r *http.Request) {
	limit := 200
	if raw := strings.TrimSpace(r.URL.Query().Get("limit")); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < 1 || parsed > 1000 {
			writeAPIError(w, http.StatusBadRequest, "invalid_limit", "limit must be between 1 and 1000")
			return
		}
		limit = parsed
	}
	items, err := s.store.ListCyberRuleCandidates(r.Context(), limit)
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, "candidate_list_failed", "could not load adaptive rule candidates")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"items":  items,
		"policy": s.audit.AdaptivePolicy(),
	})
}

func (s *HTTPService) adminSetCyberRuleCandidateStatus(w http.ResponseWriter, r *http.Request) {
	id, err := parsePathID(r)
	if err != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid_id", "candidate id is invalid")
		return
	}
	var input struct {
		Status string `json:"status"`
	}
	if err := decodeJSONBody(w, r, 16*1024, &input); err != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	status, err := normalizeCandidateWorkflowStatus(input.Status)
	if err != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid_status", err.Error())
		return
	}
	if err := s.store.SetCyberRuleCandidateStatus(r.Context(), id, status); err != nil {
		if errors.Is(err, ErrNotFound) {
			writeAPIError(w, http.StatusNotFound, "not_found", "candidate was not found or is already promoted")
			return
		}
		writeAPIError(w, http.StatusConflict, "candidate_update_failed", "candidate status could not be updated")
		return
	}
	s.auditAdmin(r, "set_status", "cyber_rule_candidate", strconv.FormatInt(id, 10), map[string]any{
		"status": status,
	})
	writeJSON(w, http.StatusOK, map[string]any{
		"id":     id,
		"status": status,
	})
}

func (s *HTTPService) adminPromoteCyberRuleCandidate(w http.ResponseWriter, r *http.Request) {
	id, err := parsePathID(r)
	if err != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid_id", "candidate id is invalid")
		return
	}
	var input struct {
		Action string `json:"action"`
	}
	if err := decodeJSONBody(w, r, 16*1024, &input); err != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	action, err := normalizeManualCandidateAction(input.Action)
	if err != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid_action", err.Error())
		return
	}

	candidate, rule, err := s.store.PromoteCyberRuleCandidateManual(r.Context(), id, action)
	if errors.Is(err, ErrNotFound) {
		writeAPIError(w, http.StatusNotFound, "not_found", "candidate was not found")
		return
	}
	if err != nil {
		writeAPIError(w, http.StatusConflict, "candidate_promotion_failed", err.Error())
		return
	}
	if err := s.audit.ReloadRules(r.Context()); err != nil {
		s.log.Warn("manual adaptive rule reload failed", "candidate_id", candidate.ID, "rule_id", rule.ID, "error", err)
		writeAPIError(w, http.StatusInternalServerError, "rule_reload_failed", "candidate was promoted but the in-memory rule set could not be reloaded")
		return
	}
	s.auditAdmin(r, "promote", "cyber_rule_candidate", strconv.FormatInt(id, 10), map[string]any{
		"action":  action,
		"rule_id": rule.ID,
		"code":    rule.Code,
	})
	writeJSON(w, http.StatusOK, map[string]any{
		"candidate": candidate,
		"rule":      rule,
	})
}
''',
)

write(
    "internal/platform/adaptive_admin_test.go",
    r'''package platform

import "testing"

func TestNormalizeManualCandidateAction(t *testing.T) {
	for input, expected := range map[string]string{
		"review":  DecisionReview,
		" BLOCK ": DecisionBlock,
	} {
		actual, err := normalizeManualCandidateAction(input)
		if err != nil || actual != expected {
			t.Fatalf("normalizeManualCandidateAction(%q) = %q, %v; want %q", input, actual, err, expected)
		}
	}
	if _, err := normalizeManualCandidateAction("allow"); err == nil {
		t.Fatal("manual candidate promotion must not create an allow rule")
	}
}

func TestNormalizeCandidateWorkflowStatus(t *testing.T) {
	for _, value := range []string{"shadow", " REJECTED "} {
		if _, err := normalizeCandidateWorkflowStatus(value); err != nil {
			t.Fatalf("expected valid status %q: %v", value, err)
		}
	}
	for _, value := range []string{"promoted", "candidate", "unknown"} {
		if _, err := normalizeCandidateWorkflowStatus(value); err == nil {
			t.Fatalf("expected invalid status %q", value)
		}
	}
}
''',
)

replace_once(
    "internal/platform/http.go",
    '''\t\tadmin.Get("/api/admin/v1/cyber-rules", s.adminListCyberRules)
\t\tadmin.With(s.requireRole("operator")).Post("/api/admin/v1/cyber-rules", s.adminSaveCyberRule)
\t\tadmin.With(s.requireRole("admin")).Delete("/api/admin/v1/cyber-rules/{id}", s.adminDeleteCyberRule)
''',
    '''\t\tadmin.Get("/api/admin/v1/cyber-rules", s.adminListCyberRules)
\t\tadmin.With(s.requireRole("operator")).Post("/api/admin/v1/cyber-rules", s.adminSaveCyberRule)
\t\tadmin.With(s.requireRole("admin")).Delete("/api/admin/v1/cyber-rules/{id}", s.adminDeleteCyberRule)
\t\tadmin.Get("/api/admin/v1/cyber-rule-candidates", s.adminListCyberRuleCandidates)
\t\tadmin.With(s.requireRole("admin")).Patch("/api/admin/v1/cyber-rule-candidates/{id}", s.adminSetCyberRuleCandidateStatus)
\t\tadmin.With(s.requireRole("admin")).Post("/api/admin/v1/cyber-rule-candidates/{id}/promote", s.adminPromoteCyberRuleCandidate)
''',
    "adaptive candidate admin routes",
)

# ---------------------------------------------------------------------------
# Visual Shadow-first review console.
# ---------------------------------------------------------------------------
replace_once(
    "internal/platform/web/index.html",
    '''          <div class="view-head"><div><h2>Cyber 规则</h2><p>规则按优先级从高到低执行。Block 或 Allow 直接决策，Review 交给小模型。内置默认规则也可以直接编辑、改动作、改优先级或禁用，保存后立即热加载。</p></div><button id="new-rule-button" class="btn btn-primary">新增规则</button></div>
          <div class="grid split">
''',
    '''          <div class="view-head"><div><h2>Cyber 规则</h2><p>规则按优先级从高到低执行。Block 或 Allow 直接决策，Review 交给小模型。内置默认规则也可以直接编辑、改动作、改优先级或禁用，保存后立即热加载。</p></div><button id="new-rule-button" class="btn btn-primary">新增规则</button></div>
          <div class="card">
            <div class="panel-head"><div><h3>自适应规则候选（Shadow-first）</h3><p class="muted">候选只收集证据，不会自动进入执法。管理员审阅后可晋升为 Review 或 Block；Block 需要明确确认。</p></div><span id="rule-candidate-policy" class="badge">加载中</span></div>
            <div id="rule-candidates-table"></div>
          </div>
          <div class="grid split">
''',
    "adaptive candidate panel",
)

replace_once(
    "internal/platform/web/index.html",
    '''      const state = { token: sessionStorage.getItem('risk_token') || '', user: null, view: 'dashboard', routes: [], profiles: [], profileFallbackChain: [], rules: [], clients: [], traceItems: [], traceTotal: 0, traceOffset: 0, traceLimit: 100 };
''',
    '''      const state = { token: sessionStorage.getItem('risk_token') || '', user: null, view: 'dashboard', routes: [], profiles: [], profileFallbackChain: [], rules: [], ruleCandidates: [], adaptivePolicy: null, clients: [], traceItems: [], traceTotal: 0, traceOffset: 0, traceLimit: 100 };
''',
    "admin state candidates",
)

html = read("internal/platform/web/index.html")
rules_start = html.find("      async function loadRules() {")
rules_end = html.find("      function resetRule() {", rules_start)
if rules_start < 0 or rules_end < 0:
    raise SystemExit("rules UI function anchors not found")
new_rules_ui = r'''      function renderRuleCandidates() {
        const policy=state.adaptivePolicy||{};
        const policyLabel=`学习 ${policy.enabled===false?'关闭':'开启'} · 自动晋升 ${policy.auto_promote?'开启':'关闭'} · 自动 Block ${policy.auto_block?'开启':'关闭'}`;
        $('rule-candidate-policy').textContent=policyLabel;
        $('rule-candidate-policy').className=`badge ${(policy.auto_promote||policy.auto_block)?'warn':'ok'}`;
        if(!state.ruleCandidates.length){
          $('rule-candidates-table').innerHTML='<div class="empty">暂无自适应候选</div>';
          return;
        }
        const canApprove=state.user?.role==='admin';
        $('rule-candidates-table').innerHTML=`<div class="table-wrap"><table><thead><tr><th>候选</th><th>证据</th><th>建议模式</th><th>状态</th><th>人工决策</th></tr></thead><tbody>${state.ruleCandidates.map(candidate=>{
          const confidence=`${(Number(candidate.confidence||0)*100).toFixed(1)}%`;
          const pattern=String(candidate.pattern||'');
          const reason=String(candidate.reason||'');
          let controls='<span class="muted">仅管理员可审批</span>';
          if(canApprove&&candidate.status!=='promoted'){
            const restore=candidate.status==='rejected'?`<button class="btn btn-small btn-secondary" data-candidate-status="${candidate.id}" data-status="shadow">恢复 Shadow</button>`:`<button class="btn btn-small btn-danger" data-candidate-status="${candidate.id}" data-status="rejected">拒绝</button>`;
            controls=`<div class="actions"><button class="btn btn-small btn-secondary" data-candidate-promote="${candidate.id}" data-action="review">晋升 Review</button><button class="btn btn-small btn-danger" data-candidate-promote="${candidate.id}" data-action="block">晋升 Block</button>${restore}</div>`;
          }else if(candidate.status==='promoted'){
            controls=`<span class="mono">规则 #${escapeHTML(candidate.promoted_rule_id||'-')}</span>`;
          }
          return `<tr><td><strong class="mono">${escapeHTML(candidate.proposed_code)}</strong><br>${escapeHTML(candidate.category)}<br><span class="muted">${escapeHTML(candidate.model||'-')} · ${escapeHTML(candidate.route_slug||'-')}</span></td><td>置信度 ${confidence}<br>样本 ${number(candidate.evidence_count)} · 用户 ${number(candidate.distinct_users)}<br><span class="muted">${escapeHTML(reason.slice(0,180))}${reason.length>180?'…':''}</span></td><td><span class="mono">${escapeHTML(candidate.pattern_type)}</span><br><span class="mono">${escapeHTML(pattern.slice(0,130))}${pattern.length>130?'…':''}</span></td><td>${badge(candidate.status||'candidate')}<br><span class="muted">${escapeHTML(dateText(candidate.last_seen_at))}</span></td><td>${controls}</td></tr>`;
        }).join('')}</tbody></table></div>`;
      }
      async function loadRules() {
        const [ruleData,candidateData]=await Promise.all([
          api('/api/admin/v1/cyber-rules'),
          api('/api/admin/v1/cyber-rule-candidates?limit=200')
        ]);
        state.rules=ruleData.items||[];
        state.ruleCandidates=candidateData.items||[];
        state.adaptivePolicy=candidateData.policy||null;
        $('rules-table').innerHTML=state.rules.length?`<div class="table-wrap"><table><thead><tr><th>规则</th><th>匹配</th><th>动作</th><th>状态</th><th>操作</th></tr></thead><tbody>${state.rules.map(rule=>`<tr><td><strong>${escapeHTML(rule.name)}</strong><br><span class="mono">${escapeHTML(rule.code)}</span><br><span class="muted">优先级 ${rule.priority}</span></td><td>${escapeHTML(rule.pattern_type)}<br><span class="mono">${escapeHTML(String(rule.pattern).slice(0,90))}${String(rule.pattern).length>90?'…':''}</span></td><td>${badge(rule.action)}<br>${escapeHTML(rule.category)}</td><td>${badge(rule.enabled?'enabled':'disabled')}</td><td><button class="btn btn-small btn-secondary" data-rule-edit="${rule.id}">编辑</button> <button class="btn btn-small btn-danger" data-rule-delete="${rule.id}">删除</button></td></tr>`).join('')}</tbody></table></div>`:'<div class="empty">尚未配置规则</div>';
        renderRuleCandidates();
      }
      async function setRuleCandidateStatus(id,status) {
        if(status==='rejected'&&!confirm('确认拒绝该候选？拒绝后仍可恢复到 Shadow。'))return;
        try{
          await api(`/api/admin/v1/cyber-rule-candidates/${id}`,{method:'PATCH',body:JSON.stringify({status})});
          toast(status==='rejected'?'候选已拒绝':'候选已恢复为 Shadow');
          await loadRules();
        }catch(error){toast(error.message,'error');}
      }
      async function promoteRuleCandidate(id,action) {
        const label=action==='block'?'Block':'Review';
        const warning=action==='block'
          ?'确认把该候选晋升为 Block 执法规则？后续命中会直接拦截。'
          :'确认把该候选晋升为 Review 规则？后续命中将交给审计模型复核。';
        if(!confirm(warning))return;
        try{
          const result=await api(`/api/admin/v1/cyber-rule-candidates/${id}/promote`,{method:'POST',body:JSON.stringify({action})});
          toast(`候选已晋升为 ${label}：${result.rule?.code||''}`);
          await loadRules();
        }catch(error){toast(error.message,'error');}
      }
'''
html = html[:rules_start] + new_rules_ui + html[rules_end:]
write("internal/platform/web/index.html", html)

replace_once(
    "internal/platform/web/index.html",
    '''      $('new-rule-button').addEventListener('click',resetRule);$('rule-reset').addEventListener('click',resetRule);$('rule-form').addEventListener('submit',saveRule);$('rules-table').addEventListener('click',event=>{const edit=event.target.closest('[data-rule-edit]');const remove=event.target.closest('[data-rule-delete]');if(edit)editRule(edit.dataset.ruleEdit);if(remove)deleteRule(remove.dataset.ruleDelete);});
''',
    '''      $('new-rule-button').addEventListener('click',resetRule);$('rule-reset').addEventListener('click',resetRule);$('rule-form').addEventListener('submit',saveRule);$('rules-table').addEventListener('click',event=>{const edit=event.target.closest('[data-rule-edit]');const remove=event.target.closest('[data-rule-delete]');if(edit)editRule(edit.dataset.ruleEdit);if(remove)deleteRule(remove.dataset.ruleDelete);});$('rule-candidates-table').addEventListener('click',event=>{const promote=event.target.closest('[data-candidate-promote]');const status=event.target.closest('[data-candidate-status]');if(promote)promoteRuleCandidate(Number(promote.dataset.candidatePromote),promote.dataset.action);if(status)setRuleCandidateStatus(Number(status.dataset.candidateStatus),status.dataset.status);});
''',
    "adaptive candidate UI events",
)

# ---------------------------------------------------------------------------
# E2E: observe in Shadow, assert no automatic enforcement, then approve.
# ---------------------------------------------------------------------------
e2e = read("scripts/e2e.sh")
adaptive_start = e2e.find("adaptive_promoted=0\nfor _ in $(seq 1 80); do")
adaptive_end = e2e.find('status="$(curl --silent --show-error -o "${WORKDIR}/adaptive-local-block.json"', adaptive_start)
if adaptive_start < 0 or adaptive_end < 0:
    raise SystemExit("adaptive E2E block anchors not found")
adaptive_replacement = r'''adaptive_candidate_id=""
for _ in $(seq 1 80); do
  curl --fail --silent --show-error \
    "${BASE_URL}/api/admin/v1/cyber-rule-candidates?limit=100" \
    "${auth[@]}" >"${WORKDIR}/adaptive-candidates.json"
  adaptive_candidate_id="$(python3 - "${WORKDIR}/adaptive-candidates.json" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    payload = json.load(handle)
policy = payload.get("policy", {})
if policy.get("auto_promote") is not False or policy.get("auto_block") is not False:
    raise SystemExit("Shadow-first policy is not active")
for item in payload.get("items", []):
    if (
        str(item.get("proposed_code", "")).startswith("CYBER_ADAPTIVE_MALWARE_")
        and item.get("status") in {"candidate", "shadow"}
        and int(item.get("evidence_count", 0)) >= 3
        and int(item.get("distinct_users", 0)) >= 2
    ):
        print(item["id"])
        break
PY
)"
  if [[ -n "${adaptive_candidate_id}" ]]; then
    break
  fi
  sleep 0.25
done
[[ -n "${adaptive_candidate_id}" ]] || fail "adaptive provider failures did not create a Shadow candidate"

curl --fail --silent --show-error \
  "${BASE_URL}/api/admin/v1/cyber-rules" \
  "${auth[@]}" >"${WORKDIR}/adaptive-rules-before-approval.json"
if python3 - "${WORKDIR}/adaptive-rules-before-approval.json" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    items = json.load(handle).get("items", [])
raise SystemExit(0 if any(
    str(item.get("code", "")).startswith("CYBER_ADAPTIVE_MALWARE_")
    and item.get("action") == "block"
    and item.get("enabled") is True
    for item in items
) else 1)
PY
then
  fail "Shadow candidate became an enforcing block rule without administrator approval"
fi

status="$(curl --silent --show-error -o "${WORKDIR}/adaptive-promote.json" -w '%{http_code}' \
  "${BASE_URL}/api/admin/v1/cyber-rule-candidates/${adaptive_candidate_id}/promote" \
  "${auth[@]}" -H 'Content-Type: application/json' \
  --data-binary '{"action":"block"}')"
assert_status 200 "${status}" "${WORKDIR}/adaptive-promote.json"
contains "${WORKDIR}/adaptive-promote.json" 'CYBER_ADAPTIVE_MALWARE_'
contains "${WORKDIR}/adaptive-promote.json" '"action":"block"'

'''
e2e = e2e[:adaptive_start] + adaptive_replacement + e2e[adaptive_end:]
write("scripts/e2e.sh", e2e)

# ---------------------------------------------------------------------------
# Safe Git fast-forward update and deployment scripts.
# ---------------------------------------------------------------------------
write(
    "scripts/upgrade.sh",
    r'''#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT_DIR}"

REMOTE="${GIT_REMOTE:-origin}"
CURRENT_BRANCH="$(git symbolic-ref --quiet --short HEAD 2>/dev/null || true)"
TARGET_BRANCH="${1:-${TARGET_BRANCH:-${CURRENT_BRANCH}}}"
BACKUP_DATABASE="${BACKUP_DATABASE:-1}"
ROLLBACK_ON_FAILURE="${ROLLBACK_ON_FAILURE:-1}"
ALLOW_BRANCH_SWITCH="${ALLOW_BRANCH_SWITCH:-0}"
ALLOW_DIRTY_WORKTREE="${ALLOW_DIRTY_WORKTREE:-0}"
LOCK_FILE="${UPGRADE_LOCK_FILE:-${ROOT_DIR}/.git/newapi-risk-upgrade.lock}"

log() {
  printf '[upgrade] %s\n' "$*"
}

fail() {
  printf '[upgrade] ERROR: %s\n' "$*" >&2
  exit 1
}

truthy() {
  [[ "${1:-}" =~ ^(1|true|yes|on)$ ]]
}

for command in git docker python3 curl flock; do
  command -v "${command}" >/dev/null 2>&1 || fail "${command} is required"
done
docker compose version >/dev/null 2>&1 || fail "Docker Compose v2 is required"
git rev-parse --is-inside-work-tree >/dev/null 2>&1 || fail "run this script inside the Git repository"

exec 9>"${LOCK_FILE}"
flock -n 9 || fail "another upgrade is already running"

[[ -n "${CURRENT_BRANCH}" ]] || fail "detached HEAD is not supported"
[[ -n "${TARGET_BRANCH}" ]] || fail "target branch is empty"

if ! truthy "${ALLOW_DIRTY_WORKTREE}"; then
  dirty="$(git status --porcelain --untracked-files=normal)"
  [[ -z "${dirty}" ]] || {
    printf '%s\n' "${dirty}" >&2
    fail "working tree is not clean; commit, stash, or remove local changes first"
  }
fi

if [[ "${CURRENT_BRANCH}" != "${TARGET_BRANCH}" ]]; then
  truthy "${ALLOW_BRANCH_SWITCH}" || fail "current branch is ${CURRENT_BRANCH}; set ALLOW_BRANCH_SWITCH=1 to switch to ${TARGET_BRANCH}"
  if git show-ref --verify --quiet "refs/heads/${TARGET_BRANCH}"; then
    git switch "${TARGET_BRANCH}"
  else
    git fetch --prune "${REMOTE}" "refs/heads/${TARGET_BRANCH}:refs/remotes/${REMOTE}/${TARGET_BRANCH}"
    git switch --track -c "${TARGET_BRANCH}" "${REMOTE}/${TARGET_BRANCH}"
  fi
  CURRENT_BRANCH="${TARGET_BRANCH}"
fi

log "fetching ${REMOTE}/${TARGET_BRANCH}"
git fetch --prune "${REMOTE}" "refs/heads/${TARGET_BRANCH}:refs/remotes/${REMOTE}/${TARGET_BRANCH}"

OLD_COMMIT="$(git rev-parse HEAD)"
TARGET_COMMIT="$(git rev-parse "${REMOTE}/${TARGET_BRANCH}")"
git merge-base --is-ancestor "${OLD_COMMIT}" "${TARGET_COMMIT}" ||
  fail "remote history is not a fast-forward from ${OLD_COMMIT}; manual review is required"

timestamp="$(date -u '+%Y%m%dT%H%M%SZ')"
BACKUP_DIR="${ROOT_DIR}/.upgrade-backups/${timestamp}-${OLD_COMMIT:0:12}"
mkdir -p "${BACKUP_DIR}"
printf '%s\n' "${OLD_COMMIT}" >"${BACKUP_DIR}/old-commit"
printf '%s\n' "${TARGET_COMMIT}" >"${BACKUP_DIR}/target-commit"
printf '%s\n' "${TARGET_BRANCH}" >"${BACKUP_DIR}/branch"

ENV_EXISTED=0
if [[ -f .env ]]; then
  ENV_EXISTED=1
  cp -p .env "${BACKUP_DIR}/env.backup"
  chmod 600 "${BACKUP_DIR}/env.backup"
fi

DB_BACKUP=""
if truthy "${BACKUP_DATABASE}"; then
  if docker compose ps --status running --services 2>/dev/null | grep -Fxq postgres; then
    DB_BACKUP="${BACKUP_DIR}/postgres.dump"
    log "creating PostgreSQL custom-format backup"
    if ! docker compose exec -T postgres sh -lc \
      'export PGPASSWORD="$POSTGRES_PASSWORD"; exec pg_dump -U "${POSTGRES_USER:-risk}" -d "${POSTGRES_DB:-risk}" -Fc' \
      >"${DB_BACKUP}"; then
      rm -f "${DB_BACKUP}"
      fail "database backup failed; code was not changed"
    fi
    [[ -s "${DB_BACKUP}" ]] || fail "database backup is empty; code was not changed"
    chmod 600 "${DB_BACKUP}"
  else
    log "PostgreSQL container is not running; database backup skipped"
  fi
else
  log "database backup disabled by BACKUP_DATABASE=${BACKUP_DATABASE}"
fi

write_manifest() {
  local status="$1"
  STATUS="${status}" OLD_COMMIT="${OLD_COMMIT}" TARGET_COMMIT="${TARGET_COMMIT}" \
  TARGET_BRANCH="${TARGET_BRANCH}" DB_BACKUP="${DB_BACKUP}" \
  python3 - "${BACKUP_DIR}/manifest.json" <<'PY'
import json
import os
import sys
from datetime import datetime, timezone

payload = {
    "status": os.environ["STATUS"],
    "branch": os.environ["TARGET_BRANCH"],
    "old_commit": os.environ["OLD_COMMIT"],
    "target_commit": os.environ["TARGET_COMMIT"],
    "database_backup": os.environ.get("DB_BACKUP", ""),
    "recorded_at": datetime.now(timezone.utc).isoformat(),
}
with open(sys.argv[1], "w", encoding="utf-8") as handle:
    json.dump(payload, handle, ensure_ascii=False, indent=2)
    handle.write("\n")
PY
}

rollback() {
  local original_error="$1"
  write_manifest "failed; rollback started"
  if ! truthy "${ROLLBACK_ON_FAILURE}"; then
    fail "${original_error}; automatic rollback is disabled; backup: ${BACKUP_DIR}"
  fi

  log "deployment failed; rolling code back to ${OLD_COMMIT}"
  git reset --hard "${OLD_COMMIT}"
  if [[ "${ENV_EXISTED}" == "1" ]]; then
    cp -p "${BACKUP_DIR}/env.backup" .env
    chmod 600 .env
  else
    rm -f .env
  fi

  if bash scripts/deploy-local.sh; then
    write_manifest "failed; code and containers rolled back"
    printf '[upgrade] Original upgrade failed: %s\n' "${original_error}" >&2
    printf '[upgrade] Code/container rollback succeeded. Database migrations are intentionally not reversed.\n' >&2
    printf '[upgrade] Backup directory: %s\n' "${BACKUP_DIR}" >&2
    exit 1
  fi

  write_manifest "failed; rollback deployment also failed"
  printf '[upgrade] ERROR: upgrade and rollback deployment both failed\n' >&2
  printf '[upgrade] Backup directory: %s\n' "${BACKUP_DIR}" >&2
  printf '[upgrade] Inspect with: docker compose ps -a && docker compose logs --tail=300 --no-color\n' >&2
  exit 1
}

if [[ "${OLD_COMMIT}" == "${TARGET_COMMIT}" ]]; then
  log "already at ${TARGET_COMMIT}; configuration and deployment will still be verified"
else
  log "fast-forwarding ${OLD_COMMIT} -> ${TARGET_COMMIT}"
  git merge --ff-only "${REMOTE}/${TARGET_BRANCH}" || fail "fast-forward merge failed"
fi

if ! bash scripts/init-env.sh; then
  rollback "environment migration failed"
fi
if ! docker compose config --quiet; then
  rollback "Docker Compose validation failed"
fi
if ! bash scripts/deploy-local.sh; then
  rollback "container build, startup, or readiness validation failed"
fi

write_manifest "success"
log "upgrade complete"
log "branch: ${TARGET_BRANCH}"
log "commit: $(git rev-parse HEAD)"
log "backup: ${BACKUP_DIR}"
if [[ -n "${DB_BACKUP}" ]]; then
  log "database backup: ${DB_BACKUP}"
fi
''',
)

write(
    "scripts/update.sh",
    r'''#!/usr/bin/env bash
set -Eeuo pipefail
exec bash "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/upgrade.sh" "$@"
''',
)

replace_once(
    ".gitignore",
    '''.env
bin/
''',
    '''.env
.upgrade-backups/
bin/
''',
    "upgrade backup ignore",
)

replace_once(
    "Makefile",
    '''.PHONY: fmt test race vet build run init-env deploy doctor docker-up docker-down
''',
    '''.PHONY: fmt test race vet build run init-env deploy update upgrade doctor docker-up docker-down
''',
    "Makefile phony upgrade",
)
replace_once(
    "Makefile",
    '''deploy:
\tbash scripts/deploy-local.sh

doctor:
''',
    '''deploy:
\tbash scripts/deploy-local.sh

update:
\tbash scripts/update.sh

upgrade:
\tbash scripts/upgrade.sh

doctor:
''',
    "Makefile upgrade targets",
)

# ---------------------------------------------------------------------------
# Documentation and API contract.
# ---------------------------------------------------------------------------
readme = read("README.md")
old_quick = '''### 1. 准备配置

```bash
git clone https://github.com/ckbkdj/newapi-risk-platform.git
cd newapi-risk-platform
cp .env.example .env

# 填入 .env
openssl rand -base64 32   # MASTER_KEY_B64，必须解码为 32 字节
openssl rand -hex 32      # JWT_SECRET
openssl rand -base64 36   # PostgreSQL、管理员和追踪 Secret
```

不要把 `.env` 提交到 Git。

### 2. 启动 PostgreSQL、Redis 和平台

```bash
docker compose up -d --build
curl http://127.0.0.1:8080/readyz
```
'''
new_quick = '''### 1. 首次部署

```bash
git clone https://github.com/ckbkdj/newapi-risk-platform.git
cd newapi-risk-platform
bash scripts/deploy-local.sh
```

`deploy-local.sh` 会基于 `.env.example` 创建或迁移 `.env`、生成缺失的随机密钥、校验 Compose、构建容器并等待 `/readyz`。不要把 `.env` 提交到 Git。

需要手工指定既有密钥时，可先编辑 `.env`，再重新执行：

```bash
bash scripts/deploy-local.sh
```

### 2. 启动 PostgreSQL、Redis 和平台

首次部署脚本已经完成启动。后续仅重新构建并检查就绪状态时仍执行：

```bash
bash scripts/deploy-local.sh
curl http://127.0.0.1:8080/readyz
```
'''
if new_quick not in readme:
    if old_quick not in readme:
        raise SystemExit("README quick-start anchor not found")
    readme = readme.replace(old_quick, new_quick, 1)

upgrade_section = r'''
## Git 更新与安全升级

已有部署不要手工 `git pull && docker compose up`。使用仓库内升级脚本：

```bash
# 在当前分支做 fast-forward 更新、备份数据库、迁移 .env、重建并验证
bash scripts/upgrade.sh

# 明确升级 main
bash scripts/upgrade.sh main

# update.sh 是兼容入口
bash scripts/update.sh main
```

默认行为：

- 只接受 fast-forward，远端改写历史时停止，不强制覆盖本地代码；
- 工作区必须干净，避免把未提交修改卷入升级；
- `.env` 原样保留，并备份到 `.upgrade-backups/<UTC时间>-<旧提交>/`；
- PostgreSQL 正在运行时，默认先生成 `pg_dump -Fc` 备份；
- 不删除 PostgreSQL、Redis 或 Kafka Volume；
- 自动执行 `.env` 配置迁移、Compose 校验、镜像构建和 `/readyz` 检查；
- 部署失败时回退代码与容器到旧提交，但不会自动反向执行数据库迁移，避免破坏升级期间产生的数据。

可控开关：

```bash
BACKUP_DATABASE=0 bash scripts/upgrade.sh main       # 明确跳过数据库备份
ROLLBACK_ON_FAILURE=0 bash scripts/upgrade.sh main   # 禁止自动代码/容器回退
ALLOW_BRANCH_SWITCH=1 bash scripts/upgrade.sh main   # 允许从当前干净分支切换
```

升级失败时先查看脚本输出的备份目录，再运行：

```bash
docker compose ps -a
docker compose logs --tail=300 --no-color
bash scripts/doctor.sh
```

'''
if "## Git 更新与安全升级" not in readme:
    marker = "## 配置审计模型\n"
    if marker not in readme:
        raise SystemExit("README audit-model marker not found")
    readme = readme.replace(marker, upgrade_section + marker, 1)
write("README.md", readme)

precision_doc = read("docs/precision-first-engineering-audit.md")
if "## Shadow-first 人工审批" not in precision_doc:
    precision_doc += r'''
## Shadow-first 人工审批

自适应学习只生成 `candidate` / `shadow` 候选。管理后台的 Cyber 规则页显示候选的置信度、样本数、不同用户数、模式和来源；只有管理员可以：

- 晋升为 `Review`，命中后继续交给语义模型；
- 在明确确认后晋升为 `Block`；
- 拒绝候选，或把已拒绝候选恢复到 Shadow。

对应接口是：

```text
GET   /api/admin/v1/cyber-rule-candidates
PATCH /api/admin/v1/cyber-rule-candidates/{id}
POST  /api/admin/v1/cyber-rule-candidates/{id}/promote
```

人工晋升在事务中锁定候选、写入规则并热加载；已晋升候选不能重复修改。自动晋升和自动 Block 仍默认关闭。

## Git 更新与部署

首次部署使用 `bash scripts/deploy-local.sh`。已有部署使用 `bash scripts/upgrade.sh <branch>`；升级脚本只接受 fast-forward，备份 `.env` 和正在运行的 PostgreSQL，保留全部 Volume，并在部署失败时回退代码与容器。数据库迁移不会被自动反向执行。
'''
write("docs/precision-first-engineering-audit.md", precision_doc)

openapi = read("docs/openapi.yaml")
candidate_paths = r'''  /api/admin/v1/cyber-rule-candidates:
    get:
      operationId: listCyberRuleCandidates
      summary: List adaptive rule candidates collected in Shadow-first mode.
      security:
        - AdminBearer: []
      parameters:
        - {name: limit, in: query, schema: {type: integer, minimum: 1, maximum: 1000, default: 200}}
      responses:
        "200":
          description: Candidate queue and the effective adaptive-learning policy.
          content:
            application/json:
              schema:
                type: object
                required: [items, policy]
                properties:
                  items:
                    type: array
                    items: {$ref: "#/components/schemas/CyberRuleCandidate"}
                  policy: {$ref: "#/components/schemas/AdaptiveRulePolicy"}
        "401": {description: Administrator authentication required.}
  /api/admin/v1/cyber-rule-candidates/{id}:
    parameters:
      - {name: id, in: path, required: true, schema: {type: integer, format: int64, minimum: 1}}
    patch:
      operationId: setCyberRuleCandidateStatus
      summary: Reject a candidate or restore it to Shadow.
      description: Requires the admin role. Promoted candidates are immutable through this endpoint.
      security:
        - AdminBearer: []
      requestBody:
        required: true
        content:
          application/json:
            schema:
              type: object
              additionalProperties: false
              required: [status]
              properties:
                status: {type: string, enum: [shadow, rejected]}
      responses:
        "200": {description: Candidate status updated.}
        "400": {description: Invalid candidate identifier or status.}
        "401": {description: Administrator authentication required.}
        "403": {description: Admin role required.}
        "404": {description: Candidate not found or already promoted.}
  /api/admin/v1/cyber-rule-candidates/{id}/promote:
    parameters:
      - {name: id, in: path, required: true, schema: {type: integer, format: int64, minimum: 1}}
    post:
      operationId: promoteCyberRuleCandidate
      summary: Manually promote a Shadow candidate to an enforcing rule.
      description: Requires the admin role. The action must be Review or Block; Allow rules cannot be created from adaptive candidates.
      security:
        - AdminBearer: []
      requestBody:
        required: true
        content:
          application/json:
            schema:
              type: object
              additionalProperties: false
              required: [action]
              properties:
                action: {type: string, enum: [review, block]}
      responses:
        "200":
          description: Candidate promoted transactionally and the rule hot-reloaded.
          content:
            application/json:
              schema:
                type: object
                required: [candidate, rule]
                properties:
                  candidate: {$ref: "#/components/schemas/CyberRuleCandidate"}
                  rule: {$ref: "#/components/schemas/CyberRule"}
        "400": {description: Invalid candidate identifier or action.}
        "401": {description: Administrator authentication required.}
        "403": {description: Admin role required.}
        "404": {description: Candidate not found.}
        "409": {description: Candidate is rejected, promoted, or otherwise not promotable.}
'''
if candidate_paths not in openapi:
    marker = "  /api/admin/v1/traces:\n"
    if marker not in openapi:
        raise SystemExit("OpenAPI traces marker not found")
    openapi = openapi.replace(marker, candidate_paths + marker, 1)

candidate_schemas = r'''    AdaptiveRulePolicy:
      type: object
      required: [enabled, auto_promote, min_confidence, min_evidence, min_distinct_users, auto_block]
      properties:
        enabled: {type: boolean}
        auto_promote: {type: boolean}
        min_confidence: {type: number, minimum: 0, maximum: 1}
        min_evidence: {type: integer, minimum: 1}
        min_distinct_users: {type: integer, minimum: 0}
        auto_block: {type: boolean}
    CyberRuleCandidate:
      type: object
      required: [id, fingerprint, proposed_code, category, pattern, pattern_type, proposed_action, confidence, evidence_count, distinct_users, status]
      properties:
        id: {type: integer, format: int64}
        fingerprint: {type: string}
        proposed_code: {type: string}
        category: {type: string}
        pattern: {type: string}
        pattern_type: {type: string, enum: [regex, contains, exact]}
        proposed_action: {type: string, enum: [review, block]}
        confidence: {type: number, minimum: 0, maximum: 1}
        model: {type: string}
        route_slug: {type: string}
        provider_error_class: {type: string}
        upstream_status: {type: integer}
        reason: {type: string}
        evidence_count: {type: integer, minimum: 1}
        distinct_users: {type: integer, minimum: 0}
        status: {type: string, enum: [candidate, shadow, promoted, rejected]}
        promoted_rule_id: {type: [integer, "null"], format: int64}
        first_seen_at: {type: string, format: date-time}
        last_seen_at: {type: string, format: date-time}
        updated_at: {type: string, format: date-time}
    CyberRule:
      type: object
      required: [id, code, name, category, pattern, pattern_type, action, priority, enabled]
      properties:
        id: {type: integer, format: int64}
        code: {type: string}
        name: {type: string}
        description: {type: string}
        category: {type: string}
        pattern: {type: string}
        pattern_type: {type: string, enum: [regex, contains, exact]}
        action: {type: string, enum: [allow, review, block]}
        priority: {type: integer}
        enabled: {type: boolean}
        created_at: {type: string, format: date-time}
        updated_at: {type: string, format: date-time}
'''
if candidate_schemas not in openapi:
    marker = "    RiskErrorEnvelope:\n"
    if marker not in openapi:
        raise SystemExit("OpenAPI schema marker not found")
    openapi = openapi.replace(marker, candidate_schemas + marker, 1)
write("docs/openapi.yaml", openapi)

print("shadow-first admin approval and safe upgrade patch applied")
