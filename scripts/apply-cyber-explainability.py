from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def replace_once(path: str, old: str, new: str, label: str) -> None:
    target = ROOT / path
    text = target.read_text(encoding="utf-8")
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected one match in {path}, found {count}")
    target.write_text(text.replace(old, new, 1), encoding="utf-8")


# ---------------------------------------------------------------------------
# Audit result carries rule evidence independently from the final model decision.
# ---------------------------------------------------------------------------
replace_once(
    "internal/platform/types.go",
    "\tAuditAttempts            []AuditAttempt `json:\"audit_attempts,omitempty\"`\n}",
    "\tAuditAttempts            []AuditAttempt        `json:\"audit_attempts,omitempty\"`\n\tRuleMatch                *RuleMatchDiagnostics `json:\"rule_match,omitempty\"`\n}",
    "audit result rule match field",
)

# ---------------------------------------------------------------------------
# Policy prompt: explicitly treat benign self-service credential management as
# benign/reviewable while retaining skepticism about mere ownership claims.
# ---------------------------------------------------------------------------
replace_once(
    "internal/platform/audit.go",
    "reverse-shell, container/Kubernetes, prompt-injection, and agent-tool requests rather than hard-blocking solely\n"
    "on keywords. Allow benign development, defensive security, incident response, detection/remediation, education,\n",
    "reverse-shell, container/Kubernetes, prompt-injection, and agent-tool requests rather than hard-blocking solely\n"
    "on keywords. Credential self-service such as checking a leaked secret, locating the requester's own key, rotating,\n"
    "revoking, redacting, recovering, or securely storing the requester's own credentials is benign unless the actual\n"
    "outcome requests access to another person's credentials; a bare ownership claim alone is not proof and ambiguous\n"
    "credential-access requests should be reviewed. Allow benign development, defensive security, incident response, detection/remediation, education,\n",
    "credential self-service prompt policy",
)

old_match = '''func (e *AuditEngine) matchRules(text string) *AuditDecision {
\trules, _ := e.rules.Load().([]compiledRule)
\tlowerText := strings.ToLower(text)
\tvar review *AuditDecision
\tfor _, rule := range rules {
\t\tmatched := false
\t\tswitch rule.PatternType {
\t\tcase "regex":
\t\t\tmatched = rule.regularExpression != nil && rule.regularExpression.MatchString(text)
\t\tcase "contains":
\t\t\tmatched = strings.Contains(lowerText, rule.lowerPattern)
\t\tcase "exact":
\t\t\tmatched = strings.EqualFold(strings.TrimSpace(text), rule.lowerPattern)
\t\t}
\t\tif !matched {
\t\t\tcontinue
\t\t}
\t\tdecision := AuditDecision{
\t\t\tDecision:   rule.Action,
\t\t\tRiskCode:   rule.Code,
\t\t\tCategory:   rule.Category,
\t\t\tConfidence: 1,
\t\t\tReason:     "matched configured cyber rule",
\t\t\tSource:     "rule",
\t\t\tRuleID:     rule.ID,
\t\t}
\t\tif rule.Action == DecisionReview {
\t\t\tif review == nil {
\t\t\t\tcopyOfDecision := decision
\t\t\t\treview = &copyOfDecision
\t\t\t}
\t\t\tcontinue
\t\t}
\t\treturn &decision
\t}
\treturn review
}
'''
new_match = '''func (e *AuditEngine) matchRules(text string) (*AuditDecision, *RuleMatchDiagnostics) {
\trules, _ := e.rules.Load().([]compiledRule)
\tlowerText := strings.ToLower(text)
\tvar review *AuditDecision
\tvar reviewDiagnostics *RuleMatchDiagnostics
\tfor index, rule := range rules {
\t\tevidence, matched := matchCyberRuleEvidence(rule, text, lowerText)
\t\tif !matched {
\t\t\tcontinue
\t\t}
\t\tdiagnostics := buildRuleMatchDiagnostics(rule, index+1, text, evidence)
\t\taction := rule.Action
\t\treason := fmt.Sprintf("matched cyber rule #%d (%s)", rule.ID, rule.Code)
\t\tif len(diagnostics.Indicators) > 0 {
\t\t\treason += ": " + strings.Join(diagnostics.Indicators, ", ")
\t\t}
\t\tif downgrade, downgradeReason := shouldReviewCredentialSelfService(rule.CyberRule, text); downgrade {
\t\t\taction = DecisionReview
\t\t\tdiagnostics.Downgraded = true
\t\t\tdiagnostics.DowngradeReason = downgradeReason
\t\t\treason = fmt.Sprintf("matched cyber rule #%d (%s), but credential self-service context requires semantic review", rule.ID, rule.Code)
\t\t}
\t\tdecision := AuditDecision{
\t\t\tDecision:   action,
\t\t\tRiskCode:   rule.Code,
\t\t\tCategory:   rule.Category,
\t\t\tConfidence: 1,
\t\t\tReason:     reason,
\t\t\tSource:     "rule",
\t\t\tRuleID:     rule.ID,
\t\t}
\t\tif action == DecisionReview {
\t\t\tif review == nil {
\t\t\t\tcopyOfDecision := decision
\t\t\t\tcopyOfDiagnostics := diagnostics
\t\t\t\treview = &copyOfDecision
\t\t\t\treviewDiagnostics = &copyOfDiagnostics
\t\t\t}
\t\t\tcontinue
\t\t}
\t\treturn &decision, &diagnostics
\t}
\treturn review, reviewDiagnostics
}
'''
replace_once("internal/platform/audit.go", old_match, new_match, "explainable rule matcher")

replace_once(
    "internal/platform/audit.go",
    "\tmatched := e.matchRules(text)\n\tif matched != nil && (matched.Decision == DecisionBlock || matched.Decision == DecisionAllow) {\n",
    "\tmatched, ruleMatch := e.matchRules(text)\n\tresult.RuleMatch = ruleMatch\n\tif matched != nil && (matched.Decision == DecisionBlock || matched.Decision == DecisionAllow) {\n",
    "audit capture rule diagnostics",
)

# ---------------------------------------------------------------------------
# Trace metadata and safe end-user remediation.
# ---------------------------------------------------------------------------
replace_once(
    "internal/platform/gateway.go",
    "\ttrace.Metadata[\"audit_source\"] = auditResult.Source\n\ttrace.Metadata[\"audit_category\"] = auditResult.Category\n",
    "\ttrace.Metadata[\"audit_source\"] = auditResult.Source\n\ttrace.Metadata[\"audit_category\"] = auditResult.Category\n\tif match := auditResult.RuleMatch; match != nil {\n"
    "\t\ttrace.Metadata[\"audit_rule_id\"] = match.RuleID\n"
    "\t\ttrace.Metadata[\"audit_rule_position\"] = match.RulePosition\n"
    "\t\ttrace.Metadata[\"audit_rule_code\"] = match.RuleCode\n"
    "\t\ttrace.Metadata[\"audit_rule_name\"] = match.RuleName\n"
    "\t\ttrace.Metadata[\"audit_rule_description\"] = truncateString(match.RuleDescription, 1000)\n"
    "\t\ttrace.Metadata[\"audit_rule_category\"] = match.Category\n"
    "\t\ttrace.Metadata[\"audit_rule_action\"] = match.Action\n"
    "\t\ttrace.Metadata[\"audit_rule_priority\"] = match.Priority\n"
    "\t\ttrace.Metadata[\"audit_rule_pattern_type\"] = match.PatternType\n"
    "\t\ttrace.Metadata[\"audit_rule_pattern\"] = truncateString(match.Pattern, 1600)\n"
    "\t\ttrace.Metadata[\"audit_rule_indicators\"] = match.Indicators\n"
    "\t\ttrace.Metadata[\"audit_rule_match\"] = truncateString(match.MatchedText, 1200)\n"
    "\t\ttrace.Metadata[\"audit_rule_context\"] = truncateString(match.Context, 1600)\n"
    "\t\ttrace.Metadata[\"audit_user_guidance\"] = truncateString(match.UserGuidance, 1200)\n"
    "\t\tif match.Downgraded {\n"
    "\t\t\ttrace.Metadata[\"audit_rule_downgraded_to_review\"] = true\n"
    "\t\t\ttrace.Metadata[\"audit_rule_downgrade_reason\"] = truncateString(match.DowngradeReason, 1200)\n"
    "\t\t}\n"
    "\t}\n",
    "gateway rule diagnostics metadata",
)

replace_once(
    "internal/platform/gateway.go",
    "\tif auditResult.Decision == DecisionBlock {\n\t\triskCode := firstNonEmpty(auditResult.RiskCode, \"CYBER_POLICY_BLOCK\")\n\t\tfinish(DecisionBlock, riskCode, g.cfg.ErrorHTTPStatus, 0, 0)\n\t\twriteRiskError(w, g.cfg.ErrorHTTPStatus, requestID, riskCode, \"request rejected by risk control\")\n\t\treturn\n\t}\n",
    "\tif auditResult.Decision == DecisionBlock {\n"
    "\t\triskCode := firstNonEmpty(auditResult.RiskCode, \"CYBER_POLICY_BLOCK\")\n"
    "\t\tfinish(DecisionBlock, riskCode, g.cfg.ErrorHTTPStatus, 0, 0)\n"
    "\t\tmessage := \"request rejected by risk control\"\n"
    "\t\tif auditResult.RuleMatch != nil && strings.TrimSpace(auditResult.RuleMatch.UserGuidance) != \"\" {\n"
    "\t\t\tmessage = auditResult.RuleMatch.UserGuidance\n"
    "\t\t}\n"
    "\t\twriteRiskError(w, g.cfg.ErrorHTTPStatus, requestID, riskCode, message)\n"
    "\t\treturn\n"
    "\t}\n",
    "safe user remediation on block",
)

# ---------------------------------------------------------------------------
# Admin UI: make built-in rule editing explicit and surface full redacted rule
# evidence in trace list/detail.
# ---------------------------------------------------------------------------
replace_once(
    "internal/platform/web/index.html",
    "<div class=\"view-head\"><div><h2>Cyber 规则</h2><p>规则按优先级从高到低执行。Block 或 Allow 直接决策，Review 交给小模型。</p></div><button id=\"new-rule-button\" class=\"btn btn-primary\">新增规则</button></div>",
    "<div class=\"view-head\"><div><h2>Cyber 规则</h2><p>规则按优先级从高到低执行。Block 或 Allow 直接决策，Review 交给小模型。内置默认规则也可以直接编辑、改动作、改优先级或禁用，保存后立即热加载。</p></div><button id=\"new-rule-button\" class=\"btn btn-primary\">新增规则</button></div>",
    "rules editable notice",
)

replace_once(
    "internal/platform/web/index.html",
    "          const requestSize=requestBodyDiagnostic(item);\n          return `<tr>",
    "          const requestSize=requestBodyDiagnostic(item);\n"
    "          const ruleIndicators=(item.metadata?.audit_rule_indicators||[]).join(' + ');\n"
    "          const ruleLine=item.metadata?.audit_rule_id?`<span class=\"trace-error-class\">规则 #${escapeHTML(item.metadata.audit_rule_id)} · 当前第 ${escapeHTML(item.metadata.audit_rule_position||'-')} 条 · ${escapeHTML(item.metadata.audit_rule_code||'')} ${ruleIndicators?`· 命中 ${escapeHTML(ruleIndicators)}`:''}${item.metadata?.audit_rule_downgraded_to_review?' · 已降级 Review':''}</span>`:'';\n"
    "          return `<tr>",
    "trace rule line setup",
)
replace_once(
    "internal/platform/web/index.html",
    "${requestSize?`<span class=\"trace-error-class\">请求体：${escapeHTML(requestSize)}</span>`:''}${errorClass?`<span class=\"trace-error-class\">${escapeHTML(errorClass)}${item.metadata?.audit_http_status?` · HTTP ${escapeHTML(item.metadata.audit_http_status)}`:''}</span>`:''}${tokenLine}</td>",
    "${requestSize?`<span class=\"trace-error-class\">请求体：${escapeHTML(requestSize)}</span>`:''}${ruleLine}${errorClass?`<span class=\"trace-error-class\">${escapeHTML(errorClass)}${item.metadata?.audit_http_status?` · HTTP ${escapeHTML(item.metadata.audit_http_status)}`:''}</span>`:''}${tokenLine}</td>",
    "trace table rule diagnostics",
)

replace_once(
    "internal/platform/web/index.html",
    "          ['实际审计模型',item.metadata?.audit_profile_name||item.metadata?.audit_model||'-'], ['模型调用次数',item.metadata?.audit_model_attempts||'-'], ['模型重试次数',item.metadata?.audit_model_retries||0], ['备用模型切换',item.metadata?.audit_fallback_count||0], ['模型链',(item.metadata?.audit_models_tried||[]).join(' → ')||'-'],\n          ['Prompt HMAC',item.prompt_hmac||'-']\n",
    "          ['实际审计模型',item.metadata?.audit_profile_name||item.metadata?.audit_model||'-'], ['模型调用次数',item.metadata?.audit_model_attempts||'-'], ['模型重试次数',item.metadata?.audit_model_retries||0], ['备用模型切换',item.metadata?.audit_fallback_count||0], ['模型链',(item.metadata?.audit_models_tried||[]).join(' → ')||'-'],\n"
    "          ['命中规则 ID',item.metadata?.audit_rule_id||'-'], ['规则执行顺序',item.metadata?.audit_rule_position?`当前第 ${item.metadata.audit_rule_position} 条`:'-'], ['规则 Code',item.metadata?.audit_rule_code||'-'], ['规则名称',item.metadata?.audit_rule_name||'-'],\n"
    "          ['规则分类',item.metadata?.audit_rule_category||'-'], ['规则原动作',item.metadata?.audit_rule_action||'-'], ['规则优先级',item.metadata?.audit_rule_priority??'-'], ['匹配方式',item.metadata?.audit_rule_pattern_type||'-'],\n"
    "          ['命中关键词',(item.metadata?.audit_rule_indicators||[]).join(' + ')||'-'], ['脱敏命中片段',item.metadata?.audit_rule_match||'-'], ['脱敏触发上下文',item.metadata?.audit_rule_context||'-'], ['规则说明',item.metadata?.audit_rule_description||'-'],\n"
    "          ['是否降级 Review',item.metadata?.audit_rule_downgraded_to_review?'是':'否'], ['降级原因',item.metadata?.audit_rule_downgrade_reason||'-'], ['给用户的修改建议',item.metadata?.audit_user_guidance||'-'],\n"
    "          ['Prompt HMAC',item.prompt_hmac||'-']\n",
    "trace detail rule diagnostics",
)

replace_once(
    "internal/platform/web/index.html",
    "const result=data.result;const diagnostics=[];if(result.error_class)",
    "const result=data.result;const diagnostics=[];if(result.rule_match){const m=result.rule_match;diagnostics.push(`规则 #${m.rule_id} / 当前第 ${m.rule_position} 条 / ${m.rule_code}${(m.indicators||[]).length?` / 命中 ${(m.indicators||[]).join(' + ')}`:''}${m.downgraded_to_review?' / 已降级 Review':''}`);}if(result.error_class)",
    "dry run rule diagnostics",
)

print("cyber explainability patch applied")
