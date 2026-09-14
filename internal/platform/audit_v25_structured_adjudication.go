package platform

import (
	"context"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"
)

var (
	serializedAuditEventHeaderV26 = regexp.MustCompile(`(?m)^\s*\[(\d{1,6})\]\s+(user|assistant|tool(?:\s+[A-Za-z0-9_.:-]+)?(?:\s+(?:call|result))?)\s*:\s*`)
	bareContinuationV26           = regexp.MustCompile(`(?i)^\s*(?:继续(?:执行|做|测试)?|运行自动化测试|跑一下测试|运行测试|执行测试|开始(?:吧)?|按(?:这个|上面|之前的)(?:做|执行)|照做|可以继续|好的?[，, ]*继续|continue|go ahead|proceed|do it|run it|run the tests?|test it|yes[,. ]*(?:continue|proceed))\s*[。！.!]*\s*$`)
	chineseSourceRelationV26      = regexp.MustCompile(`(?:文档|记录|日志|表格|工作簿|描述|说明).{0,24}(?:中|里|内|写着|写有|显示|描述|说明|提到|包含|出现|记录)`)
	englishSourceRelationV26      = regexp.MustCompile(`(?i)(?:\b(?:in|from|according to)\s+(?:the\s+)?(?:logs?|records?|documents?|spreadsheet)\b|\b(?:logs?|records?|documents?|spreadsheet)\b.{0,24}\b(?:say|says|said|mention|mentions|mentioned|contain|contains|contained|show|shows|showed|describe|describes|described)\b)`)
	transformReferenceV26         = regexp.MustCompile(`(?i)(?:翻译|总结|摘要|整理|改写|润色|校对|解释|引用).{0,64}(?:这|该|上述|以下|句|段|内容|文本|文字|记录|文档|日志|表格|工作簿|描述|说明)|\b(?:translate|summari[sz]e|rewrite|proofread|explain|quote)\b.{0,64}\b(?:this|that|the following|sentence|passage|text|record|document|log|entry)\b`)
	conditionalMentionV26         = regexp.MustCompile(`(?i)(?:(?:待复现|待验证).{0,40}(?:判断|确认|看).{0,20}(?:是否|是不是|需不需要)|(?:判断|确认).{0,32}(?:是否|是不是|需不需要)|是否需要|是不是需要|可能需要|考虑是否|\bwhether\b|\bmight need\b|\bmay need\b|\bconsider(?:ing)?\s+whether\b)`)
)

// ROLE markers are a rendered transport representation, not authorization
// boundaries. Terminal lexical vetoes are limited to the newest current-user
// action plus an explicitly adopted prior user action. Older user turns,
// assistant content and tool data remain semantic context.
func cyberRuleRoleKindV25(line string) (string, bool) {
	switch strings.TrimSpace(line) {
	case "ROLE=USER":
		return "user", true
	case "ROLE=USER_REFERENCED":
		return "user_referenced", true
	case "ROLE=ASSISTANT_REFERENCED":
		return "assistant_referenced", true
	case "ROLE=ASSISTANT_DATA":
		return "assistant_data", true
	case "ROLE=TOOL_DATA":
		return "tool_data", true
	default:
		return "", false
	}
}

func splitCyberRuleRoleUnitsV25(text string) []auditRuleUnit {
	text = strings.ReplaceAll(text, "\r\n", "\n")
	lines := strings.Split(text, "\n")
	units := make([]auditRuleUnit, 0, 8)
	kind := "document"
	seenRole := false
	var builder strings.Builder
	flush := func() {
		value := strings.TrimSpace(builder.String())
		builder.Reset()
		if value == "" {
			return
		}
		units = append(units, auditRuleUnit{Index: len(units) + 1, Kind: kind, Text: value})
	}
	for _, line := range lines {
		if nextKind, ok := cyberRuleRoleKindV25(line); ok {
			flush()
			kind = nextKind
			seenRole = true
			continue
		}
		if builder.Len() > 0 {
			builder.WriteByte('\n')
		}
		builder.WriteString(line)
	}
	flush()
	if len(units) == 0 && strings.TrimSpace(text) != "" {
		units = append(units, auditRuleUnit{Index: 1, Kind: "document", Text: strings.TrimSpace(text)})
	}
	if !seenRole {
		for i := range units {
			units[i].Kind = "document"
		}
		units = expandSerializedAuditTranscriptV26(units)
		return reindexAuditRuleUnitsV26(applyContinuationAdoptionV26(units))
	}

	lastUser := -1
	for i := range units {
		if units[i].Kind == "user" {
			lastUser = i
		}
	}
	if lastUser >= 0 {
		activeStart := lastUser
		for activeStart > 0 && units[activeStart-1].Kind == "user" {
			activeStart--
		}
		for i := range units {
			if units[i].Kind == "user" && (i < activeStart || i > lastUser) {
				units[i].Kind = "user_history"
			}
		}
	}
	units = expandSerializedAuditTranscriptV26(units)
	return reindexAuditRuleUnitsV26(applyContinuationAdoptionV26(units))
}

func reindexAuditRuleUnitsV26(units []auditRuleUnit) []auditRuleUnit {
	out := units[:0]
	for _, unit := range units {
		unit.Text = strings.TrimSpace(unit.Text)
		if unit.Text == "" {
			continue
		}
		unit.Index = len(out) + 1
		out = append(out, unit)
	}
	return out
}

// Agent clients sometimes serialize internal events into one outer USER string,
// e.g. "[43] tool ... call:" followed by "[45] user: 继续". Require a
// monotonically increasing multi-event sequence with at least one non-user event
// before treating it as transcript history. Only the final contiguous user event
// run remains current for lexical enforcement.
func expandSerializedAuditTranscriptV26(units []auditRuleUnit) []auditRuleUnit {
	out := make([]auditRuleUnit, 0, len(units)+4)
	for _, unit := range units {
		if unit.Kind != "user" && unit.Kind != "document" {
			out = append(out, unit)
			continue
		}
		matches := serializedAuditEventHeaderV26.FindAllStringSubmatchIndex(unit.Text, -1)
		if len(matches) < 2 || !validSerializedAuditTranscriptV26(unit.Text, matches) {
			out = append(out, unit)
			continue
		}
		kinds := make([]string, len(matches))
		lastUser := -1
		for i, match := range matches {
			kinds[i] = serializedAuditEventKindV26(unit.Text[match[4]:match[5]])
			if kinds[i] == "user" {
				lastUser = i
			}
		}
		if lastUser < 0 {
			out = append(out, unit)
			continue
		}
		activeStart := lastUser
		for activeStart > 0 && kinds[activeStart-1] == "user" {
			activeStart--
		}
		if prefix := strings.TrimSpace(unit.Text[:matches[0][0]]); prefix != "" {
			out = append(out, auditRuleUnit{Kind: "user_referenced", Text: prefix})
		}
		for i, match := range matches {
			start := match[1]
			end := len(unit.Text)
			if i+1 < len(matches) {
				end = matches[i+1][0]
			}
			body := strings.TrimSpace(unit.Text[start:end])
			if body == "" {
				continue
			}
			kind := kinds[i]
			if kind == "user" && (i < activeStart || i > lastUser) {
				kind = "user_history"
			}
			out = append(out, auditRuleUnit{Kind: kind, Text: body})
		}
	}
	return out
}

func validSerializedAuditTranscriptV26(text string, matches [][]int) bool {
	previous := -1
	nonUser := false
	for _, match := range matches {
		value, err := strconv.Atoi(text[match[2]:match[3]])
		if err != nil || value <= previous {
			return false
		}
		previous = value
		if serializedAuditEventKindV26(text[match[4]:match[5]]) != "user" {
			nonUser = true
		}
	}
	return nonUser
}

func serializedAuditEventKindV26(header string) string {
	header = strings.ToLower(strings.TrimSpace(header))
	switch {
	case header == "user":
		return "user"
	case header == "assistant":
		return "assistant_data"
	case strings.HasPrefix(header, "tool"):
		return "tool_data"
	default:
		return "user_referenced"
	}
}

// A bare continuation adopts the preceding explicit USER action, not assistant
// or tool text. This preserves "继续/run the tests" after a prohibited request
// without letting risky words in tool output become user intent.
func applyContinuationAdoptionV26(units []auditRuleUnit) []auditRuleUnit {
	current := make([]int, 0, 2)
	for i := range units {
		if units[i].Kind == "user" {
			current = append(current, i)
		}
	}
	if len(current) == 0 {
		return units
	}
	for _, i := range current {
		if !bareContinuationV26.MatchString(strings.TrimSpace(units[i].Text)) {
			return units
		}
	}
	firstCurrent := current[0]
	for i := firstCurrent - 1; i >= 0; i-- {
		if units[i].Kind == "user_history" {
			units[i].Kind = "user_adopted"
			break
		}
	}
	return units
}

func semanticOnlyRuleMatchV26(rule compiledRule, unit auditRuleUnit, evidence cyberRuleEvidence) string {
	if unit.Kind != "user" && unit.Kind != "user_adopted" && unit.Kind != "document" {
		return "non_current_provenance_requires_semantic_review"
	}
	// Only known shipped guard/review rules are demoted. Custom operator rules
	// keep their historical hard-veto semantics and are never silently weakened.
	if rule.Code == "CYBER_UNTRUSTED_CONTEXT_CLAIM" || ((rule.Action == DecisionReview || rule.Action == DecisionAllow) && precisionRule(rule)) {
		return "lexical_guard_requires_semantic_review"
	}
	if descriptiveOrConditionalMentionV26(unit.Text, evidence) {
		return "descriptive_or_conditional_mention_requires_semantic_review"
	}
	return ""
}

func descriptiveOrConditionalMentionV26(text string, evidence cyberRuleEvidence) bool {
	start := evidence.start - 224
	if start < 0 {
		start = 0
	}
	for start > 0 && !utf8.RuneStart(text[start]) {
		start--
	}
	end := evidence.end + 224
	if end > len(text) {
		end = len(text)
	}
	for end < len(text) && !utf8.RuneStart(text[end]) {
		end++
		if end >= len(text) {
			end = len(text)
			break
		}
	}
	window := text[start:end]
	return chineseSourceRelationV26.MatchString(window) ||
		englishSourceRelationV26.MatchString(window) ||
		transformReferenceV26.MatchString(window) ||
		conditionalMentionV26.MatchString(window)
}

func appendRuleSuppressionV26(items []RuleSuppressionDiagnostic, rule compiledRule, unit auditRuleUnit, evidence cyberRuleEvidence, reason string) []RuleSuppressionDiagnostic {
	if reason == "" || len(items) >= 16 {
		return items
	}
	return append(items, RuleSuppressionDiagnostic{RuleCode: rule.Code, UnitIndex: unit.Index, Reason: reason, MatchedText: redactCyberTraceText(evidence.matchedRaw)})
}

func matchCyberRuleStructuredV25(ctx context.Context, rule compiledRule, text string) (cyberRuleEvidence, bool, auditRuleUnit, []RuleSuppressionDiagnostic, error) {
	units := splitCyberRuleRoleUnitsV25(text)
	var suppressions []RuleSuppressionDiagnostic
	candidateCount := 0
	for _, unit := range units {
		if err := ctx.Err(); err != nil {
			return cyberRuleEvidence{}, false, auditRuleUnit{}, suppressions, err
		}
		lower := strings.ToLower(unit.Text)
		folded := ""
		if len(unit.Text) > 8192 {
			folded = auditCanonicalFold(unit.Text)
		}
		evidence, matched := matchCyberRuleEvidence(rule, unit.Text, lower, folded)
		offset := 0
		for matched {
			if err := ctx.Err(); err != nil {
				return cyberRuleEvidence{}, false, auditRuleUnit{}, suppressions, err
			}
			reason := ""
			if rule.PatternType == "regex" && precisionRule(rule) {
				reason = weakDevelopmentRuleEvidence(rule, unit.Text, evidence)
			}
			if reason == "" {
				reason = semanticOnlyRuleMatchV26(rule, unit, evidence)
			}
			if reason == "" {
				return evidence, true, unit, suppressions, nil
			}
			suppressions = appendRuleSuppressionV26(suppressions, rule, unit, evidence, reason)
			candidateCount++
			if candidateCount >= 1024 {
				return cyberRuleEvidence{}, false, auditRuleUnit{}, suppressions, newAuditModelCallError("cyber_rule_candidate_budget", 0, "too many unresolved rule candidates; no authorization to forward", nil)
			}
			if rule.PatternType != "regex" {
				break
			}
			_, width := utf8.DecodeRuneInString(unit.Text[evidence.start:])
			offset = evidence.start + max(1, width)
			if offset >= len(unit.Text) {
				break
			}
			location := rule.regularExpression.FindStringIndex(unit.Text[offset:])
			matched = location != nil
			if matched {
				evidence = cyberRuleEvidence{start: offset + location[0], end: offset + location[1], matchedRaw: unit.Text[offset+location[0] : offset+location[1]]}
			}
		}
	}

	if len(suppressions) == 0 && strings.TrimSpace(text) != "" {
		lower := strings.ToLower(text)
		folded := ""
		if len(text) > 8192 {
			folded = auditCanonicalFold(text)
		}
		if evidence, legacyMatched := matchCyberRuleEvidence(rule, text, lower, folded); legacyMatched {
			reason := "cross_role_or_noncurrent_match_disallowed"
			if rule.PatternType == "regex" && precisionRule(rule) {
				if specific := weakDevelopmentRuleEvidence(rule, text, evidence); specific != "" {
					reason = specific
				}
			}
			suppressions = appendRuleSuppressionV26(suppressions, rule, auditRuleUnit{}, evidence, reason)
		}
	}
	return cyberRuleEvidence{}, false, auditRuleUnit{}, suppressions, nil
}

func (e *AuditEngine) canonicalCyberRiskCodeV25(code string) bool {
	code = strings.ToUpper(strings.TrimSpace(code))
	if code == "" {
		return false
	}
	loaded, _ := e.rules.Load().([]compiledRule)
	for _, rule := range loaded {
		if rule.Enabled && strings.EqualFold(strings.TrimSpace(rule.Code), code) {
			return true
		}
	}
	for _, rule := range cyberDenyBaseline {
		if rule.Enabled && strings.EqualFold(strings.TrimSpace(rule.Code), code) {
			return true
		}
	}
	return false
}

func (e *AuditEngine) cyberCandidateNeedsSemanticAdjudicationV25(candidate AuditDecision) bool {
	switch candidate.Decision {
	case DecisionAllow, DecisionReview:
		return true
	case DecisionBlock:
		return !e.canonicalCyberRiskCodeV25(candidate.RiskCode)
	default:
		return true
	}
}

// Reuse the proven v24 Cyber-only normalization and six-field independent second
// pass. Benign allow/no_harm results are not required to quote proof of absence,
// while verifier errors, incomplete fusion and validated denials remain fail-closed.
func (e *AuditEngine) semanticAdjudicateCyberCandidateV25(ctx context.Context, profile AuditProfile, text, source string, candidate AuditDecision, state *auditSemanticState) (AuditDecision, error) {
	candidate = normalizeCyberOnlyScopeV24(candidate, text, source)
	normalized, err := cyberDenyVerdict(candidate)
	if err != nil || normalized.Decision != DecisionAllow {
		return normalized, err
	}
	candidate = normalized

	review := AuditSemanticReview{Status: "error", Candidate: cleanSemanticDecision(candidate)}
	defer func() { state.record(review) }()
	verifyCtx := context.WithValue(ctx, cyberDenySecondPassKey{}, true)
	verifier, verifierErr := e.semanticVerifierProfile(ctx, profile)
	if verifierErr != nil {
		return AuditDecision{}, verifierErr
	}
	profiles := []AuditProfile{verifier}
	var fusion *AuditFusionResult
	if _, enabled := auditProfileExtra(profile)["_risk_fusion_profile_ids"]; enabled {
		profiles, _, err = e.auditFusionProfiles(ctx, profile)
		if err != nil {
			return AuditDecision{}, err
		}
		fusion = &AuditFusionResult{Strategy: "cyber_deny_overrides.v1", Status: "error"}
		review.Fusion = fusion
	}

	var failure error
	last := candidate
	for _, p := range profiles {
		if !state.reserveReview() {
			return AuditDecision{}, newAuditModelCallError("semantic_review_budget", 0, "Cyber verification budget exhausted", nil)
		}
		plan := e.auditOutputPlan(p, 0)
		if p.ID == profile.ID {
			plan = auditOutputPlanFromContext(ctx)
		}
		plan.VerifyIntent = false
		callCtx, outputState := withAuditOutputAttempt(verifyCtx, plan)
		d, callErr := e.callCyberGroundedModel(callCtx, p, text, source)
		if class, _, _ := auditModelErrorDetails(callErr); class == "invalid_evidence" {
			callErr = newAuditModelCallError("cyber_evidence_unresolved", 0, "non-allow verifier evidence is unresolved", callErr)
		}
		if callErr == nil {
			d = normalizeCyberOnlyScopeV24(d, text, source)
			d, callErr = cyberDenyVerdict(d)
		}
		if callErr != nil {
			diag := outputState.snapshot(true)
			diag.Mode, diag.MaxTokens, diag.Failed = plan.Mode, plan.MaxTokens, true
			callErr = annotateAuditOutputError(callErr, diag)
		}

		vote := AuditFusionVote{ProfileID: p.ID, Model: p.Model}
		review.ProfileID, review.Model = p.ID, p.Model
		if callErr != nil {
			vote.ErrorClass, _, _ = auditModelErrorDetails(callErr)
			failure = callErr
		} else {
			clean := cleanSemanticDecision(d)
			vote.Outcome = &clean
			last = d
		}
		if fusion != nil {
			fusion.Votes = append(fusion.Votes, vote)
		}
		if callErr == nil && d.Decision != DecisionAllow {
			if fusion != nil {
				fusion.Status = "deny_override"
				fusion.Disagreement = true
			}
			return finishSemanticReview(candidate, d, &review), nil
		}
	}
	if failure != nil {
		if fusion != nil {
			return AuditDecision{}, newAuditModelCallError("fusion_incomplete", 0, "Cyber fusion has missing or invalid assessments; cannot allow", failure)
		}
		return AuditDecision{}, failure
	}
	if fusion != nil {
		fusion.Status = "all_allow"
	}
	return finishSemanticReview(candidate, last, &review), nil
}
