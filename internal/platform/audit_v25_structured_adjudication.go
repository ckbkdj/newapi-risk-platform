package platform

import (
	"context"
	"strings"
	"unicode/utf8"
)

// v25 stops hard lexical rules from manufacturing a relationship across
// independent request roles. The Cyber extractor emits one ROLE= marker for each
// user/tool/assistant-data document. A hard regex may span arbitrary text inside
// one role document, but it must not join words from different role documents.
// Cross-role intent/adoption is semantic and is evaluated by the model over the
// complete request after the lexical pass.
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
	}
	return units
}

// matchCyberRuleStructuredV25 preserves all existing rule semantics inside a
// source unit, including precision suppressions and overlapping candidates, but
// never allows a dot-all expression to cross a role boundary. This applies to
// operator regexes too: a regex relationship spanning independent roles is not
// a valid hard lexical fact; the full semantic audit still sees every role.
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
		if rule.PatternType == "regex" && precisionRule(rule) {
			offset := 0
			for matched {
				if err := ctx.Err(); err != nil {
					return cyberRuleEvidence{}, false, auditRuleUnit{}, suppressions, err
				}
				reason := weakDevelopmentRuleEvidence(rule, unit.Text, evidence)
				if reason == "" {
					break
				}
				if len(suppressions) < 16 {
					suppressions = append(suppressions, RuleSuppressionDiagnostic{
						RuleCode:    rule.Code,
						UnitIndex:   unit.Index,
						Reason:      reason,
						MatchedText: redactCyberTraceText(evidence.matchedRaw),
					})
				}
				candidateCount++
				if candidateCount >= 1024 {
					return cyberRuleEvidence{}, false, auditRuleUnit{}, suppressions, newAuditModelCallError("cyber_rule_candidate_budget", 0, "too many unresolved rule candidates; no authorization to forward", nil)
				}
				_, width := utf8.DecodeRuneInString(unit.Text[evidence.start:])
				offset = evidence.start + max(1, width)
				if offset >= len(unit.Text) {
					matched = false
					break
				}
				location := rule.regularExpression.FindStringIndex(unit.Text[offset:])
				matched = location != nil
				if matched {
					evidence = cyberRuleEvidence{
						start:      offset + location[0],
						end:        offset + location[1],
						matchedRaw: unit.Text[offset+location[0] : offset+location[1]],
					}
				}
			}
		}
		if matched {
			return evidence, true, unit, suppressions, nil
		}
	}

	// Observability only: if the legacy whole-document matcher would have fired
	// but no source unit did, record why the hard candidate was discarded. Never
	// use this diagnostic-only match as authorization or as a block.
	if len(suppressions) == 0 && strings.TrimSpace(text) != "" {
		lower := strings.ToLower(text)
		folded := ""
		if len(text) > 8192 {
			folded = auditCanonicalFold(text)
		}
		if evidence, legacyMatched := matchCyberRuleEvidence(rule, text, lower, folded); legacyMatched {
			reason := "cross_role_match_disallowed"
			if rule.PatternType == "regex" && precisionRule(rule) {
				if specific := weakDevelopmentRuleEvidence(rule, text, evidence); specific != "" {
					reason = specific
				}
			}
			suppressions = append(suppressions, RuleSuppressionDiagnostic{
				RuleCode:    rule.Code,
				Reason:      reason,
				MatchedText: redactCyberTraceText(evidence.matchedRaw),
			})
		}
	}
	return cyberRuleEvidence{}, false, auditRuleUnit{}, suppressions, nil
}

// The primary six-field classifier is intentionally compact for local models,
// but its risk_code field is still free-form JSON. Keep the canonical lookup for
// diagnostics and strict-precedence decisions; noncanonical candidates still
// enter the compatibility adjudication path below so v24 scope normalization can
// reject model-invented non-Cyber taxonomies without weakening real Cyber blocks.
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

// semanticAdjudicateCyberCandidateV25 deliberately reuses the proven v24
// Cyber-only normalization and six-field independent second pass. The earlier
// v25 experiment sent every benign allow through the nine-field operation-proof
// verifier; local 27B models legitimately returned no request_evidence for
// allow/no_harm, which converted ordinary Android/Gradle/SDK work into
// AUDIT_MODEL_ERROR. Evidence/harm proof is still mandatory where the model is
// asserting a harmful operation, while a benign allow uses the stable independent
// classifier contract. Any verifier error or missing fusion vote remains
// fail-closed, and any validated deny keeps strict precedence.
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
