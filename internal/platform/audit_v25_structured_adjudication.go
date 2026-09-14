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
	return cyberRuleEvidence{}, false, auditRuleUnit{}, suppressions, nil
}

// The primary six-field classifier is intentionally compact for local models,
// but its risk_code field is still free-form JSON. Only codes that are actually
// enabled by the platform rule set are canonical enough for a single model deny
// to be terminal. Invented labels such as CYBER_FRAUD or CYBER_DATA_TAMPERING
// are routed to the stronger nine-field semantic contract instead of becoming
// new policy by model fiat.
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

// semanticAdjudicateCyberCandidateV25 uses the already-hardened nine-field
// verifier contract (exact current request evidence + enumerated harm_type).
// Verification errors, missing panel votes and unresolved disagreements remain
// fail-closed. This is not a permissive fallback.
func (e *AuditEngine) semanticAdjudicateCyberCandidateV25(ctx context.Context, profile AuditProfile, text, source string, candidate AuditDecision, state *auditSemanticState) (AuditDecision, error) {
	review := AuditSemanticReview{Status: "error", Candidate: cleanSemanticDecision(candidate)}
	defer func() { state.record(review) }()
	verifyCtx := context.WithValue(ctx, cyberDenySecondPassKey{}, true)

	var verified AuditDecision
	var err error
	if _, enabled := auditProfileExtra(profile)["_risk_fusion_profile_ids"]; enabled {
		var fusion *AuditFusionResult
		verified, fusion, err = e.fuseAuditIntent(verifyCtx, profile, text, source, state)
		review.Fusion = fusion
	} else {
		var verifier AuditProfile
		verifier, err = e.semanticVerifierProfile(verifyCtx, profile)
		if err == nil {
			review.ProfileID, review.Model = verifier.ID, verifier.Model
			verified, review.Attempts, err = e.verifyAuditIntent(verifyCtx, verifier, text, source, state)
		}
	}
	if err != nil {
		return AuditDecision{}, err
	}
	out := finishSemanticReview(candidate, verified, &review)
	return cyberDenyVerdict(out)
}
