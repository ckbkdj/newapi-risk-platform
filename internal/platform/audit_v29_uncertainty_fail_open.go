package platform

import "strings"

// v29 makes the business policy explicit: uncertainty is observable but is not
// authorization to return HTTP 555. Only a confirmed rule/model block may stop
// the request. The original candidate is retained in SemanticReview so traces
// can still show what the model tried to classify.
func cyberUncertaintyAllowV29(candidate AuditDecision, reason, source string) AuditDecision {
	original := cleanSemanticDecision(candidate)
	if strings.TrimSpace(reason) == "" {
		reason = "Cyber risk was not confirmed; request allowed by uncertainty fail-open policy"
	}
	if strings.TrimSpace(source) == "" {
		source = "model_uncertainty_fail_open_v29"
	}
	return AuditDecision{
		Decision:   DecisionAllow,
		Category:   "audit_uncertainty",
		Confidence: 0,
		Reason:     truncateString(sanitizeAuditDiagnostic(reason), 240),
		Source:     source,
		SemanticReview: &AuditSemanticReview{
			Status:    "fail_open",
			Candidate: original,
		},
	}
}

func cyberModelErrorAllowV29(err error) AuditDecision {
	class, _, reason := auditModelErrorDetails(err)
	if strings.TrimSpace(class) == "" {
		class = "audit_unverified"
	}
	if strings.TrimSpace(reason) == "" {
		reason = class
	}
	return AuditDecision{
		Decision:   DecisionAllow,
		Category:   "audit_uncertainty",
		Confidence: 0,
		Reason:     truncateString(sanitizeAuditDiagnostic("Cyber audit unverified ("+class+"): "+reason), 240),
		Source:     "model_error_fail_open_v29",
	}
}

// A risk code is a hard-block governance code only when its enabled rule is
// actually configured as action=block. Legacy migration 009 once converted
// review rules to block; migration 014 restores their intended actions. This
// runtime check prevents a review-labelled code from becoming terminal merely
// because the model echoed a known code string.
func (e *AuditEngine) canonicalCyberBlockRiskCodeV29(code string) bool {
	code = strings.ToUpper(strings.TrimSpace(code))
	if code == "" {
		return false
	}
	loaded, _ := e.rules.Load().([]compiledRule)
	for _, rule := range loaded {
		if rule.Enabled && rule.Action == DecisionBlock && strings.EqualFold(strings.TrimSpace(rule.Code), code) {
			return true
		}
	}
	for _, rule := range cyberDenyBaseline {
		if rule.Enabled && rule.Action == DecisionBlock && strings.EqualFold(strings.TrimSpace(rule.Code), code) {
			return true
		}
	}
	return false
}

// confirmedCyberBlockV29 separates a proved harmful operation from a model
// label. A primary six-field model block needs both a block-governed policy code
// and concrete harmful evidence. A semantic verifier may use a noncanonical
// label, but only after its stronger relation/harm/evidence contract has been
// validated. This prevents label mismatch from laundering an actually confirmed
// harmful request while failing open invented, review-only, or weak labels.
func confirmedCyberBlockV29(e *AuditEngine, d AuditDecision) bool {
	if d.Decision != DecisionBlock {
		return false
	}
	evidence := strings.TrimSpace(d.Evidence)
	if evidence == "" || !concreteHarmfulCyberActionV28.MatchString(evidence) {
		return false
	}
	if e.canonicalCyberBlockRiskCodeV29(d.RiskCode) {
		return true
	}
	relation := strings.ToLower(strings.TrimSpace(d.EvidenceRelation))
	harm := strings.ToLower(strings.TrimSpace(d.HarmType))
	return d.EvidenceVerified && semanticHarmTypes[harm] &&
		(relation == "direct_request" || relation == "adopted_reference")
}

func cyberDecisionNeedsFailOpenV29(e *AuditEngine, d AuditDecision) bool {
	if d.Decision == DecisionReview {
		return true
	}
	if d.Decision == DecisionBlock {
		return !confirmedCyberBlockV29(e, d)
	}
	// v28 uses policyOriginalDecision when a model block/review was downgraded
	// because its evidence was only topical, descriptive, defensive, or otherwise
	// insufficient to prove a prohibited operation.
	return d.Decision == DecisionAllow && d.policyOriginalDecision != ""
}
