package platform

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
)

// Fusion is opt-in and candidate-only. It combines contract-validated evidence,
// not self-reported probabilities. A fresh adjudicator can resolve a complete
// panel's disagreement, but never conceal failed/missing assessments.
type AuditFusionVote struct {
	ProfileID  int64          `json:"profile_id"`
	Model      string         `json:"model"`
	Outcome    *AuditDecision `json:"outcome,omitempty"`
	Attempts   []AuditAttempt `json:"attempts,omitempty"`
	ErrorClass string         `json:"error_class,omitempty"`
}
type AuditFusionResult struct {
	Strategy     string            `json:"strategy"`
	Status       string            `json:"status"`
	Disagreement bool              `json:"disagreement"`
	Votes        []AuditFusionVote `json:"votes"`
	Adjudicator  *AuditFusionVote  `json:"adjudicator,omitempty"`
}

func auditProfileID(raw any) (int64, bool) {
	n, ok := raw.(float64)
	return int64(n), ok && n >= 1 && n <= 9007199254740991 && n == float64(int64(n))
}

func (e *AuditEngine) auditFusionProfiles(ctx context.Context, root AuditProfile) ([]AuditProfile, *AuditProfile, error) {
	invalid := func(message string) ([]AuditProfile, *AuditProfile, error) {
		return nil, nil, newAuditModelCallError("fusion_configuration", 0, message, nil)
	}
	extra := auditProfileExtra(root)
	ids, ok := extra["_risk_fusion_profile_ids"].([]any)
	if !ok || len(ids) < 2 || len(ids) > 3 {
		return invalid("_risk_fusion_profile_ids must contain 2 or 3 distinct enabled audit profile IDs")
	}
	profiles := make([]AuditProfile, 0, len(ids)+1)
	seenIDs, seenModels := map[int64]bool{}, map[string]bool{}
	load := func(raw any) (AuditProfile, error) {
		id, ok := auditProfileID(raw)
		if !ok || seenIDs[id] {
			return AuditProfile{}, newAuditModelCallError("fusion_configuration", 0, "fusion profile ID is invalid or duplicated", nil)
		}
		p := root
		if id != root.ID {
			var err error
			p, err = e.getAuditProfile(ctx, &id)
			if err != nil || !p.Enabled {
				return AuditProfile{}, newAuditModelCallError("fusion_profile_unavailable", 0, "fusion profile is unavailable", nil)
			}
		}
		// Exact endpoint/model aliases do not count as multiple experts. Distinct
		// endpoints/names still do not prove statistical independence of weights.
		key := strings.TrimRight(strings.ToLower(strings.TrimSpace(p.Endpoint)), "/") + "\x00" + strings.ToLower(strings.TrimSpace(p.Model))
		if seenModels[key] {
			return AuditProfile{}, newAuditModelCallError("fusion_configuration", 0, "fusion profiles repeat the same endpoint and model", nil)
		}
		seenIDs[id], seenModels[key] = true, true
		return governingAuditVerifier(root, p), nil
	}
	for _, raw := range ids {
		p, err := load(raw)
		if err != nil {
			return nil, nil, err
		}
		profiles = append(profiles, p)
	}
	var adjudicator *AuditProfile
	if raw, exists := extra["_risk_fusion_adjudicator_profile_id"]; exists {
		p, err := load(raw)
		if err != nil {
			return nil, nil, err
		}
		adjudicator = &p
	}
	return profiles, adjudicator, nil
}

func fusionAgreement(a, b AuditDecision) bool {
	if a.Decision != b.Decision || a.Decision == DecisionReview {
		return false
	}
	if a.Decision == DecisionAllow {
		return a.HarmType == "none" && b.HarmType == "none"
	}
	// Common harm category alone is not enough: require the same actual capability
	// and current action (quote containment permits different exact quote lengths).
	compatibleQuote := func(x, y string) bool {
		x, y = strings.TrimSpace(x), strings.TrimSpace(y)
		return x != "" && y != "" && (strings.Contains(x, y) || strings.Contains(y, x))
	}
	return a.HarmType == b.HarmType && a.EvidenceRelation == b.EvidenceRelation &&
		compatibleQuote(a.Evidence, b.Evidence) && compatibleQuote(a.RequestEvidence, b.RequestEvidence)
}

func (e *AuditEngine) fuseAuditIntent(ctx context.Context, root AuditProfile, text, source string, state *auditSemanticState) (AuditDecision, *AuditFusionResult, error) {
	result := &AuditFusionResult{Strategy: "validated_consensus_then_fresh_adjudication.v1", Status: "error"}
	profiles, arbiter, err := e.auditFusionProfiles(ctx, root)
	if err != nil {
		return AuditDecision{}, result, err
	}
	result.Votes = make([]AuditFusionVote, len(profiles))
	decisions := make([]AuditDecision, len(profiles))
	failures := make([]error, len(profiles))
	var workers sync.WaitGroup
	for i, p := range profiles {
		workers.Add(1)
		go func(i int, p AuditProfile) {
			defer workers.Done()
			d, attempts, err := e.verifyAuditIntent(ctx, p, text, source, state)
			if err == nil && d.Decision == DecisionBlock && !auditConfidenceMeets(d, root.BlockThreshold) {
				d.Decision, d.Category, d.RiskCode = DecisionReview, "audit_uncertainty", "AUDIT_LOW_CONFIDENCE"
			}
			vote := AuditFusionVote{ProfileID: p.ID, Model: p.Model, Attempts: attempts}
			decisions[i], failures[i] = d, err
			if err == nil {
				clean := cleanSemanticDecision(d)
				vote.Outcome = &clean
			} else {
				vote.ErrorClass, _, _ = auditModelErrorDetails(err)
			}
			result.Votes[i] = vote // unique slice element per worker; observed after Wait.
		}(i, p)
	}
	workers.Wait()
	for _, err := range failures {
		if err != nil {
			return AuditDecision{}, result, newAuditModelCallError("fusion_incomplete", 0, "fusion panel has missing or invalid assessments", nil)
		}
	}
	if ctx.Err() != nil {
		return AuditDecision{}, result, classifyAuditTransportError(ctx.Err())
	}
	unanimous := decisions[0].Decision != DecisionReview
	for _, d := range decisions[1:] {
		if !fusionAgreement(decisions[0], d) {
			unanimous = false
		}
	}
	if unanimous {
		result.Status = "consensus"
		return decisions[0], result, nil
	}
	result.Disagreement = true
	if arbiter != nil {
		// No panel verdicts, scores, labels or reasons are supplied to the arbiter.
		d, attempts, err := e.verifyAuditIntent(ctx, *arbiter, text, source, state)
		vote := &AuditFusionVote{ProfileID: arbiter.ID, Model: arbiter.Model, Attempts: attempts}
		result.Adjudicator = vote
		if err != nil {
			vote.ErrorClass, _, _ = auditModelErrorDetails(err)
			return AuditDecision{}, result, newAuditModelCallError("fusion_incomplete", 0, "fusion adjudication could not be validated", nil)
		}
		clean := cleanSemanticDecision(d)
		vote.Outcome = &clean
		if d.Decision != DecisionReview && auditConfidenceMeets(d, root.BlockThreshold) {
			for _, panel := range decisions {
				if fusionAgreement(d, panel) {
					result.Status = "adjudicated"
					return d, result, nil
				}
			}
		}
	}
	result.Status = "unresolved"
	// Preserve full votes rather than claiming one dissenting block is proven.
	return AuditDecision{Decision: DecisionReview, RiskCode: "AUDIT_FUSION_DISAGREEMENT", Category: "audit_uncertainty", Confidence: 0, Source: "model_fusion", Reason: "validated audit assessments disagree; no supported adjudication is available"}, result, nil
}

// Validate the shape at save time too; availability is rechecked when invoked.
func validateFusionExtra(raw json.RawMessage) error {
	if len(raw) == 0 {
		return nil
	}
	var extra map[string]any
	if err := json.Unmarshal(raw, &extra); err != nil {
		return err
	}
	ids, exists := extra["_risk_fusion_profile_ids"]
	if !exists {
		if _, yes := extra["_risk_fusion_adjudicator_profile_id"]; yes {
			return fmt.Errorf("fusion adjudicator requires a fusion panel")
		}
		return nil
	}
	values, ok := ids.([]any)
	if !ok || len(values) < 2 || len(values) > 3 {
		return fmt.Errorf("fusion requires 2 or 3 profile IDs")
	}
	seen := map[int64]bool{}
	if a, yes := extra["_risk_fusion_adjudicator_profile_id"]; yes {
		values = append(append([]any{}, values...), a)
	}
	for _, raw := range values {
		id, ok := auditProfileID(raw)
		if !ok || seen[id] {
			return fmt.Errorf("fusion profile IDs must be positive and distinct")
		}
		seen[id] = true
	}
	return nil
}
