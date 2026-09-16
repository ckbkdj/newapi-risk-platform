package platform

import (
	"context"
	"errors"
	"testing"
)

func TestCyberDenyVerdictV29ReviewFailsOpen(t *testing.T) {
	got, err := cyberDenyVerdict(AuditDecision{
		Decision:   DecisionReview,
		RiskCode:   "CYBER_UNKNOWN",
		Category:   "security_testing",
		Confidence: 0.51,
		Reason:     "needs verification",
		Evidence:   "扫描目标端口",
		Source:     "model",
	})
	if err != nil {
		t.Fatalf("review must not return an error: %v", err)
	}
	if got.Decision != DecisionAllow || got.RiskCode != "" || got.Source != "model_review_fail_open_v29" {
		t.Fatalf("review uncertainty must fail open: %#v", got)
	}
	if got.SemanticReview == nil || got.SemanticReview.Candidate.Decision != DecisionReview {
		t.Fatalf("original review must remain observable: %#v", got.SemanticReview)
	}
}

func TestCyberDenyVerdictV29LowConfidenceAllowStillAllows(t *testing.T) {
	got, err := cyberDenyVerdict(AuditDecision{
		Decision:   DecisionAllow,
		RiskCode:   "CYBER_CONTRADICTORY",
		Category:   "exploitation",
		Confidence: 0.2,
		Reason:     "contradictory low confidence",
		Source:     "model",
	})
	if err != nil || got.Decision != DecisionAllow || got.RiskCode != "" {
		t.Fatalf("uncertain allow must remain fail-open, got=%#v err=%v", got, err)
	}
}

func TestCyberDecisionNeedsFailOpenV29NoncanonicalBlock(t *testing.T) {
	engine := &AuditEngine{}
	engine.rules.Store([]compiledRule{})
	if !cyberDecisionNeedsFailOpenV29(engine, AuditDecision{Decision: DecisionBlock, RiskCode: "CYBER_MODEL_INVENTED", Source: "model"}) {
		t.Fatal("noncanonical model block must require fail-open")
	}
}

func TestCyberModelErrorAllowV29(t *testing.T) {
	got := cyberModelErrorAllowV29(errors.New("synthetic verifier failure"))
	if got.Decision != DecisionAllow || got.RiskCode != "" || got.Category != "audit_uncertainty" || got.Source != "model_error_fail_open_v29" {
		t.Fatalf("model/verifier error must be observable fail-open: %#v", got)
	}
}

func TestAuditIncompleteInputDecisionV29AlwaysFailsOpen(t *testing.T) {
	for _, closed := range []bool{true, false} {
		got := auditIncompleteInputDecision(closed, []string{"unsupported_input_content"})
		if got.Decision != DecisionAllow || got.RiskCode != "" || got.Source != "coverage_fail_open_v29" {
			t.Fatalf("coverage uncertainty must fail open regardless of legacy flag: closed=%v got=%#v", closed, got)
		}
	}
}

func TestCyberDenyModelV29TransportErrorFailsOpen(t *testing.T) {
	engine, profile := incidentEngine(t, func(*http.Request) (*http.Response, error) {
		return nil, context.DeadlineExceeded
	})
	got, err := engine.callCyberDenyModel(context.Background(), cyberDenyProfile(profile), "检查资产状态", "检查资产状态")
	if err != nil || got.Decision != DecisionAllow || got.Source != "model_error_fail_open_v29" {
		t.Fatalf("transport uncertainty must fail open, got=%#v err=%v", got, err)
	}
}
