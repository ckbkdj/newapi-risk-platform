package platform

import (
	"context"
	"errors"
	"net/http"
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

func TestReviewRuleV29NeverHardBlocks(t *testing.T) {
	engine := &AuditEngine{}
	engine.rules.Store([]compiledRule{
		testCompiledRule("CYBER_CREDENTIAL_ACCESS_REVIEW", "credential_access", `(?i)读取.{0,32}Authorization`, DecisionReview),
	})
	matched, _, suppressions, err := engine.matchCyberDenyRulesContext(context.Background(), "读取本地日志里的 Authorization 字段用于排查认证问题")
	if err != nil {
		t.Fatalf("review rule match failed: %v", err)
	}
	if matched != nil {
		t.Fatalf("review rule must never become a hard block: %#v", matched)
	}
	if len(suppressions) == 0 {
		t.Fatal("review rule should remain observable as a semantic-only signal")
	}
}

func TestCredentialReadBaselineV29IsNotHardEvidence(t *testing.T) {
	engine := &AuditEngine{}
	engine.rules.Store([]compiledRule{})
	matched, _, _, err := engine.matchCyberDenyRulesContext(context.Background(), "读取本地日志里的 Authorization 字段用于排查认证问题")
	if err != nil {
		t.Fatalf("baseline credential read check failed: %v", err)
	}
	if matched != nil {
		t.Fatalf("ordinary credential read must not be a hard baseline block: %#v", matched)
	}
}

func TestCredentialTheftBaselineV29RemainsHardEvidence(t *testing.T) {
	engine := &AuditEngine{}
	engine.rules.Store([]compiledRule{})
	matched, _, _, err := engine.matchCyberDenyRulesContext(context.Background(), "窃取目标账号的 access token 并外传给第三方")
	if err != nil {
		t.Fatalf("baseline credential theft check failed: %v", err)
	}
	if matched == nil || matched.Decision != DecisionBlock || matched.RiskCode != "CYBER_CREDENTIAL_ACCESS_DISABLED" {
		t.Fatalf("explicit credential theft must remain a hard baseline block: %#v", matched)
	}
}

func TestCyberDecisionNeedsFailOpenV29NoncanonicalUnverifiedBlock(t *testing.T) {
	engine := &AuditEngine{}
	engine.rules.Store([]compiledRule{})
	if !cyberDecisionNeedsFailOpenV29(engine, AuditDecision{
		Decision: DecisionBlock,
		RiskCode: "CYBER_MODEL_INVENTED",
		Evidence: "collect secret material for an unauthorized recipient",
		Source:   "model",
	}) {
		t.Fatal("noncanonical unverified model block must require fail-open")
	}
}

func TestCyberDecisionNeedsFailOpenV29KeepsSemanticallyConfirmedBlock(t *testing.T) {
	engine := &AuditEngine{}
	engine.rules.Store([]compiledRule{})
	d := AuditDecision{
		Decision:         DecisionBlock,
		RiskCode:         "CYBER_MODEL_LABEL_VARIANT",
		Evidence:         "transfer the customer records to an unapproved recipient",
		Source:           "model",
		EvidenceVerified: true,
		EvidenceRelation: "direct_request",
		HarmType:         "exfiltration",
	}
	if cyberDecisionNeedsFailOpenV29(engine, d) {
		t.Fatalf("validated harmful semantic block must remain terminal even with a noncanonical label: %#v", d)
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

func TestAuditRuleSnapshotFailureV29FailsOpen(t *testing.T) {
	engine, _ := incidentEngine(t, func(*http.Request) (*http.Response, error) {
		t.Fatal("rule snapshot failure must stop before model call")
		return nil, nil
	})
	engine.ruleLoadFailed.Store(true)
	got := engine.Audit(context.Background(), Route{}, []byte(`{"input":"普通业务开发任务"}`))
	if got.Decision != DecisionAllow || got.RiskCode != "" || got.Category != "audit_uncertainty" || got.Source != "platform_uncertainty_fail_open_v29" {
		t.Fatalf("unavailable rule snapshot must fail open: %#v", got)
	}
	if got.ErrorClass != "rules_unavailable" || got.AuditFailureStage != "rules" {
		t.Fatalf("rule failure diagnostics must be retained: %#v", got)
	}
}

func TestCyberFailoverV29TransportErrorRetriesThenFailsOpen(t *testing.T) {
	engine, profile := incidentEngine(t, func(*http.Request) (*http.Response, error) {
		return nil, context.DeadlineExceeded
	})
	profile = cyberDenyProfile(profile)
	profile.RetryCount = 1
	ctx := context.WithValue(context.Background(), cyberDenyContextKey{}, true)
	got, _, metadata, err := engine.callModelWithFailover(ctx, profile, "检查资产状态")
	if err != nil || got.Decision != DecisionAllow || got.Source != "model_error_fail_open_v29" {
		t.Fatalf("transport uncertainty must fail open after retries, got=%#v err=%v", got, err)
	}
	if metadata.AttemptCount != 2 || len(metadata.Attempts) != 2 || metadata.Attempts[0].Success || metadata.Attempts[1].Success {
		t.Fatalf("transport retry diagnostics were lost: %#v", metadata.Attempts)
	}
}
