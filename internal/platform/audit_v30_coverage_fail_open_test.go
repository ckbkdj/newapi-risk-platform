package platform

import (
	"encoding/json"
	"testing"
)

func TestV30UnknownProtocolItemIsWarningOnly(t *testing.T) {
	body := []byte(`{"input":[{"role":"user","content":[{"type":"input_text","text":"Explain ordinary code"},{"type":"private_future_type","value":"PRIVATE_VALUE"}]}]}`)
	got := extractCyberAuditText(body, 8192)
	if got.CoverageStatus != "complete" {
		t.Fatalf("unknown future item must not make text audit fail closed: %+v", got)
	}
	if len(got.CoverageDetails) != 1 || got.CoverageDetails[0].Code != "unsupported_input_content" || got.CoverageDetails[0].ContentType != "unknown" {
		t.Fatalf("unknown item diagnostic mismatch: %+v", got.CoverageDetails)
	}
	encoded, _ := json.Marshal(got.CoverageDetails)
	if string(encoded) == "" || containsAny(string(encoded), "private_future_type", "PRIVATE_VALUE") {
		t.Fatalf("private unknown protocol values leaked: %s", encoded)
	}
}

func TestV30NonTextCoverageIsIncompleteButDecisionFailsOpen(t *testing.T) {
	body := []byte(`{"input":[{"role":"user","content":[{"type":"input_text","text":"Explain this"},{"type":"input_image","image_url":"https://image.invalid/synthetic"}]}]}`)
	got := extractCyberAuditText(body, 8192)
	if got.CoverageStatus != "incomplete" {
		t.Fatalf("unseen non-text modality must remain observable as incomplete: %+v", got)
	}
	if len(got.CoverageDetails) != 1 || got.CoverageDetails[0].Code != "unsupported_nontext_content" || got.CoverageDetails[0].ContentType != "input_image" {
		t.Fatalf("non-text diagnostic mismatch: %+v", got.CoverageDetails)
	}
	decision := auditIncompleteInputDecision(true, got.CoverageIssues)
	if decision.Decision != DecisionAllow || decision.Source != "coverage_fail_open_v29" || decision.RiskCode != "" {
		t.Fatalf("coverage uncertainty must fail open: %+v", decision)
	}
}

func containsAny(s string, values ...string) bool {
	for _, value := range values {
		if value != "" && stringContains(s, value) {
			return true
		}
	}
	return false
}

func stringContains(s, sub string) bool {
	if len(sub) == 0 {
		return true
	}
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
