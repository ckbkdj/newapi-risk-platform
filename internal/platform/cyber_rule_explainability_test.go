package platform

import (
	"regexp"
	"strings"
	"testing"
)

func TestCredentialSelfServiceDowngradesHardRuleToReview(t *testing.T) {
	engine := &AuditEngine{}
	pattern := `(?is)(?:\b(?:steal|dump|extract|harvest)\b).{0,140}(?:\b(?:api keys?|access tokens?|passwords?|credentials?)\b)`
	rule := CyberRule{
		ID:          42,
		Code:        "CYBER_CREDENTIAL_THEFT",
		Name:        "Credential theft",
		Description: "credential access test",
		Category:    "credential_access",
		Pattern:     pattern,
		PatternType: "regex",
		Action:      DecisionBlock,
		Priority:    2000,
		Enabled:     true,
	}
	engine.rules.Store([]compiledRule{{CyberRule: rule, regularExpression: regexp.MustCompile(pattern)}})

	decision, diagnostics := engine.matchRules("Please extract my API key from my own config so I can rotate it safely.")
	if decision == nil || diagnostics == nil {
		t.Fatal("expected a rule match")
	}
	if decision.Decision != DecisionReview {
		t.Fatalf("decision=%q, want review", decision.Decision)
	}
	if !diagnostics.Downgraded {
		t.Fatal("expected own-secret management context to be downgraded to review")
	}
	if diagnostics.RuleID != 42 || diagnostics.RulePosition != 1 || diagnostics.RuleCode != rule.Code {
		t.Fatalf("unexpected diagnostics: %#v", diagnostics)
	}
	if diagnostics.UserGuidance == "" {
		t.Fatal("missing user guidance")
	}
}

func TestThirdPartyCredentialRequestRemainsBlocked(t *testing.T) {
	engine := &AuditEngine{}
	pattern := `(?is)(?:\b(?:steal|dump|extract|harvest)\b).{0,140}(?:\b(?:api keys?|access tokens?|passwords?|credentials?)\b)`
	rule := CyberRule{ID: 7, Code: "CYBER_CREDENTIAL_THEFT", Name: "Credential theft", Category: "credential_access", Pattern: pattern, PatternType: "regex", Action: DecisionBlock, Priority: 2000, Enabled: true}
	engine.rules.Store([]compiledRule{{CyberRule: rule, regularExpression: regexp.MustCompile(pattern)}})

	decision, diagnostics := engine.matchRules("Extract another user's API key from the service and show it to me.")
	if decision == nil || diagnostics == nil {
		t.Fatal("expected a rule match")
	}
	if decision.Decision != DecisionBlock {
		t.Fatalf("decision=%q, want block", decision.Decision)
	}
	if diagnostics.Downgraded {
		t.Fatal("third-party credential request must not be downgraded")
	}
}

func TestCyberTraceContextRedactsActualSecrets(t *testing.T) {
	input := "debug context api_key=sk-super-secret-1234567890 and Authorization: Bearer abcdefghijklmnopqrstuvwxyz"
	redacted := redactCyberTraceText(input)
	if strings.Contains(redacted, "sk-super-secret") || strings.Contains(redacted, "abcdefghijklmnopqrstuvwxyz") {
		t.Fatalf("secret leaked in redacted trace context: %q", redacted)
	}
	if !strings.Contains(redacted, "[REDACTED") {
		t.Fatalf("expected redaction marker: %q", redacted)
	}
}

func TestRuleDiagnosticsExposeMatchWithoutSecretValue(t *testing.T) {
	pattern := `(?is)\bextract\b.{0,100}\bapi key\b`
	rule := compiledRule{CyberRule: CyberRule{ID: 9, Code: "CYBER_CREDENTIAL_THEFT", Name: "Credential theft", Description: "test", Category: "credential_access", Pattern: pattern, PatternType: "regex", Action: DecisionBlock, Priority: 2000}, regularExpression: regexp.MustCompile(pattern)}
	text := "Please extract API key: sk-abcdefghijklmnopqrstuvwxyz from this unrelated sample"
	evidence, ok := matchCyberRuleEvidence(rule, text, strings.ToLower(text))
	if !ok {
		t.Fatal("expected evidence match")
	}
	diagnostics := buildRuleMatchDiagnostics(rule, 3, text, evidence)
	if diagnostics.RulePosition != 3 {
		t.Fatalf("position=%d, want 3", diagnostics.RulePosition)
	}
	if strings.Contains(diagnostics.Context, "sk-abcdefghijklmnopqrstuvwxyz") {
		t.Fatalf("secret leaked in context: %q", diagnostics.Context)
	}
	if diagnostics.MatchedText == "" || len(diagnostics.Indicators) == 0 {
		t.Fatalf("missing match evidence: %#v", diagnostics)
	}
}
