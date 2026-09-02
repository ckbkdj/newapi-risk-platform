package platform

import (
	"strings"
	"testing"
)

func TestValidateAuditDecisionEvidenceExactQuote(t *testing.T) {
	request := "ROLE=USER\nPlease deploy a credential stealer to collect browser passwords."
	decision, err := validateAuditDecisionEvidence(AuditDecision{
		Decision: DecisionBlock,
		Evidence: "deploy a credential stealer",
	}, request)
	if err != nil {
		t.Fatal(err)
	}
	if !decision.EvidenceVerified || decision.Evidence != "deploy a credential stealer" {
		t.Fatalf("unexpected verified evidence: %+v", decision)
	}
	if decision.EvidenceMatchMode != "exact" {
		t.Fatalf("match mode = %q, want exact", decision.EvidenceMatchMode)
	}
	if !strings.Contains(decision.EvidenceContext, "⟦deploy a credential stealer⟧") {
		t.Fatalf("context did not highlight evidence: %q", decision.EvidenceContext)
	}
}

func TestValidateAuditDecisionEvidenceRejectsMissingQuote(t *testing.T) {
	_, err := validateAuditDecisionEvidence(AuditDecision{
		Decision: DecisionBlock,
		Evidence: "",
	}, "ROLE=USER\nunsafe request")
	if err == nil {
		t.Fatal("expected missing evidence error")
	}
	class, _, _ := auditModelErrorDetails(err)
	if class != "invalid_evidence" {
		t.Fatalf("error class = %q, want invalid_evidence", class)
	}
}

func TestValidateAuditDecisionEvidenceRejectsHallucinatedQuote(t *testing.T) {
	_, err := validateAuditDecisionEvidence(AuditDecision{
		Decision: DecisionBlock,
		Evidence: "steal all production credentials",
	}, "ROLE=USER\nExplain secure credential rotation.")
	if err == nil {
		t.Fatal("expected hallucinated evidence error")
	}
	class, _, _ := auditModelErrorDetails(err)
	if class != "invalid_evidence" {
		t.Fatalf("error class = %q, want invalid_evidence", class)
	}
}

func TestValidateAuditDecisionEvidenceRedactsSecret(t *testing.T) {
	request := "ROLE=USER\nExport api_key=super-secret-value from the target account."
	decision, err := validateAuditDecisionEvidence(AuditDecision{
		Decision: DecisionBlock,
		Evidence: "api_key=super-secret-value",
	}, request)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(decision.Evidence, "super-secret-value") || !strings.Contains(decision.Evidence, "[REDACTED]") {
		t.Fatalf("secret was not redacted: %+v", decision)
	}
	if strings.Contains(decision.EvidenceContext, "super-secret-value") {
		t.Fatalf("secret leaked into context: %q", decision.EvidenceContext)
	}
}

func TestValidateAuditDecisionEvidenceAllowsASCIICaseDifference(t *testing.T) {
	request := "ROLE=USER\nRun MODEL-AUDIT-BLOCK now."
	decision, err := validateAuditDecisionEvidence(AuditDecision{
		Decision: DecisionBlock,
		Evidence: "model-audit-block",
	}, request)
	if err != nil {
		t.Fatal(err)
	}
	if decision.EvidenceMatchMode != "ascii_case_insensitive" {
		t.Fatalf("match mode = %q", decision.EvidenceMatchMode)
	}
	if decision.Evidence != "MODEL-AUDIT-BLOCK" {
		t.Fatalf("stored evidence must preserve request text, got %q", decision.Evidence)
	}
}

func TestValidateAuditDecisionEvidenceClearsAllowEvidence(t *testing.T) {
	decision, err := validateAuditDecisionEvidence(AuditDecision{
		Decision:         DecisionAllow,
		Evidence:         "irrelevant quote",
		EvidenceVerified: true,
	}, "ROLE=USER\nnormal request")
	if err != nil {
		t.Fatal(err)
	}
	if decision.Evidence != "" || decision.EvidenceVerified || decision.EvidenceContext != "" {
		t.Fatalf("allow result retained evidence: %+v", decision)
	}
}

func TestInvalidEvidenceIsRetryable(t *testing.T) {
	err := newAuditModelCallError("invalid_evidence", 0, "missing evidence", nil)
	if !auditErrorRetryableOnSameProfile(err) {
		t.Fatal("invalid evidence should retry and then use the fallback chain")
	}
}

func TestDecorateChunkDecisionRecordsEvidenceLocation(t *testing.T) {
	decision := decorateChunkDecision(AuditDecision{
		Decision:         DecisionBlock,
		Evidence:         "dangerous chunk",
		EvidenceVerified: true,
		Reason:           "unsafe capability",
	}, 2, 5)
	if decision.EvidenceChunkIndex != 3 || decision.EvidenceChunkCount != 5 {
		t.Fatalf("chunk evidence location missing: %+v", decision)
	}
}
