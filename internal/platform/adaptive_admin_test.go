package platform

import "testing"

func TestNormalizeManualCandidateAction(t *testing.T) {
	for input, expected := range map[string]string{
		"review":  DecisionReview,
		" BLOCK ": DecisionBlock,
	} {
		actual, err := normalizeManualCandidateAction(input)
		if err != nil || actual != expected {
			t.Fatalf("normalizeManualCandidateAction(%q) = %q, %v; want %q", input, actual, err, expected)
		}
	}
	if _, err := normalizeManualCandidateAction("allow"); err == nil {
		t.Fatal("manual candidate promotion must not create an allow rule")
	}
}

func TestNormalizeCandidateWorkflowStatus(t *testing.T) {
	for _, value := range []string{"shadow", " REJECTED "} {
		if _, err := normalizeCandidateWorkflowStatus(value); err != nil {
			t.Fatalf("expected valid status %q: %v", value, err)
		}
	}
	for _, value := range []string{"promoted", "candidate", "unknown"} {
		if _, err := normalizeCandidateWorkflowStatus(value); err == nil {
			t.Fatalf("expected invalid status %q", value)
		}
	}
}
