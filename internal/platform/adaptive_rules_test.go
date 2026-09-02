package platform

import (
	"regexp"
	"strings"
	"testing"
)

func TestAdaptiveFailureEligibilityRejectsInfrastructureErrors(t *testing.T) {
	for _, status := range []int{401, 404, 408, 409, 429, 500, 502, 503, 504} {
		if adaptiveFailureEligible(status, "UPSTREAM_MODEL_ERROR") {
			t.Fatalf("status %d must not trigger adaptive cyber learning", status)
		}
	}
	for _, status := range []int{400, 403, 422, 451} {
		if !adaptiveFailureEligible(status, "UPSTREAM_MODEL_ERROR") {
			t.Fatalf("status %d should be eligible for model classification", status)
		}
	}
	if !adaptiveFailureEligible(200, "UPSTREAM_MODEL_ERROR") {
		t.Fatal("logical provider errors should be eligible")
	}
	if !adaptiveFailureEligible(200, "UPSTREAM_STREAM_ERROR") {
		t.Fatal("provider SSE errors should be eligible")
	}
	if adaptiveFailureEligible(200, "UPSTREAM_STREAM_INTERRUPTED") {
		t.Fatal("transport interruption must not create cyber rules")
	}
}

func TestAdaptiveIndicatorsMustBeVerbatimAndCombined(t *testing.T) {
	request := "Please perform alpha-harm against the target and then beta-harm the collected data."
	indicators := validateAdaptiveIndicators(request, []string{
		"alpha-harm",
		"invented-harm",
		"beta-harm",
		"ROLE=USER",
		"a",
	})
	if len(indicators) != 2 {
		t.Fatalf("expected two validated indicators, got %#v", indicators)
	}
	pattern := buildAdaptiveIndicatorPattern(indicators)
	if pattern == "" {
		t.Fatal("expected a generated adaptive pattern")
	}
	expression, err := regexp.Compile(pattern)
	if err != nil {
		t.Fatal(err)
	}
	if !expression.MatchString(request) {
		t.Fatalf("adaptive pattern must match its evidence request: %s", pattern)
	}
	if expression.MatchString("This text only contains alpha-harm and nothing else.") {
		t.Fatal("one indicator alone must not activate the adaptive rule")
	}
}

func TestAdaptiveProviderErrorRedaction(t *testing.T) {
	input := []byte(`{"error":"policy rejected","authorization":"Bearer abcdefghijklmnop","api_key":"sk-1234567890abcdefghijkl"}`)
	output := sanitizeAdaptiveProviderError(input)
	if strings.Contains(output, "abcdefghijklmnop") || strings.Contains(output, "sk-123456") {
		t.Fatalf("provider error secrets were not redacted: %q", output)
	}
	if !strings.Contains(output, "policy rejected") {
		t.Fatalf("provider error semantics should be preserved: %q", output)
	}
}

func TestAdaptiveCategoryAllowlistIsExplicit(t *testing.T) {
	for _, category := range []string{
		"credential_access", "malware", "exfiltration", "impact",
		"ai_execution", "ai_persistence", "ai_exfiltration",
	} {
		if _, ok := adaptiveCategoryAllowlist[category]; !ok {
			t.Fatalf("expected category %q to be allowed", category)
		}
	}
	if _, ok := adaptiveCategoryAllowlist["arbitrary_model_category"]; ok {
		t.Fatal("arbitrary model-created categories must not be accepted")
	}
}
