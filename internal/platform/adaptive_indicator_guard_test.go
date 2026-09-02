package platform

import "testing"

func TestAdaptiveIndicatorSensitiveValuesAreRejected(t *testing.T) {
	for _, value := range []string{
		"169.254.169.254",
		"https://internal.example.com/token",
		"admin@example.com",
		"550e8400-e29b-41d4-a716-446655440000",
		"0123456789abcdef0123456789abcdef",
		"Bearer abcdefghijklmnopqrstuvwxyz",
		"api_key=sk-1234567890abcdefghijkl",
		"customer-938472938472-account",
	} {
		if !adaptiveIndicatorLooksSensitive(value) {
			t.Fatalf("expected %q to be rejected as an adaptive indicator", value)
		}
	}
}

func TestAdaptiveIndicatorHumanPolicyTermsAreAllowed(t *testing.T) {
	for _, value := range []string{
		"credential stealer",
		"bypass endpoint protection",
		"横向移动",
		"窃取会话令牌",
		"prompt injection",
	} {
		if adaptiveIndicatorLooksSensitive(value) {
			t.Fatalf("expected %q to remain eligible as a policy indicator", value)
		}
	}
}
