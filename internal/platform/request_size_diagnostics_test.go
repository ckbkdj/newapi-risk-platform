package platform

import (
	"strings"
	"testing"
)

func TestAutomaticRequestBodyPolicyAllowsObservedProductionSize(t *testing.T) {
	const observed = int64(60853983)
	policy := resolveRequestBodyLimit(0, 64*1024*1024, observed)
	if policy.Mode != "auto_actual_size" || policy.EffectiveLimitBytes != observed {
		t.Fatalf("unexpected automatic policy: %+v", policy)
	}
	if policy.ExceedsKnownLength(observed) {
		t.Fatalf("observed production body should pass automatically: %+v", policy)
	}
}

func TestAutomaticRequestBodyPolicyRejectsOnlyAboveHardCeiling(t *testing.T) {
	policy := resolveRequestBodyLimit(0, 64*1024*1024, 80*1024*1024)
	if policy.Mode != "auto_hard_ceiling" || !policy.ExceedsKnownLength(80*1024*1024) {
		t.Fatalf("hard-ceiling policy is wrong: %+v", policy)
	}
}

func TestConfiguredRequestBodyPolicyPreservesExplicitLimit(t *testing.T) {
	policy := resolveRequestBodyLimit(8*1024*1024, 64*1024*1024, 10*1024*1024)
	if policy.Mode != "configured" || !policy.ExceedsKnownLength(10*1024*1024) {
		t.Fatalf("explicit limit policy is wrong: %+v", policy)
	}
	trace := TraceEvent{Metadata: map[string]any{}}
	reason := markRequestTooLarge(&trace, 10*1024*1024, policy, true)
	if !strings.Contains(reason, "configured") || !strings.Contains(reason, "before audit and upstream") {
		t.Fatalf("reason lacks source and mode: %q", reason)
	}
	if trace.Metadata["request_body_remediation"] == "" || trace.Metadata["audit_started"] != false || trace.Metadata["upstream_started"] != false {
		t.Fatalf("source diagnostics missing: %#v", trace.Metadata)
	}
}

func TestUnknownLengthUsesHardCeilingAndLargeSlot(t *testing.T) {
	policy := resolveRequestBodyLimit(0, 64*1024*1024, -1)
	if policy.Mode != "auto_hard_ceiling" || policy.EffectiveLimitBytes != 64*1024*1024 {
		t.Fatalf("unexpected unknown-length policy: %+v", policy)
	}
	if !requestBodyNeedsLargeSlot(-1, 8*1024*1024) {
		t.Fatal("unknown-length request must use a bounded large-body slot")
	}
}
