package platform

import (
	"strings"
	"testing"
)

func TestMarkRequestTooLargeExact(t *testing.T) {
	trace := TraceEvent{Metadata: map[string]any{}}
	reason := markRequestTooLarge(&trace, 10*1024*1024, 8*1024*1024, true)
	if trace.RequestBytes != 10*1024*1024 {
		t.Fatalf("request bytes = %d", trace.RequestBytes)
	}
	if trace.Metadata["request_body_size_exact"] != true {
		t.Fatalf("expected exact size metadata: %#v", trace.Metadata)
	}
	if trace.Metadata["request_body_over_limit_bytes"] != int64(2*1024*1024) {
		t.Fatalf("unexpected over-limit bytes: %#v", trace.Metadata)
	}
	if !strings.Contains(reason, "10485760") || !strings.Contains(reason, "8388608") {
		t.Fatalf("reason lacks sizes: %q", reason)
	}
	if !strings.Contains(reason, "Risk Gateway ingress") || !strings.Contains(reason, "before audit and upstream") {
		t.Fatalf("reason does not identify the owning stage: %q", reason)
	}
	for key, expected := range map[string]any{
		"error_origin":      "risk_gateway",
		"failure_stage":     "gateway_ingress",
		"failure_component": "request_body_guard",
		"limit_config":      "REQUEST_MAX_BYTES",
		"audit_started":     false,
		"upstream_started":  false,
	} {
		if got := trace.Metadata[key]; got != expected {
			t.Fatalf("%s = %#v, want %#v; metadata=%#v", key, got, expected, trace.Metadata)
		}
	}
	if trace.Metadata["request_body_recommended_limit_bytes"] != int64(16*1024*1024) {
		t.Fatalf("unexpected recommended limit: %#v", trace.Metadata)
	}
	if guidance, _ := trace.Metadata["request_body_remediation"].(string); !strings.Contains(guidance, "not an audit-model or upstream-model limit") {
		t.Fatalf("remediation lacks source distinction: %#v", trace.Metadata)
	}
}

func TestMarkRequestTooLargeLowerBound(t *testing.T) {
	trace := TraceEvent{Metadata: map[string]any{}}
	reason := markRequestTooLarge(&trace, 65537, 65536, false)
	if trace.Metadata["request_body_size_exact"] != false {
		t.Fatalf("expected lower-bound metadata: %#v", trace.Metadata)
	}
	if !strings.Contains(reason, "at least") {
		t.Fatalf("lower-bound reason is not explicit: %q", reason)
	}
}

func TestRecommendedRequestMaxBytesForObservedProductionSize(t *testing.T) {
	const observed = int64(60853983)
	if got := recommendedRequestMaxBytes(observed); got != 64*1024*1024 {
		t.Fatalf("recommended limit = %d, want %d", got, int64(64*1024*1024))
	}
}

func TestMarkRequestTooLargeAboveSupportedCeiling(t *testing.T) {
	trace := TraceEvent{Metadata: map[string]any{}}
	_ = markRequestTooLarge(&trace, 80*1024*1024, 8*1024*1024, true)
	if _, exists := trace.Metadata["request_body_recommended_limit_bytes"]; exists {
		t.Fatalf("unsupported request must not receive an unsafe recommendation: %#v", trace.Metadata)
	}
	guidance, _ := trace.Metadata["request_body_remediation"].(string)
	if !strings.Contains(guidance, "supported 64 MiB body ceiling") {
		t.Fatalf("hard-ceiling guidance missing: %#v", trace.Metadata)
	}
}
