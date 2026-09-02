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
