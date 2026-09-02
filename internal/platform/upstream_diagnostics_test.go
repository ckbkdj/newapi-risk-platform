package platform

import (
	"strings"
	"testing"
)

func TestTraceFailureReasonUsesUpstreamReasonForLateStreamFailure(t *testing.T) {
	metadata := map[string]any{
		"audit_reason":          "Benign enterprise data synchronization implementation; no harmful cyber capability requested.",
		"upstream_error_reason": "late stream failure",
	}
	got := traceFailureReason("UPSTREAM_STREAM_ERROR", 200, metadata)
	if got != "late stream failure" {
		t.Fatalf("trace failure reason = %q, want upstream reason", got)
	}
}

func TestTraceFailureReasonStillUsesAuditReasonForAuditFailure(t *testing.T) {
	metadata := map[string]any{
		"audit_reason":          "audit model returned HTTP 404: model not found",
		"upstream_error_reason": "must not win",
	}
	got := traceFailureReason("AUDIT_MODEL_ERROR", 0, metadata)
	if got != metadata["audit_reason"] {
		t.Fatalf("trace failure reason = %q, want audit reason", got)
	}
}

func TestExtractUpstreamFailureReasonFromSSE(t *testing.T) {
	evidence := []byte("event: error\ndata: {\"error\":{\"message\":\"late stream failure\"}}\n\n")
	if got := extractUpstreamFailureReason(evidence); got != "late stream failure" {
		t.Fatalf("upstream failure reason = %q", got)
	}
}

func TestExtractUpstreamFailureReasonRedactsSecret(t *testing.T) {
	evidence := []byte(`{"error":{"message":"provider rejected api_key=super-secret-value"}}`)
	got := extractUpstreamFailureReason(evidence)
	if strings.Contains(got, "super-secret-value") || !strings.Contains(got, "[REDACTED]") {
		t.Fatalf("upstream diagnostic was not redacted: %q", got)
	}
}

func TestRecordUpstreamFailureMetadataKeepsStagesSeparate(t *testing.T) {
	trace := TraceEvent{Metadata: map[string]any{"audit_reason": "benign audit"}}
	recordUpstreamFailureMetadata(
		&trace,
		"UPSTREAM_STREAM_ERROR",
		200,
		[]byte("event: error\ndata: {\"error\":{\"message\":\"late stream failure\"}}\n\n"),
		"upstream_stream",
	)
	if trace.Metadata["failure_stage"] != "upstream_stream" {
		t.Fatalf("failure stage = %#v", trace.Metadata["failure_stage"])
	}
	if trace.Metadata["upstream_error_reason"] != "late stream failure" {
		t.Fatalf("upstream reason = %#v", trace.Metadata["upstream_error_reason"])
	}
	if trace.Metadata["audit_reason"] != "benign audit" {
		t.Fatalf("audit reason was mutated: %#v", trace.Metadata["audit_reason"])
	}
}
