package platform

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestParseAuditModelResponseContentAcceptsReasoningWrappedJSON(t *testing.T) {
	content := `<think>I should classify the request carefully. The final answer must be JSON.</think>
Here is the result:
` + "```json\n" + `{"decision":"allow","risk_code":"","category":"benign","confidence":0.99,"reason":"normal request"}` + "\n```"
	result, err := parseAuditModelResponseContent(content)
	if err != nil {
		t.Fatal(err)
	}
	if result.Decision != DecisionAllow || result.Category != "benign" || result.Confidence != 0.99 {
		t.Fatalf("unexpected result: %+v", result)
	}
}

func TestParseAuditModelResponseContentRejectsConflictingPolicyJSON(t *testing.T) {
	content := `thinking example {"decision":"review","confidence":0.1} final {"decision":"allow","risk_code":"","confidence":0.999,"reason":"final"}`
	_, err := parseAuditModelResponseContent(content)
	class, _, _ := auditModelErrorDetails(err)
	if class != "ambiguous_output" {
		t.Fatalf("multiple policies must not select allow: %v", err)
	}
}

func TestParseAuditModelResponseContentRejectsInvalidDecision(t *testing.T) {
	_, err := parseAuditModelResponseContent(`{"decision":"maybe","confidence":0.8}`)
	if err == nil {
		t.Fatal("expected invalid decision error")
	}
	class, _, _ := auditModelErrorDetails(err)
	if class != "invalid_decision" {
		t.Fatalf("unexpected error class: %s", class)
	}
}

func TestAuditHTTPStatusErrorIncludesSanitizedProviderMessage(t *testing.T) {
	err := auditHTTPStatusError(401, []byte(`{"error":{"message":"invalid api_key=super-secret-value"}}`))
	class, status, reason := auditModelErrorDetails(err)
	if class != "authentication" || status != 401 {
		t.Fatalf("unexpected details: class=%s status=%d reason=%s", class, status, reason)
	}
	if strings.Contains(reason, "super-secret-value") || !strings.Contains(reason, "[REDACTED]") {
		t.Fatalf("diagnostic was not sanitized: %s", reason)
	}
}

func TestAuditHTTPStatusErrorParsesRealVLLMContextMessage(t *testing.T) {
	body := []byte(`{"error":{"message":"This model's maximum context length is 262144 tokens. However, you requested 128 output tokens and your prompt contains 270000 input tokens, for a total of 270128 tokens."}}`)
	err := auditHTTPStatusError(400, body)
	class, status, reason := auditModelErrorDetails(err)
	if class != "context_length" || status != 400 {
		t.Fatalf("unexpected context details: class=%s status=%d reason=%s", class, status, reason)
	}
	maximum, requested := auditContextTokenCounts(err)
	if maximum != 262144 || requested != 270000 {
		t.Fatalf("token counts = max:%d requested:%d, want max:262144 requested:270000", maximum, requested)
	}
}

func TestParseAuditContextTokenCountsDoesNotConfuseOutputTokens(t *testing.T) {
	message := "This model's maximum context length is 262,144 tokens. However, you requested 128 output tokens and your prompt contains 270,000 input tokens, for a total of 270,128 tokens."
	maximum, requested := parseAuditContextTokenCounts(message)
	if maximum != 262144 || requested != 270000 {
		t.Fatalf("token counts = max:%d requested:%d", maximum, requested)
	}
}

func TestClassifyAuditTransportErrorTimeout(t *testing.T) {
	class, _, reason := auditModelErrorDetails(classifyAuditTransportError(context.DeadlineExceeded))
	if class != "timeout" || !strings.Contains(reason, "timed out") {
		t.Fatalf("unexpected timeout details: class=%s reason=%s", class, reason)
	}
}

func TestAuditModelCallErrorUnwrap(t *testing.T) {
	cause := errors.New("dial failed")
	err := newAuditModelCallError("connection", 0, "audit model connection failed", cause)
	if !errors.Is(err, cause) {
		t.Fatal("wrapped cause is not discoverable")
	}
}

func TestTraceFailureReasonPrefersAuditDiagnostic(t *testing.T) {
	metadata := map[string]any{"audit_reason": "audit model returned HTTP 404: model not found"}
	reason := traceFailureReason("AUDIT_MODEL_ERROR", 0, metadata)
	if reason != metadata["audit_reason"] {
		t.Fatalf("unexpected reason: %s", reason)
	}
}
