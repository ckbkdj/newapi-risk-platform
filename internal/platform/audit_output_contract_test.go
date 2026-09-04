package platform

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestQwenAuditOutputPlanChangesAcrossRetries(t *testing.T) {
	engine := &AuditEngine{outputMaxTokens: 256}
	profile := AuditProfile{Model: "Qwen3.8-27B"}
	want := []string{
		auditOutputModeJSONSchema,
		auditOutputModeVLLMStructuredJSON,
		auditOutputModeJSONObject,
		auditOutputModeGuidedJSON,
		auditOutputModePromptOnly,
	}
	for attempt, expected := range want {
		plan := engine.auditOutputPlan(profile, attempt)
		if plan.Mode != expected {
			t.Fatalf("attempt %d mode=%q, want %q", attempt+1, plan.Mode, expected)
		}
		if plan.MaxTokens < 256 || plan.MaxTokens > 1024 {
			t.Fatalf("attempt %d max_tokens=%d", attempt+1, plan.MaxTokens)
		}
	}
}

func TestApplyAuditOutputContractOverridesConflictingExtra(t *testing.T) {
	payload := map[string]any{
		"response_format":    map[string]any{"type": "text"},
		"structured_outputs": map[string]any{"choice": []string{"bad"}},
		"guided_json":        map[string]any{"type": "string"},
		"stream":             true,
		"max_tokens":         32,
	}
	applyAuditOutputContract(payload, auditOutputPlan{Mode: auditOutputModeJSONSchema, MaxTokens: 256})
	if payload["stream"] != false || payload["max_tokens"] != 256 {
		t.Fatalf("hard output controls were not applied: %#v", payload)
	}
	format, ok := payload["response_format"].(map[string]any)
	if !ok || format["type"] != "json_schema" {
		t.Fatalf("JSON schema response format missing: %#v", payload)
	}
	if _, exists := payload["structured_outputs"]; exists {
		t.Fatalf("mutually exclusive structured_outputs was retained: %#v", payload)
	}
	if _, exists := payload["guided_json"]; exists {
		t.Fatalf("mutually exclusive guided_json was retained: %#v", payload)
	}
}

func TestExtractAuditCompletionReadsReasoningContentFallback(t *testing.T) {
	body := []byte(`{"id":"audit-1","choices":[{"finish_reason":"stop","message":{"content":"","reasoning_content":"{\"decision\":\"allow\",\"risk_code\":\"\",\"category\":\"benign\",\"confidence\":0.99,\"reason\":\"ok\",\"evidence\":\"\"}"}}]}`)
	response, err := extractAuditCompletionResponse(body)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(response.Source, "reasoning_content") || response.FinishReason != "stop" || response.ResponseID != "audit-1" {
		t.Fatalf("unexpected response diagnostics: %+v", response)
	}
	result, err := parseAuditModelResponseContent(response.Content)
	if err != nil || result.Decision != DecisionAllow {
		t.Fatalf("reasoning-content policy was not parsed: result=%+v err=%v", result, err)
	}
}

func TestParseAuditModelResponseContentAcceptsDoubleEncodedAndNestedJSON(t *testing.T) {
	nested := map[string]any{
		"result": map[string]any{
			"decision": "allow", "risk_code": "", "category": "benign",
			"confidence": 0.98, "reason": "safe", "evidence": "",
		},
	}
	encoded, _ := json.Marshal(nested)
	doubleEncoded, _ := json.Marshal(string(encoded))
	result, err := parseAuditModelResponseContent(string(doubleEncoded))
	if err != nil || result.Decision != DecisionAllow || result.Category != "benign" {
		t.Fatalf("double-encoded nested result failed: result=%+v err=%v", result, err)
	}
}

func TestAuditInvalidModelOutputClassifiesTruncation(t *testing.T) {
	err := auditInvalidModelOutputError(auditCompletionResponse{FinishReason: "length"})
	class, _, _ := auditModelErrorDetails(err)
	if class != "output_truncated" {
		t.Fatalf("class=%q, want output_truncated", class)
	}
}

func TestStructuredOutputUnsupportedDetection(t *testing.T) {
	err := auditHTTPStatusError(400, []byte(`{"error":{"message":"response_format json_schema is not supported"}}`))
	class, status, _ := auditModelErrorDetails(err)
	if class != "structured_output_unsupported" || status != 400 {
		t.Fatalf("class=%q status=%d", class, status)
	}
	if !auditErrorRetryableOnSameProfile(err) {
		t.Fatal("structured output incompatibility must advance to the next recovery mode")
	}
}
