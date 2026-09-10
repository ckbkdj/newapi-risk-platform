package main

import (
	"net/http"
	"strings"
)

// Only the dedicated inert fixture model uses these deterministic results.
func mockFullRequestV14(w http.ResponseWriter, r chatRequest) bool {
	if r.Model != "qwen-v14-plan" {
		return false
	}
	// userMessageText already decodes the risk_audit_request.v2 document.
	text := strings.TrimSuffix(userMessageText(r), "\n")
	if len(text) > 2200 {
		writeJSON(w, 400, map[string]any{"error": map[string]any{"message": "This model's maximum context length is 4096 tokens. Your request contains 16000 input tokens."}})
		return true
	}
	if strings.Contains(text, "V14_TAIL_INVALID") {
		writeJSON(w, 200, map[string]any{"choices": []any{map[string]any{"finish_reason": "stop", "message": map[string]any{"content": "not-json"}}}})
		return true
	}
	if strings.Contains(text, "synthetic prohibited operation") {
		writeStrictCyberFixture(w, "synthetic prohibited operation", "synthetic terminal tail veto")
		return true
	}
	content := `{"decision":"allow","risk_code":"","category":"normal","confidence":0.99,"reason":"synthetic complete-chunk verdict","evidence":""}`
	writeJSON(w, 200, map[string]any{"choices": []any{map[string]any{"finish_reason": "stop", "message": map[string]any{"content": content}}}})
	return true
}
