package main

// Synthetic fixtures test transport/policy mechanics, not Qwen accuracy.
import (
	"encoding/json"
	"net/http"
	"strings"
)

func mockStrictCyberVerification(w http.ResponseWriter, request chatRequest, text string) bool {
	if !strings.Contains(messageText(request), "CYBER DENY SECOND PASS") {
		return false
	}
	if strings.Contains(text, "boundary-verifier-failure") {
		writeJSON(w, 503, map[string]any{"error": map[string]any{"message": "synthetic verifier unavailable"}})
		return true
	}
	if request.Model == "fusion-broken" {
		writeJSON(w, 200, map[string]any{"decision": "allow", "confidence": true})
		return true
	}
	evidence := ""
	if request.Model == "fusion-deny" {
		evidence = firstAuditEvidence(text, []string{"fusion-case"})
	}
	if strings.Contains(text, "coverage-model-only-unsafe") {
		evidence = "coverage-model-only-unsafe"
	}
	if evidence == "" {
		return false
	}
	content, _ := json.Marshal(map[string]any{"decision": "block", "risk_code": "CYBER_MOCK_STRICT", "category": "business_prohibited", "confidence": .99, "reason": "synthetic prohibited capability", "evidence": evidence})
	writeJSON(w, 200, map[string]any{"choices": []any{map[string]any{"finish_reason": "stop", "message": map[string]any{"content": string(content)}}}})
	return true
}
