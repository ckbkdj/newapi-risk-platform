package main

import (
	"encoding/json"
	"net/http"
	"strings"
)

// Deliberate false classifications for a disposable stack. Nothing from the
// user's original requests or credentials is embedded or executed here.
func mockV12Accuracy(w http.ResponseWriter, text, control string) {
	grounding := strings.Contains(control, "OPERATION EVIDENCE CHECK v1")
	second := strings.Contains(control, "CYBER DENY SECOND PASS")
	quote := ""
	if _, after, ok := strings.Cut(text, "V12_INPUT\n"); ok {
		quote = strings.SplitN(after, "\n", 2)[0]
	}
	if strings.Contains(text, "v12-valid-deny") || (grounding && strings.Contains(text, "v12-recovered-deny")) {
		writeStrictCyberFixture(w, "perform the prohibited operation", "synthetic valid operation")
		return
	}
	if grounding && strings.Contains(text, "v12-unavailable") {
		writeJSON(w, 503, map[string]any{"error": map[string]any{"message": "synthetic unavailable"}})
		return
	}
	if grounding && strings.Contains(text, "v12-invalid") {
		writeJSON(w, 200, map[string]any{"choices": []any{map[string]any{"finish_reason": "stop", "message": map[string]any{"content": "invalid-json"}}}})
		return
	}
	weak := strings.Contains(text, "v12-primary") || strings.Contains(text, "v12-verifier")
	if weak && ((!grounding && second == strings.Contains(text, "v12-verifier")) || strings.Contains(text, "v12-repeat")) {
		d, _ := json.Marshal(map[string]any{"decision": "block", "risk_code": "CYBER_CREDENTIAL_EXFIL", "category": "credential_access", "confidence": .95, "reason": "synthetic local load misclassified as disclosure", "evidence": quote})
		writeJSON(w, 200, map[string]any{"choices": []any{map[string]any{"finish_reason": "stop", "message": map[string]any{"content": string(d)}}}})
		return
	}
	if strings.Contains(text, "v12-masking") && strings.Contains(text, "synthetic-v12-secret-value-not-for-logs") {
		writeJSON(w, 500, map[string]any{"error": map[string]any{"message": "synthetic secret masking failure"}})
		return
	}
	d, _ := json.Marshal(map[string]any{"decision": "allow", "risk_code": "", "category": "normal", "confidence": .99, "reason": "synthetic normal credential loading", "evidence": ""})
	writeJSON(w, 200, map[string]any{"choices": []any{map[string]any{"finish_reason": "stop", "message": map[string]any{"content": string(d)}}}})
}
