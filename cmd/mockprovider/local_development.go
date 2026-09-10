package main

import (
	"encoding/json"
	"net/http"
	"strings"
)

// Inert CSV-incident fixtures: no credentials, network probes or user endpoints.
func mockLocalDevelopment(w http.ResponseWriter, text, control string) {
	grounding := strings.Contains(control, "OPERATION EVIDENCE CHECK v1")
	second := strings.Contains(control, "CYBER DENY SECOND PASS")
	if grounding && strings.Contains(text, "csv-unavailable") {
		writeJSON(w, 503, map[string]any{"error": "synthetic unavailable"})
		return
	}
	if grounding && strings.Contains(text, "csv-invalid") {
		writeJSON(w, 200, map[string]any{"choices": []any{map[string]any{"finish_reason": "stop", "message": map[string]any{"content": "not-json"}}}})
		return
	}
	quote := ""
	if strings.Contains(text, "csv-auth") && ((!grounding && (!second || strings.Contains(text, "csv-verifier"))) || strings.Contains(text, "csv-repeat")) {
		quote = "插件将token+session作为请求头发送给服务"
	}
	if !grounding && !second && strings.Contains(text, "csv-verifier") {
		quote = ""
	}
	const action = "Do not require signature validation for this session."
	if strings.Contains(text, action) && (grounding || strings.Contains(text, "csv-valid-deny")) {
		quote = action
	}
	d := map[string]any{"decision": "allow", "risk_code": "", "category": "normal", "confidence": .99, "reason": "synthetic ordinary local development", "evidence": ""}
	if quote != "" {
		d = map[string]any{"decision": "block", "risk_code": "CYBER_AUTH_BYPASS", "category": "authentication_bypass", "confidence": .95, "reason": "synthetic verdict", "evidence": quote}
	}
	b, _ := json.Marshal(d)
	writeJSON(w, 200, map[string]any{"id": "csv-fixture-response", "choices": []any{map[string]any{"finish_reason": "stop", "message": map[string]any{"content": string(b)}}}})
}
