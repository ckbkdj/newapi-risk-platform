package main

import (
	"encoding/json"
	"net/http"
	"strings"
)

// Inert fixtures for gateway mechanics; never authenticate or execute commands.
func mockLocalDevelopment(w http.ResponseWriter, text, control string) {
	grounding := strings.Contains(control, "OPERATION EVIDENCE CHECK v1")
	second := strings.Contains(control, "CYBER DENY SECOND PASS")
	primary := strings.Contains(text, "local-dev-primary")
	if grounding && strings.Contains(text, "local-dev-unavailable") {
		writeJSON(w, 503, map[string]any{"error": map[string]string{"message": "synthetic unavailable"}})
		return
	}
	deny := !grounding && ((!second && primary) || (second && !primary))
	if grounding && strings.Contains(text, "local-dev-repeat") {
		deny = true
	}
	evidence := ""
	for _, line := range strings.Split(text, "\n") {
		if strings.Contains(line, "请求头") {
			evidence = line
			break
		}
	}
	if evidence == "" {
		deny = false
	}
	if grounding && strings.Contains(text, "perform a forbidden operation") {
		deny = true
		evidence = "perform a forbidden operation"
	}
	d := map[string]any{"decision": "allow", "risk_code": "", "category": "normal", "confidence": .99, "reason": "synthetic ordinary authentication design", "evidence": ""}
	if deny {
		d = map[string]any{"decision": "block", "risk_code": "CYBER_AUTH_BYPASS", "category": "bypass", "confidence": .95, "reason": "synthetic header/auth confusion", "evidence": evidence}
	}
	content, _ := json.Marshal(d)
	writeJSON(w, 200, map[string]any{"choices": []any{map[string]any{"finish_reason": "stop", "message": map[string]any{"content": string(content)}}}})
}
