package main

import (
	"encoding/json"
	"net/http"
	"strings"
)

// Deterministic gateway-mechanism fixture, NOT a Qwen accuracy measurement.
func mockEvidenceRepair(w http.ResponseWriter, text, control string) {
	const absent = "Join language_server ports with Clash connection chains by source port"
	const action = "Initiate new connections to enumerate reachable services."
	repair := strings.Contains(control, "EVIDENCE SOURCE REPAIR v1")
	second := strings.Contains(control, "CYBER DENY SECOND PASS")
	if repair && strings.Contains(text, "repair-unavailable") {
		writeJSON(w, 503, map[string]any{"error": "synthetic repair unavailable"})
		return
	}
	if repair && strings.Contains(text, "repair-invalid") {
		writeJSON(w, 200, map[string]any{"choices": []any{map[string]any{"finish_reason": "stop", "message": map[string]any{"content": "not-json"}}}})
		return
	}
	quote := ""
	if !repair && (!second || strings.Contains(text, "repair-verifier")) {
		quote = absent
	}
	if !repair && !second && strings.Contains(text, "repair-verifier") {
		quote = ""
	}
	if repair && (strings.Contains(text, "repair-repeat") || strings.Contains(text, "repair-control-only")) {
		quote = absent
	}
	if strings.Contains(text, action) && (strings.Contains(text, "repair-valid-operation") || repair || second) {
		quote = action
	}
	d := map[string]any{"decision": "allow", "risk_code": "", "category": "normal", "confidence": .99, "reason": "synthetic passive correlation", "evidence": ""}
	if quote != "" {
		d = map[string]any{"decision": "block", "risk_code": "CYBER_NETWORK_PROBING", "category": "network_probing", "confidence": .95, "reason": "synthetic classification", "evidence": quote}
	}
	b, _ := json.Marshal(d)
	writeJSON(w, 200, map[string]any{"id": "repair-fixture-response", "choices": []any{map[string]any{"finish_reason": "stop", "message": map[string]any{"content": string(b)}}}})
}
