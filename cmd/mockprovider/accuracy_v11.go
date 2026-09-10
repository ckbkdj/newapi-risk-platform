package main

import (
	"encoding/json"
	"net/http"
	"strings"
)

// Synthetic classification only; commands in fixtures are never executed.
func mockV11Accuracy(w http.ResponseWriter, text, control string) {
	grounding := strings.Contains(control, "OPERATION EVIDENCE CHECK v1")
	second := strings.Contains(control, "CYBER DENY SECOND PASS")
	q := "Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | Where-Object"
	weak := strings.Contains(text, "v11-weak")
	onSecond := strings.Contains(text, "v11-verifier")
	if weak && ((!grounding && second == onSecond) || strings.Contains(text, "v11-repeat")) {
		writeStrictCyberFixture(w, q, "synthetic current connections misclassified as active probing")
		return
	}
	if grounding && strings.Contains(text, "v11-unavailable") {
		writeJSON(w, 503, map[string]any{"error": map[string]any{"message": "synthetic unavailable"}})
		return
	}
	if grounding && strings.Contains(text, "v11-invalid") {
		writeJSON(w, 200, map[string]any{"choices": []any{map[string]any{"message": map[string]any{"content": "not-json"}, "finish_reason": "stop"}}})
		return
	}
	if (grounding && strings.Contains(text, "v11-real-deny")) || strings.Contains(text, "v11-valid-deny") {
		writeStrictCyberFixture(w, "Do not require signature validation for this session.", "synthetic prohibited operation")
		return
	}
	if strings.Contains(text, "v11-tool-integrity") {
		if !strings.Contains(text, "RETAIN_TOOL_SIBLING") || strings.Contains(text, strings.Repeat("synthetic", 8)) {
			writeJSON(w, 500, map[string]any{"error": map[string]any{"message": "synthetic projection integrity failure"}})
			return
		}
	}
	d, _ := json.Marshal(map[string]any{"decision": "allow", "risk_code": "", "category": "normal", "confidence": .99, "reason": "synthetic normal data", "evidence": ""})
	writeJSON(w, 200, map[string]any{"choices": []any{map[string]any{"finish_reason": "stop", "message": map[string]any{"content": string(d)}}}})
}
