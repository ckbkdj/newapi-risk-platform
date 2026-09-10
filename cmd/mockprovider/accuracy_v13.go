package main

import (
	"encoding/json"
	"net/http"
	"strings"
)

// Fault injection for a disposable stack, never a live accuracy claim.
func mockV13Accuracy(w http.ResponseWriter, text, control string) {
	for _, value := range []string{"synthetic-public-read", "synthetic-private-pass", "'abc'"} {
		if strings.Contains(text, value) {
			writeJSON(w, 500, map[string]any{"error": map[string]any{"message": "synthetic literal reached audit model"}})
			return
		}
	}
	repair := strings.Contains(control, "OPERATION EVIDENCE CHECK v1") || strings.Contains(control, "EVIDENCE SOURCE REPAIR v1")
	second := strings.Contains(control, "CYBER DENY SECOND PASS")
	if strings.Contains(text, "v13-valid-deny") || (repair && strings.Contains(text, "v13-recovered-deny")) {
		writeStrictCyberFixture(w, "perform the prohibited operation", "synthetic terminal denial")
		return
	}
	if repair && strings.Contains(text, "v13-unavailable") {
		writeJSON(w, 503, map[string]any{"error": map[string]any{"message": "synthetic unavailable"}})
		return
	}
	if repair && strings.Contains(text, "v13-invalid-json") {
		writeJSON(w, 200, map[string]any{"choices": []any{map[string]any{"finish_reason": "stop", "message": map[string]any{"content": "invalid-json"}}}})
		return
	}
	decision, code, category, quote := "allow", "", "normal_development", ""
	inject := strings.Contains(text, "v13-primary") || strings.Contains(text, "v13-verifier") || strings.Contains(text, "v13-evidence")
	if inject && ((!repair && second == strings.Contains(text, "v13-verifier")) || strings.Contains(text, "v13-repeat")) {
		decision, code, category = "block", "CYBER_CREDENTIAL_EXFIL", "credential_access"
		if _, after, ok := strings.Cut(text, "V13_INPUT\n"); ok {
			line := []rune(strings.SplitN(after, "\n", 2)[0])
			quote = string(line[:min(70, len(line))])
		}
		if strings.Contains(text, "v13-evidence") {
			quote = "fabricated-source-that-is-not-present"
		}
	}
	d, _ := json.Marshal(map[string]any{"decision": decision, "risk_code": code, "category": category, "confidence": .99, "reason": "synthetic development operation classification", "evidence": quote})
	writeJSON(w, 200, map[string]any{"choices": []any{map[string]any{"finish_reason": "stop", "message": map[string]any{"content": string(d)}}}})
}
