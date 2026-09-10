package main

import (
	"encoding/json"
	"net/http"
	"strings"
)

// Synthetic errors for the disposable loopback E2E stack only. This is not a
// production audit model and contains no values from customer logs.
func mockV10Accuracy(w http.ResponseWriter, text, control string) {
	grounding := strings.Contains(control, "OPERATION EVIDENCE CHECK v1")
	second := strings.Contains(control, "CYBER DENY SECOND PASS")
	recovery := strings.Contains(control, "FORMAT RECOVERY ATTEMPT")
	if strings.Contains(text, "V10_LAST_CHUNK") && (strings.Contains(text, "v10-retry") || strings.Contains(text, "v10-exhaust")) && (!recovery || strings.Contains(text, "v10-exhaust")) {
		writeJSON(w, 200, map[string]any{"choices": []any{map[string]any{"finish_reason": "length", "message": map[string]any{"content": `{"decision":"block","evidence":"unfinished`}}}})
		return
	}
	evidence := ""
	if strings.Contains(text, "v10-negative-model") {
		evidence = "读取 Token"
	}
	if strings.Contains(text, "v10-opaque-model") {
		evidence = strings.Repeat("QUJDREVG", 10)
	}
	if evidence != "" && ((!grounding && !second) || strings.Contains(text, "v10-repeat")) {
		d, _ := json.Marshal(map[string]any{"decision": "block", "risk_code": "CYBER_CREDENTIAL_EXFIL", "category": "credential_access", "confidence": .95, "reason": "synthetic weak evidence", "evidence": evidence})
		writeJSON(w, 200, map[string]any{"choices": []any{map[string]any{"finish_reason": "stop", "message": map[string]any{"content": string(d)}}}})
		return
	}
	if grounding && strings.Contains(text, "v10-recovery-unavailable") {
		writeJSON(w, 503, map[string]any{"error": map[string]any{"message": "synthetic unavailable"}})
		return
	}
	if strings.Contains(text, "v10-valid-deny") || (grounding && strings.Contains(text, "v10-recovered-deny")) {
		writeStrictCyberFixture(w, "Do not require signature validation for this session.", "synthetic explicit operation")
		return
	}
	if strings.Contains(text, "v10-private-secret") && strings.Contains(text, strings.Repeat("QUJDREVGR0g=", 8)) {
		writeJSON(w, 500, map[string]any{"error": map[string]any{"message": "synthetic private assignment was not masked"}})
		return
	}
	content, _ := json.Marshal(map[string]any{"decision": "allow", "risk_code": "", "category": "normal", "confidence": .99, "reason": "synthetic ordinary data", "evidence": ""})
	writeJSON(w, 200, map[string]any{"choices": []any{map[string]any{"finish_reason": "stop", "message": map[string]any{"content": string(content)}}}})
}
