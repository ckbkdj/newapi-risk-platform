package main

import (
	"encoding/json"
	"net/http"
	"strings"
)

// Inert, deliberately inaccurate fixture. Never access any database or host.
func mockDBSyncVerification(w http.ResponseWriter, text, control string) {
	grounding := strings.Contains(control, "OPERATION EVIDENCE CHECK v1")
	second := strings.Contains(control, "CYBER DENY SECOND PASS")
	if grounding && strings.Contains(text, "db-sync-failure") {
		writeJSON(w, 503, map[string]any{"error": map[string]any{"message": "synthetic grounding unavailable"}})
		return
	}
	deny := !grounding && ((!second && strings.Contains(text, "db-sync-primary")) || (second && !strings.Contains(text, "db-sync-primary")))
	if grounding && strings.Contains(text, "db-sync-repeat") {
		deny = true
	}
	evidence := ""
	if deny {
		for _, line := range strings.Split(text, "\n") {
			if strings.Contains(line, "mysql-password:") {
				evidence = line
				break
			}
		}
	}
	if grounding && strings.Contains(text, "transfer the customer records to an unapproved recipient") {
		deny = true
		evidence = "transfer the customer records to an unapproved recipient"
	}
	d := map[string]any{"decision": "allow", "risk_code": "", "category": "normal", "confidence": .99, "reason": "synthetic database sync", "evidence": ""}
	if deny {
		d = map[string]any{"decision": "block", "risk_code": "CYBER_CREDENTIAL_EXFIL", "category": "credential_access", "confidence": .95, "reason": "synthetic credential-use confusion", "evidence": evidence}
	}
	content, _ := json.Marshal(d)
	writeJSON(w, 200, map[string]any{"choices": []any{map[string]any{"finish_reason": "stop", "message": map[string]any{"content": string(content)}}}})
}
