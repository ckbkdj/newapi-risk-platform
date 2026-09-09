package main

// Deliberately inaccurate classifier fixtures test the gateway's admission
// checks. This is not a production classifier or a Qwen accuracy evaluation.
import (
	"encoding/json"
	"net/http"
	"strings"
)

func mockAccuracyVerification(w http.ResponseWriter, request chatRequest) bool {
	text := userMessageText(request)
	if !strings.Contains(text, "accuracy-mechanism-fixture") {
		return false
	}
	control := messageText(request)
	grounding := strings.Contains(control, "OPERATION EVIDENCE CHECK v1")
	if grounding && strings.Contains(text, "accuracy-grounding-unavailable") {
		writeJSON(w, 503, map[string]any{"error": map[string]any{"message": "synthetic grounding unavailable"}})
		return true
	}
	evidence := ""
	if !grounding && strings.Contains(control, "CYBER DENY SECOND PASS") {
		for _, line := range strings.Split(text, "\n") {
			if strings.HasPrefix(line, "rg ") {
				evidence = line
				break
			}
		}
		if evidence == "" && strings.Contains(text, "copyfile/magisk/install_magisk.sh") {
			evidence = "copyfile/magisk/install_magisk.sh"
		}
	}
	if evidence != "" {
		writeStrictCyberFixture(w, evidence, "synthetic ungrounded classification from artifact names")
		return true
	}
	content, _ := json.Marshal(map[string]any{"decision": "allow", "risk_code": "", "category": "normal", "confidence": .99, "reason": "synthetic normal operation", "evidence": ""})
	writeJSON(w, 200, map[string]any{"choices": []any{map[string]any{"finish_reason": "stop", "message": map[string]any{"content": string(content)}}}})
	return true
}
