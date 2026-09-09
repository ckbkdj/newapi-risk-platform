package main

// Synthetic fixtures test transport/policy mechanics, not Qwen accuracy.
import (
	"encoding/json"
	"net/http"
	"strings"
)

func mockStrictCyberVerification(w http.ResponseWriter, request chatRequest, text string) bool {
	if mockAccuracyVerification(w, request) {
		return true
	}
	// Legacy replay/persistence cases exercise a MODEL Cyber hit, just like
	// policy-test-routine-engineering. These exact fixture texts deliberately
	// simulate a classifier verdict; ordinary event replay/data persistence
	// are not hereby labelled attacks, and no production keyword rule is added.
	for _, fixture := range []string{
		"为并行 MCP 提供方补齐事件重放管线并对称唤醒；不同子会话使用不同 cardId。",
		"调查 rootcanal 地址持久化。",
	} {
		if strings.Contains(text, fixture) {
			writeStrictCyberFixture(w, fixture, "synthetic model Cyber hit; denial-latch regression only")
			return true
		}
	}
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
	writeStrictCyberFixture(w, evidence, "synthetic prohibited capability")
	return true
}

func writeStrictCyberFixture(w http.ResponseWriter, evidence, reason string) {
	content, _ := json.Marshal(map[string]any{"decision": "block", "risk_code": "CYBER_MOCK_STRICT", "category": "business_prohibited", "confidence": .99, "reason": reason, "evidence": evidence})
	writeJSON(w, 200, map[string]any{"choices": []any{map[string]any{"finish_reason": "stop", "message": map[string]any{"content": string(content)}}}})
}
