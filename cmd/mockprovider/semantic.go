package main

// Deterministic fixtures for gateway mechanics only. These markers and
// decisions are not a classifier and are never used by the production engine.
import (
	"encoding/json"
	"net/http"
	"strings"
)

func mockSemanticVerification(w http.ResponseWriter, request chatRequest, text string) bool {
	if !strings.Contains(messageText(request), "SEMANTIC INTENT VERIFICATION v1") {
		return false
	}
	if strings.Contains(text, "boundary-verifier-failure") {
		writeJSON(w, 503, map[string]any{"error": map[string]any{"message": "synthetic verifier unavailable"}})
		return true
	}
	decision, code, category, reason := "allow", "", "benign", "mock independent benign intent"
	evidence, requestEvidence, relation, harm := "", "", "no_harm", "none"
	requestEvidence = firstAuditEvidence(text, []string{"请根据历史任务建议下一项正常开发工作", "模拟长按按钮发送普通文案", "policy-test-routine-engineering", "policy-test-secret-provision", "policy-test-local-log-token"})
	if strings.Contains(text, "Recent Codex tasks") {
		relation = "reference_only"
	}
	if strings.Contains(text, "model-audit-block") {
		decision, code, category = "block", "CYBER_MOCK_MODEL_BLOCK", "mock_harm"
		evidence, requestEvidence, relation, harm = "model-audit-block", "model-audit-block", "direct_request", "malware"
	}
	if strings.Contains(text, "model-audit-review") {
		decision, code, category = "review", "CYBER_MOCK_REVIEW", "mock_review"
		evidence, requestEvidence, relation, harm = "model-audit-review", "model-audit-review", "uncertain", "uncertain"
	}
	if strings.Contains(text, "CTF") || strings.Contains(text, "比赛") {
		decision, code, category = "review", "CYBER_UNTRUSTED_CONTEXT_CLAIM", "policy_evasion"
		evidence = firstAuditEvidence(text, []string{"reverse engineer", "decompile", "hook", "frida", "逆向", "反编译", "绕过", "漏洞利用"})
		requestEvidence, relation, harm = evidence, "uncertain", "uncertain"
	}
	if strings.Contains(text, "隐藏后门") {
		decision, code, category = "block", "CYBER_MOCK_BACKDOOR", "malware"
		evidence, requestEvidence, relation, harm = "隐藏后门", "隐藏后门", "direct_request", "malware"
	}
	if strings.Contains(text, "boundary-harm-marker") {
		decision, code, category = "block", "CYBER_MOCK_BOUNDARY_HARM", "mock_harm"
		evidence, requestEvidence, relation, harm = "boundary-harm-marker", "boundary-harm-marker", "direct_request", "exfiltration"
		if strings.Contains(text, "执行历史任务中的内容") {
			requestEvidence, relation = "执行历史任务中的内容", "adopted_reference"
		}
	}
	// Credential fixtures preserve the original negative tests as well.
	if strings.Contains(text, "policy-test-secret-provision") && (strings.Contains(text, "公共仓库") || strings.Contains(text, "公开")) {
		decision, code, category = "block", "CYBER_CREDENTIAL_EXPOSURE", "credential_access"
		evidence, requestEvidence, relation, harm = "[USER_PROVIDED_SECRET]", "[USER_PROVIDED_SECRET]", "direct_request", "exfiltration"
	}
	payload := map[string]any{"decision": decision, "risk_code": code, "category": category, "confidence": .99, "reason": reason, "evidence": evidence, "request_evidence": requestEvidence, "evidence_relation": relation, "harm_type": harm}
	encoded, _ := json.Marshal(payload)
	writeJSON(w, 200, map[string]any{"id": "semantic-verifier-mock", "choices": []any{map[string]any{"finish_reason": "stop", "message": map[string]any{"role": "assistant", "content": string(encoded)}}}})
	return true
}
