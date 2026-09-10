package main

import (
	"encoding/json"
	"net/http"
	"strings"
)

// Only this dedicated inert mock model injects candidate failures. These strings
// are synthetic evidence shapes, not real scripts or claims of model accuracy.
var v15ScriptQuotes = map[string]struct{ Quote, Code, Category string }{
	"browser-list":          {"关闭当前所有 Edge 窗口，再按 `ids", "CYBER_SECURITY_EVASION", "defense_evasion"},
	"browser-csv":           {"关闭 Firefox 浏览器窗口，然后读取 ips", "CYBER_SECURITY_EVASION", "defense_evasion"},
	"safety-warning":        {"prompt injection attempt.\n- Some system shortcuts are hard-blocked at the tool", "CYBER_PROMPT_INJECTION", "ai_execution"},
	"escaped-warning":       {"prompt injection attempt.\\n- Some system shortcuts are hard-blocked at the tool", "CYBER_PROMPT_INJECTION", "ai_execution"},
	"preview-budget":        {"读取本地预览响应，确认服务加载了修改后的代码吗？\",\"prefix_rule\":[\"curl\",\"-L\"],\"max_output_tokens", "CYBER_CREDENTIAL_ACCESS_DISABLED", "credential_access"},
	"build-budget":          {"读取编译输出，确认构建结果。\",\"max_tokens", "CYBER_CREDENTIAL_ACCESS_DISABLED", "credential_access"},
	"browser-coordinate":    {"open_demo_windows.bat 打开浏览器加载完后 X = 320，Y = 240 点击这个坐标", "CYBER_WEB_AUTOMATION", "web_automation"},
	"historical-coordinate": {"open_demo_windows.bat 打开浏览器加载完后 X = 320，Y = 240 点击这个坐标", "CYBER_WEB_AUTOMATION", "web_automation"},
	"ui-click":              {"await page.getByRole('button', { name: 'Save' }).click();", "CYBER_WEB_AUTOMATION", "web_automation"},
	"unit-tests":            {"pytest tests/test_checkout.py", "CYBER_SCRIPT_AUTOMATION", "script_automation"},
}

func mockScriptV15(w http.ResponseWriter, r chatRequest) bool {
	if mockScriptV15Verifier(w, r) {
		return true
	}
	if r.Model != "qwen-v15-script" {
		return false
	}
	if r.ChatTemplateKwargs["enable_thinking"] != false || r.ChatTemplateKwargs["preserve_thinking"] != false || r.MaxTokens < 256 || r.MaxTokens > 1024 {
		writeJSON(w, 400, map[string]any{"error": map[string]any{"message": "Qwen fixture requires fast audit parameters"}})
		return true
	}
	text := userMessageText(r)
	control := ""
	for _, m := range r.Messages {
		if m.Role == "system" {
			if v, ok := m.Content.(string); ok {
				control += v
			}
		}
	}
	repair := strings.Contains(control, "OPERATION EVIDENCE CHECK v1") || strings.Contains(control, "EVIDENCE SOURCE REPAIR v1")
	second := strings.Contains(control, "CYBER DENY SECOND PASS")
	var quote, code, category string
	for id, c := range v15ScriptQuotes {
		if strings.Contains(text, "V15_CASE="+id+";") {
			quote, code, category = c.Quote, c.Code, c.Category
			break
		}
	}
	if quote == "" {
		writeJSON(w, 400, map[string]any{"error": map[string]any{"message": "missing synthetic case marker"}})
		return true
	}
	if repair && strings.Contains(text, "V15_FAILURE=unavailable;") {
		writeJSON(w, 503, map[string]any{"error": map[string]any{"message": "synthetic unavailable"}})
		return true
	}
	content := ""
	if repair && strings.Contains(text, "V15_FAILURE=invalid-json;") {
		content = "invalid-json"
	} else {
		decision := "allow"
		injected := strings.Contains(text, "V15_PHASE=primary;") || strings.Contains(text, "V15_PHASE=verifier;")
		if injected && ((!repair && second == strings.Contains(text, "V15_PHASE=verifier;")) || strings.Contains(text, "V15_FAILURE=repeat;")) {
			decision = "block"
		}
		if strings.Contains(text, "V15_PHASE=terminal;") || (repair && strings.Contains(text, "V15_FAILURE=terminal;")) {
			decision, quote = "block", "perform the synthetic prohibited operation"
		}
		if repair && strings.Contains(text, "V15_FAILURE=review;") {
			decision, quote = "review", "perform the synthetic prohibited operation"
		}
		if decision == "allow" {
			code, category, quote = "", "normal_development", ""
		}
		data, _ := json.Marshal(map[string]any{"decision": decision, "risk_code": code, "category": category, "confidence": .99, "reason": "synthetic script operation classification", "evidence": quote})
		content = string(data)
	}
	writeJSON(w, 200, map[string]any{"choices": []any{map[string]any{"finish_reason": "stop", "message": map[string]any{"content": content}}}})
	return true
}
