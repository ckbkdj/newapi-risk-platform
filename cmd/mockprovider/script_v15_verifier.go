package main

import (
	"net/http"
	"strings"
)

// Faults belong to the fixture model, not to a substring of a chunk. Otherwise
// legitimate context recovery could remove a marker and accidentally make a
// supposedly unavailable verifier return allow. No production model is matched.
func mockScriptV15Verifier(w http.ResponseWriter, r chatRequest) bool {
	mode := ""
	switch r.Model {
	case "qwen-v15-verifier-invalid":
		mode = "invalid"
	case "qwen-v15-verifier-unavailable":
		mode = "unavailable"
	case "qwen-v15-verifier-context":
		mode = "context"
	default:
		return false
	}
	if r.ChatTemplateKwargs["enable_thinking"] != false || r.ChatTemplateKwargs["preserve_thinking"] != false || r.MaxTokens < 256 || r.MaxTokens > 1024 {
		writeJSON(w, 400, map[string]any{"error": map[string]any{"message": "Qwen fixture requires fast audit parameters"}})
		return true
	}
	second := false
	for _, message := range r.Messages {
		if message.Role == "system" {
			control, _ := message.Content.(string)
			second = second || strings.Contains(control, "CYBER DENY SECOND PASS")
		}
	}
	if second {
		switch mode {
		case "unavailable":
			writeJSON(w, 503, map[string]any{"error": map[string]any{"message": "synthetic required verifier unavailable"}})
			return true
		case "context":
			writeJSON(w, 400, map[string]any{"error": map[string]any{"message": "This model's maximum context length is 4096 tokens. Your request contains 5000 input tokens."}})
			return true
		case "invalid":
			writeJSON(w, 200, map[string]any{"choices": []any{map[string]any{"finish_reason": "stop", "message": map[string]any{"content": "not-json"}}}})
			return true
		}
	}
	content := `{"decision":"allow","risk_code":"","category":"normal_development","confidence":0.99,"reason":"synthetic ordinary chunk primary","evidence":""}`
	writeJSON(w, 200, map[string]any{"choices": []any{map[string]any{"finish_reason": "stop", "message": map[string]any{"content": content}}}})
	return true
}
