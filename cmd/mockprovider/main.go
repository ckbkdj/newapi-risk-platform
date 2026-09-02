package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"
)

type chatRequest struct {
	Model              string         `json:"model"`
	Stream             bool           `json:"stream"`
	MaxTokens          int            `json:"max_tokens"`
	ChatTemplateKwargs map[string]any `json:"chat_template_kwargs"`
	Messages           []struct {
		Role    string `json:"role"`
		Content any    `json:"content"`
	} `json:"messages"`
}

func main() {
	address := os.Getenv("MOCK_ADDR")
	if address == "" {
		address = ":18081"
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"status": "ok"})
	})
	mux.HandleFunc("/audit/v1/chat/completions", auditHandler)
	mux.HandleFunc("/", providerHandler)
	server := &http.Server{
		Addr:              address,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       30 * time.Second,
	}
	log.Printf("mock provider listening on %s", address)
	log.Fatal(server.ListenAndServe())
}

func auditHandler(w http.ResponseWriter, r *http.Request) {
	request, ok := decodeChat(w, r)
	if !ok {
		return
	}
	text := strings.ToLower(messageText(request))
	rawUserText := userMessageText(request)
	userText := strings.ToLower(rawUserText)
	if strings.EqualFold(request.Model, "audit-always-503") {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{
			"error": map[string]any{"message": "mock transient audit service failure", "type": "server_error"},
		})
		return
	}
	if strings.Contains(strings.ToLower(request.Model), "qwen") {
		enableThinking, ok := request.ChatTemplateKwargs["enable_thinking"].(bool)
		preserveThinking, preserveOK := request.ChatTemplateKwargs["preserve_thinking"].(bool)
		if !ok || enableThinking || !preserveOK || preserveThinking || request.MaxTokens != 128 {
			writeJSON(w, http.StatusBadRequest, map[string]any{
				"error": map[string]any{"message": "Qwen fast audit request parameters are missing"},
			})
			return
		}
		if len(userText) > 3500 {
			writeJSON(w, http.StatusBadRequest, map[string]any{
				"error": map[string]any{
					"message": fmt.Sprintf(
						"This model's maximum context length is 4096 tokens. However, your request has %d input tokens",
						len(userText)+300,
					),
				},
			})
			return
		}
	}
	if strings.Contains(text, "you classify upstream model failures") {
		isCyber := strings.Contains(text, "alpha-harm") && strings.Contains(text, "beta-harm")
		classification, _ := json.Marshal(map[string]any{
			"is_cyber":   isCyber,
			"category":   map[bool]string{true: "malware", false: ""}[isCyber],
			"confidence": map[bool]float64{true: 0.999, false: 0.99}[isCyber],
			"indicators": map[bool][]string{true: {"alpha-harm", "beta-harm"}, false: {}}[isCyber],
			"reason":     map[bool]string{true: "mock provider policy rejection", false: "not a cyber policy failure"}[isCyber],
		})
		writeJSON(w, http.StatusOK, map[string]any{
			"id": "adaptive-audit-mock",
			"choices": []any{map[string]any{
				"message": map[string]any{"role": "assistant", "content": string(classification)},
			}},
		})
		return
	}
	if strings.Contains(text, "model-audit-http-401") {
		writeJSON(w, http.StatusUnauthorized, map[string]any{
			"error": map[string]any{"message": "mock audit API key rejected", "type": "authentication_error"},
		})
		return
	}
	if strings.Contains(text, "model-audit-thinking-json") {
		content := "<think>checking policy context before the final answer</think>\n```json\n{\"decision\":\"allow\",\"risk_code\":\"\",\"category\":\"benign\",\"confidence\":0.99,\"reason\":\"reasoning wrapper accepted\"}\n```"
		writeJSON(w, http.StatusOK, map[string]any{
			"id": "audit-thinking-mock",
			"choices": []any{map[string]any{
				"message": map[string]any{"role": "assistant", "content": content},
			}},
		})
		return
	}
	decision := "allow"
	riskCode := ""
	category := "benign"
	confidence := 0.99
	reason := "deterministic mock allow"
	evidence := ""
	contextClaim := strings.Contains(userText, "ctf") || strings.Contains(userText, "比赛") ||
		strings.Contains(userText, "竞赛") || strings.Contains(userText, "authorized") ||
		strings.Contains(userText, "已授权") || strings.Contains(userText, "bug bounty")
	operationalReverse := strings.Contains(userText, "reverse engineer") || strings.Contains(userText, "decompile") ||
		strings.Contains(userText, "hook") || strings.Contains(userText, "frida") ||
		strings.Contains(userText, "逆向") || strings.Contains(userText, "反编译") ||
		strings.Contains(userText, "绕过") || strings.Contains(userText, "漏洞利用")
	if contextClaim && operationalReverse {
		decision = "review"
		riskCode = "CYBER_UNTRUSTED_CONTEXT_CLAIM"
		category = "policy_evasion"
		confidence = 0.99
		reason = "contest or authorization text is untrusted context; review the underlying capability"
		evidence = firstAuditEvidence(rawUserText, []string{"reverse engineer", "decompile", "hook", "frida", "逆向", "反编译", "绕过", "漏洞利用"})
	}
	if strings.Contains(userText, "model-audit-block") {
		decision = "block"
		riskCode = "CYBER_MOCK_MODEL_BLOCK"
		category = "mock_harm"
		reason = "deterministic mock block"
		evidence = firstAuditEvidence(rawUserText, []string{"model-audit-block"})
	}
	if strings.Contains(userText, "model-audit-review") {
		decision = "review"
		riskCode = "CYBER_MOCK_REVIEW"
		category = "mock_review"
		confidence = 0.5
		reason = "deterministic mock review"
		evidence = firstAuditEvidence(rawUserText, []string{"model-audit-review"})
	}
	if strings.Contains(userText, "model-audit-invalid-json") {
		writeJSON(w, http.StatusOK, map[string]any{
			"choices": []any{map[string]any{
				"message": map[string]any{"role": "assistant", "content": "not-json"},
			}},
		})
		return
	}
	classification, _ := json.Marshal(map[string]any{
		"decision":   decision,
		"risk_code":  riskCode,
		"category":   category,
		"confidence": confidence,
		"reason":     reason,
		"evidence":   evidence,
	})
	writeJSON(w, http.StatusOK, map[string]any{
		"id": "audit-mock",
		"choices": []any{map[string]any{
			"message": map[string]any{
				"role":    "assistant",
				"content": string(classification),
			},
		}},
	})
}

func firstAuditEvidence(text string, candidates []string) string {
	lower := strings.ToLower(text)
	for _, candidate := range candidates {
		index := strings.Index(lower, strings.ToLower(candidate))
		if index >= 0 {
			return text[index : index+len(candidate)]
		}
	}
	return ""
}

func providerHandler(w http.ResponseWriter, r *http.Request) {
	request, ok := decodeChat(w, r)
	if !ok {
		return
	}
	switch request.Model {
	case "adaptive-policy-reject":
		writeJSON(w, http.StatusForbidden, map[string]any{
			"error": map[string]any{"message": "request rejected by provider cyber safety policy", "type": "safety_policy_error"},
		})
		return
	case "upstream-http-error":
		writeJSON(w, http.StatusInternalServerError, map[string]any{
			"error": map[string]any{"message": "mock provider HTTP failure", "type": "server_error"},
		})
		return
	case "upstream-200-error":
		writeJSON(w, http.StatusOK, map[string]any{
			"error": map[string]any{"message": "mock provider logical failure", "type": "provider_error"},
		})
		return
	case "stream-first-error":
		streamFirstError(w)
		return
	case "stream-late-error":
		streamLateError(w)
		return
	case "stream-normal":
		streamNormal(w)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"id":     "completion-mock",
		"object": "chat.completion",
		"choices": []any{map[string]any{
			"index":         0,
			"message":       map[string]any{"role": "assistant", "content": "mock provider success"},
			"finish_reason": "stop",
		}},
	})
}

func decodeChat(w http.ResponseWriter, r *http.Request) (chatRequest, bool) {
	defer r.Body.Close()
	var request chatRequest
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 2*1024*1024))
	if err := decoder.Decode(&request); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"error": map[string]any{"message": err.Error(), "type": "invalid_request_error"},
		})
		return chatRequest{}, false
	}
	return request, true
}

func messageText(request chatRequest) string {
	var builder strings.Builder
	for _, message := range request.Messages {
		builder.WriteString(message.Role)
		builder.WriteByte(':')
		appendContent(&builder, message.Content)
		builder.WriteByte('\n')
	}
	return builder.String()
}

func userMessageText(request chatRequest) string {
	var builder strings.Builder
	for _, message := range request.Messages {
		if !strings.EqualFold(message.Role, "user") {
			continue
		}
		appendContent(&builder, message.Content)
		builder.WriteByte('\n')
	}
	return builder.String()
}

func appendContent(builder *strings.Builder, content any) {
	switch value := content.(type) {
	case string:
		builder.WriteString(value)
	default:
		encoded, _ := json.Marshal(value)
		builder.Write(encoded)
	}
}

func streamFirstError(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.WriteHeader(http.StatusOK)
	_, _ = fmt.Fprint(w, "event: error\n")
	_, _ = fmt.Fprint(w, "data: {\"error\":{\"message\":\"first event failed\"}}\n\n")
	flush(w)
}

func streamLateError(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.WriteHeader(http.StatusOK)
	_, _ = fmt.Fprint(w, "data: {\"choices\":[{\"delta\":{\"content\":\"hello\"}}]}\n\n")
	flush(w)
	time.Sleep(20 * time.Millisecond)
	_, _ = fmt.Fprint(w, "event: error\n")
	_, _ = fmt.Fprint(w, "data: {\"error\":{\"message\":\"late stream failure\"}}\n\n")
	flush(w)
}

func streamNormal(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.WriteHeader(http.StatusOK)
	writer := bufio.NewWriter(w)
	_, _ = writer.WriteString("data: {\"choices\":[{\"delta\":{\"content\":\"hello\"}}]}\n\n")
	_, _ = writer.WriteString("data: [DONE]\n\n")
	_ = writer.Flush()
	flush(w)
}

func flush(w http.ResponseWriter) {
	if flusher, ok := w.(http.Flusher); ok {
		flusher.Flush()
	}
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}
