package platform

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
)

const (
	auditOutputModeAuto               = "auto"
	auditOutputModeJSONSchema         = "json_schema"
	auditOutputModeVLLMStructuredJSON = "vllm_structured_json"
	auditOutputModeJSONObject         = "json_object"
	auditOutputModeGuidedJSON         = "guided_json"
	auditOutputModePromptOnly         = "prompt_only"

	auditResponsePreviewLimit = 320
)

type auditOutputPlan struct {
	Mode      string
	MaxTokens int
	Attempt   int
}

type auditOutputDiagnostics struct {
	Mode                 string
	MaxTokens            int
	FinishReason         string
	ResponseContentBytes int
	ResponseSource       string
	ResponsePreview      string
	ResponseID           string
	Failed               bool
}

type auditOutputAttemptState struct {
	mu          sync.Mutex
	latest      auditOutputDiagnostics
	lastFailure auditOutputDiagnostics
	hasFailure  bool
}

type auditOutputAttemptContext struct {
	Plan  auditOutputPlan
	State *auditOutputAttemptState
}

type auditOutputAttemptContextKey struct{}

type auditCompletionResponse struct {
	Content      string
	FinishReason string
	ResponseID   string
	Source       string
	ContentBytes int
	Preview      string
}

func (e *AuditEngine) auditOutputPlan(profile AuditProfile, attempt int) auditOutputPlan {
	if attempt < 0 {
		attempt = 0
	}
	maxTokens := e.outputMaxTokens
	if maxTokens < 256 {
		maxTokens = 256
	}
	switch {
	case attempt == 1 && maxTokens < 384:
		maxTokens = 384
	case attempt >= 2 && maxTokens < 512:
		maxTokens = 512
	}
	if maxTokens > 1024 {
		maxTokens = 1024
	}

	configured := auditOutputModeAuto
	if value, ok := auditProfileExtra(profile)["_risk_structured_output_mode"].(string); ok {
		if normalized := normalizeAuditOutputMode(value); normalized != "" {
			configured = normalized
		}
	}
	mode := configured
	if mode == auditOutputModeAuto {
		mode = automaticAuditOutputMode(profile, attempt)
	}
	return auditOutputPlan{Mode: mode, MaxTokens: maxTokens, Attempt: attempt}
}

func normalizeAuditOutputMode(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", "auto":
		return auditOutputModeAuto
	case "json_schema", "response_format_json_schema":
		return auditOutputModeJSONSchema
	case "vllm_structured_json", "structured_outputs", "structured_outputs_json":
		return auditOutputModeVLLMStructuredJSON
	case "json_object", "response_format_json_object":
		return auditOutputModeJSONObject
	case "guided_json", "legacy_guided_json":
		return auditOutputModeGuidedJSON
	case "prompt_only", "none", "disabled":
		return auditOutputModePromptOnly
	default:
		return ""
	}
}

func automaticAuditOutputMode(profile AuditProfile, attempt int) string {
	if isQwenModel(profile.Model) {
		sequence := []string{
			auditOutputModeJSONSchema,
			auditOutputModeVLLMStructuredJSON,
			auditOutputModeJSONObject,
			auditOutputModeGuidedJSON,
			auditOutputModePromptOnly,
		}
		if attempt >= len(sequence) {
			return sequence[len(sequence)-1]
		}
		return sequence[attempt]
	}
	sequence := []string{
		auditOutputModeJSONSchema,
		auditOutputModeJSONObject,
		auditOutputModePromptOnly,
	}
	if attempt >= len(sequence) {
		return sequence[len(sequence)-1]
	}
	return sequence[attempt]
}

func auditDecisionJSONSchema() map[string]any {
	return map[string]any{
		"type":                 "object",
		"additionalProperties": false,
		"required":             []string{"decision", "risk_code", "category", "confidence", "reason", "evidence"},
		"properties": map[string]any{
			"decision": map[string]any{
				"type": "string",
				"enum": []string{DecisionAllow, DecisionReview, DecisionBlock},
			},
			"risk_code": map[string]any{"type": "string"},
			"category":  map[string]any{"type": "string"},
			"confidence": map[string]any{
				"type":    "number",
				"minimum": 0,
				"maximum": 1,
			},
			"reason":   map[string]any{"type": "string"},
			"evidence": map[string]any{"type": "string"},
		},
	}
}

func applyAuditOutputContract(payload map[string]any, plan auditOutputPlan) {
	if payload == nil {
		return
	}
	for _, key := range []string{"response_format", "structured_outputs", "guided_json", "guided_regex", "guided_choice"} {
		delete(payload, key)
	}
	payload["stream"] = false
	payload["temperature"] = 0
	payload["max_tokens"] = plan.MaxTokens

	schema := auditDecisionJSONSchema()
	switch plan.Mode {
	case auditOutputModeJSONSchema:
		payload["response_format"] = map[string]any{
			"type": "json_schema",
			"json_schema": map[string]any{
				"name":   "risk_audit_decision",
				"strict": true,
				"schema": schema,
			},
		}
	case auditOutputModeVLLMStructuredJSON:
		payload["structured_outputs"] = map[string]any{"json": schema}
	case auditOutputModeJSONObject:
		payload["response_format"] = map[string]any{"type": "json_object"}
	case auditOutputModeGuidedJSON:
		payload["guided_json"] = schema
	case auditOutputModePromptOnly:
		// The mandatory prompt contract remains active. This is the final
		// compatibility mode for OpenAI-compatible servers that reject every
		// structured-output extension.
	}
}

func auditOutputPlanDirective(plan auditOutputPlan) string {
	base := fmt.Sprintf(
		"Platform-enforced output contract: mode=%s, max_tokens=%d. Return all six required fields: decision, risk_code, category, confidence, reason, evidence.",
		plan.Mode,
		plan.MaxTokens,
	)
	if plan.Attempt == 0 {
		return base
	}
	return fmt.Sprintf(
		"FORMAT RECOVERY ATTEMPT %d: the previous model response was not machine-readable. %s Do not repeat prose, Markdown, analysis, or an incomplete object.",
		plan.Attempt+1,
		base,
	)
}

func withAuditOutputAttempt(ctx context.Context, plan auditOutputPlan) (context.Context, *auditOutputAttemptState) {
	state := &auditOutputAttemptState{
		latest: auditOutputDiagnostics{Mode: plan.Mode, MaxTokens: plan.MaxTokens},
	}
	value := auditOutputAttemptContext{Plan: plan, State: state}
	return context.WithValue(ctx, auditOutputAttemptContextKey{}, value), state
}

func auditOutputPlanFromContext(ctx context.Context) auditOutputPlan {
	if value, ok := ctx.Value(auditOutputAttemptContextKey{}).(auditOutputAttemptContext); ok {
		return value.Plan
	}
	return auditOutputPlan{Mode: auditOutputModePromptOnly, MaxTokens: 256}
}

func recordAuditOutputDiagnostics(ctx context.Context, diagnostics auditOutputDiagnostics) {
	value, ok := ctx.Value(auditOutputAttemptContextKey{}).(auditOutputAttemptContext)
	if !ok || value.State == nil {
		return
	}
	diagnostics.ResponsePreview = sanitizeAuditResponsePreview(diagnostics.ResponsePreview)
	diagnostics.ResponseID = truncateString(strings.TrimSpace(diagnostics.ResponseID), 200)
	diagnostics.ResponseSource = truncateString(strings.TrimSpace(diagnostics.ResponseSource), 120)
	value.State.mu.Lock()
	value.State.latest = diagnostics
	if diagnostics.Failed {
		value.State.lastFailure = diagnostics
		value.State.hasFailure = true
	}
	value.State.mu.Unlock()
}

func (state *auditOutputAttemptState) snapshot(preferFailure bool) auditOutputDiagnostics {
	if state == nil {
		return auditOutputDiagnostics{}
	}
	state.mu.Lock()
	defer state.mu.Unlock()
	if preferFailure && state.hasFailure {
		return state.lastFailure
	}
	return state.latest
}

func sanitizeAuditResponsePreview(value string) string {
	value = sanitizeAuditDiagnostic(value)
	return truncateString(value, auditResponsePreviewLimit)
}

func auditOutputDiagnosticsForResponse(plan auditOutputPlan, response auditCompletionResponse, failed bool) auditOutputDiagnostics {
	return auditOutputDiagnostics{
		Mode:                 plan.Mode,
		MaxTokens:            plan.MaxTokens,
		FinishReason:         truncateString(strings.TrimSpace(response.FinishReason), 100),
		ResponseContentBytes: response.ContentBytes,
		ResponseSource:       response.Source,
		ResponsePreview:      response.Preview,
		ResponseID:           response.ResponseID,
		Failed:               failed,
	}
}

func annotateAuditOutputError(err error, diagnostics auditOutputDiagnostics) error {
	if err == nil {
		return nil
	}
	var callError *AuditModelCallError
	if !errors.As(err, &callError) {
		return err
	}
	diagnostics.ResponsePreview = sanitizeAuditResponsePreview(diagnostics.ResponsePreview)
	diagnostics.ResponseID = truncateString(strings.TrimSpace(diagnostics.ResponseID), 200)
	diagnostics.ResponseSource = truncateString(strings.TrimSpace(diagnostics.ResponseSource), 120)
	copyError := *callError
	copyError.OutputMode = diagnostics.Mode
	copyError.OutputMaxTokens = diagnostics.MaxTokens
	copyError.FinishReason = diagnostics.FinishReason
	copyError.ResponseContentBytes = diagnostics.ResponseContentBytes
	copyError.ResponseSource = diagnostics.ResponseSource
	copyError.ResponsePreview = diagnostics.ResponsePreview
	copyError.ResponseID = diagnostics.ResponseID
	if diagnostics.Mode != "" && !strings.Contains(copyError.Message, "output mode=") {
		detail := fmt.Sprintf("output mode=%s, max_tokens=%d", diagnostics.Mode, diagnostics.MaxTokens)
		if diagnostics.FinishReason != "" {
			detail += ", finish_reason=" + diagnostics.FinishReason
		}
		if diagnostics.ResponseContentBytes > 0 {
			detail += fmt.Sprintf(", content_bytes=%d", diagnostics.ResponseContentBytes)
		}
		copyError.Message = strings.TrimSpace(copyError.Message) + " (" + detail + ")"
	}
	return &copyError
}

func auditInvalidModelOutputError(response auditCompletionResponse) error {
	if isAuditFinishReasonTruncated(response.FinishReason) {
		return newAuditModelCallError(
			"output_truncated",
			0,
			"audit model output was truncated before a complete policy JSON object",
			nil,
		)
	}
	return newAuditModelCallError(
		"invalid_json",
		0,
		"audit model output did not contain a valid policy JSON object",
		nil,
	)
}

func isAuditFinishReasonTruncated(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "length", "max_tokens", "max_output_tokens", "token_limit":
		return true
	default:
		return false
	}
}

func looksLikeStructuredOutputUnsupported(value string) bool {
	lower := strings.ToLower(value)
	structuredMarker := strings.Contains(lower, "response_format") ||
		strings.Contains(lower, "json_schema") ||
		strings.Contains(lower, "structured_outputs") ||
		strings.Contains(lower, "guided_json") ||
		strings.Contains(lower, "guided decoding")
	if !structuredMarker {
		return false
	}
	for _, marker := range []string{
		"unsupported", "not supported", "unknown", "unrecognized", "extra_forbidden",
		"not permitted", "invalid", "unexpected", "not allowed",
	} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}

func extractAuditCompletionResponse(body []byte) (auditCompletionResponse, error) {
	var decoded any
	if err := json.Unmarshal(body, &decoded); err != nil {
		return auditCompletionResponse{}, fmt.Errorf("decode audit model response: %w", err)
	}

	if object, ok := decoded.(map[string]any); ok {
		if _, hasDecision := object["decision"]; hasDecision {
			content := strings.TrimSpace(strings.ToValidUTF8(string(body), ""))
			return auditCompletionResponse{
				Content:      content,
				Source:       "direct_body",
				ContentBytes: len(content),
				Preview:      sanitizeAuditResponsePreview(content),
			}, nil
		}
	}

	root, ok := decoded.(map[string]any)
	if !ok {
		if text, ok := decoded.(string); ok && strings.TrimSpace(text) != "" {
			text = strings.TrimSpace(text)
			return auditCompletionResponse{
				Content:      text,
				Source:       "response_body_string",
				ContentBytes: len(text),
				Preview:      sanitizeAuditResponsePreview(text),
			}, nil
		}
		return auditCompletionResponse{}, errors.New("audit model response is not an object")
	}

	responseID, _ := root["id"].(string)
	candidates := make([]string, 0, 6)
	sources := make([]string, 0, 6)
	appendCandidate := func(source string, value any) {
		text := strings.TrimSpace(flattenAuditResponseText(value))
		if text == "" {
			return
		}
		candidates = append(candidates, text)
		sources = append(sources, source)
	}

	finishReason := ""
	if choices, ok := root["choices"].([]any); ok && len(choices) > 0 {
		for choiceIndex, rawChoice := range choices {
			choice, ok := rawChoice.(map[string]any)
			if !ok {
				continue
			}
			if finishReason == "" {
				finishReason = auditStringValue(choice["finish_reason"])
			}
			if message, ok := choice["message"].(map[string]any); ok {
				appendCandidate(fmt.Sprintf("choices[%d].message.reasoning_content", choiceIndex), message["reasoning_content"])
				appendCandidate(fmt.Sprintf("choices[%d].message.reasoning", choiceIndex), message["reasoning"])
				appendCandidate(fmt.Sprintf("choices[%d].message.content", choiceIndex), message["content"])
				if toolCalls, ok := message["tool_calls"].([]any); ok {
					for toolIndex, rawToolCall := range toolCalls {
						toolCall, ok := rawToolCall.(map[string]any)
						if !ok {
							continue
						}
						if function, ok := toolCall["function"].(map[string]any); ok {
							appendCandidate(
								fmt.Sprintf("choices[%d].message.tool_calls[%d].function.arguments", choiceIndex, toolIndex),
								function["arguments"],
							)
						}
					}
				}
			}
			appendCandidate(fmt.Sprintf("choices[%d].text", choiceIndex), choice["text"])
		}
	}
	appendCandidate("output_text", root["output_text"])
	appendCandidate("output", root["output"])
	appendCandidate("content", root["content"])

	if len(candidates) == 0 {
		// Preserve nested/direct policy wrappers for the tolerant parser. This is
		// still sanitized before any diagnostic is persisted.
		content := strings.TrimSpace(strings.ToValidUTF8(string(body), ""))
		if content == "" {
			return auditCompletionResponse{}, errors.New("audit model response content is empty")
		}
		return auditCompletionResponse{
			Content:      content,
			FinishReason: finishReason,
			ResponseID:   responseID,
			Source:       "response_body_fallback",
			ContentBytes: len(content),
			Preview:      sanitizeAuditResponsePreview(content),
		}, nil
	}
	content := strings.Join(candidates, "\n")
	return auditCompletionResponse{
		Content:      content,
		FinishReason: finishReason,
		ResponseID:   responseID,
		Source:       strings.Join(uniqueStrings(sources), ","),
		ContentBytes: len(content),
		Preview:      sanitizeAuditResponsePreview(content),
	}, nil
}

func flattenAuditResponseText(value any) string {
	switch typed := value.(type) {
	case nil:
		return ""
	case string:
		return typed
	case []any:
		parts := make([]string, 0, len(typed))
		for _, child := range typed {
			if text := strings.TrimSpace(flattenAuditResponseText(child)); text != "" {
				parts = append(parts, text)
			}
		}
		return strings.Join(parts, "\n")
	case map[string]any:
		if _, hasDecision := typed["decision"]; hasDecision {
			encoded, _ := json.Marshal(typed)
			return string(encoded)
		}
		parts := make([]string, 0, 4)
		for _, key := range []string{"text", "output_text", "content", "arguments"} {
			if child, exists := typed[key]; exists {
				if text := strings.TrimSpace(flattenAuditResponseText(child)); text != "" {
					parts = append(parts, text)
				}
			}
		}
		return strings.Join(parts, "\n")
	default:
		return ""
	}
}

func uniqueStrings(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	return result
}

func auditStringValue(value any) string {
	if value == nil {
		return ""
	}
	if text, ok := value.(string); ok {
		return strings.TrimSpace(text)
	}
	return strings.TrimSpace(fmt.Sprint(value))
}
