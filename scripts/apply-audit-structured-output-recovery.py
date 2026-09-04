from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def write(path: str, content: str) -> None:
    target = ROOT / path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content, encoding="utf-8")


def replace_once(path: str, old: str, new: str, label: str) -> None:
    content = read(path)
    if new in content:
        return
    count = content.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected one match in {path}, found {count}")
    write(path, content.replace(old, new, 1))


def replace_range(path: str, start_marker: str, end_marker: str, replacement: str, label: str) -> None:
    content = read(path)
    start = content.find(start_marker)
    if start < 0:
        raise SystemExit(f"{label}: start marker not found in {path}")
    end = content.find(end_marker, start)
    if end < 0:
        raise SystemExit(f"{label}: end marker not found in {path}")
    write(path, content[:start] + replacement + content[end:])


# ---------------------------------------------------------------------------
# Structured-output contract, retry-mode diversity, response extraction and
# safe diagnostics. No raw model response or secret is persisted.
# ---------------------------------------------------------------------------
write(
    "internal/platform/audit_output_contract.go",
    r'''package platform

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
				finishReason = stringValue(choice["finish_reason"])
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

func stringValue(value any) string {
	if value == nil {
		return ""
	}
	if text, ok := value.(string); ok {
		return strings.TrimSpace(text)
	}
	return strings.TrimSpace(fmt.Sprint(value))
}
''',
)

write(
    "internal/platform/audit_output_contract_test.go",
    r'''package platform

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestQwenAuditOutputPlanChangesAcrossRetries(t *testing.T) {
	engine := &AuditEngine{outputMaxTokens: 256}
	profile := AuditProfile{Model: "Qwen3.8-27B"}
	want := []string{
		auditOutputModeJSONSchema,
		auditOutputModeVLLMStructuredJSON,
		auditOutputModeJSONObject,
		auditOutputModeGuidedJSON,
		auditOutputModePromptOnly,
	}
	for attempt, expected := range want {
		plan := engine.auditOutputPlan(profile, attempt)
		if plan.Mode != expected {
			t.Fatalf("attempt %d mode=%q, want %q", attempt+1, plan.Mode, expected)
		}
		if plan.MaxTokens < 256 || plan.MaxTokens > 1024 {
			t.Fatalf("attempt %d max_tokens=%d", attempt+1, plan.MaxTokens)
		}
	}
}

func TestApplyAuditOutputContractOverridesConflictingExtra(t *testing.T) {
	payload := map[string]any{
		"response_format":   map[string]any{"type": "text"},
		"structured_outputs": map[string]any{"choice": []string{"bad"}},
		"guided_json":       map[string]any{"type": "string"},
		"stream":            true,
		"max_tokens":        32,
	}
	applyAuditOutputContract(payload, auditOutputPlan{Mode: auditOutputModeJSONSchema, MaxTokens: 256})
	if payload["stream"] != false || payload["max_tokens"] != 256 {
		t.Fatalf("hard output controls were not applied: %#v", payload)
	}
	format, ok := payload["response_format"].(map[string]any)
	if !ok || format["type"] != "json_schema" {
		t.Fatalf("JSON schema response format missing: %#v", payload)
	}
	if _, exists := payload["structured_outputs"]; exists {
		t.Fatalf("mutually exclusive structured_outputs was retained: %#v", payload)
	}
	if _, exists := payload["guided_json"]; exists {
		t.Fatalf("mutually exclusive guided_json was retained: %#v", payload)
	}
}

func TestExtractAuditCompletionReadsReasoningContentFallback(t *testing.T) {
	body := []byte(`{"id":"audit-1","choices":[{"finish_reason":"stop","message":{"content":"","reasoning_content":"{\"decision\":\"allow\",\"risk_code\":\"\",\"category\":\"benign\",\"confidence\":0.99,\"reason\":\"ok\",\"evidence\":\"\"}"}}]}`)
	response, err := extractAuditCompletionResponse(body)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(response.Source, "reasoning_content") || response.FinishReason != "stop" || response.ResponseID != "audit-1" {
		t.Fatalf("unexpected response diagnostics: %+v", response)
	}
	result, err := parseAuditModelResponseContent(response.Content)
	if err != nil || result.Decision != DecisionAllow {
		t.Fatalf("reasoning-content policy was not parsed: result=%+v err=%v", result, err)
	}
}

func TestParseAuditModelResponseContentAcceptsDoubleEncodedAndNestedJSON(t *testing.T) {
	nested := map[string]any{
		"result": map[string]any{
			"decision": "allow", "risk_code": "", "category": "benign",
			"confidence": 0.98, "reason": "safe", "evidence": "",
		},
	}
	encoded, _ := json.Marshal(nested)
	doubleEncoded, _ := json.Marshal(string(encoded))
	result, err := parseAuditModelResponseContent(string(doubleEncoded))
	if err != nil || result.Decision != DecisionAllow || result.Category != "benign" {
		t.Fatalf("double-encoded nested result failed: result=%+v err=%v", result, err)
	}
}

func TestAuditInvalidModelOutputClassifiesTruncation(t *testing.T) {
	err := auditInvalidModelOutputError(auditCompletionResponse{FinishReason: "length"})
	class, _, _ := auditModelErrorDetails(err)
	if class != "output_truncated" {
		t.Fatalf("class=%q, want output_truncated", class)
	}
}

func TestStructuredOutputUnsupportedDetection(t *testing.T) {
	err := auditHTTPStatusError(400, []byte(`{"error":{"message":"response_format json_schema is not supported"}}`))
	class, status, _ := auditModelErrorDetails(err)
	if class != "structured_output_unsupported" || status != 400 {
		t.Fatalf("class=%q status=%d", class, status)
	}
	if !auditErrorRetryableOnSameProfile(err) {
		t.Fatal("structured output incompatibility must advance to the next recovery mode")
	}
}
''',
)

# ---------------------------------------------------------------------------
# Audit request construction and model response handling.
# ---------------------------------------------------------------------------
replace_once(
    "internal/platform/audit.go",
    '''\tendpoint := strings.TrimRight(profile.Endpoint, "/")
\tif !strings.HasSuffix(endpoint, "/chat/completions") {
\t\tendpoint += "/chat/completions"
\t}
\tpayload := map[string]any{
\t\t"model":       profile.Model,
\t\t"temperature": 0,
\t\t"max_tokens":  e.outputMaxTokens,
\t\t"messages":    e.auditMessages(profile, text),
\t}
''',
    '''\tendpoint := strings.TrimRight(profile.Endpoint, "/")
\tif !strings.HasSuffix(endpoint, "/chat/completions") {
\t\tendpoint += "/chat/completions"
\t}
\toutputPlan := auditOutputPlanFromContext(ctx)
\tpayload := map[string]any{
\t\t"model":       profile.Model,
\t\t"temperature": 0,
\t\t"max_tokens":  outputPlan.MaxTokens,
\t\t"messages":    e.auditMessagesWithPlan(profile, text, outputPlan),
\t}
''',
    "audit request output plan",
)
replace_once(
    "internal/platform/audit.go",
    '''\te.applyFastAuditDefaults(profile, payload)
\tencoded, err := json.Marshal(payload)
''',
    '''\te.applyFastAuditDefaults(profile, payload)
\tapplyAuditOutputContract(payload, outputPlan)
\tencoded, err := json.Marshal(payload)
''',
    "enforce audit output contract",
)

old_response_block = '''\tif response.StatusCode < 200 || response.StatusCode >= 300 {
\t\treturn AuditDecision{}, auditHTTPStatusError(response.StatusCode, responseBody)
\t}
\tcontent, err := extractChatCompletionContent(responseBody)
\tif err != nil {
\t\treturn AuditDecision{}, newAuditModelCallError("response_format", 0, err.Error(), nil)
\t}
\tmodelResult, err := parseAuditModelResponseContent(content)
\tif err != nil {
\t\treturn AuditDecision{}, err
\t}
\tdecision := AuditDecision{
\t\tDecision:   modelResult.Decision,
\t\tRiskCode:   strings.TrimSpace(modelResult.RiskCode),
\t\tCategory:   strings.TrimSpace(modelResult.Category),
\t\tConfidence: modelResult.Confidence,
\t\tReason:     modelResult.Reason,
\t\tSource:     "model",
\t\tEvidence:   modelResult.Evidence,
\t}
\treturn validateAuditDecisionEvidence(decision, evidenceSource)
'''
new_response_block = '''\tresponseRequestID := firstNonEmpty(
\t\tresponse.Header.Get("X-Request-ID"),
\t\tresponse.Header.Get("X-Request-Id"),
\t\tresponse.Header.Get("X-Oneapi-Request-Id"),
\t)
\tif response.StatusCode < 200 || response.StatusCode >= 300 {
\t\tdiagnostics := auditOutputDiagnostics{
\t\t\tMode:                 outputPlan.Mode,
\t\t\tMaxTokens:            outputPlan.MaxTokens,
\t\t\tResponseContentBytes: len(responseBody),
\t\t\tResponseSource:       "http_error_body",
\t\t\tResponsePreview:      string(responseBody),
\t\t\tResponseID:           responseRequestID,
\t\t\tFailed:               true,
\t\t}
\t\trecordAuditOutputDiagnostics(ctx, diagnostics)
\t\treturn AuditDecision{}, annotateAuditOutputError(
\t\t\tauditHTTPStatusError(response.StatusCode, responseBody),
\t\t\tdiagnostics,
\t\t)
\t}
\tcompletion, err := extractAuditCompletionResponse(responseBody)
\tif err != nil {
\t\tdiagnostics := auditOutputDiagnostics{
\t\t\tMode:                 outputPlan.Mode,
\t\t\tMaxTokens:            outputPlan.MaxTokens,
\t\t\tResponseContentBytes: len(responseBody),
\t\t\tResponseSource:       "response_envelope",
\t\t\tResponsePreview:      string(responseBody),
\t\t\tResponseID:           responseRequestID,
\t\t\tFailed:               true,
\t\t}
\t\trecordAuditOutputDiagnostics(ctx, diagnostics)
\t\treturn AuditDecision{}, annotateAuditOutputError(
\t\t\tnewAuditModelCallError("response_format", 0, err.Error(), nil),
\t\t\tdiagnostics,
\t\t)
\t}
\tif completion.ResponseID == "" {
\t\tcompletion.ResponseID = responseRequestID
\t}
\tdiagnostics := auditOutputDiagnosticsForResponse(outputPlan, completion, false)
\tmodelResult, err := parseAuditModelResponseContent(completion.Content)
\tif err != nil {
\t\tif errorClass, _, _ := auditModelErrorDetails(err); errorClass == "invalid_json" {
\t\t\terr = auditInvalidModelOutputError(completion)
\t\t}
\t\tdiagnostics.Failed = true
\t\trecordAuditOutputDiagnostics(ctx, diagnostics)
\t\treturn AuditDecision{}, annotateAuditOutputError(err, diagnostics)
\t}
\tdecision := AuditDecision{
\t\tDecision:   modelResult.Decision,
\t\tRiskCode:   strings.TrimSpace(modelResult.RiskCode),
\t\tCategory:   strings.TrimSpace(modelResult.Category),
\t\tConfidence: modelResult.Confidence,
\t\tReason:     modelResult.Reason,
\t\tSource:     "model",
\t\tEvidence:   modelResult.Evidence,
\t}
\tvalidated, err := validateAuditDecisionEvidence(decision, evidenceSource)
\tif err != nil {
\t\tdiagnostics.Failed = true
\t\trecordAuditOutputDiagnostics(ctx, diagnostics)
\t\treturn AuditDecision{}, annotateAuditOutputError(err, diagnostics)
\t}
\t// A successful policy result does not persist the full JSON response. The
\t// mode, byte count, finish reason and response field remain observable.
\tdiagnostics.ResponsePreview = ""
\trecordAuditOutputDiagnostics(ctx, diagnostics)
\treturn validated, nil
'''
replace_once("internal/platform/audit.go", old_response_block, new_response_block, "audit response diagnostics")

start_marker = "func extractChatCompletionContent(body []byte) (string, error) {"
end_marker = "func ExtractAuditText(body []byte, maxBytes int) string {"
replace_range(
    "internal/platform/audit.go",
    start_marker,
    end_marker,
    '''func extractChatCompletionContent(body []byte) (string, error) {
\tresponse, err := extractAuditCompletionResponse(body)
\tif err != nil {
\t\treturn "", err
\t}
\treturn response.Content, nil
}

''',
    "replace chat completion content parser",
)

# ---------------------------------------------------------------------------
# Prompt-level recovery instruction while retaining compatibility wrappers.
# ---------------------------------------------------------------------------
replace_once(
    "internal/platform/audit_fast_mode.go",
    '''func (e *AuditEngine) auditMessages(profile AuditProfile, text string) []map[string]string {
\tsystemPrompt := strings.TrimSpace(profile.SystemPrompt)
\tif systemPrompt == "" {
\t\tsystemPrompt = DefaultAuditSystemPrompt
\t}
\tsystemPrompt = appendFastAuditDirective(systemPrompt)
\tsystemPrompt += "\\n\\n" + auditPolicySystemDirective(profile)
\treturn []map[string]string{
\t\t{"role": "system", "content": systemPrompt},
\t\t{"role": "user", "content": e.auditUserContent(profile, text)},
\t}
}

func (e *AuditEngine) auditUserContent(profile AuditProfile, text string) string {
\tif !e.qwenFastModeEnabled(profile) {
\t\treturn text
\t}
\treturn text + fastAuditUserSuffix
}
''',
    '''func (e *AuditEngine) auditMessages(profile AuditProfile, text string) []map[string]string {
\treturn e.auditMessagesWithPlan(
\t\tprofile,
\t\ttext,
\t\tauditOutputPlan{Mode: auditOutputModePromptOnly, MaxTokens: e.outputMaxTokens},
\t)
}

func (e *AuditEngine) auditMessagesWithPlan(profile AuditProfile, text string, plan auditOutputPlan) []map[string]string {
\tsystemPrompt := strings.TrimSpace(profile.SystemPrompt)
\tif systemPrompt == "" {
\t\tsystemPrompt = DefaultAuditSystemPrompt
\t}
\tsystemPrompt = appendFastAuditDirective(systemPrompt)
\tsystemPrompt += "\\n\\n" + auditPolicySystemDirective(profile)
\tsystemPrompt += "\\n\\n" + auditOutputPlanDirective(plan)
\treturn []map[string]string{
\t\t{"role": "system", "content": systemPrompt},
\t\t{"role": "user", "content": e.auditUserContentWithPlan(profile, text, plan)},
\t}
}

func (e *AuditEngine) auditUserContent(profile AuditProfile, text string) string {
\treturn e.auditUserContentWithPlan(
\t\tprofile,
\t\ttext,
\t\tauditOutputPlan{Mode: auditOutputModePromptOnly, MaxTokens: e.outputMaxTokens},
\t)
}

func (e *AuditEngine) auditUserContentWithPlan(profile AuditProfile, text string, plan auditOutputPlan) string {
\tresult := text
\tif e.qwenFastModeEnabled(profile) {
\t\tresult += fastAuditUserSuffix
\t}
\tif plan.Attempt > 0 {
\t\tresult += "\\n\\n[FORMAT RECOVERY]\\n" + auditOutputPlanDirective(plan)
\t}
\treturn result
}
''',
    "audit messages with output plan",
)

# ---------------------------------------------------------------------------
# Diagnostics parser: nested/double-encoded JSON, structured-output HTTP
# compatibility errors, output preview metadata.
# ---------------------------------------------------------------------------
replace_once(
    "internal/platform/audit_diagnostics.go",
    '''\tMaxContextTokens int
\tRequestedTokens  int
}
''',
    '''\tMaxContextTokens     int
\tRequestedTokens      int
\tOutputMode           string
\tOutputMaxTokens      int
\tFinishReason         string
\tResponseContentBytes int
\tResponseSource       string
\tResponsePreview      string
\tResponseID           string
}
''',
    "audit call error output fields",
)
replace_once(
    "internal/platform/audit_diagnostics.go",
    '''\tmaxContextTokens := 0
\trequestedTokens := 0
\tif (status == 400 || status == 413 || status == 422) && looksLikeAuditContextLength(message) {
''',
    '''\tif (status == 400 || status == 422) && looksLikeStructuredOutputUnsupported(message) {
\t\tclass = "structured_output_unsupported"
\t}
\tmaxContextTokens := 0
\trequestedTokens := 0
\tif (status == 400 || status == 413 || status == 422) && looksLikeAuditContextLength(message) {
''',
    "structured output HTTP classification",
)

parse_start = "func parseAuditModelResponseContent(content string) (modelAuditResponse, error) {"
parse_end = "func validateAuditModelResponse(result modelAuditResponse) (modelAuditResponse, error) {"
new_parser = r'''func parseAuditModelResponseContent(content string) (modelAuditResponse, error) {
	return parseAuditModelResponseContentDepth(content, 0)
}

func parseAuditModelResponseContentDepth(content string, depth int) (modelAuditResponse, error) {
	content = strings.TrimSpace(strings.ToValidUTF8(content, ""))
	if content == "" {
		return modelAuditResponse{}, newAuditModelCallError("empty_response", 0, "audit model returned empty content", nil)
	}
	if depth > 5 {
		return modelAuditResponse{}, newAuditModelCallError("invalid_json", 0, "audit model output exceeded nested JSON recovery depth", nil)
	}

	var decoded any
	if json.Unmarshal([]byte(content), &decoded) == nil {
		if result, found, err := auditModelResponseFromValue(decoded, depth); found || err != nil {
			return result, err
		}
	}

	candidates := balancedJSONObjects(content)
	var candidateError error
	for index := len(candidates) - 1; index >= 0; index-- {
		var value any
		if json.Unmarshal([]byte(candidates[index]), &value) != nil {
			continue
		}
		result, found, err := auditModelResponseFromValue(value, depth)
		if found && err == nil {
			return result, nil
		}
		if err != nil && candidateError == nil {
			candidateError = err
		}
	}
	if candidateError != nil {
		return modelAuditResponse{}, candidateError
	}
	return modelAuditResponse{}, newAuditModelCallError(
		"invalid_json",
		0,
		"audit model output did not contain a valid policy JSON object",
		nil,
	)
}

func auditModelResponseFromValue(value any, depth int) (modelAuditResponse, bool, error) {
	switch typed := value.(type) {
	case map[string]any:
		if _, exists := typed["decision"]; exists {
			encoded, err := json.Marshal(typed)
			if err != nil {
				return modelAuditResponse{}, true, newAuditModelCallError("invalid_json", 0, "encode nested audit model policy object", err)
			}
			var result modelAuditResponse
			if err := json.Unmarshal(encoded, &result); err != nil {
				return modelAuditResponse{}, true, newAuditModelCallError("invalid_json", 0, "decode nested audit model policy object", err)
			}
			validated, err := validateAuditModelResponse(result)
			return validated, true, err
		}
		for _, key := range []string{"result", "policy", "decision_result", "output", "response", "data"} {
			if child, exists := typed[key]; exists {
				if result, found, err := auditModelResponseFromValue(child, depth+1); found || err != nil {
					return result, found, err
				}
			}
		}
	case []any:
		for index := len(typed) - 1; index >= 0; index-- {
			if result, found, err := auditModelResponseFromValue(typed[index], depth+1); found || err != nil {
				return result, found, err
			}
		}
	case string:
		text := strings.TrimSpace(typed)
		if text == "" {
			return modelAuditResponse{}, false, nil
		}
		result, err := parseAuditModelResponseContentDepth(text, depth+1)
		if err == nil {
			return result, true, nil
		}
	}
	return modelAuditResponse{}, false, nil
}

'''
replace_range(
    "internal/platform/audit_diagnostics.go",
    parse_start,
    parse_end,
    new_parser,
    "tolerant audit policy parser",
)

# ---------------------------------------------------------------------------
# Retry loop records a distinct output mode per attempt and exposes diagnostics.
# ---------------------------------------------------------------------------
replace_once(
    "internal/platform/audit_failover.go",
    '''\tAttempts        []AuditAttempt
}
''',
    '''\tAttempts          []AuditAttempt
\tOutputDiagnostics auditOutputDiagnostics
}
''',
    "failover output diagnostics",
)
replace_once(
    "internal/platform/audit_failover.go",
    '''\t\t\tdecision, callMetadata, err := e.callModel(ctx, profile, text)
\t\t\tmetadata.CallMetadata = mergeAuditCallMetadata(metadata.CallMetadata, callMetadata)
\t\t\tmetadata.AttemptCount++
\t\t\tattemptRecord := AuditAttempt{
\t\t\t\tProfileID:   profile.ID,
\t\t\t\tProfileName: profile.Name,
\t\t\t\tModel:       profile.Model,
\t\t\t\tAttempt:     attempt + 1,
\t\t\t\tSuccess:     err == nil,
\t\t\t}
''',
    '''\t\t\toutputPlan := e.auditOutputPlan(profile, attempt)
\t\t\tattemptContext, outputState := withAuditOutputAttempt(ctx, outputPlan)
\t\t\tdecision, callMetadata, err := e.callModel(attemptContext, profile, text)
\t\t\toutputDiagnostics := outputState.snapshot(err != nil)
\t\t\tmetadata.OutputDiagnostics = outputDiagnostics
\t\t\tmetadata.CallMetadata = mergeAuditCallMetadata(metadata.CallMetadata, callMetadata)
\t\t\tmetadata.AttemptCount++
\t\t\tattemptRecord := AuditAttempt{
\t\t\t\tProfileID:           profile.ID,
\t\t\t\tProfileName:         profile.Name,
\t\t\t\tModel:               profile.Model,
\t\t\t\tAttempt:             attempt + 1,
\t\t\t\tSuccess:             err == nil,
\t\t\t\tOutputMode:          outputDiagnostics.Mode,
\t\t\t\tOutputMaxTokens:     outputDiagnostics.MaxTokens,
\t\t\t\tFinishReason:        outputDiagnostics.FinishReason,
\t\t\t\tResponseContentBytes: outputDiagnostics.ResponseContentBytes,
\t\t\t\tResponseSource:      outputDiagnostics.ResponseSource,
\t\t\t\tResponsePreview:     outputDiagnostics.ResponsePreview,
\t\t\t\tResponseID:          outputDiagnostics.ResponseID,
\t\t\t}
''',
    "diverse output retry plan",
)
replace_once(
    "internal/platform/audit_failover.go",
    '''\t\t\tlastErr = err
\t\t\tattemptRecord.ErrorClass, attemptRecord.HTTPStatus, attemptRecord.Reason = auditModelErrorDetails(err)
''',
    '''\t\t\terr = annotateAuditOutputError(err, outputDiagnostics)
\t\t\tlastErr = err
\t\t\tattemptRecord.ErrorClass, attemptRecord.HTTPStatus, attemptRecord.Reason = auditModelErrorDetails(err)
''',
    "annotate retry failure",
)
replace_once(
    "internal/platform/audit_failover.go",
    '''\t\t"invalid_json",
\t\t"invalid_decision",
\t\t"invalid_evidence":
''',
    '''\t\t"invalid_json",
\t\t"output_truncated",
\t\t"structured_output_unsupported",
\t\t"invalid_decision",
\t\t"invalid_evidence":
''',
    "retry new output error classes",
)

# ---------------------------------------------------------------------------
# Result/attempt types and gateway Trace metadata.
# ---------------------------------------------------------------------------
replace_once(
    "internal/platform/types.go",
    '''\tHTTPStatus  int     `json:"http_status,omitempty"`
\tReason      string  `json:"reason,omitempty"`
}
''',
    '''\tHTTPStatus           int     `json:"http_status,omitempty"`
\tReason               string  `json:"reason,omitempty"`
\tOutputMode           string  `json:"output_mode,omitempty"`
\tOutputMaxTokens      int     `json:"output_max_tokens,omitempty"`
\tFinishReason         string  `json:"finish_reason,omitempty"`
\tResponseContentBytes int     `json:"response_content_bytes,omitempty"`
\tResponseSource       string  `json:"response_source,omitempty"`
\tResponsePreview      string  `json:"response_preview,omitempty"`
\tResponseID           string  `json:"response_id,omitempty"`
}
''',
    "audit attempt output fields",
)
replace_once(
    "internal/platform/types.go",
    '''\tAuditPolicyMode             string                      `json:"audit_policy_mode,omitempty"`
\tAuditPolicyAdjustment       *AuditPolicyAdjustment      `json:"audit_policy_adjustment,omitempty"`
}
''',
    '''\tAuditPolicyMode             string                      `json:"audit_policy_mode,omitempty"`
\tAuditPolicyAdjustment       *AuditPolicyAdjustment      `json:"audit_policy_adjustment,omitempty"`
\tAuditOutputMode             string                      `json:"audit_output_mode,omitempty"`
\tAuditOutputMaxTokens        int                         `json:"audit_output_max_tokens,omitempty"`
\tAuditFinishReason           string                      `json:"audit_finish_reason,omitempty"`
\tAuditResponseContentBytes   int                         `json:"audit_response_content_bytes,omitempty"`
\tAuditResponseSource         string                      `json:"audit_response_source,omitempty"`
\tAuditResponsePreview        string                      `json:"audit_response_preview,omitempty"`
\tAuditResponseID             string                      `json:"audit_response_id,omitempty"`
}
''',
    "audit result output fields",
)

replace_once(
    "internal/platform/audit.go",
    '''\tresult.AuditAttempts = append([]AuditAttempt(nil), failoverMetadata.Attempts...)
\tresult.AuditModelsTried = auditAttemptModelNames(failoverMetadata.Attempts)
''',
    '''\tresult.AuditAttempts = append([]AuditAttempt(nil), failoverMetadata.Attempts...)
\tresult.AuditModelsTried = auditAttemptModelNames(failoverMetadata.Attempts)
\tresult.AuditOutputMode = failoverMetadata.OutputDiagnostics.Mode
\tresult.AuditOutputMaxTokens = failoverMetadata.OutputDiagnostics.MaxTokens
\tresult.AuditFinishReason = failoverMetadata.OutputDiagnostics.FinishReason
\tresult.AuditResponseContentBytes = failoverMetadata.OutputDiagnostics.ResponseContentBytes
\tresult.AuditResponseSource = failoverMetadata.OutputDiagnostics.ResponseSource
\tresult.AuditResponsePreview = failoverMetadata.OutputDiagnostics.ResponsePreview
\tresult.AuditResponseID = failoverMetadata.OutputDiagnostics.ResponseID
''',
    "audit result output diagnostics mapping",
)

replace_once(
    "internal/platform/gateway.go",
    '''\tif len(auditResult.AuditAttempts) > 0 {
\t\ttrace.Metadata["audit_attempts"] = auditResult.AuditAttempts
\t}
''',
    '''\tif len(auditResult.AuditAttempts) > 0 {
\t\ttrace.Metadata["audit_attempts"] = auditResult.AuditAttempts
\t}
\tif auditResult.AuditOutputMode != "" {
\t\ttrace.Metadata["audit_output_mode"] = auditResult.AuditOutputMode
\t}
\tif auditResult.AuditOutputMaxTokens > 0 {
\t\ttrace.Metadata["audit_output_max_tokens"] = auditResult.AuditOutputMaxTokens
\t}
\tif auditResult.AuditFinishReason != "" {
\t\ttrace.Metadata["audit_finish_reason"] = auditResult.AuditFinishReason
\t}
\tif auditResult.AuditResponseContentBytes > 0 {
\t\ttrace.Metadata["audit_response_content_bytes"] = auditResult.AuditResponseContentBytes
\t}
\tif auditResult.AuditResponseSource != "" {
\t\ttrace.Metadata["audit_response_source"] = auditResult.AuditResponseSource
\t}
\tif auditResult.AuditResponsePreview != "" {
\t\ttrace.Metadata["audit_response_preview"] = auditResult.AuditResponsePreview
\t}
\tif auditResult.AuditResponseID != "" {
\t\ttrace.Metadata["audit_response_id"] = auditResult.AuditResponseID
\t}
''',
    "gateway audit output diagnostics",
)

# ---------------------------------------------------------------------------
# UI observability.
# ---------------------------------------------------------------------------
replace_once(
    "internal/platform/web/index.html",
    '''          ['审计阶段',(item.metadata?.audit_attempts||[]).length?((item.metadata.audit_attempts[item.metadata.audit_attempts.length-1]?.success===true)?'成功':'失败'):'-'], ['审计错误分类',item.metadata?.audit_error_class||'-'], ['审计模型 HTTP',item.metadata?.audit_http_status||'-'],
''',
    '''          ['审计阶段',(item.metadata?.audit_attempts||[]).length?((item.metadata.audit_attempts[item.metadata.audit_attempts.length-1]?.success===true)?'成功':'失败'):'-'], ['审计错误分类',item.metadata?.audit_error_class||'-'], ['审计模型 HTTP',item.metadata?.audit_http_status||'-'],
          ['结构化输出模式',item.metadata?.audit_output_mode||'-'], ['审计输出上限',item.metadata?.audit_output_max_tokens?`${number(item.metadata.audit_output_max_tokens)} tokens`:'-'], ['审计结束原因',item.metadata?.audit_finish_reason||'-'], ['审计响应字段',item.metadata?.audit_response_source||'-'], ['审计响应字节',item.metadata?.audit_response_content_bytes??'-'], ['审计响应 ID',item.metadata?.audit_response_id||'-'], ['脱敏响应预览',item.metadata?.audit_response_preview||'-'],
''',
    "trace structured output fields",
)
replace_once(
    "internal/platform/web/index.html",
    '''          ['审计尝试详情',(item.metadata?.audit_attempts||[]).map(a=>`${a.profile_name||a.model||'-'} #${a.attempt}: ${a.success?(a.decision||'success'):(a.error_class||'error')}${a.risk_code?` / ${a.risk_code}`:''}${a.evidence?` / 证据 ${a.evidence}`:''}${a.reason?` / ${a.reason}`:''}`).join(' | ')||'-'],
''',
    '''          ['审计尝试详情',(item.metadata?.audit_attempts||[]).map(a=>`${a.profile_name||a.model||'-'} #${a.attempt}: ${a.success?(a.decision||'success'):(a.error_class||'error')}${a.output_mode?` / 输出 ${a.output_mode}`:''}${a.output_max_tokens?`:${a.output_max_tokens}`:''}${a.finish_reason?` / finish=${a.finish_reason}`:''}${a.response_content_bytes?` / ${a.response_content_bytes}B`:''}${a.response_source?` / ${a.response_source}`:''}${a.risk_code?` / ${a.risk_code}`:''}${a.evidence?` / 证据 ${a.evidence}`:''}${a.response_preview?` / 预览 ${a.response_preview}`:''}${a.reason?` / ${a.reason}`:''}`).join(' | ')||'-'],
''',
    "trace attempt structured diagnostics",
)
replace_once(
    "internal/platform/web/index.html",
    '''          const errorClass=item.metadata?.audit_error_class||'';
''',
    '''          const errorClass=item.metadata?.audit_error_class||'';
          const auditOutputLine=(item.metadata?.audit_output_mode||item.metadata?.audit_finish_reason)?`<span class="trace-error-class">审计输出：${escapeHTML(item.metadata?.audit_output_mode||'-')}${item.metadata?.audit_output_max_tokens?` · ${escapeHTML(item.metadata.audit_output_max_tokens)} tokens`:''}${item.metadata?.audit_finish_reason?` · finish=${escapeHTML(item.metadata.audit_finish_reason)}`:''}${item.metadata?.audit_response_content_bytes?` · ${escapeHTML(item.metadata.audit_response_content_bytes)}B`:''}</span>`:'';
''',
    "trace list output diagnostic line",
)
replace_once(
    "internal/platform/web/index.html",
    '''${ruleLine}${errorClass?`<span class="trace-error-class">${escapeHTML(errorClass)}${item.metadata?.audit_http_status?` · HTTP ${escapeHTML(item.metadata.audit_http_status)}`:''}</span>`:''}${tokenLine}</td>''',
    '''${ruleLine}${errorClass?`<span class="trace-error-class">${escapeHTML(errorClass)}${item.metadata?.audit_http_status?` · HTTP ${escapeHTML(item.metadata.audit_http_status)}`:''}</span>`:''}${auditOutputLine}${tokenLine}</td>''',
    "trace list render output diagnostics",
)

# ---------------------------------------------------------------------------
# Defaults: 256 tokens is still a tiny/fast policy response but leaves enough
# room for six JSON fields and evidence. Historical 128 is migrated.
# ---------------------------------------------------------------------------
replace_once(
    "internal/platform/config.go",
    'AuditOutputMaxTokens:           envInt("AUDIT_OUTPUT_MAX_TOKENS", 128),',
    'AuditOutputMaxTokens:           envInt("AUDIT_OUTPUT_MAX_TOKENS", 256),',
    "config audit output default",
)
replace_once(
    "internal/platform/config.go",
    'AuditMaxChunks:                 envInt("AUDIT_MAX_CHUNKS", 64),',
    'AuditMaxChunks:                 envInt("AUDIT_MAX_CHUNKS", 256),',
    "config audit chunk default consistency",
)
replace_once(".env.example", "AUDIT_OUTPUT_MAX_TOKENS=128", "AUDIT_OUTPUT_MAX_TOKENS=256", "env audit output default")
replace_once("docker-compose.yml", "AUDIT_OUTPUT_MAX_TOKENS: ${AUDIT_OUTPUT_MAX_TOKENS:-128}", "AUDIT_OUTPUT_MAX_TOKENS: ${AUDIT_OUTPUT_MAX_TOKENS:-256}", "compose audit output default")
replace_once("deploy/kubernetes.yaml", 'AUDIT_OUTPUT_MAX_TOKENS: "128"', 'AUDIT_OUTPUT_MAX_TOKENS: "256"', "k8s audit output default")
replace_once(
    "scripts/init-env.sh",
    '    "AUDIT_OUTPUT_MAX_TOKENS": "128",',
    '    "AUDIT_OUTPUT_MAX_TOKENS": "256",',
    "init env audit output default",
)
replace_once(
    "scripts/init-env.sh",
    '''    if key == "AUDIT_MAX_CHUNKS" and current == "64":
        should_set = True
        warnings.append(
            "AUDIT_MAX_CHUNKS was increased from 64 to 256 for complete large-text request auditing."
        )
''',
    '''    if key == "AUDIT_OUTPUT_MAX_TOKENS" and current == "128":
        should_set = True
        warnings.append(
            "AUDIT_OUTPUT_MAX_TOKENS was increased from 128 to 256 so the six-field structured policy JSON is not truncated."
        )
    if key == "AUDIT_MAX_CHUNKS" and current == "64":
        should_set = True
        warnings.append(
            "AUDIT_MAX_CHUNKS was increased from 64 to 256 for complete large-text request auditing."
        )
''',
    "init env output migration",
)

ci = read(".github/workflows/ci.yml")
ci = ci.replace("'AUDIT_OUTPUT_MAX_TOKENS': '128'", "'AUDIT_OUTPUT_MAX_TOKENS': '256'")
write(".github/workflows/ci.yml", ci)

# ---------------------------------------------------------------------------
# Mock provider and E2E prove that retry 1 and retry 2 are not identical: the
# first JSON-schema result is invalid text, the second vLLM structured mode
# returns a valid policy and the real upstream is reached.
# ---------------------------------------------------------------------------
replace_once(
    "cmd/mockprovider/main.go",
    '''\tChatTemplateKwargs map[string]any `json:"chat_template_kwargs"`
\tMessages           []struct {
''',
    '''\tChatTemplateKwargs map[string]any `json:"chat_template_kwargs"`
\tResponseFormat     map[string]any `json:"response_format"`
\tStructuredOutputs  map[string]any `json:"structured_outputs"`
\tGuidedJSON         any            `json:"guided_json"`
\tMessages           []struct {
''',
    "mock structured output request fields",
)
replace_once(
    "cmd/mockprovider/main.go",
    '''\t\tif !ok || enableThinking || !preserveOK || preserveThinking || request.MaxTokens != 128 {
''',
    '''\t\tif !ok || enableThinking || !preserveOK || preserveThinking || request.MaxTokens < 256 || request.MaxTokens > 1024 {
''',
    "mock Qwen output budget",
)
replace_once(
    "cmd/mockprovider/main.go",
    '''\tif strings.Contains(text, "model-audit-http-401") {
''',
    '''\tif strings.Contains(userText, "model-audit-structured-recovery") && mockAuditOutputMode(request) == "json_schema" {
\t\twriteJSON(w, http.StatusOK, map[string]any{
\t\t\t"id": "audit-structured-recovery-first",
\t\t\t"choices": []any{map[string]any{
\t\t\t\t"finish_reason": "stop",
\t\t\t\t"message": map[string]any{"role": "assistant", "content": "The request is safe, but this first response forgot the required JSON object."},
\t\t\t}},
\t\t})
\t\treturn
\t}
\tif strings.Contains(text, "model-audit-http-401") {
''',
    "mock structured output recovery first failure",
)
replace_once(
    "cmd/mockprovider/main.go",
    '''func firstAuditEvidence(text string, candidates []string) string {
''',
    '''func mockAuditOutputMode(request chatRequest) string {
\tif value, _ := request.ResponseFormat["type"].(string); strings.EqualFold(value, "json_schema") {
\t\treturn "json_schema"
\t} else if strings.EqualFold(value, "json_object") {
\t\treturn "json_object"
\t}
\tif len(request.StructuredOutputs) > 0 {
\t\treturn "vllm_structured_json"
\t}
\tif request.GuidedJSON != nil {
\t\treturn "guided_json"
\t}
\treturn "prompt_only"
}

func firstAuditEvidence(text string, candidates []string) string {
''',
    "mock output mode helper",
)
replace_once(
    "cmd/mockprovider/main.go",
    '''\twriteJSON(w, http.StatusOK, map[string]any{
\t\t"id": "audit-mock",
\t\t"choices": []any{map[string]any{
\t\t\t"message": map[string]any{
''',
    '''\twriteJSON(w, http.StatusOK, map[string]any{
\t\t"id": "audit-mock",
\t\t"choices": []any{map[string]any{
\t\t\t"finish_reason": "stop",
\t\t\t"message": map[string]any{
''',
    "mock normal finish reason",
)
replace_once(
    "cmd/mockprovider/main.go",
    '''\t\twriteJSON(w, http.StatusOK, map[string]any{
\t\t\t"choices": []any{map[string]any{
\t\t\t\t"message": map[string]any{"role": "assistant", "content": "not-json"},
''',
    '''\t\twriteJSON(w, http.StatusOK, map[string]any{
\t\t\t"choices": []any{map[string]any{
\t\t\t\t"finish_reason": "stop",
\t\t\t\t"message": map[string]any{"role": "assistant", "content": "not-json"},
''',
    "mock invalid finish reason",
)

replace_once(
    "scripts/e2e.sh",
    '''contains "${WORKDIR}/audit-thinking.json" 'mock provider success'

status="$(curl --silent --show-error -o "${WORKDIR}/audit-http-401.json" -w '%{http_code}' \\
''',
    '''contains "${WORKDIR}/audit-thinking.json" 'mock provider success'

status="$(curl --silent --show-error -o "${WORKDIR}/audit-structured-recovery.json" -w '%{http_code}' \\
  "${gateway}" "${gateway_auth[@]}" \\
  -H 'X-Request-ID: e2e-audit-structured-recovery' \\
  --data-binary '{"model":"normal","messages":[{"role":"user","content":"model-audit-structured-recovery"}]}')"
assert_status 200 "${status}" "${WORKDIR}/audit-structured-recovery.json"
contains "${WORKDIR}/audit-structured-recovery.json" 'mock provider success'

status="$(curl --silent --show-error -o "${WORKDIR}/audit-http-401.json" -w '%{http_code}' \\
''',
    "E2E structured recovery request",
)
replace_once(
    "scripts/e2e.sh",
    '''     grep -Fq 'e2e-audit-failover' "${WORKDIR}/traces.json"; then
''',
    '''     grep -Fq 'e2e-audit-failover' "${WORKDIR}/traces.json" && \\
     grep -Fq 'e2e-audit-structured-recovery' "${WORKDIR}/traces.json"; then
''',
    "E2E wait for structured recovery trace",
)
replace_once(
    "scripts/e2e.sh",
    '''too_large = next((item for item in items if item.get("request_id") == "e2e-request-too-large"), None)
''',
    '''structured_recovery = next((item for item in items if item.get("request_id") == "e2e-audit-structured-recovery"), None)
if not structured_recovery:
    raise RuntimeError("structured-output recovery trace is missing")
srm = structured_recovery.get("metadata", {})
if structured_recovery.get("decision") != "allow" or int(structured_recovery.get("http_status", 0)) != 200:
    raise RuntimeError(f"structured-output recovery did not reach upstream: {structured_recovery}")
attempts = srm.get("audit_attempts", [])
if len(attempts) != 2:
    raise RuntimeError(f"expected one invalid JSON attempt and one recovery attempt: {attempts}")
first, second = attempts
if first.get("success") is not False or first.get("error_class") != "invalid_json" or first.get("output_mode") != "json_schema":
    raise RuntimeError(f"first structured-output failure diagnostics are wrong: {first}")
if "forgot the required JSON" not in str(first.get("response_preview", "")):
    raise RuntimeError(f"sanitized invalid response preview is missing: {first}")
if second.get("success") is not True or second.get("output_mode") != "vllm_structured_json":
    raise RuntimeError(f"second structured-output recovery mode did not succeed: {second}")
if int(second.get("output_max_tokens", 0)) < 384 or second.get("finish_reason") != "stop":
    raise RuntimeError(f"recovery output budget/finish reason is wrong: {second}")
if int(srm.get("audit_model_attempts", 0)) != 2 or int(srm.get("audit_model_retries", 0)) != 1:
    raise RuntimeError(f"structured recovery retry counts are wrong: {srm}")
if srm.get("audit_output_mode") != "vllm_structured_json" or srm.get("audit_response_preview"):
    raise RuntimeError(f"successful final output diagnostics are wrong: {srm}")

too_large = next((item for item in items if item.get("request_id") == "e2e-request-too-large"), None)
''',
    "E2E structured recovery trace assertions",
)

# ---------------------------------------------------------------------------
# Documentation.
# ---------------------------------------------------------------------------
write(
    "docs/audit-structured-output-recovery.md",
    '''# 审计模型结构化输出恢复

## 根因

`invalid_json` 表示审计 HTTP 调用成功，但模型输出中没有可验证的策略 JSON。旧实现存在三个问题：

1. 三次重试发送完全相同的请求，模型重复同一种格式错误；
2. `max_tokens=128` 可能在六字段 JSON、原因和证据尚未闭合前截断；
3. 平台没有保存 `finish_reason`、响应字段、响应字节数或脱敏预览，无法区分解释性文本、截断、reasoning 字段输出和协议差异。

## 恢复顺序

Qwen 同一 Profile 的自动重试依次使用：

```text
1. response_format=json_schema，至少 256 output tokens
2. structured_outputs.json，至少 384 output tokens
3. response_format=json_object，至少 512 output tokens
4. legacy guided_json
5. prompt_only 兼容模式
```

默认重试两次，因此正常链路最多使用前三种。服务端明确拒绝某种结构化参数时，错误分类为 `structured_output_unsupported` 并进入下一模式；`finish_reason=length` 分类为 `output_truncated` 并增加下一次输出预算。

审计 Profile 的 Extra 可设置：

```json
{"_risk_structured_output_mode":"auto"}
```

也可明确设为 `json_schema`、`vllm_structured_json`、`json_object`、`guided_json` 或 `prompt_only`。所有 `_risk_*` 字段只由平台使用，不发送到模型。

## 解析兼容

平台可以从以下位置恢复最终策略对象：

- `choices[].message.content`；
- `choices[].message.reasoning_content` / `reasoning`；
- `choices[].text`；
- tool-call function arguments；
- content parts 数组；
- 直接 JSON、Markdown/思考文本中的平衡 JSON；
- 双重编码 JSON；
- `result`、`policy`、`output`、`response` 等嵌套对象。

## 追踪字段

每次尝试会记录：

```text
output_mode
output_max_tokens
finish_reason
response_content_bytes
response_source
response_id
response_preview
```

`response_preview` 只在失败时保存，经过凭据脱敏、空白折叠和长度限制；成功响应不保存完整策略 JSON。真实 API Key、Token 或 Authorization 不会写入 Trace。

所有结构化输出恢复和备用模型均失败后，仍遵循现有 fail-closed/fail-open 路由配置，不会因为格式错误静默绕过审计。
''',
)

print("audit structured-output recovery patch applied")
