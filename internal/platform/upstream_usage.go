package platform

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"strings"
	"time"
)

var (
	errUpstreamRequestTimeout    = errors.New("upstream request timeout")
	errUpstreamStreamIdleTimeout = errors.New("upstream stream idle timeout")
)

type upstreamTokenUsage struct {
	InputTokens         int64
	OutputTokens        int64
	TotalTokens         int64
	CachedTokens        int64
	CacheCreationTokens int64
	ReasoningTokens     int64
	Source              string
	Exact               bool
}

func (u upstreamTokenUsage) HasAny() bool {
	return u.InputTokens > 0 || u.OutputTokens > 0 || u.TotalTokens > 0 ||
		u.CachedTokens > 0 || u.CacheCreationTokens > 0 || u.ReasoningTokens > 0
}

func (u *upstreamTokenUsage) Merge(other upstreamTokenUsage) {
	if u == nil || !other.HasAny() {
		return
	}
	u.InputTokens = maxInt64(u.InputTokens, other.InputTokens)
	u.OutputTokens = maxInt64(u.OutputTokens, other.OutputTokens)
	u.TotalTokens = maxInt64(u.TotalTokens, other.TotalTokens)
	u.CachedTokens = maxInt64(u.CachedTokens, other.CachedTokens)
	u.CacheCreationTokens = maxInt64(u.CacheCreationTokens, other.CacheCreationTokens)
	u.ReasoningTokens = maxInt64(u.ReasoningTokens, other.ReasoningTokens)
	if u.Source == "" {
		u.Source = other.Source
	}
	u.Exact = u.Exact || other.Exact
	if u.TotalTokens == 0 && (u.InputTokens > 0 || u.OutputTokens > 0) {
		u.TotalTokens = u.InputTokens + u.OutputTokens
	}
}

type upstreamResponseObservation struct {
	Usage                        upstreamTokenUsage
	CompletionObserved           bool
	CompletionSemantics          string
	TransportClosedAfterTerminal bool
	ReadError                    string
	Duration                     time.Duration
}

func (o *upstreamResponseObservation) ObserveSSEEvent(lines []string) {
	if o == nil {
		return
	}
	usage, terminal, semantics := parseSSEObservation(lines)
	o.Usage.Merge(usage)
	if terminal {
		o.CompletionObserved = true
		if semantics != "" {
			o.CompletionSemantics = semantics
		}
	}
}

func (o *upstreamResponseObservation) ObserveBufferedBody(body []byte, complete bool) {
	if o == nil || !complete {
		return
	}
	o.Usage.Merge(parseUpstreamTokenUsage(body))
	o.CompletionObserved = true
	o.CompletionSemantics = "buffered_response_complete"
}

func recordUpstreamObservationMetadata(trace *TraceEvent, observation upstreamResponseObservation) {
	if trace == nil {
		return
	}
	if trace.Metadata == nil {
		trace.Metadata = map[string]any{}
	}
	usage := observation.Usage
	if usage.InputTokens > 0 {
		trace.Metadata["upstream_input_tokens"] = usage.InputTokens
	}
	if usage.OutputTokens > 0 {
		trace.Metadata["upstream_output_tokens"] = usage.OutputTokens
	}
	if usage.TotalTokens > 0 {
		trace.Metadata["upstream_total_tokens"] = usage.TotalTokens
	}
	if usage.CachedTokens > 0 {
		trace.Metadata["upstream_cached_tokens"] = usage.CachedTokens
	}
	if usage.CacheCreationTokens > 0 {
		trace.Metadata["upstream_cache_creation_tokens"] = usage.CacheCreationTokens
	}
	if usage.ReasoningTokens > 0 {
		trace.Metadata["upstream_reasoning_tokens"] = usage.ReasoningTokens
	}
	if usage.HasAny() {
		trace.Metadata["upstream_usage_exact"] = usage.Exact
		trace.Metadata["upstream_usage_source"] = firstNonEmpty(usage.Source, "upstream_response")
	}
	if observation.Duration > 0 {
		trace.Metadata["upstream_response_duration_ms"] = observation.Duration.Milliseconds()
		if usage.OutputTokens > 0 && observation.Duration >= 10*time.Millisecond {
			rate := float64(usage.OutputTokens) / observation.Duration.Seconds()
			trace.Metadata["upstream_output_tokens_per_second"] = math.Round(rate*100) / 100
		}
	}
	if observation.CompletionSemantics != "" {
		trace.Metadata["upstream_completion_semantics"] = observation.CompletionSemantics
	}
	if observation.TransportClosedAfterTerminal {
		trace.Metadata["upstream_transport_closed_after_terminal"] = true
	}
	if observation.ReadError != "" {
		trace.Metadata["upstream_stream_read_error"] = truncateString(observation.ReadError, auditDiagnosticTextLimit)
	}
}

func parseUpstreamTokenUsage(body []byte) upstreamTokenUsage {
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.UseNumber()
	var root any
	if err := decoder.Decode(&root); err != nil {
		return upstreamTokenUsage{}
	}
	var result upstreamTokenUsage
	walkUsagePayload(root, "root", &result)
	if result.TotalTokens == 0 && (result.InputTokens > 0 || result.OutputTokens > 0) {
		result.TotalTokens = result.InputTokens + result.OutputTokens
	}
	return result
}

func walkUsagePayload(value any, parentKey string, result *upstreamTokenUsage) {
	switch typed := value.(type) {
	case map[string]any:
		if isUsageContainer(parentKey) || hasTokenUsageSignature(typed) {
			result.Merge(tokenUsageFromMap(typed, parentKey))
		}
		for key, child := range typed {
			switch child.(type) {
			case map[string]any, []any:
				walkUsagePayload(child, key, result)
			}
		}
	case []any:
		for _, child := range typed {
			walkUsagePayload(child, parentKey, result)
		}
	}
}

func isUsageContainer(key string) bool {
	normalized := normalizeUsageKey(key)
	return normalized == "usage" || normalized == "usagemetadata" ||
		normalized == "tokenusage" || normalized == "tokenusageinfo"
}

func hasTokenUsageSignature(values map[string]any) bool {
	input := hasAnyUsageKey(values, "prompt_tokens", "input_tokens", "promptTokenCount")
	output := hasAnyUsageKey(values, "completion_tokens", "output_tokens", "candidatesTokenCount")
	total := hasAnyUsageKey(values, "total_tokens", "totalTokenCount")
	return (input && (output || total)) || (output && total)
}

func tokenUsageFromMap(values map[string]any, parentKey string) upstreamTokenUsage {
	usage := upstreamTokenUsage{Exact: true}
	usage.InputTokens = maxTokenValue(values, "prompt_tokens", "input_tokens", "promptTokenCount")
	usage.OutputTokens = maxTokenValue(values, "completion_tokens", "output_tokens", "candidatesTokenCount")
	usage.TotalTokens = maxTokenValue(values, "total_tokens", "totalTokenCount")
	usage.CachedTokens = maxTokenValue(values, "cached_tokens", "cache_read_input_tokens", "cachedContentTokenCount")
	usage.CacheCreationTokens = maxTokenValue(values, "cache_creation_input_tokens")
	usage.ReasoningTokens = maxTokenValue(values, "reasoning_tokens", "thoughtsTokenCount")

	for _, key := range []string{"prompt_tokens_details", "input_tokens_details"} {
		if details, ok := values[key].(map[string]any); ok {
			usage.CachedTokens = maxInt64(usage.CachedTokens, maxTokenValue(details, "cached_tokens", "cache_read_input_tokens"))
		}
	}
	for _, key := range []string{"completion_tokens_details", "output_tokens_details"} {
		if details, ok := values[key].(map[string]any); ok {
			usage.ReasoningTokens = maxInt64(usage.ReasoningTokens, maxTokenValue(details, "reasoning_tokens"))
		}
	}

	normalizedParent := normalizeUsageKey(parentKey)
	switch {
	case normalizedParent == "usagemetadata" || hasAnyUsageKey(values, "promptTokenCount", "candidatesTokenCount"):
		usage.Source = "gemini_usage_metadata"
	case hasAnyUsageKey(values, "cache_read_input_tokens", "cache_creation_input_tokens"):
		usage.Source = "anthropic_usage"
	case hasAnyUsageKey(values, "prompt_tokens", "completion_tokens"):
		usage.Source = "openai_chat_usage"
	case hasAnyUsageKey(values, "input_tokens", "output_tokens"):
		usage.Source = "responses_usage"
	default:
		usage.Source = "upstream_usage"
	}
	if !usage.HasAny() {
		usage.Exact = false
	}
	return usage
}

func parseSSEObservation(lines []string) (upstreamTokenUsage, bool, string) {
	var eventName string
	dataLines := make([]string, 0, 2)
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		lower := strings.ToLower(trimmed)
		switch {
		case strings.HasPrefix(lower, "event:"):
			eventName = strings.TrimSpace(trimmed[len("event:"):])
		case strings.HasPrefix(lower, "data:"):
			dataLines = append(dataLines, strings.TrimSpace(trimmed[len("data:"):]))
		}
	}
	joined := strings.TrimSpace(strings.Join(dataLines, "\n"))
	if strings.EqualFold(joined, "[DONE]") {
		return upstreamTokenUsage{}, true, "data_done"
	}
	usage := parseUpstreamTokenUsage([]byte(joined))
	if terminalEventName(eventName) {
		return usage, true, strings.ToLower(strings.TrimSpace(eventName))
	}
	if joined == "" {
		return usage, false, ""
	}
	decoder := json.NewDecoder(strings.NewReader(joined))
	decoder.UseNumber()
	var payload map[string]any
	if err := decoder.Decode(&payload); err != nil {
		return usage, false, ""
	}
	if terminal, semantics := terminalPayload(payload); terminal {
		return usage, true, semantics
	}
	return usage, false, ""
}

func terminalEventName(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "done", "completed", "completion", "message_stop", "response.completed", "response.done":
		return true
	default:
		return false
	}
}

func terminalPayload(payload map[string]any) (bool, string) {
	if value, _ := payload["type"].(string); terminalEventName(value) {
		return true, strings.ToLower(strings.TrimSpace(value))
	}
	if value, _ := payload["status"].(string); strings.EqualFold(strings.TrimSpace(value), "completed") {
		return true, "status_completed"
	}
	if done, _ := payload["done"].(bool); done {
		return true, "done_true"
	}
	if response, ok := payload["response"].(map[string]any); ok {
		if value, _ := response["status"].(string); strings.EqualFold(strings.TrimSpace(value), "completed") {
			return true, "response_completed"
		}
	}
	if finishReason := stringValue(payload["finish_reason"]); finishReason != "" {
		return true, "finish_reason:" + strings.ToLower(finishReason)
	}
	if choices, ok := payload["choices"].([]any); ok {
		for _, rawChoice := range choices {
			choice, ok := rawChoice.(map[string]any)
			if !ok {
				continue
			}
			if finishReason := stringValue(choice["finish_reason"]); finishReason != "" {
				return true, "finish_reason:" + strings.ToLower(finishReason)
			}
		}
	}
	return false, ""
}

func classifyUpstreamStreamReadError(response *http.Response, readError error) (string, []byte) {
	cause := error(nil)
	if response != nil && response.Request != nil {
		cause = context.Cause(response.Request.Context())
	}
	switch {
	case errors.Is(cause, errUpstreamStreamIdleTimeout):
		return "UPSTREAM_STREAM_TIMEOUT", []byte("upstream stream idle timeout: no SSE event arrived before the configured route timeout")
	case errors.Is(cause, errUpstreamRequestTimeout), errors.Is(cause, context.DeadlineExceeded):
		return "UPSTREAM_STREAM_TIMEOUT", []byte("upstream stream request deadline expired while reading SSE data")
	case errors.Is(cause, context.Canceled):
		return "CLIENT_DISCONNECT", nil
	default:
		return "UPSTREAM_STREAM_INTERRUPTED", []byte(fmt.Sprintf("upstream SSE read failed: %v", readError))
	}
}

func maxTokenValue(values map[string]any, keys ...string) int64 {
	var maximum int64
	for _, key := range keys {
		if value := tokenInt64(values[key]); value > maximum {
			maximum = value
		}
	}
	return maximum
}

func tokenInt64(value any) int64 {
	switch typed := value.(type) {
	case json.Number:
		integer, err := typed.Int64()
		if err == nil && integer > 0 {
			return integer
		}
	case float64:
		if typed > 0 {
			return int64(typed)
		}
	case float32:
		if typed > 0 {
			return int64(typed)
		}
	case int:
		if typed > 0 {
			return int64(typed)
		}
	case int64:
		if typed > 0 {
			return typed
		}
	case int32:
		if typed > 0 {
			return int64(typed)
		}
	}
	return 0
}

func hasAnyUsageKey(values map[string]any, keys ...string) bool {
	for _, key := range keys {
		if _, exists := values[key]; exists {
			return true
		}
	}
	return false
}

func normalizeUsageKey(value string) string {
	return strings.NewReplacer("_", "", "-", "", " ", "").Replace(strings.ToLower(strings.TrimSpace(value)))
}

func stringValue(value any) string {
	text, _ := value.(string)
	return strings.TrimSpace(text)
}

func maxInt64(left int64, right int64) int64 {
	if right > left {
		return right
	}
	return left
}
