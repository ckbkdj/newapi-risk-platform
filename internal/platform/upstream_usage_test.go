package platform

import (
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestParseOpenAIChatUsage(t *testing.T) {
	usage := parseUpstreamTokenUsage([]byte(`{
		"usage": {
			"prompt_tokens": 17969,
			"completion_tokens": 4970,
			"total_tokens": 22939,
			"prompt_tokens_details": {"cached_tokens": 9984},
			"completion_tokens_details": {"reasoning_tokens": 321}
		}
	}`))
	if usage.InputTokens != 17969 || usage.OutputTokens != 4970 || usage.TotalTokens != 22939 {
		t.Fatalf("unexpected core usage: %+v", usage)
	}
	if usage.CachedTokens != 9984 || usage.ReasoningTokens != 321 || !usage.Exact {
		t.Fatalf("unexpected detailed usage: %+v", usage)
	}
	if usage.Source != "openai_chat_usage" {
		t.Fatalf("source = %q", usage.Source)
	}
}

func TestParseResponsesCompletedUsage(t *testing.T) {
	lines := []string{
		"event: response.completed",
		`data: {"type":"response.completed","response":{"status":"completed","usage":{"input_tokens":101468,"output_tokens":6189,"total_tokens":107657,"input_tokens_details":{"cached_tokens":99840}}}}`,
		"",
	}
	usage, terminal, semantics := parseSSEObservation(lines)
	if !terminal || semantics != "response.completed" {
		t.Fatalf("terminal=%v semantics=%q", terminal, semantics)
	}
	if usage.InputTokens != 101468 || usage.OutputTokens != 6189 || usage.CachedTokens != 99840 {
		t.Fatalf("unexpected responses usage: %+v", usage)
	}
}

func TestParseChatCompletionFinishReasonAndUsage(t *testing.T) {
	lines := []string{
		`data: {"choices":[{"delta":{},"finish_reason":"stop"}],"usage":{"prompt_tokens":17969,"completion_tokens":4970,"total_tokens":22939}}`,
		"",
	}
	usage, terminal, semantics := parseSSEObservation(lines)
	if !terminal || semantics != "finish_reason:stop" {
		t.Fatalf("terminal=%v semantics=%q", terminal, semantics)
	}
	if usage.InputTokens != 17969 || usage.OutputTokens != 4970 {
		t.Fatalf("unexpected usage: %+v", usage)
	}
}

func TestDoneMarkerIsTerminal(t *testing.T) {
	_, terminal, semantics := parseSSEObservation([]string{"data: [DONE]", ""})
	if !terminal || semantics != "data_done" {
		t.Fatalf("terminal=%v semantics=%q", terminal, semantics)
	}
}

func TestRecordUpstreamObservationMetadata(t *testing.T) {
	trace := &TraceEvent{Metadata: map[string]any{}}
	recordUpstreamObservationMetadata(trace, upstreamResponseObservation{
		Usage: upstreamTokenUsage{
			InputTokens:  17969,
			OutputTokens: 4970,
			TotalTokens:  22939,
			CachedTokens: 9984,
			Source:       "openai_chat_usage",
			Exact:        true,
		},
		CompletionObserved:  true,
		CompletionSemantics: "data_done",
		Duration:            2 * time.Second,
	})
	if trace.Metadata["upstream_input_tokens"] != int64(17969) || trace.Metadata["upstream_output_tokens"] != int64(4970) {
		t.Fatalf("usage metadata missing: %#v", trace.Metadata)
	}
	if rate, ok := trace.Metadata["upstream_output_tokens_per_second"].(float64); !ok || rate != 2485 {
		t.Fatalf("unexpected output rate: %#v", trace.Metadata["upstream_output_tokens_per_second"])
	}
}

func TestClassifyStreamIdleTimeout(t *testing.T) {
	ctx, cancel := contextWithCauseForTest(errUpstreamStreamIdleTimeout)
	defer cancel()
	response := &http.Response{Request: (&http.Request{}).WithContext(ctx)}
	code, evidence := classifyUpstreamStreamReadError(response, errors.New("context canceled"))
	if code != "UPSTREAM_STREAM_TIMEOUT" || !strings.Contains(string(evidence), "idle timeout") {
		t.Fatalf("code=%q evidence=%q", code, evidence)
	}
}

func contextWithCauseForTest(cause error) (context.Context, func()) {
	ctx, cancel := context.WithCancelCause(context.Background())
	cancel(cause)
	return ctx, func() { cancel(context.Canceled) }
}
