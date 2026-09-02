package platform

import (
	"strings"
	"testing"
	"time"
)

func TestApplyFastAuditDefaultsForQwen38(t *testing.T) {
	engine := &AuditEngine{
		outputMaxTokens:      128,
		disableThinking:      true,
		promptTruncateTokens: 260000,
	}
	payload := map[string]any{
		"max_tokens": 9999,
		"chat_template_kwargs": map[string]any{
			"custom":          "kept",
			"enable_thinking": true,
		},
	}
	engine.applyFastAuditDefaults(AuditProfile{Model: "Qwen3.8-27B"}, payload)

	if got := payload["max_tokens"]; got != 128 {
		t.Fatalf("max_tokens = %#v, want 128", got)
	}
	arguments, ok := payload["chat_template_kwargs"].(map[string]any)
	if !ok {
		t.Fatalf("chat_template_kwargs type = %T", payload["chat_template_kwargs"])
	}
	if got := arguments["enable_thinking"]; got != false {
		t.Fatalf("enable_thinking = %#v, want false", got)
	}
	if got := arguments["preserve_thinking"]; got != false {
		t.Fatalf("preserve_thinking = %#v, want false", got)
	}
	if got := arguments["custom"]; got != "kept" {
		t.Fatalf("custom template arg = %#v, want kept", got)
	}
	if got := payload["truncate_prompt_tokens"]; got != 260000 {
		t.Fatalf("truncate_prompt_tokens = %#v, want 260000", got)
	}
	if got := payload["truncation_side"]; got != "left" {
		t.Fatalf("truncation_side = %#v, want left", got)
	}
}

func TestApplyFastAuditDefaultsDoesNotLeakQwenFieldsToOtherModels(t *testing.T) {
	engine := &AuditEngine{
		outputMaxTokens:      128,
		disableThinking:      true,
		promptTruncateTokens: 260000,
	}
	payload := map[string]any{}
	engine.applyFastAuditDefaults(AuditProfile{Model: "gpt-4.1-mini"}, payload)

	if _, ok := payload["chat_template_kwargs"]; ok {
		t.Fatal("non-Qwen model received chat_template_kwargs")
	}
	if _, ok := payload["truncate_prompt_tokens"]; ok {
		t.Fatal("non-Qwen model received truncate_prompt_tokens")
	}
	if got := payload["max_tokens"]; got != 128 {
		t.Fatalf("max_tokens = %#v, want 128", got)
	}
}

func TestAuditRequestTimeoutRaisesOnlyForLongInput(t *testing.T) {
	engine := &AuditEngine{
		longContextThresholdBytes: 128 * 1024,
		longContextTimeout:        120 * time.Second,
	}
	profile := AuditProfile{TimeoutMS: 8000}
	if got := engine.auditRequestTimeout(profile, 64*1024); got != 8*time.Second {
		t.Fatalf("short timeout = %s, want 8s", got)
	}
	if got := engine.auditRequestTimeout(profile, 178922); got != 120*time.Second {
		t.Fatalf("long timeout = %s, want 120s", got)
	}
}

func TestAuditUserContentAppendsNoThinkForQwen(t *testing.T) {
	engine := &AuditEngine{disableThinking: true}
	got := engine.auditUserContent(AuditProfile{Model: "qwen3.8-27b"}, "request")
	if !strings.Contains(got, "/no_think") {
		t.Fatalf("Qwen audit content missing /no_think: %q", got)
	}
	if got := engine.auditUserContent(AuditProfile{Model: "other"}, "request"); got != "request" {
		t.Fatalf("non-Qwen content changed: %q", got)
	}
}

func TestAppendFastAuditDirectiveIsIdempotent(t *testing.T) {
	first := appendFastAuditDirective("custom policy")
	second := appendFastAuditDirective(first)
	if first != second {
		t.Fatal("fast audit directive was appended more than once")
	}
	if !strings.Contains(first, "Do not reveal chain-of-thought") {
		t.Fatalf("directive missing no-thinking requirement: %q", first)
	}
}
