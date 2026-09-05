package platform

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestApplyFastAuditDefaultsForQwen(t *testing.T) {
	engine := &AuditEngine{
		outputMaxTokens: 128,
		disableThinking: true,
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
	if _, ok := payload["truncate_prompt_tokens"]; ok {
		t.Fatal("request must not silently truncate prompt tokens")
	}
	if _, ok := payload["truncation_side"]; ok {
		t.Fatal("request must not silently truncate either side")
	}
}

func TestQwenAliasCanEnableFastModeWithoutLeakingInternalExtra(t *testing.T) {
	extra, _ := json.Marshal(map[string]any{"_risk_qwen_fast_mode": true})
	profile := AuditProfile{Model: "audit-fast", Extra: extra}
	engine := &AuditEngine{outputMaxTokens: 128, disableThinking: true}
	payload := map[string]any{}
	engine.applyFastAuditDefaults(profile, payload)
	arguments, ok := payload["chat_template_kwargs"].(map[string]any)
	if !ok || arguments["enable_thinking"] != false {
		t.Fatalf("Qwen alias did not enable no-thinking: %#v", payload)
	}
	if !isInternalAuditExtraKey("_risk_qwen_fast_mode") {
		t.Fatal("internal audit extra key was not recognized")
	}
}

func TestApplyFastAuditDefaultsDoesNotLeakQwenFieldsToOtherModels(t *testing.T) {
	engine := &AuditEngine{outputMaxTokens: 128, disableThinking: true}
	payload := map[string]any{}
	engine.applyFastAuditDefaults(AuditProfile{Model: "gpt-4.1-mini"}, payload)

	if _, ok := payload["chat_template_kwargs"]; ok {
		t.Fatal("non-Qwen model received chat_template_kwargs")
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

func TestAuditUserContentIsOnlyARequestDocument(t *testing.T) {
	engine := &AuditEngine{disableThinking: true}
	for _, model := range []string{"qwen3.8-27b", "other"} {
		for _, attempt := range []int{0, 1, 2} {
			text := "request with \"quotes\" and a newline\nend"
			got := engine.auditUserContentWithPlan(AuditProfile{Model: model}, text, auditOutputPlan{Attempt: attempt})
			var document auditRequestDocument
			if json.Unmarshal([]byte(got), &document) != nil || document.Schema != auditInputContractVersion || document.RequestText != text {
				t.Fatalf("altered user data: %s", got)
			}
			if strings.Contains(got, "/no_think") || strings.Contains(got, "FORMAT RECOVERY") || strings.Contains(got, "Return only the compact policy") {
				t.Fatal("platform instruction leaked into user data")
			}
		}
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
