package platform

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// Regression: the admin form's custom prompt is supplemental and never replaces
// the fixed Cyber policy or contaminates the evidence-bearing user document.
func TestAuditProfileEditorCustomPromptPreservesCyberPolicy(t *testing.T) {
	engine := &AuditEngine{}
	for _, tc := range []struct {
		name, prompt string
		wantCustom   bool
	}{
		{name: "empty"},
		{name: "legacy built-in", prompt: CyberDenyAuditSystemPrompt},
		{name: "legacy generic", prompt: DefaultAuditSystemPrompt},
		{name: "operator guidance", prompt: "Prefer concise Chinese reasons for benign UI maintenance.", wantCustom: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			profile := cyberDenyProfile(AuditProfile{SystemPrompt: tc.prompt, Extra: json.RawMessage(`{"_risk_policy_mode":"legacy","_risk_allow_user_provided_secrets":true}`)})
			if profile.SystemPrompt != tc.prompt {
				t.Fatal("operator prompt was silently overwritten before dispatch")
			}
			messages := engine.auditMessagesWithPlan(profile, "Update a button label.", auditOutputPlan{})
			if len(messages) != 2 || messages[0]["role"] != "system" || messages[1]["role"] != "user" {
				t.Fatalf("control/user message roles changed: %+v", messages)
			}
			system := messages[0]["content"]
			if !strings.HasPrefix(system, CyberDenyAuditSystemPrompt) || strings.Count(system, CyberDenyAuditSystemPrompt) != 1 {
				t.Fatal("fixed Cyber policy missing or duplicated")
			}
			if tc.wantCustom && (!strings.Contains(system, "ADDITIONAL OPERATOR GUIDANCE") || !strings.Contains(system, tc.prompt)) {
				t.Fatal("operator text missing from supplemental system guidance")
			}
			if !tc.wantCustom && strings.Contains(system, "ADDITIONAL OPERATOR GUIDANCE") {
				t.Fatal("legacy default was reinserted as a custom policy")
			}
			if !strings.Contains(system, "decision=allow|block|review") {
				t.Fatal("mandatory six-field output contract was lost")
			}
			var doc auditRequestDocument
			if err := json.Unmarshal([]byte(messages[1]["content"]), &doc); err != nil || doc.RequestText != "Update a button label." {
				t.Fatalf("evidence source was modified: %v", err)
			}
			if strings.Contains(messages[1]["content"], "Prefer concise Chinese reasons") {
				t.Fatal("operator instructions leaked into request evidence")
			}
			extra := auditProfileExtra(profile)
			if extra["_risk_policy_mode"] != cyberDenyMode || extra["_risk_allow_user_provided_secrets"] != false || !profile.FailClosed {
				t.Fatalf("platform-enforced policy was weakened: %+v", extra)
			}
		})
	}
}

func TestAuditProfileEditorWebControls(t *testing.T) {
	body, err := os.ReadFile("web/index.html")
	if err != nil {
		t.Fatal(err)
	}
	html := string(body)
	if strings.Contains(html, `id="profile-system-prompt" readonly`) ||
		!strings.Contains(html, `id="profile-system-prompt" maxlength="65536"`) {
		t.Fatal("admin system prompt is not editable")
	}
	if strings.Contains(html, `id="profile-threshold" disabled`) ||
		strings.Contains(html, `id="profile-policy-mode" disabled`) {
		t.Fatal("review threshold or audit strategy selector is still locked")
	}
	for _, required := range []string{
		`id="profile-model-options"`,
		`value="cyber_deny_verify_all"`,
		`value="cyber_deny_threshold"`,
		`extra._risk_verify_weak_allows=$('profile-policy-mode').value`,
		`extra._risk_verify_clean_allows=$('profile-policy-mode').value`,
		`id="profile-threshold" type="number"`,
		`editableProfileExtra(extra)`,
		`protectedProfileExtras.has(key)`,
		`额外参数必须是 JSON 对象`,
	} {
		if !strings.Contains(html, required) {
			t.Fatalf("model editor regression: missing %q", required)
		}
	}
}

// Operator UI settings have real effects without replacing hard Cyber vetoes.
func TestAuditProfileEditorVerificationThresholdAndStrategy(t *testing.T) {
	for _, tc := range []struct {
		name                  string
		threshold, confidence float64
		decision              string
		want                  bool
	}{
		{name: "below threshold", threshold: 0.65, confidence: 0.64, decision: DecisionAllow, want: true},
		{name: "at threshold", threshold: 0.65, confidence: 0.65, decision: DecisionAllow},
		{name: "above threshold", threshold: 0.65, confidence: 0.99, decision: DecisionAllow},
		{name: "disabled threshold", threshold: 0, confidence: 0.2, decision: DecisionAllow},
		{name: "block stays terminal", threshold: 0.95, confidence: 0.1, decision: DecisionBlock},
		{name: "qualitative allow has no numeric threshold", threshold: 0.65, confidence: 0, decision: DecisionAllow},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := cyberLowConfidenceAllowNeedsVerification(AuditProfile{BlockThreshold: tc.threshold}, AuditDecision{Decision: tc.decision, Confidence: tc.confidence, ConfidenceKind: map[string]string{"qualitative allow has no numeric threshold": "qualitative"}[tc.name]})
			if got != tc.want {
				t.Fatalf("threshold trigger got=%v want=%v", got, tc.want)
			}
		})
	}
	for _, enhanced := range []bool{false, true} {
		profile := cyberDenyProfile(AuditProfile{Extra: json.RawMessage(`{"_risk_verify_clean_allows":` + map[bool]string{true: "true", false: "false"}[enhanced] + `,"_risk_policy_mode":"legacy"}`)})
		extra := auditProfileExtra(profile)
		if extra["_risk_verify_clean_allows"] != enhanced || extra["_risk_policy_mode"] != cyberDenyMode || !profile.FailClosed {
			t.Fatalf("strategy was not preserved under fixed Cyber policy: %+v", extra)
		}
	}
	for _, weak := range []bool{false, true} {
		mode := "false"
		if weak { mode = "true" }
		profile := cyberDenyProfile(AuditProfile{Extra: json.RawMessage(`{"_risk_verify_weak_allows":` + mode + `}`)})
		if auditProfileExtra(profile)["_risk_verify_weak_allows"] != weak { t.Fatalf("low confidence review mode lost: %v", weak) }
	}

}
