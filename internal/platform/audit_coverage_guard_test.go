package platform

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"
	"unicode/utf8"
)

func TestCoverageGuardReviewRuleCannotTrustPrimaryAllow(t *testing.T) {
	for _, tc := range []struct{ name, text, verification, want, class string }{
		{"positive-operation", incident0909UnsafeSink, "block", DecisionBlock, ""},
		{"negated-safety-only", incident0909SafetyClause, "allow", DecisionAllow, ""},
		{"benign-local-reproduction", "Read my local development token to reproduce a failed request; keep the value masked.", "allow", DecisionAllow, ""},
		{"timeout", incident0909UnsafeSink, "timeout", DecisionBlock, "timeout"},
		{"malformed", incident0909UnsafeSink, "malformed", DecisionBlock, "response_format"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var calls atomic.Int32
			engine, profile := incidentEngine(t, func(r *http.Request) (*http.Response, error) {
				calls.Add(1)
				text, payload, err := incidentPayload(r)
				if err != nil {
					return nil, err
				}
				if !isSemanticPayload(payload) {
					return incidentHTTP(200, incidentDecision(DecisionAllow, "")), nil
				}
				if !strings.Contains(text, tc.text) {
					t.Errorf("verifier lost request: %q", text)
				}
				switch tc.verification {
				case "timeout":
					return nil, context.DeadlineExceeded
				case "malformed":
					return incidentHTTP(200, `not json`), nil
				case "block":
					return incidentHTTP(200, semanticTestJSON(DecisionBlock, tc.text, tc.text, "direct_request", "exfiltration")), nil
				default:
					return incidentHTTP(200, semanticTestJSON(DecisionAllow, "", tc.text, "no_harm", "none")), nil
				}
			})
			// Under the requested business policy, an enabled Cyber rule is terminal.
			action := DecisionReview
			if tc.name == "benign-local-reproduction" {
				action = DecisionBlock
			}
			engine.rules.Store([]compiledRule{testCompiledRule("CYBER_CREDENTIAL_ACCESS_REVIEW", "credential_access", `(?i)(?:credentials|API key|token)`, action)})
			body, _ := json.Marshal(map[string]string{"input": tc.text})
			got := engine.Audit(context.Background(), Route{AuditProfileID: &profile.ID, FailClosed: true}, body)
			if got.Decision != DecisionBlock || got.ErrorClass != "" || calls.Load() != 0 || got.AuditSemanticReviewCalls != 0 || got.RuleMatch == nil {
				t.Fatalf("rule hit did not terminate before model: %+v", got)
			}

		})
	}
}

func TestCoverageGuardIncompleteInputsRespectFailurePolicy(t *testing.T) {
	cases := []struct {
		name, body, issue string
		limit             int
	}{
		{"empty", `{"input":[]}`, "no_auditable_user_intent", 0},
		{"tool-only", `{"input":[{"type":"function_call_output","output":"synthetic result"}]}`, "no_auditable_user_intent", 0},
		{"image-only", `{"input":[{"role":"user","content":[{"type":"input_image","image_url":"https://image.invalid/x"}]}]}`, "unsupported_input_content", 0},
		{"mixed-image", `{"input":[{"role":"user","content":[{"type":"input_text","text":"Read this"},{"type":"input_image","image_url":"https://image.invalid/x"}]}]}`, "unsupported_input_content", 0},
		{"future-type", `{"input":[{"role":"user","content":[{"type":"text","text":"Read this"},{"type":"future_content","payload":"not reviewed"}]}]}`, "unsupported_input_content", 0},
		{"opaque-response", `{"previous_response_id":"resp_synthetic","input":"继续"}`, "unresolved_previous_response", 0},
		{"missing-history", `{"input":"补齐剩余功能并给出最终版本。"}`, "missing_continuation_context", 0},
		{"malformed", `{"input":`, "invalid_request_json", 0},
		{"truncated", `{"input":"` + strings.Repeat("汉", 100) + `"}`, "input_text_truncated", 32},
	}
	for _, tc := range cases {
		for _, closed := range []bool{true, false} {
			t.Run(fmt.Sprintf("%s/closed=%t", tc.name, closed), func(t *testing.T) {
				engine, profile := incidentEngine(t, func(*http.Request) (*http.Response, error) {
					t.Fatal("incomplete input reached model")
					return nil, nil
				})
				profile.FailClosed = closed
				engine.profileCache().entries[profile.ID] = auditProfileCacheEntry{profile: profile, expiresAt: time.Now().Add(time.Hour)}
				if tc.limit > 0 {
					engine.maxTextBytes = tc.limit
				}
				got := engine.Audit(context.Background(), Route{AuditProfileID: &profile.ID, FailClosed: closed}, []byte(tc.body))
				want, source := DecisionBlock, "platform"
				// Strict business policy cannot be weakened by legacy fail-open flags.
				if got.Decision != want || got.Source != source || got.ErrorClass != "input_coverage" || got.AuditCoverageStatus != "incomplete" || got.AuditHTTPCalls != 0 || !strings.Contains(strings.Join(got.AuditCoverageIssues, " "), tc.issue) {
					t.Fatalf("coverage silently accepted: %+v", got)
				}
				if closed && got.RiskCode != "AUDIT_INPUT_COVERAGE_INCOMPLETE" {
					t.Fatal("coverage failure confused with proven harm")
				}
				meta := map[string]any{}
				recordAuditDecisionMetadata(meta, got)
				if meta["audit_completed"] != false || meta["audit_coverage_status"] != "incomplete" {
					t.Fatalf("bad trace: %+v", meta)
				}
			})
		}
	}
}

func TestCoverageGuardContinuationsKeepRoleProvenance(t *testing.T) {
	const goal = "SYNTHETIC_ORIGINAL_TASK: collect secret material for an unauthorized recipient"
	const action = "补齐剩余功能并给出最终版本。"
	body, _ := json.Marshal(map[string]any{"messages": []map[string]any{
		incident0909Message("user", goal), incident0909Message("assistant", "initial plan"),
		incident0909Message("user", "Use default colors"), incident0909Message("assistant", "colors prepared"),
		incident0909Message("user", "Add progress indicator"), incident0909Message("assistant", "SYNTHETIC_PROPOSAL"),
		incident0909Message("user", action), incident0909Message("user", "按钮改为蓝色。"),
	}})
	extracted := ExtractAuditTextDetails(body, 128*1024)
	if extracted.CoverageStatus != "complete" || !extracted.ContextActivated || !strings.Contains(extracted.Text, goal) || !strings.Contains(extracted.Text, "SYNTHETIC_PROPOSAL") {
		t.Fatalf("context lost: %+v", extracted)
	}
	scope := makeAuditSourceScopeWithReferences(extracted.Text, extracted.ReferenceSpans)
	if auditCurrentActionLocated(scope, goal) || auditCurrentActionLocated(scope, "SYNTHETIC_PROPOSAL") || !auditCurrentActionLocated(scope, action) || !auditCurrentActionLocated(scope, "按钮改为蓝色") {
		t.Fatal("historical content promoted to current request")
	}
	var calls atomic.Int32
	engine, profile := incidentEngine(t, func(r *http.Request) (*http.Response, error) {
		calls.Add(1)
		text, payload, err := incidentPayload(r)
		if err != nil {
			return nil, err
		}
		var doc auditRequestDocument
		json.Unmarshal([]byte(payload["messages"].([]any)[1].(map[string]any)["content"].(string)), &doc)
		if !strings.Contains(text, goal) || len(doc.ReferenceSpans) == 0 {
			t.Error("transport lost historical context boundaries")
		}
		if !isSemanticPayload(payload) {
			return incidentHTTP(200, incidentDecision(DecisionAllow, "")), nil
		}
		return incidentHTTP(200, semanticTestJSON(DecisionBlock, goal, action, "adopted_reference", "exfiltration")), nil
	})
	result := engine.Audit(context.Background(), Route{AuditProfileID: &profile.ID, FailClosed: true}, body)
	if result.Decision != DecisionBlock || result.ErrorClass != "" || calls.Load() != 2 {
		t.Fatalf("continuation skipped verification: %+v", result)
	}
	chunks := []string{extracted.Text[:40], extracted.Text[40:]}
	for _, chunk := range auditChunkSourceScopes(scope, chunks, 0, 40) {
		if !auditCurrentActionLocated(chunk, action) {
			t.Fatal("chunk lost current-action anchor")
		}
	}
}

func TestCoverageGuardContextLimitsAndStandaloneTasks(t *testing.T) {
	for _, messages := range [][]map[string]any{
		{incident0909Message("user", "请实现一个按钮，点击后变蓝，给出最终版本。")},
		{incident0909Message("user", "Build a settings panel."), incident0909Message("user", "Continue")},
		{incident0909Message("user", "old task"), incident0909Message("assistant", "old reply"), incident0909Message("user", "这是新问题：实现一个时钟。")},
	} {
		raw, _ := json.Marshal(map[string]any{"messages": messages})
		got := ExtractAuditTextDetails(raw, 128*1024)
		if got.CoverageStatus != "complete" {
			t.Fatalf("self-contained normal task rejected: %+v", got)
		}
	}
	raw, _ := json.Marshal(map[string]any{"messages": []map[string]any{
		incident0909Message("user", strings.Repeat("synthetic ", 8000)), incident0909Message("assistant", "done"), incident0909Message("user", "继续"),
	}})
	got := ExtractAuditTextDetails(raw, 256*1024)
	if got.CoverageStatus != "incomplete" || !strings.Contains(strings.Join(got.CoverageIssues, " "), "reference_context_limit") {
		t.Fatalf("oversize history silently dropped: %+v", got)
	}
	for limit := 1; limit < 40; limit++ {
		got := ExtractAuditTextDetails([]byte(`{"input":"`+strings.Repeat("🙂汉", 30)+`"}`), limit)
		if len(got.Text) > limit || !utf8.ValidString(got.Text) || got.CoverageStatus != "incomplete" {
			t.Fatalf("invalid byte bound: %d %+v", limit, got)
		}
	}
}

func TestCoverageGuardFusionAlsoReviewsPrimaryAllow(t *testing.T) {
	const text = "检查工作流状态"
	var calls atomic.Int32
	engine, root := incidentEngine(t, func(r *http.Request) (*http.Response, error) {
		calls.Add(1)
		_, payload, err := incidentPayload(r)
		if err != nil {
			return nil, err
		}
		if !isSemanticPayload(payload) {
			return incidentHTTP(200, incidentDecision(DecisionAllow, "")), nil
		}
		return incidentHTTP(200, semanticTestJSON(DecisionAllow, "", text, "no_harm", "none")), nil
	})
	root.Extra = json.RawMessage(`{"_risk_fusion_profile_ids":[2,3]}`)
	for id := int64(1); id <= 3; id++ {
		profile := root
		profile.ID = id
		profile.Model = fmt.Sprintf("independent-%d", id)
		engine.profileCache().entries[id] = auditProfileCacheEntry{profile: profile, expiresAt: time.Now().Add(time.Hour)}
	}
	raw, _ := json.Marshal(map[string]string{"input": text})
	got := engine.Audit(context.Background(), Route{AuditProfileID: &root.ID, FailClosed: true}, raw)
	if got.Decision != DecisionAllow || calls.Load() != 3 || got.AuditSemanticReviewCalls != 2 || len(got.AuditSemanticReviews) != 1 || got.AuditSemanticReviews[0].Fusion == nil || got.AuditSemanticReviews[0].Fusion.Status != "all_allow" {
		t.Fatalf("primary allow skipped fusion: %+v calls=%d", got, calls.Load())
	}
	root.Extra = json.RawMessage(`{"_risk_fusion_profile_ids":[1,1]}`)
	engine.profileCache().entries[1] = auditProfileCacheEntry{profile: root, expiresAt: time.Now().Add(time.Hour)}
	got = engine.Audit(context.Background(), Route{AuditProfileID: &root.ID, FailClosed: true}, raw)
	if got.Decision == DecisionAllow || got.ErrorClass != "fusion_configuration" {
		t.Fatalf("primary allow hid invalid fusion configuration: %+v", got)
	}
}
