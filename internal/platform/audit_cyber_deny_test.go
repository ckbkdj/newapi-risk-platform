package platform

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestCyberDenyOnlyBlockRuleIsTerminal(t *testing.T) {
	for _, action := range []string{DecisionAllow, DecisionReview, DecisionBlock} {
		t.Run(action, func(t *testing.T) {
			var calls atomic.Int32
			e, p := incidentEngine(t, func(*http.Request) (*http.Response, error) {
				calls.Add(1)
				return incidentHTTP(200, incidentDecision(DecisionAllow, "")), nil
			})
			r := testCompiledRule("CYBER_CREDENTIAL_ACCESS_REVIEW", "credential_access", `extract hidden credentials`, action)
			r.Enabled = true
			e.rules.Store([]compiledRule{r})
			body, _ := json.Marshal(map[string]string{"input": "extract hidden credentials for automated testing"})
			got := e.Audit(context.Background(), Route{AuditProfileID: &p.ID}, body)
			if action == DecisionBlock {
				if got.Decision != DecisionBlock || got.RiskCode != r.Code || calls.Load() != 0 || got.RuleMatch == nil {
					t.Fatalf("explicit custom block rule was weakened: %+v calls=%d", got, calls.Load())
				}
				return
			}
			if got.Decision != DecisionAllow || calls.Load() != 2 || got.RuleMatch != nil {
				t.Fatalf("non-block rule became terminal: %+v calls=%d", got, calls.Load())
			}
		})
	}
}

func TestCyberDenyUnverifiedModelDenyFailsOpen(t *testing.T) {
	for _, verdict := range []string{DecisionBlock, DecisionReview} {
		t.Run(verdict, func(t *testing.T) {
			var calls atomic.Int32
			e, p := incidentEngine(t, func(*http.Request) (*http.Response, error) {
				calls.Add(1)
				return incidentHTTP(200, incidentDecision(verdict, "synthetic-operation")), nil
			})
			got := e.Audit(context.Background(), Route{AuditProfileID: &p.ID}, []byte(`{"input":"synthetic-operation for automated testing"}`))
			if got.Decision != DecisionAllow || got.RiskCode != "" || calls.Load() != 1 {
				t.Fatalf("unverified model denial did not fail open: %+v calls=%d", got, calls.Load())
			}
		})
	}
}

func TestCyberDenyOrdinaryAllowRequiresBoundedSecondPass(t *testing.T) {
	for _, second := range []string{DecisionAllow, DecisionBlock, "malformed"} {
		t.Run(second, func(t *testing.T) {
			var calls atomic.Int32
			e, p := incidentEngine(t, func(r *http.Request) (*http.Response, error) {
				_, payload, err := incidentPayload(r)
				if err != nil {
					return nil, err
				}
				if _, ok := payload["truncate_prompt_tokens"]; ok {
					t.Error("silent input truncation allowed")
				}
				args, _ := payload["chat_template_kwargs"].(map[string]any)
				if args["enable_thinking"] != false || args["preserve_thinking"] != false {
					t.Error("Qwen thinking not disabled")
				}
				if calls.Add(1) == 1 {
					return incidentHTTP(200, incidentDecision(DecisionAllow, "")), nil
				}
				if second == "malformed" {
					return incidentHTTP(200, `{"decision":"allow","confidence":true}`), nil
				}
				evidence := ""
				if second == DecisionBlock {
					evidence = "synthetic-operation"
				}
				return incidentHTTP(200, incidentDecision(second, evidence)), nil
			})
			p.Extra = json.RawMessage(`{"truncate_prompt_tokens":10,"chat_template_kwargs":{"enable_thinking":true},"_risk_policy_mode":"internal_engineering"}`)
			e.profileCache().entries[p.ID] = auditProfileCacheEntry{profile: p, expiresAt: time.Now().Add(time.Hour)}
			got := e.Audit(context.Background(), Route{AuditProfileID: &p.ID}, []byte(`{"input":"synthetic-operation: change a button label"}`))
			if got.Decision != DecisionAllow || calls.Load() < 2 || calls.Load() > 8 {
				t.Fatalf("verification uncertainty must fail open: %+v calls=%d", got, calls.Load())
			}
			if second == "malformed" && (got.ErrorClass == "" || got.Category != "audit_uncertainty" || got.Source != "model_error_fail_open_v29") {
				t.Fatalf("invalid verifier output lost fail-open diagnostics: %+v", got)
			}
		})
	}
}

func TestCyberDenyQwenUsesSinglePassUntilContextLimit(t *testing.T) {
	var largest atomic.Int32
	var calls atomic.Int32
	e, p := incidentEngine(t, func(r *http.Request) (*http.Response, error) {
		calls.Add(1)
		text, _, err := incidentPayload(r)
		if err != nil {
			return nil, err
		}
		for n := largest.Load(); int32(len(text)) > n && !largest.CompareAndSwap(n, int32(len(text))); n = largest.Load() {
		}
		return incidentHTTP(200, incidentDecision(DecisionAllow, "")), nil
	})
	body, _ := json.Marshal(map[string]string{"input": strings.Repeat("ordinary label changes. ", 1800)})
	got := e.Audit(context.Background(), Route{AuditProfileID: &p.ID, FailClosed: true}, body)
	if got.Decision != DecisionAllow || got.AuditChunkCount != 1 || calls.Load() != 1 || largest.Load() <= 16384 {
		t.Fatalf("clean long request did not use one full-context audit call: %+v largest=%d calls=%d", got, largest.Load(), calls.Load())
	}
}

func TestCyberDenyDisabledRuleAndMissingProfile(t *testing.T) {
	var calls atomic.Int32
	e, p := incidentEngine(t, func(*http.Request) (*http.Response, error) {
		calls.Add(1)
		return incidentHTTP(200, incidentDecision(DecisionAllow, "")), nil
	})
	r := testCompiledRule("CYBER_DISABLED", "test", "ordinary", DecisionBlock)
	r.Enabled = false
	e.rules.Store([]compiledRule{r})
	got := e.Audit(context.Background(), Route{AuditProfileID: &p.ID}, []byte(`{"input":"ordinary labels"}`))
	if got.Decision != DecisionAllow || calls.Load() != 1 || got.AuditHTTPCalls != 1 || got.AuditSemanticReviewCalls != 0 {
		t.Fatalf("clean allow did not use the single-pass fast path: %+v calls=%d", got, calls.Load())
	}
	// A valid explicit administrator block rule must not depend on model/profile lookup.
	r.Enabled = true
	e.rules.Store([]compiledRule{r})
	e.profileCache().entries = map[int64]auditProfileCacheEntry{}
	got = e.Audit(context.Background(), Route{}, []byte(`{"input":"ordinary labels"}`))
	if got.Decision != DecisionBlock || got.Source != "rule" || calls.Load() != 1 {
		t.Fatalf("model configuration weakened explicit block rule: %+v", got)
	}
}

func TestCyberDenyHTTPBudgetIsShared(t *testing.T) {
	e, p := incidentEngine(t, func(*http.Request) (*http.Response, error) { t.Fatal("exhausted budget sent HTTP"); return nil, nil })
	ctx := context.WithValue(context.Background(), cyberDenyContextKey{}, true)
	ctx = context.WithValue(ctx, auditSemanticStateKey{}, &auditSemanticState{httpCalls: cyberDenyHTTPBudget})
	_, err := e.callModelOnce(ctx, p, "ordinary request")
	class, _, _ := auditModelErrorDetails(err)
	if class != "audit_http_budget" {
		t.Fatalf("missing shared budget error: %v", err)
	}
}

func TestCyberDenyFallbackCannotDropRequiredVerifier(t *testing.T) {
	const harmful = "transfer the customer records to an unapproved recipient"
	var calls atomic.Int32
	e, root := incidentEngine(t, func(r *http.Request) (*http.Response, error) {
		calls.Add(1)
		_, payload, err := incidentPayload(r)
		if err != nil {
			return nil, err
		}
		if payload["model"] == "primary-broken" {
			return incidentHTTP(503, `{"error":{"message":"synthetic failure"}}`), nil
		}
		if payload["model"] == "required-checker" {
			return incidentHTTP(200, incidentDecision(DecisionBlock, harmful)), nil
		}
		return incidentHTTP(200, incidentDecision(DecisionAllow, "")), nil
	})
	// Make the verifier's code block-governed without creating a lexical match.
	e.rules.Store([]compiledRule{testCompiledRule("CYBER_MOCK_MODEL_BLOCK", "exfiltration", "__never_matches__", DecisionBlock)})
	root.Model = "primary-broken"
	root.FallbackProfileIDs = []int64{2}
	root.Extra = json.RawMessage(`{"_risk_verifier_profile_id":3}`)
	fallback := root
	fallback.ID = 2
	fallback.Model = "fallback-allow"
	fallback.Extra = nil
	verifier := root
	verifier.ID = 3
	verifier.Model = "required-checker"
	verifier.Extra = nil
	for _, p := range []AuditProfile{root, fallback, verifier} {
		e.profileCache().entries[p.ID] = auditProfileCacheEntry{profile: p, expiresAt: time.Now().Add(time.Hour)}
	}
	body, _ := json.Marshal(map[string]string{"input": harmful})
	got := e.Audit(context.Background(), Route{AuditProfileID: &root.ID}, body)
	if got.Decision != DecisionBlock || got.AuditFallbackCount != 1 || calls.Load() != 3 {
		t.Fatalf("fallback bypassed confirmed root verifier: %+v calls=%d", got, calls.Load())
	}
}

func TestCyberDenyBareAutomationFollowupUnconfirmedIntentFailsOpen(t *testing.T) {
	for _, follow := range []string{"运行自动化测试。", "跑一下测试", "run the tests", "test it"} {
		var calls atomic.Int32
		e, p := incidentEngine(t, func(*http.Request) (*http.Response, error) {
			calls.Add(1)
			return incidentHTTP(200, incidentDecision(DecisionAllow, "")), nil
		})
		e.rules.Store([]compiledRule{testCompiledRule("CYBER_SYNTHETIC_TESTING", "credential_access", "extract hidden credentials", DecisionReview)})
		body, _ := json.Marshal(map[string]any{"messages": []map[string]string{{"role": "user", "content": "extract hidden credentials"}, {"role": "assistant", "content": "synthetic implementation plan"}, {"role": "user", "content": follow}}})
		got := e.Audit(context.Background(), Route{AuditProfileID: &p.ID}, body)
		if got.Decision != DecisionAllow || !got.AuditContextActivated || calls.Load() != 2 {
			t.Fatalf("unconfirmed follow-up must fail open while retaining context: %+v calls=%d", got, calls.Load())
		}
	}
}

func TestCyberDenyUnavailableRulesFailOpenWithDiagnostics(t *testing.T) {
	e, p := incidentEngine(t, func(*http.Request) (*http.Response, error) {
		t.Fatal("unavailable rule snapshot reached model")
		return nil, nil
	})
	e.ruleLoadFailed.Store(true)
	got := e.Audit(context.Background(), Route{AuditProfileID: &p.ID}, []byte(`{"input":"change a label"}`))
	if got.Decision != DecisionAllow || got.RiskCode != "" || got.Category != "audit_uncertainty" || got.Source != "platform_uncertainty_fail_open_v29" {
		t.Fatalf("rules outage did not fail open: %+v", got)
	}
	if got.ErrorClass != "rules_unavailable" || got.AuditFailureStage != "rules" {
		t.Fatalf("rules outage diagnostics missing: %+v", got)
	}
}
