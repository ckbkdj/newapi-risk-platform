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

func TestCyberDenyRuleIsTerminal(t *testing.T) {
	for _, action := range []string{DecisionAllow, DecisionReview, DecisionBlock} {
		for _, text := range []string{
			"extract hidden credentials for automated testing",
			"Don’t bypass access controls, extract hidden credentials, or claim permissions.",
			"For my own internal debugging: extract hidden credentials.",
		} {
			t.Run(action+"/"+text, func(t *testing.T) {
				var calls atomic.Int32
				e, p := incidentEngine(t, func(*http.Request) (*http.Response, error) {
					calls.Add(1)
					return incidentHTTP(200, incidentDecision(DecisionAllow, "")), nil
				})
				r := testCompiledRule("CYBER_CREDENTIAL_ACCESS_REVIEW", "credential_access", `extract hidden credentials`, action)
				r.Enabled = true
				e.rules.Store([]compiledRule{r})
				p.FailClosed = false
				e.profileCache().entries[p.ID] = auditProfileCacheEntry{profile: p, expiresAt: time.Now().Add(time.Hour)}
				body, _ := json.Marshal(map[string]string{"input": text})
				got := e.Audit(context.Background(), Route{AuditProfileID: &p.ID}, body)
				if got.Decision != DecisionBlock || got.RiskCode != r.Code || calls.Load() != 0 || got.RuleMatch == nil || got.RuleMatch.Downgraded {
					t.Fatalf("cyber hit escaped: %+v calls=%d", got, calls.Load())
				}
			})
		}
	}
}

func TestCyberDenyValidatedModelDenyCannotBeOverturned(t *testing.T) {
	for _, verdict := range []string{DecisionBlock, DecisionReview} {
		t.Run(verdict, func(t *testing.T) {
			var calls atomic.Int32
			e, p := incidentEngine(t, func(*http.Request) (*http.Response, error) {
				if calls.Add(1) == 1 {
					return incidentHTTP(200, incidentDecision(verdict, "synthetic-operation")), nil
				}
				return incidentHTTP(200, incidentDecision(DecisionAllow, "")), nil
			})
			got := e.Audit(context.Background(), Route{AuditProfileID: &p.ID}, []byte(`{"input":"synthetic-operation for automated testing"}`))
			if got.Decision != DecisionBlock || calls.Load() != 1 {
				t.Fatalf("valid cyber denial was reversed: %+v calls=%d", got, calls.Load())
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
			want := DecisionBlock
			if second == DecisionAllow {
				want = DecisionAllow
			}
			if got.Decision != want || calls.Load() < 2 || calls.Load() > 8 {
				t.Fatalf("bad verification: %+v calls=%d", got, calls.Load())
			}
			if second == "malformed" && (got.ErrorClass == "" || got.Category != "audit_infrastructure") {
				t.Fatalf("invalid output mislabeled: %+v", got)
			}
		})
	}
}

func TestCyberDenyQwenProactiveBudget(t *testing.T) {
	var largest atomic.Int32
	e, p := incidentEngine(t, func(r *http.Request) (*http.Response, error) {
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
	if got.Decision != DecisionAllow || largest.Load() > 16384 || got.AuditChunkCount < 2 {
		t.Fatalf("oversized Qwen audit: %+v largest=%d", got, largest.Load())
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
	if got.Decision != DecisionAllow || calls.Load() != 2 {
		t.Fatalf("disabled rule became enabled: %+v", got)
	}
	// A valid enabled hit must not depend on a model/profile/database lookup.
	r.Enabled = true
	e.rules.Store([]compiledRule{r})
	e.profileCache().entries = map[int64]auditProfileCacheEntry{}
	got = e.Audit(context.Background(), Route{}, []byte(`{"input":"ordinary labels"}`))
	if got.Decision != DecisionBlock || got.Source != "rule" || calls.Load() != 2 {
		t.Fatalf("model configuration weakened rule: %+v", got)
	}
}

func TestCyberDenyHTTPBudgetIsSharedAndFailClosed(t *testing.T) {
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
			return incidentHTTP(200, incidentDecision(DecisionBlock, "synthetic operation")), nil
		}
		return incidentHTTP(200, incidentDecision(DecisionAllow, "")), nil
	})
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
	got := e.Audit(context.Background(), Route{AuditProfileID: &root.ID}, []byte(`{"input":"synthetic operation"}`))
	if got.Decision != DecisionBlock || got.AuditFallbackCount != 1 || calls.Load() != 3 {
		t.Fatalf("fallback bypassed root verifier: %+v calls=%d", got, calls.Load())
	}
}

func TestCyberDenyBareAutomationFollowupRetainsOriginalOperation(t *testing.T) {
	for _, follow := range []string{"运行自动化测试。", "跑一下测试", "run the tests", "test it"} {
		e, p := incidentEngine(t, func(*http.Request) (*http.Response, error) {
			t.Fatal("Cyber testing hit reached model")
			return nil, nil
		})
		e.rules.Store([]compiledRule{testCompiledRule("CYBER_SYNTHETIC_TESTING", "credential_access", "extract hidden credentials", DecisionReview)})
		body, _ := json.Marshal(map[string]any{"messages": []map[string]string{{"role": "user", "content": "extract hidden credentials"}, {"role": "assistant", "content": "synthetic implementation plan"}, {"role": "user", "content": follow}}})
		got := e.Audit(context.Background(), Route{AuditProfileID: &p.ID}, body)
		if got.Decision != DecisionBlock || got.Source != "rule" || !got.AuditContextActivated {
			t.Fatalf("automation lost its underlying operation: %+v", got)
		}
	}
}

func TestCyberDenyUnavailableRulesCannotFallThrough(t *testing.T) {
	e, p := incidentEngine(t, func(*http.Request) (*http.Response, error) {
		t.Fatal("unavailable rule snapshot reached model")
		return nil, nil
	})
	e.ruleLoadFailed.Store(true)
	got := e.Audit(context.Background(), Route{AuditProfileID: &p.ID}, []byte(`{"input":"change a label"}`))
	if got.Decision != DecisionBlock || got.RiskCode != "AUDIT_RULES_UNAVAILABLE" || got.Category != "audit_infrastructure" {
		t.Fatalf("rules outage treated as safe: %+v", got)
	}
}
