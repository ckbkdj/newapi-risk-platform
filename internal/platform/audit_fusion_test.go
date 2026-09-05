package platform

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync/atomic"
	"testing"
	"time"
)

func TestFusionPanelConsensusDisagreementAndFreshAdjudication(t *testing.T) {
	const text = "检查工作流状态"
	for _, tc := range []struct {
		name                    string
		votes                   map[string]string
		arbiter                 bool
		decision, status, class string
		calls                   int32
	}{
		{"consensus-allow", map[string]string{"v2": "allow", "v3": "allow"}, false, "allow", "consensus", "", 3},
		{"consensus-block", map[string]string{"v2": "block", "v3": "block"}, false, "block", "consensus", "", 3},
		{"disagree-review", map[string]string{"v2": "allow", "v3": "block"}, false, "block", "unresolved", "", 3},
		{"adjudicated-allow", map[string]string{"v2": "allow", "v3": "block", "v4": "allow"}, true, "allow", "adjudicated", "", 4},
		{"adjudicated-block", map[string]string{"v2": "allow", "v3": "block", "v4": "block"}, true, "block", "adjudicated", "", 4},
		{"invalid-vote", map[string]string{"v2": "allow", "v3": "invalid"}, false, "block", "error", "fusion_incomplete", 4},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var calls atomic.Int32
			engine, root := incidentEngine(t, func(r *http.Request) (*http.Response, error) {
				calls.Add(1)
				_, payload, err := incidentPayload(r)
				if err != nil {
					return nil, err
				}
				model := payload["model"].(string)
				if !isSemanticPayload(payload) {
					return incidentHTTP(200, incidentDecision(DecisionBlock, text)), nil
				}
				kind := tc.votes[model]
				switch kind {
				case "allow":
					return incidentHTTP(200, semanticTestJSON(DecisionAllow, "", text, "no_harm", "none")), nil
				case "block":
					return incidentHTTP(200, semanticTestJSON(DecisionBlock, text, text, "direct_request", "unauthorized_access")), nil
				default:
					return incidentHTTP(200, `{"decision":"allow","confidence":true}`), nil
				}
			})
			extra := map[string]any{"_risk_policy_mode": "internal_engineering", "_risk_fusion_profile_ids": []int{2, 3}}
			if tc.arbiter {
				extra["_risk_fusion_adjudicator_profile_id"] = 4
			}
			root.Extra, _ = json.Marshal(extra)
			for id := int64(2); id <= 4; id++ {
				p := root
				p.ID = id
				p.Model = fmt.Sprintf("v%d", id)
				engine.profileCache().entries[id] = auditProfileCacheEntry{profile: p, expiresAt: time.Now().Add(time.Hour)}
			}
			engine.profileCache().entries[1] = auditProfileCacheEntry{profile: root, expiresAt: time.Now().Add(time.Hour)}
			body, _ := json.Marshal(map[string]string{"input": text})
			result := engine.Audit(context.Background(), Route{AuditProfileID: &root.ID, FailClosed: true}, body)
			if result.Decision != tc.decision || result.ErrorClass != tc.class || calls.Load() != tc.calls {
				t.Fatalf("wrong result: %+v calls=%d", result, calls.Load())
			}
			if len(result.AuditSemanticReviews) != 1 || result.AuditSemanticReviews[0].Fusion.Status != tc.status {
				t.Fatalf("missing fusion trace: %+v", result)
			}
			if tc.name == "disagree-review" && result.Category != "audit_uncertainty" {
				t.Fatal("disagreement labelled as proven harm")
			}
		})
	}
}

func TestFusionRejectsDuplicateAndMalformedConfig(t *testing.T) {
	for _, raw := range []string{`{"_risk_fusion_profile_ids":[1]}`, `{"_risk_fusion_profile_ids":[1,1]}`, `{"_risk_fusion_profile_ids":[1,"2"]}`, `{"_risk_fusion_profile_ids":[1,2],"_risk_fusion_adjudicator_profile_id":2}`, `{"_risk_fusion_adjudicator_profile_id":3}`} {
		if validateFusionExtra(json.RawMessage(raw)) == nil {
			t.Fatalf("accepted bad config %s", raw)
		}
	}
	engine, root := incidentEngine(t, func(*http.Request) (*http.Response, error) { t.Fatal("network should not be called"); return nil, nil })
	root.Extra = json.RawMessage(`{"_risk_fusion_profile_ids":[1,2]}`)
	p := root
	p.ID = 2
	engine.profileCache().entries[2] = auditProfileCacheEntry{profile: p, expiresAt: time.Now().Add(time.Hour)}
	if _, _, err := engine.auditFusionProfiles(context.Background(), root); err == nil {
		t.Fatal("same model endpoint counted twice")
	}
}

func TestFusionBudgetBoundedAndErrorsNeverDisappear(t *testing.T) {
	engine, profile := incidentEngine(t, func(*http.Request) (*http.Response, error) {
		t.Fatal("budget exhaustion must not send HTTP")
		return nil, nil
	})
	state := &auditSemanticState{reviewCalls: maxAuditSemanticCalls}
	_, _, err := engine.verifyAuditIntent(context.Background(), profile, "x", "x", state)
	class, _, _ := auditModelErrorDetails(err)
	if class != "semantic_review_budget" {
		t.Fatalf("missing budget error: %v", err)
	}
}

func TestFusionFailureCannotEscapeThroughUnconfiguredFallback(t *testing.T) {
	var calls atomic.Int32
	engine, root := incidentEngine(t, func(*http.Request) (*http.Response, error) {
		calls.Add(1)
		return incidentHTTP(200, incidentDecision(DecisionBlock, "检查工作流")), nil
	})
	root.Extra = json.RawMessage(`{"_risk_fusion_profile_ids":[1,1]}`)
	root.FallbackProfileIDs = []int64{5}
	fallback := root
	fallback.ID = 5
	fallback.Extra = nil
	engine.profileCache().entries[5] = auditProfileCacheEntry{profile: fallback, expiresAt: time.Now().Add(time.Hour)}
	_, _, metadata, err := engine.callModelWithFailover(context.Background(), root, "检查工作流")
	class, _, _ := auditModelErrorDetails(err)
	if class != "fusion_configuration" || calls.Load() != 1 || metadata.FallbackCount != 0 {
		t.Fatalf("required fusion bypassed: %s calls=%d metadata=%+v", class, calls.Load(), metadata)
	}
}
