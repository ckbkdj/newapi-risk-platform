package platform

import (
	"context"
	"encoding/json"
	"net/http"
	"sync/atomic"
	"testing"
)

// A terminal synthetic verdict must remain distinct from the ordinary primitive
// it follows. The existing real-operation and all grounding-failure tests remain.
func TestV15TerminalFixtureStopsBeforeAnotherVerification(t *testing.T) {
	const marker = "V15_SYNTHETIC_TERMINAL_VETO"
	for _, c := range v15Cases(t)[6:] {
		for _, phase := range []int32{1, 2} {
			for _, review := range []bool{false, true} {
				var calls atomic.Int32
				e, p := incidentEngine(t, func(*http.Request) (*http.Response, error) {
					n := calls.Add(1)
					if n == phase {
						return incidentHTTP(200, v15Vote(c, DecisionBlock, c.Quote)), nil
					}
					if n == phase+1 {
						decision := DecisionBlock
						if review {
							decision = DecisionReview
						}
						d := AuditDecision{Decision: decision, RiskCode: "CYBER_MOCK_TERMINAL", Category: "synthetic_test", Confidence: .99, Reason: "synthetic terminal veto", Evidence: marker}
						b, _ := json.Marshal(d)
						return incidentHTTP(200, string(b)), nil
					}
					return incidentHTTP(200, v15Vote(c, DecisionAllow, "")), nil
				})
				b, _ := json.Marshal(map[string]string{"input": c.Text + "\n" + marker})
				got := e.Audit(context.Background(), Route{AuditProfileID: &p.ID}, b)
				if got.Decision != DecisionBlock || got.ErrorClass != "" || got.RiskCode != "CYBER_MOCK_TERMINAL" || calls.Load() != phase+1 {
					t.Fatalf("%s phase=%d review=%v: decision=%s error=%s code=%s calls=%d", c.ID, phase, review, got.Decision, got.ErrorClass, got.RiskCode, calls.Load())
				}
			}
		}
	}
}
