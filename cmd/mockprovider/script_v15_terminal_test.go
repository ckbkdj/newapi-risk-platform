package main

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
)

// Confirm that a fault injected after evidence correction is terminal rather
// than silently changing to allow. Real-operation denials are separate fixtures.
func TestV15TerminalFaultIsNotOrdinaryScriptEvidence(t *testing.T) {
	for _, phase := range []string{"primary", "verifier", "terminal"} {
		for _, failure := range []string{"terminal", "review"} {
			for _, repair := range []bool{false, true} {
				text := "V15_CASE=unit-tests; V15_PHASE=" + phase + "; V15_FAILURE=" + failure + ";\npytest tests/test_checkout.py\n" + v15TerminalQuote
				control := "Classify this synthetic request."
				if phase == "verifier" {
					control += " CYBER DENY SECOND PASS"
				}
				if repair {
					control += " OPERATION EVIDENCE CHECK v1"
				}
				r := chatRequest{Model: "qwen-v15-script", MaxTokens: 256,
					ChatTemplateKwargs: map[string]any{"enable_thinking": false, "preserve_thinking": false}}
				r.Messages = []struct {
					Role    string `json:"role"`
					Content any    `json:"content"`
				}{{"system", control}, {"user", text}}
				w := httptest.NewRecorder()
				if !mockScriptV15(w, r) || w.Code != 200 {
					t.Fatal("fixture request failed", w.Code, w.Body.String())
				}
				var response struct {
					Choices []struct{ Message struct{ Content string } }
				}
				if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil || len(response.Choices) != 1 {
					t.Fatal("bad fixture response", err)
				}
				var vote struct{ Decision, RiskCode, Evidence string }
				var raw map[string]any
				if err := json.Unmarshal([]byte(response.Choices[0].Message.Content), &raw); err != nil {
					t.Fatal(err)
				}
				vote.Decision, _ = raw["decision"].(string)
				vote.RiskCode, _ = raw["risk_code"].(string)
				vote.Evidence, _ = raw["evidence"].(string)
				wantDecision, wantQuote := "block", "pytest tests/test_checkout.py"
				if repair || phase == "terminal" {
					wantQuote = v15TerminalQuote
				}
				if repair && failure == "review" {
					wantDecision = "review"
				}
				if vote.Decision != wantDecision || vote.Evidence != wantQuote || !strings.Contains(text, vote.Evidence) {
					t.Fatalf("%s/%s repair=%v: %#v", phase, failure, repair, vote)
				}
				if wantQuote == v15TerminalQuote && vote.RiskCode != "CYBER_MOCK_TERMINAL" {
					t.Fatal("terminal fixture inherited a primitive classification")
				}
			}
		}
	}
}
