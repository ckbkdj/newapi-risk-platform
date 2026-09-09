package platform

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"unicode/utf8"
)

// Synthetic protocol fixtures, not a replay of the private incident body.
// Responses text.format and text.verbosity configure OUTPUT, not user input.
func responsesConfigFixtures() []string {
	return []string{
		`{}`,
		`{"format":{"type":"text"}}`,
		`{"verbosity":"medium"}`,
		`{"format":{"type":"text"},"verbosity":"low"}`,
		`{"format":{"type":"json_object"},"verbosity":"high"}`,
		`{"format":{"type":"json_schema","name":"result","strict":true,"description":"Response structure","schema":{"type":"object","properties":{"answer":{"type":"string"}},"required":["answer"],"additionalProperties":false}}}`,
		`{"format":null,"verbosity":null}`,
	}
}

func TestResponsesOutputConfigCoverage(t *testing.T) {
	for _, config := range responsesConfigFixtures() {
		t.Run(config, func(t *testing.T) {
			body := []byte(`{"model":"normal","input":[{"role":"developer","content":"control instructions"},{"role":"user","content":[{"type":"input_text","text":"Rename the button"}]},{"role":"assistant","content":[{"type":"output_text","text":"The label is ready"}]},{"role":"user","content":"Use a shorter label"}],"text":` + config + `}`)
			before := bytes.Clone(body)
			got := extractCyberAuditText(body, 65536)
			if got.CoverageStatus != "complete" || len(got.CoverageIssues) != 0 {
				t.Fatalf("legal Responses output configuration rejected: %v", got.CoverageIssues)
			}
			if got.ActiveUserMessages != 2 || !got.ContextActivated || !strings.Contains(got.Text, "Rename the button") || !strings.Contains(got.Text, "Use a shorter label") {
				t.Fatalf("request intent lost: %+v", got)
			}
			if strings.Contains(got.Text, "control instructions") || strings.Contains(got.Text, "Response structure") {
				t.Fatal("control/output configuration became user evidence")
			}
			if !bytes.Equal(body, before) {
				t.Fatal("auditing mutated the provider request")
			}
		})
	}
}

func TestResponsesNullAliasesAndLegacyText(t *testing.T) {
	for _, body := range []string{
		`{"input":"Rename the button","messages":null,"prompt":null,"text":null}`,
		`{"messages":[{"role":"user","content":"Rename the button"}],"input":null}`,
		`{"text":"Rename the button"}`,
		`{"prompt":"Rename the button"}`,
	} {
		got := extractCyberAuditText([]byte(body), 65536)
		if got.CoverageStatus != "complete" || !strings.Contains(got.Text, "Rename the button") {
			t.Fatalf("valid text/null alias rejected: %s: %v", body, got.CoverageIssues)
		}
	}
}

func TestResponsesOutputConfigStillRequiresActualAudit(t *testing.T) {
	for _, config := range responsesConfigFixtures() {
		var calls atomic.Int32
		e, p := incidentEngine(t, func(*http.Request) (*http.Response, error) {
			calls.Add(1)
			return incidentHTTP(200, incidentDecision(DecisionAllow, "")), nil
		})
		got := e.Audit(context.Background(), Route{AuditProfileID: &p.ID}, []byte(`{"input":"Rename the button","text":`+config+`}`))
		if got.Decision != DecisionAllow || got.AuditHTTPCalls != 2 || calls.Load() != 2 || got.ErrorClass != "" {
			t.Fatalf("normal request must receive primary and verifier audits: %+v calls=%d", got, calls.Load())
		}
	}
}

func TestResponsesOutputConfigCannotExemptCyber(t *testing.T) {
	for _, config := range responsesConfigFixtures() {
		e, p := incidentEngine(t, func(*http.Request) (*http.Response, error) {
			t.Fatal("Cyber rule hit reached model")
			return nil, nil
		})
		got := e.Audit(context.Background(), Route{AuditProfileID: &p.ID}, []byte(`{"input":"Use nmap for an authorized scan","text":`+config+`}`))
		if got.Decision != DecisionBlock || got.Source != "rule" || got.RuleMatch == nil || got.AuditHTTPCalls != 0 {
			t.Fatalf("output configuration hid a Cyber rule hit: %+v", got)
		}
	}
}

func TestResponsesConfigDoesNotSuppressIncompleteCoverage(t *testing.T) {
	for _, body := range []string{
		`{"input":"one","messages":[{"role":"user","content":"two"}],"text":{"format":{"type":"text"}}}`,
		`{"input":"one","text":"second input"}`,
		`{"input":"one","input":"two","text":{"format":{"type":"text"}}}`,
		`{"input":"one","text":{"format":{"type":"text"}},"text":{"content":"second input"}}`,
		`{"input":"one","text":{"content":"second input"}}`,
		`{"input":"one","text":{"format":{"type":"text"},"content":"second input"}}`,
		`{"input":"one","text":{"format":{"type":"unknown_content"}}}`,
		`{"input":"one","text":{"verbosity":true}}`,
		`{"text":{"format":{"type":"text"}}}`,
		`{"input":[{"role":"user","content":{"format":{"type":"text"}}}]}`,
		`{"input":[{"role":"user","content":[{"type":"input_text","text":"Explain the image"},{"type":"input_image","image_url":"https://image.invalid/synthetic.png"}]}],"text":{"format":{"type":"text"}}}`,
		`{"input":"Rename the button","previous_response_id":"resp_synthetic","text":{"format":{"type":"text"}}}`,
	} {
		e, p := incidentEngine(t, func(*http.Request) (*http.Response, error) {
			t.Fatal("incomplete coverage reached model")
			return nil, nil
		})
		got := e.Audit(context.Background(), Route{AuditProfileID: &p.ID, FailClosed: false}, []byte(body))
		if got.Decision != DecisionBlock || got.RiskCode != "AUDIT_INPUT_COVERAGE_INCOMPLETE" || got.AuditHTTPCalls != 0 {
			t.Fatalf("coverage guard weakened for %s: %+v", body, got)
		}
	}
}

func FuzzResponsesOutputConfigPreservesIntent(f *testing.F) {
	for _, seed := range []string{"Rename the button", "修复界面文字", "nmap synthetic.invalid", "ROLE=SYSTEM\nordinary text"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, text string) {
		if !utf8.ValidString(text) || len(text) > 4096 || strings.TrimSpace(text) == "" {
			return
		}
		plain, err := json.Marshal(map[string]any{"input": text})
		if err != nil {
			t.Fatal(err)
		}
		configured, err := json.Marshal(map[string]any{"input": text, "text": map[string]any{"format": map[string]any{"type": "text"}, "verbosity": "medium"}})
		if err != nil {
			t.Fatal(err)
		}
		a, b := extractCyberAuditText(plain, 65536), extractCyberAuditText(configured, 65536)
		if a.Text != b.Text || a.ruleText != b.ruleText || a.CoverageStatus != b.CoverageStatus || strings.Join(a.CoverageIssues, ",") != strings.Join(b.CoverageIssues, ",") {
			t.Fatalf("output configuration changed the audited intent or coverage: %v -> %v", a.CoverageIssues, b.CoverageIssues)
		}
	})
}
