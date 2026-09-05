package platform

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
)

const qualitativeIncident = `{"decision":"allow","risk_code":"NONE","category":"routine_engineering","confidence":"high","reason":"Routine memory consolidation task in internal engineering mode; no harmful cyber capability requested.","evidence":""}`

func TestOutputIncidentQualitativeAllowDoesNotBecomeInfrastructureFailure(t *testing.T) {
	var calls atomic.Int32
	engine, profile := incidentEngine(t, func(r *http.Request) (*http.Response, error) {
		calls.Add(1)
		return incidentHTTP(200, qualitativeIncident), nil
	})
	result := engine.Audit(context.Background(), Route{AuditProfileID: &profile.ID, FailClosed: true}, []byte(`{"input":"整理这次开发任务的记忆"}`))
	if result.Decision != DecisionAllow || result.ErrorClass != "" || calls.Load() != 1 {
		t.Fatalf("recoverable allow was lost: %+v", result)
	}
	if result.ConfidenceKind != "qualitative" || result.ConfidenceLabel != "high" || result.Confidence != 0 {
		t.Fatalf("invented numeric probability: %+v", result)
	}
	metadata := map[string]any{}
	recordAuditDecisionMetadata(metadata, result)
	if metadata["audit_model_confidence"] != nil || metadata["audit_output_contract"] != auditOutputContractVersion {
		t.Fatalf("wrong metadata: %+v", metadata)
	}
	if len(result.OutputNormalizations) != 2 {
		t.Fatal("missing normalization audit trail")
	}
}

func TestOutputNormalizationAndSchemaFailures(t *testing.T) {
	for _, tc := range []struct{ name, body, class string }{
		{"numeric-string", `{"decision":"allow","confidence":"0.95","risk_code":"NONE"}`, ""},
		{"qualitative-low", `{"decision":"allow","confidence":"low"}`, ""},
		{"missing-decision", `{"confidence":0.95}`, "invalid_schema"},
		{"missing-confidence", `{"decision":"allow"}`, "invalid_schema"},
		{"bool-confidence", `{"decision":"allow","confidence":true}`, "invalid_schema"},
		{"null-confidence", `{"decision":"allow","confidence":null}`, "invalid_schema"},
		{"infinite-confidence", `{"decision":"allow","confidence":"NaN"}`, "invalid_schema"},
		{"overflow", `{"decision":"allow","confidence":1e999}`, "invalid_schema"},
		{"out-of-range", `{"decision":"allow","confidence":95}`, "invalid_schema"},
		{"contradiction", `{"decision":"allow","confidence":0.99,"risk_code":"CREDENTIAL_THEFT"}`, "invalid_schema"},
		{"harm-contradiction", `{"decision":"allow","confidence":0.99,"harm_type":"malware"}`, "invalid_schema"},
		{"wrong-reason", `{"decision":"allow","confidence":0.99,"reason":{}}`, "invalid_schema"},
		{"duplicate-key", `{"decision":"block","decision":"allow","confidence":0.99}`, "ambiguous_output"},
		{"duplicate-case", `{"decision":"allow","Decision":"block","confidence":0.99}`, "invalid_schema"},
		{"concatenated", `{"decision":"block","confidence":0.99}{"decision":"allow","confidence":0.99}`, "ambiguous_output"},
		{"trailing-data", `{"decision":"allow","confidence":0.99}null`, "invalid_json"},
		{"truncated-array", `[{"decision":"allow","confidence":0.99}`, "invalid_json"},
		{"truncated-string", `"{\"decision\":\"allow\",\"confidence\":0.99}`, "invalid_json"},
		{"multi-wrappers", `{"result":{"decision":"block","confidence":0.99},"policy":{"decision":"allow","confidence":0.99}}`, "ambiguous_output"},
		{"deep", strings.Repeat("[", 40) + "0" + strings.Repeat("]", 40), "output_limits"},
		{"too-large", strings.Repeat(" ", maxAuditResponseBytes) + "x", "response_too_large"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parseAuditModelResponseContent(tc.body)
			class, _, _ := auditModelErrorDetails(err)
			if class != tc.class {
				t.Fatalf("got %s want %s: %v", class, tc.class, err)
			}
		})
	}
}

func TestOutputQualitativeConfidenceNeverOverridesStricterThreshold(t *testing.T) {
	d := AuditDecision{ConfidenceKind: "qualitative", ConfidenceLabel: "high"}
	if !auditConfidenceMeets(d, .9) || auditConfidenceMeets(d, .95) {
		t.Fatal("categorical confidence treated as an arbitrary probability")
	}
	d.ConfidenceLabel = "low"
	if auditConfidenceMeets(d, .9) {
		t.Fatal("low label meets high gate")
	}
}

func TestOutputFinalContentNeverFallsBackToEarlierReasoningAllow(t *testing.T) {
	body, _ := json.Marshal(map[string]any{"choices": []any{map[string]any{"finish_reason": "stop", "message": map[string]any{"content": "broken final JSON", "reasoning_content": qualitativeIncident}}}})
	response, err := extractAuditCompletionResponse(body)
	if err != nil {
		t.Fatal(err)
	}
	if response.Content != "broken final JSON" {
		t.Fatal("earlier allow replaced malformed final answer")
	}
	if _, err := parseAuditModelResponseContent(response.Content); err == nil {
		t.Fatal("broken final answer allowed")
	}
}

func TestOutputTruncationAndOversizeNeverAllow(t *testing.T) {
	cases := []struct{ body, class string }{
		{fmt.Sprintf(`{"choices":[{"finish_reason":"length","message":{"content":%q}}]}`, qualitativeIncident), "output_truncated"},
		{strings.Repeat("x", maxAuditResponseBytes+1), "response_too_large"},
	}
	for _, tc := range cases {
		engine, profile := incidentEngine(t, func(r *http.Request) (*http.Response, error) { return incidentHTTP(200, tc.body), nil })
		result := engine.Audit(context.Background(), Route{AuditProfileID: &profile.ID, FailClosed: true}, []byte(`{"input":"正常开发"}`))
		if result.Decision != DecisionBlock || result.ErrorClass != tc.class {
			t.Fatalf("unsafe malformed result: %+v", result)
		}
	}
}

func FuzzAuditOutputDecode(f *testing.F) {
	for _, seed := range []string{qualitativeIncident, `{"decision":"allow","confidence":0.99}`, `{"decision":"block","decision":"allow"}`, `[{"decision":"allow","confidence":0.99}`, strings.Repeat("[", 40)} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, value string) {
		result, err := parseAuditModelResponseContent(value)
		if err == nil {
			if result.Decision != DecisionAllow && result.Decision != DecisionBlock && result.Decision != DecisionReview {
				t.Fatal("invalid decision escaped parser")
			}
			if _, err := json.Marshal(result); err != nil {
				t.Fatal("decoder created non-serializable result")
			}
		}
	})
}
