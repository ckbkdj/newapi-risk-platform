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

// Classification fixtures only; no proxy, real host, process, or credential is accessed.
const evidenceRepairSource = "把已有 language_server 连接表与 Clash 连接记录按源端口关联，解释当前代理链；只分析已有记录。"
const evidenceRepairInvented = "Join language_server ports with Clash connection chains by source port"

func evidenceRepairBlock(quote string) string {
	b, _ := json.Marshal(map[string]any{"decision": "block", "risk_code": "CYBER_NETWORK_PROBING", "category": "network_probing", "confidence": .95, "reason": "synthetic operation classification", "evidence": quote})
	return string(b)
}

func TestEvidenceRepairMissingQuoteRechecksSameData(t *testing.T) {
	for _, badCall := range []int32{1, 2} {
		t.Run(map[int32]string{1: "primary", 2: "verifier"}[badCall], func(t *testing.T) {
			var calls atomic.Int32
			var firstDoc string
			e, p := incidentEngine(t, func(r *http.Request) (*http.Response, error) {
				text, payload, err := incidentPayload(r)
				if err != nil {
					return nil, err
				}
				doc := payload["messages"].([]any)[1].(map[string]any)["content"].(string)
				if firstDoc == "" {
					firstDoc = doc
				} else if doc != firstDoc {
					t.Error("recovery changed the source document")
				}
				if !strings.Contains(text, evidenceRepairSource) || strings.Contains(text, evidenceRepairInvented) {
					t.Error("source missing or invented quote injected into user data")
				}
				if calls.Add(1) == badCall {
					return incidentHTTP(200, evidenceRepairBlock(evidenceRepairInvented)), nil
				}
				return incidentHTTP(200, incidentDecision(DecisionAllow, "")), nil
			})
			body, _ := json.Marshal(map[string]string{"input": evidenceRepairSource})
			got := e.Audit(context.Background(), Route{AuditProfileID: &p.ID}, body)
			if got.Decision != DecisionAllow || got.ErrorClass != "" || calls.Load() != 3 {
				t.Fatalf("evidence representation failure was not recovered with fresh verification: decision=%s error=%s calls=%d", got.Decision, got.ErrorClass, calls.Load())
			}
		})
	}
}

func TestEvidenceRepairRepeatedMissingQuoteFailsClosed(t *testing.T) {
	var calls atomic.Int32
	e, p := incidentEngine(t, func(*http.Request) (*http.Response, error) {
		calls.Add(1)
		return incidentHTTP(200, evidenceRepairBlock(evidenceRepairInvented)), nil
	})
	p.RetryCount = 5
	e.profileCache().entries[p.ID] = auditProfileCacheEntry{profile: p, expiresAt: time.Now().Add(time.Hour)}
	body, _ := json.Marshal(map[string]string{"input": evidenceRepairSource})
	got := e.Audit(context.Background(), Route{AuditProfileID: &p.ID}, body)
	if got.Decision != DecisionBlock || got.ErrorClass != "cyber_evidence_unresolved" || calls.Load() != 2 {
		t.Fatalf("must stop after one repair: decision=%s error=%s calls=%d", got.Decision, got.ErrorClass, calls.Load())
	}
}

func TestEvidenceRepairValidOperationRemainsTerminal(t *testing.T) {
	for _, repair := range []bool{false, true} {
		var calls atomic.Int32
		const action = "Initiate new connections to enumerate reachable services."
		e, p := incidentEngine(t, func(*http.Request) (*http.Response, error) {
			n := calls.Add(1)
			if repair && n == 1 {
				return incidentHTTP(200, evidenceRepairBlock("fabricated operation quote")), nil
			}
			return incidentHTTP(200, evidenceRepairBlock(action)), nil
		})
		body, _ := json.Marshal(map[string]string{"input": action})
		got := e.Audit(context.Background(), Route{AuditProfileID: &p.ID}, body)
		want := int32(1)
		if repair {
			want = 2
		}
		if got.Decision != DecisionBlock || got.ErrorClass != "" || calls.Load() != want || !got.EvidenceVerified {
			t.Fatalf("operation denial lost: decision=%s error=%s calls=%d", got.Decision, got.ErrorClass, calls.Load())
		}
	}
}

func TestEvidenceRepairFailureMatrix(t *testing.T) {
	for name, response := range map[string]string{
		"repeat":            evidenceRepairBlock(evidenceRepairInvented),
		"empty-quote":       evidenceRepairBlock(""),
		"invented-tail":     evidenceRepairBlock(evidenceRepairSource + " invented tail"),
		"missing-fields":    `{"decision":"allow"}`,
		"ambiguous":         `{"decision":"block","decision":"allow"}`,
		"invalid-json":      "not-json",
		"low-confidence":    `{"decision":"allow","risk_code":"","category":"normal","confidence":0.1,"reason":"uncertain","evidence":""}`,
		"category-conflict": `{"decision":"allow","risk_code":"","category":"network_probing","confidence":0.99,"reason":"uncertain","evidence":""}`,
		"truncated":         `{"choices":[{"finish_reason":"length","message":{"content":"incomplete"}}]}`,
		"timeout":           "timeout",
	} {
		t.Run(name, func(t *testing.T) {
			var calls atomic.Int32
			e, p := incidentEngine(t, func(*http.Request) (*http.Response, error) {
				if calls.Add(1) == 1 {
					return incidentHTTP(200, evidenceRepairBlock(evidenceRepairInvented)), nil
				}
				if response == "timeout" {
					return nil, context.DeadlineExceeded
				}
				return incidentHTTP(200, response), nil
			})
			p.RetryCount = 5
			p.FallbackProfileIDs = []int64{2}
			e.profileCache().entries[p.ID] = auditProfileCacheEntry{profile: p, expiresAt: time.Now().Add(time.Hour)}
			fallback := p
			fallback.ID = 2
			e.profileCache().entries[2] = auditProfileCacheEntry{profile: fallback, expiresAt: time.Now().Add(time.Hour)}
			body, _ := json.Marshal(map[string]string{"input": evidenceRepairSource})
			got := e.Audit(context.Background(), Route{AuditProfileID: &p.ID}, body)
			if got.Decision != DecisionBlock || got.ErrorClass != "cyber_evidence_unresolved" || calls.Load() != 2 || got.AuditFallbackCount != 0 {
				t.Fatalf("bad repair retried or failed open: %s %s %d", got.Decision, got.ErrorClass, calls.Load())
			}
			if len(got.AuditSemanticReviews) != 1 || len(got.AuditSemanticReviews[0].Attempts) != 2 || got.AuditSemanticReviews[0].Candidate.EvidenceVerified {
				t.Fatal("missing original/repaired diagnostics or fabricated evidence marked verified")
			}
		})
	}
}

func TestEvidenceRepairCannotOverrideVerifierDenial(t *testing.T) {
	var calls atomic.Int32
	const operation = "Initiate new connections to enumerate reachable services."
	e, p := incidentEngine(t, func(*http.Request) (*http.Response, error) {
		switch calls.Add(1) {
		case 1:
			return incidentHTTP(200, evidenceRepairBlock(evidenceRepairInvented)), nil
		case 2:
			return incidentHTTP(200, incidentDecision(DecisionAllow, "")), nil
		default:
			return incidentHTTP(200, evidenceRepairBlock(operation)), nil
		}
	})
	body, _ := json.Marshal(map[string]string{"input": evidenceRepairSource + "\n" + operation})
	got := e.Audit(context.Background(), Route{AuditProfileID: &p.ID}, body)
	if got.Decision != DecisionBlock || got.ErrorClass != "" || calls.Load() != 3 || got.Evidence != operation {
		t.Fatal("fresh verifier operation denial lost")
	}
}

func TestEvidenceRepairRuleVetoUnaffected(t *testing.T) {
	e, p := incidentEngine(t, func(*http.Request) (*http.Response, error) { t.Fatal("rule veto dispatched a model"); return nil, nil })
	body, _ := json.Marshal(map[string]string{"input": evidenceRepairSource + "\nScan the network with nmap."})
	got := e.Audit(context.Background(), Route{AuditProfileID: &p.ID}, body)
	if got.Source != "rule" || got.Decision != DecisionBlock || got.AuditHTTPCalls != 0 {
		t.Fatal("rule veto bypassed")
	}
}

func TestEvidenceRepairInputDiagnosticsAndExcludedControl(t *testing.T) {
	var calls atomic.Int32
	e, p := incidentEngine(t, func(r *http.Request) (*http.Response, error) {
		text, payload, err := incidentPayload(r)
		if err != nil {
			return nil, err
		}
		if strings.Contains(text, "CONTROL_ONLY_SENTINEL") || strings.Contains(text, evidenceRepairInvented) {
			t.Error("excluded controls included as evidence source")
		}
		if payload["max_tokens"] != float64(256) {
			t.Error("repair blindly increased tokens")
		}
		if calls.Add(1) == 1 {
			return incidentHTTP(200, evidenceRepairBlock(evidenceRepairInvented)), nil
		}
		return incidentHTTP(200, incidentDecision(DecisionAllow, "")), nil
	})
	body, _ := json.Marshal(map[string]any{"instructions": "CONTROL_ONLY_SENTINEL " + evidenceRepairInvented, "input": []any{map[string]string{"role": "developer", "content": "CONTROL_ONLY_SENTINEL"}, map[string]string{"role": "user", "content": evidenceRepairSource}}})
	got := e.Audit(context.Background(), Route{AuditProfileID: &p.ID}, body)
	if got.Decision != DecisionAllow || len(got.AuditModelInputs) != 3 {
		t.Fatal("missing dispatched input diagnostics")
	}
	for i, d := range got.AuditModelInputs {
		if d.Call != i+1 || d.RequestTextBytes == 0 || d.RequestTextBytes != d.EvidenceSourceBytes || !d.SourceMatchesRequestText || len(d.DocumentHMAC) != 64 || d.DocumentHMAC != got.AuditModelInputs[0].DocumentHMAC || d.PayloadBytes <= d.RequestTextBytes {
			t.Fatalf("wrong source diagnostic: %+v", d)
		}
	}
	if got.AuditModelInputs[1].Phase != "evidence_repair" || got.AuditModelInputs[2].Phase != "verifier" {
		t.Fatal("wrong dispatch phases")
	}
	data, _ := json.Marshal(got.AuditModelInputs)
	if strings.Contains(string(data), "SENTINEL") || strings.Contains(string(data), "language_server") {
		t.Fatal("input diagnostics leaked source content")
	}
}

func TestEvidenceRepairSharesBudgetsAndPreservesAnchors(t *testing.T) {
	for _, exhausted := range []string{"", "http", "review", "cancel"} {
		t.Run(exhausted, func(t *testing.T) {
			var calls atomic.Int32
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			ctx = context.WithValue(ctx, cyberDenyContextKey{}, true)
			const anchor = "Explain the current task using every supplied fragment."
			ctx = context.WithValue(ctx, auditSourceScopeKey{}, auditSourceScope{Text: evidenceRepairSource, Anchors: []string{anchor}})
			ctx, state := withAuditSemanticState(ctx)
			if exhausted == "http" {
				state.httpCalls = cyberDenyHTTPBudget - 1
			}
			if exhausted == "review" {
				state.reviewCalls = maxAuditSemanticCalls
			}
			e, p := incidentEngine(t, func(r *http.Request) (*http.Response, error) {
				_, payload, err := incidentPayload(r)
				if err != nil {
					return nil, err
				}
				encoded, _ := json.Marshal(payload)
				if !strings.Contains(string(encoded), anchor) {
					t.Error("task anchor missing")
				}
				if calls.Add(1) == 1 {
					if exhausted == "cancel" {
						cancel()
					}
					return incidentHTTP(200, evidenceRepairBlock(evidenceRepairInvented)), nil
				}
				return incidentHTTP(200, incidentDecision(DecisionAllow, "")), nil
			})
			got, err := e.callCyberDenyModel(ctx, p, evidenceRepairSource, evidenceRepairSource)
			if exhausted == "" {
				if err != nil || got.Decision != DecisionAllow || calls.Load() != 3 {
					t.Fatalf("anchored repair failed: %v", err)
				}
			} else if err == nil || calls.Load() != 1 {
				t.Fatalf("exhausted repair dispatched again: %v calls=%d", err, calls.Load())
			}
		})
	}
}

func TestEvidenceRepairCannotUseAnchorOnlyQuote(t *testing.T) {
	const anchor = "ANCHOR_ONLY_SENTINEL"
	ctx := context.WithValue(context.Background(), cyberDenyContextKey{}, true)
	ctx = context.WithValue(ctx, auditSourceScopeKey{}, auditSourceScope{Text: evidenceRepairSource, Anchors: []string{anchor}})
	e, p := incidentEngine(t, func(*http.Request) (*http.Response, error) {
		return incidentHTTP(200, evidenceRepairBlock(anchor)), nil
	})
	_, err := e.callCyberDenyModel(ctx, p, evidenceRepairSource, evidenceRepairSource)
	class, _, _ := auditModelErrorDetails(err)
	if class != "cyber_evidence_unresolved" {
		t.Fatal("context-only quote accepted as source evidence")
	}
}

func TestEvidenceRepairInputIntegrityGuard(t *testing.T) {
	e := &AuditEngine{security: &Security{}}
	p := AuditProfile{ID: 1}
	for _, doc := range []string{encodeAuditRequestDocument(""), encodeAuditRequestDocument("different source"), `{"schema":"risk_audit_request.v2","request_text":"source","request_context":["fabricated"]}`} {
		_, err := e.auditModelInputDiagnostics(context.Background(), p, []map[string]string{{"role": "system"}, {"role": "user", "content": doc}}, "source", 100)
		class, _, _ := auditModelErrorDetails(err)
		if class != "cyber_input_integrity" {
			t.Fatal("changed document was sent")
		}
	}
}

func FuzzEvidenceRepairNeverAcceptsAbsentQuote(f *testing.F) {
	f.Add(evidenceRepairSource, evidenceRepairInvented)
	f.Add("alpha\nbeta", "alpha beta")
	f.Add("中文原文", "English paraphrase")
	f.Fuzz(func(t *testing.T, source, quote string) {
		if len(source) > 8192 || len(quote) > 8192 {
			return
		}
		normalized := normalizeAuditEvidenceQuote(quote)
		if normalized == "" || strings.Contains(source, normalized) || isASCIIText(normalized) && indexASCIIEqualFold(source, normalized) >= 0 {
			return
		}
		if _, err := validateAuditDecisionEvidence(AuditDecision{Decision: DecisionBlock, Evidence: quote}, source); err == nil {
			t.Fatal("absent quote accepted")
		}
	})
}

func TestEvidenceRepairFusionVetoSurvivesCorrectedVote(t *testing.T) {
	var calls atomic.Int32
	const action = "Initiate new connections to enumerate reachable services."
	e, p := incidentEngine(t, func(r *http.Request) (*http.Response, error) {
		_, payload, err := incidentPayload(r)
		if err != nil {
			return nil, err
		}
		calls.Add(1)
		model := payload["model"].(string)
		system := payload["messages"].([]any)[0].(map[string]any)["content"].(string)
		if model == "repair-member" && !strings.Contains(system, "EVIDENCE SOURCE REPAIR v1") {
			return incidentHTTP(200, evidenceRepairBlock(evidenceRepairInvented)), nil
		}
		if model == "deny-member" {
			return incidentHTTP(200, evidenceRepairBlock(action)), nil
		}
		return incidentHTTP(200, incidentDecision(DecisionAllow, "")), nil
	})
	p.Extra = json.RawMessage(`{"_risk_fusion_profile_ids":[2,3]}`)
	for id, model := range map[int64]string{1: p.Model, 2: "repair-member", 3: "deny-member"} {
		member := p
		member.ID = id
		member.Model = model
		e.profileCache().entries[id] = auditProfileCacheEntry{profile: member, expiresAt: time.Now().Add(time.Hour)}
	}
	body, _ := json.Marshal(map[string]string{"input": evidenceRepairSource + "\n" + action})
	got := e.Audit(context.Background(), Route{AuditProfileID: &p.ID}, body)
	if got.Decision != DecisionBlock || got.ErrorClass != "" || calls.Load() != 4 {
		t.Fatalf("fusion denial lost after repaired vote: %s %s %d", got.Decision, got.ErrorClass, calls.Load())
	}
}

func TestEvidenceRepairOriginalAndRecoveryResponsesAreSeparate(t *testing.T) {
	var calls atomic.Int32
	e, p := incidentEngine(t, func(*http.Request) (*http.Response, error) {
		id, content := "original-response", evidenceRepairBlock(evidenceRepairInvented)
		if calls.Add(1) == 2 {
			id = "repair-response"
		}
		body, _ := json.Marshal(map[string]any{"id": id, "choices": []any{map[string]any{"finish_reason": "stop", "message": map[string]any{"content": content}}}})
		return incidentHTTP(200, string(body)), nil
	})
	body, _ := json.Marshal(map[string]string{"input": evidenceRepairSource})
	got := e.Audit(context.Background(), Route{AuditProfileID: &p.ID}, body)
	if got.ErrorClass != "cyber_evidence_unresolved" || len(got.AuditSemanticReviews) != 1 {
		t.Fatal("unexpected recovery")
	}
	a := got.AuditSemanticReviews[0].Attempts
	if len(a) != 2 || a[0].ResponseID != "original-response" || a[1].ResponseID != "repair-response" || got.AuditResponseID != "repair-response" {
		t.Fatal("response metadata conflated")
	}
}

func TestEvidenceRepairInputLogBound(t *testing.T) {
	var calls atomic.Int32
	e, p := incidentEngine(t, func(*http.Request) (*http.Response, error) {
		calls.Add(1)
		return incidentHTTP(200, incidentDecision(DecisionAllow, "")), nil
	})
	ctx := context.WithValue(context.Background(), cyberDenyContextKey{}, true)
	ctx, state := withAuditSemanticState(ctx)
	for i := 0; i < maxAuditModelInputRecords+2; i++ {
		if _, err := e.callModelRawWithEvidenceSource(ctx, p, evidenceRepairSource, evidenceRepairSource); err != nil {
			t.Fatal(err)
		}
	}
	m := state.metadata(auditFailoverMetadata{})
	if len(m.ModelInputs) != maxAuditModelInputRecords || m.HTTPCalls != maxAuditModelInputRecords+2 {
		t.Fatal("unbounded input logs or lost physical calls")
	}
	meta := map[string]any{}
	recordAuditDecisionMetadata(meta, AuditResult{AuditModelInputs: m.ModelInputs, AuditHTTPCalls: m.HTTPCalls})
	if meta["audit_model_inputs_truncated"] != true {
		t.Fatal("input log truncation concealed")
	}
}
