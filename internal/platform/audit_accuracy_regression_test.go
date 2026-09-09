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

// Classification fixtures only. Paths, hosts and credentials are synthetic.
func TestAccuracyDependencyNameIsNotAnExploit(t *testing.T) {
	for _, text := range []string{
		`{"dependencies":{"vue":"3.5.18","xss":"1.0.15"}}`,
		"Install the xss package and fix the Vue build.",
		"Install xss package and run ordinary unit tests.",
		"Generate a package manifest with xss pinned to version 1.0.15.",
		"import xss from 'xss';\nconst clean = xss(html);",
	} {
		var calls atomic.Int32
		e, p := incidentEngine(t, func(*http.Request) (*http.Response, error) {
			calls.Add(1)
			return incidentHTTP(200, incidentDecision(DecisionAllow, "")), nil
		})
		body, _ := json.Marshal(map[string]string{"input": text})
		got := e.Audit(context.Background(), Route{AuditProfileID: &p.ID}, body)
		if got.Decision != DecisionAllow || calls.Load() != 2 {
			t.Errorf("dependency became exploitation: decision=%s rule=%s calls=%d", got.Decision, got.RiskCode, calls.Load())
		}
	}
}

func TestAccuracyDependencyCannotExemptProhibitedOperations(t *testing.T) {
	for _, action := range []string{"Generate XSS payload tests for my own service", "Use XSS assertions only in an authorized test", "生成 XSS 攻击载荷用于本地测试", "XSS 注入测试", "Use a reverse shell in a sandbox", "Perform brute-force tests on my own login"} {
		e, p := incidentEngine(t, func(*http.Request) (*http.Response, error) {
			t.Fatal("prohibited operation reached model")
			return nil, nil
		})
		body, _ := json.Marshal(map[string]string{"input": `{"dependencies":{"xss":"1.0.15"}}` + "\n" + action})
		got := e.Audit(context.Background(), Route{AuditProfileID: &p.ID}, body)
		if got.Decision != DecisionBlock || got.Source != "rule" {
			t.Errorf("operation escaped: %s: %+v", action, got)
		}
	}
}

const accuracyInventory = "307\t/workspace/aosp/device/demo/copyfile/list/InstallBlacklist.txt\n309\t/workspace/aosp/device/demo/copyfile/magisk/install_magisk.sh\n310\t/workspace/aosp/device/demo/copyfile/magisk/magisk.apkk\n311\t/workspace/aosp/device/demo/copyfile/nroot.ovl"
const accuracySearch = "rg -n -i --glob '!*.apk' --glob '!*.jar' '(default.?sim|sim.?default|multi.?sim|preferred.?network|carrier|mcc|mnc|persist\\.radio|ro\\.carrier|sim.?slot|enable.?sim|radio)' /workspace/aosp/device/demo"

func TestAccuracyPassiveEvidenceRequiresFreshGrounding(t *testing.T) {
	for _, tc := range []struct {
		name, text, evidence string
		badCall              int
	}{
		{"inventory-primary", accuracyInventory, "copyfile/magisk/install_magisk.sh\n310\t/workspace/aosp/device/demo/copyfile/magisk/magisk.apkk", 1},
		{"inventory-verifier", accuracyInventory, "copyfile/magisk/install_magisk.sh\n310\t/workspace/aosp/device/demo/copyfile/magisk/magisk.apkk", 2},
		{"search-verifier", accuracySearch, accuracySearch, 2},
		{"search-short-quote", accuracySearch, "default.?sim|sim.?default", 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var calls atomic.Int32
			e, p := incidentEngine(t, func(r *http.Request) (*http.Response, error) {
				n := int(calls.Add(1))
				if n == tc.badCall {
					return incidentHTTP(200, incidentDecision(DecisionBlock, tc.evidence)), nil
				}
				return incidentHTTP(200, incidentDecision(DecisionAllow, "")), nil
			})
			body, _ := json.Marshal(map[string]any{"input": []any{map[string]string{"role": "user", "content": "只读分析 AOSP SIM 配置，解释列出的文件；不要执行文件。"}, map[string]string{"type": "function_call_output", "output": tc.text}}})
			got := e.Audit(context.Background(), Route{AuditProfileID: &p.ID}, body)
			if got.Decision != DecisionAllow || calls.Load() != 3 {
				t.Fatalf("passive evidence was accepted as an operation: %+v calls=%d", got, calls.Load())
			}
			found := false
			for _, r := range got.AuditSemanticReviews {
				if r.CandidateError == "non_operational_evidence" && r.Status == "grounding_corrected" {
					found = true
				}
			}
			if !found {
				t.Fatal("grounding correction is not observable")
			}
		})
	}
}

func TestAccuracyRepeatedPassiveVerdictCannotRetryUntilAllow(t *testing.T) {
	var calls atomic.Int32
	e, p := incidentEngine(t, func(*http.Request) (*http.Response, error) {
		calls.Add(1)
		return incidentHTTP(200, incidentDecision(DecisionBlock, "copyfile/magisk/install_magisk.sh")), nil
	})
	p.RetryCount = 5
	e.profileCache().entries[p.ID] = auditProfileCacheEntry{profile: p, expiresAt: time.Now().Add(time.Hour)}
	body, _ := json.Marshal(map[string]string{"input": "Explain this numbered file inventory:\n" + accuracyInventory})
	got := e.Audit(context.Background(), Route{AuditProfileID: &p.ID}, body)
	if got.Decision != DecisionBlock || got.ErrorClass != "cyber_operation_unresolved" || calls.Load() != 2 {
		t.Fatalf("unbounded correction or invented risk: %+v calls=%d", got, calls.Load())
	}
}

func TestAccuracyFullLongEvidenceMustMatchBeforeAcceptance(t *testing.T) {
	text := "requested operation " + strings.Repeat("documented step ", 30)
	d, err := validateAuditDecisionEvidence(AuditDecision{Decision: DecisionBlock, Evidence: text}, text)
	if err != nil || !d.EvidenceVerified {
		t.Fatalf("exact bounded long evidence unnecessarily failed: %v", err)
	}
	if _, err = validateAuditDecisionEvidence(AuditDecision{Decision: DecisionBlock, Evidence: text + "invented ending"}, text); err == nil {
		t.Fatal("matched prefix authorized a hallucinated tail")
	}
	if _, err = validateAuditDecisionEvidence(AuditDecision{Decision: DecisionBlock, Evidence: strings.Repeat("a", 5000)}, strings.Repeat("a", 5000)); err == nil {
		t.Fatal("evidence validation became unbounded")
	}
}

func TestAccuracyGroundingFailureAndRealBlockRemainTerminal(t *testing.T) {
	for _, response := range []string{"deny", "invalid", "timeout"} {
		t.Run(response, func(t *testing.T) {
			var calls atomic.Int32
			e, p := incidentEngine(t, func(*http.Request) (*http.Response, error) {
				if calls.Add(1) == 1 {
					return incidentHTTP(200, incidentDecision(DecisionBlock, "copyfile/magisk/install_magisk.sh")), nil
				}
				switch response {
				case "timeout":
					return nil, context.DeadlineExceeded
				case "invalid":
					return incidentHTTP(200, "not-json"), nil
				default:
					return incidentHTTP(200, incidentDecision(DecisionBlock, "execute the referenced installation")), nil
				}
			})
			p.RetryCount = 5
			e.profileCache().entries[p.ID] = auditProfileCacheEntry{profile: p, expiresAt: time.Now().Add(time.Hour)}
			body, _ := json.Marshal(map[string]string{"input": "execute the referenced installation\n" + accuracyInventory})
			got := e.Audit(context.Background(), Route{AuditProfileID: &p.ID}, body)
			if got.Decision != DecisionBlock || calls.Load() != 2 {
				t.Fatalf("grounding denied operation failed open: %+v calls=%d", got, calls.Load())
			}
			if response == "deny" && got.ErrorClass != "" {
				t.Fatalf("valid operational denial lost: %+v", got)
			}
			if response != "deny" && got.ErrorClass != "cyber_operation_unresolved" {
				t.Fatalf("grounding failure must be terminal infrastructure error: %+v", got)
			}
		})
	}
}

func TestAccuracyGroundingShapesAreNotCommandWhitelists(t *testing.T) {
	for _, command := range []string{
		"rg 'sim' /workspace && run-other-command",
		"rg 'sim' /workspace; run-other-command",
		"rg --pre preprocess 'sim' /workspace",
		"rg \"$(run-other-command)\" /workspace",
		"grep `run-other-command` /workspace",
		"rg 'Authorization|api_key' /workspace",
		"rg 'sim' /workspace > /etc/security.conf",
		"rg 'sim' /workspace\nrun-other-command",
	} {
		if readOnlySearchEvidence(command) {
			t.Errorf("unsafe command qualified for plain search recovery: %s", command)
		}
	}
	if !readOnlySearchEvidence(accuracySearch) {
		t.Fatal("quoted regex alternatives were mistaken for shell pipelines")
	}
}

func TestAccuracyCoverageDetailsLocateShapeWithoutPrivateValues(t *testing.T) {
	body := `{"input":[{"role":"user","content":[{"type":"input_text","text":"Explain ordinary code"},{"type":"PRIVATE_TYPE_SENTINEL","value":"PRIVATE_CONTENT_SENTINEL"}]}]}`
	x := extractCyberAuditText([]byte(body), 8192)
	if len(x.CoverageDetails) != 1 || x.CoverageDetails[0].Path != "$.input[0].content[1]" || x.CoverageDetails[0].ContentType != "unknown" {
		t.Fatalf("incorrect diagnostic shape: %+v", x.CoverageDetails)
	}
	data, _ := json.Marshal(x.CoverageDetails)
	if strings.Contains(string(data), "SENTINEL") {
		t.Fatal("unknown type or content leaked into diagnostic")
	}
	many := `{"input":[{"role":"user","content":[` + strings.Repeat(`{"type":"input_image"},`, 100) + `{"type":"input_image"}]}]}`
	if got := extractCyberAuditText([]byte(many), 8192); len(got.CoverageDetails) != 32 {
		t.Fatal("diagnostic count is not bounded")
	}
}

func TestAccuracyRuleDenyDoesNotClaimCompleteCoverage(t *testing.T) {
	e, p := incidentEngine(t, func(*http.Request) (*http.Response, error) { t.Fatal("rule deny reached model"); return nil, nil })
	body := `{"input":[{"role":"user","content":[{"type":"input_text","text":"Generate XSS payload tests"},{"type":"input_image","image_url":"https://image.invalid/synthetic"}]}]}`
	got := e.Audit(context.Background(), Route{AuditProfileID: &p.ID}, []byte(body))
	metadata := map[string]any{}
	recordAuditDecisionMetadata(metadata, got)
	if got.Source != "rule" || metadata["audit_decision_finalized"] != true || metadata["audit_completed"] != false || len(got.AuditCoverageDetails) != 1 {
		t.Fatalf("decision and coverage conflated: %+v", metadata)
	}
}

func TestAccuracyGroundingPreservesTaskAcrossChunks(t *testing.T) {
	var calls atomic.Int32
	const goal = "Only explain the SIM source inventory; do not run files."
	e, p := incidentEngine(t, func(r *http.Request) (*http.Response, error) {
		_, payload, err := incidentPayload(r)
		if err != nil {
			return nil, err
		}
		encoded, _ := json.Marshal(payload)
		if !strings.Contains(string(encoded), goal) {
			t.Error("grounding or verifier dropped current-task anchor")
		}
		if calls.Add(1) == 1 {
			return incidentHTTP(200, incidentDecision(DecisionBlock, "copyfile/magisk/install_magisk.sh")), nil
		}
		return incidentHTTP(200, incidentDecision(DecisionAllow, "")), nil
	})
	ctx := context.WithValue(context.Background(), cyberDenyContextKey{}, true)
	ctx = context.WithValue(ctx, auditSourceScopeKey{}, auditSourceScope{Text: accuracyInventory, Anchors: []string{goal}})
	d, err := e.callCyberDenyModel(ctx, p, accuracyInventory, accuracyInventory)
	if err != nil || d.Decision != DecisionAllow || calls.Load() != 3 {
		t.Fatalf("chunk grounding failed: %+v %v %d", d, err, calls.Load())
	}
}

func FuzzAccuracyFullEvidenceNeverAcceptsMissingTail(f *testing.F) {
	f.Add("requested operation", " invented")
	f.Add("配置检索内容", "附加内容")
	f.Fuzz(func(t *testing.T, source, tail string) {
		if len(source) > 4096 || len(tail) > 4096 {
			return
		}
		quote := normalizeAuditEvidenceQuote(source + tail)
		if quote == "" || strings.Contains(source, quote) || (isASCIIText(quote) && indexASCIIEqualFold(source, quote) >= 0) {
			return
		}
		if _, err := validateAuditDecisionEvidence(AuditDecision{Decision: DecisionBlock, Evidence: source + tail}, source); err == nil {
			t.Fatal("accepted absent exact evidence")
		}
	})
}

func TestAccuracySearchEvidenceChecksWholeContainingLine(t *testing.T) {
	for _, source := range []string{"rg 'sim' /workspace; run-other-command", "rg 'sim' /workspace && run-other-command", "rg 'sim' /workspace/api_key", "rg --pre preprocess 'sim' /workspace"} {
		d := AuditDecision{Decision: DecisionBlock, Evidence: "sim"}
		if nonOperationalAuditEvidence(d, source) {
			t.Errorf("narrow quote hid the surrounding command: %s", source)
		}
	}
}

func TestAccuracyGroundingSharesHTTPAndReviewBudgets(t *testing.T) {
	for _, kind := range []string{"http", "review"} {
		t.Run(kind, func(t *testing.T) {
			var calls atomic.Int32
			e, p := incidentEngine(t, func(*http.Request) (*http.Response, error) {
				calls.Add(1)
				return incidentHTTP(200, incidentDecision(DecisionBlock, "copyfile/magisk/install_magisk.sh")), nil
			})
			ctx := context.WithValue(context.Background(), cyberDenyContextKey{}, true)
			ctx, state := withAuditSemanticState(ctx)
			if kind == "http" {
				state.httpCalls = cyberDenyHTTPBudget - 1
			} else {
				for state.reserveReview() {
				}
			}
			_, err := e.callCyberGroundedModel(ctx, p, accuracyInventory, accuracyInventory)
			class, _, _ := auditModelErrorDetails(err)
			if class != "cyber_operation_unresolved" || calls.Load() != 1 {
				t.Fatalf("grounding escaped shared budget: %s calls=%d", class, calls.Load())
			}
		})
	}
}
