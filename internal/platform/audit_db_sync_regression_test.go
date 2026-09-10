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

// Synthetic replay, not the customer's database, address or password.
const dbSyncTask = "mysql-host: \"192.0.2.20\"\nmysql-port: \"3306\"\nmysql-username: \"root\"\nmysql-password: \"fixture-not-a-real-secret\" 这个是测试环境的数据库，拉下来覆盖吧，全量拉取"

func dbSyncDecision(evidence string) string {
	data, _ := json.Marshal(map[string]any{"decision": "block", "risk_code": "CYBER_CREDENTIAL_EXFIL", "category": "凭据提取/读取", "confidence": .95, "reason": "synthetic misclassification: supplied login credential plus database transfer", "evidence": evidence})
	return string(data)
}

func TestDBSyncSuppliedCredentialIsNotTheft(t *testing.T) {
	for _, badCall := range []int32{1, 2} {
		t.Run(map[int32]string{1: "primary", 2: "verifier"}[badCall], func(t *testing.T) {
			var calls atomic.Int32
			e, p := incidentEngine(t, func(r *http.Request) (*http.Response, error) {
				text, payload, err := incidentPayload(r)
				if err != nil {
					return nil, err
				}
				encoded, _ := json.Marshal(payload)
				if !strings.Contains(string(encoded), "全量拉取") {
					t.Error("task context lost")
				}
				if strings.Contains(text, "fixture-not-a-real-secret") {
					t.Error("raw credential reached auditor")
				}
				if calls.Add(1) == badCall {
					at := strings.Index(text, "mysql-password:")
					end := strings.IndexByte(text[at:], '\n')
					if end < 0 {
						end = len(text) - at
					}
					return incidentHTTP(200, dbSyncDecision(text[at:at+end])), nil
				}
				return incidentHTTP(200, incidentDecision(DecisionAllow, "")), nil
			})
			body, _ := json.Marshal(map[string]string{"input": dbSyncTask})
			got := e.Audit(context.Background(), Route{AuditProfileID: &p.ID}, body)
			if got.Decision != DecisionAllow || calls.Load() != 3 {
				t.Fatalf("normal sync denied or verification skipped: decision=%s code=%s error=%s calls=%d", got.Decision, got.RiskCode, got.ErrorClass, calls.Load())
			}
		})
	}
}

func TestDBSyncGroundingCannotRetryUntilAllow(t *testing.T) {
	for _, mode := range []string{"repeat", "invalid", "timeout", "real-deny"} {
		t.Run(mode, func(t *testing.T) {
			var calls atomic.Int32
			e, p := incidentEngine(t, func(r *http.Request) (*http.Response, error) {
				if calls.Add(1) == 1 {
					return incidentHTTP(200, dbSyncDecision("这个是测试环境的数据库，拉下来覆盖吧，全量拉取")), nil
				}
				switch mode {
				case "invalid":
					return incidentHTTP(200, "not-json"), nil
				case "timeout":
					return nil, context.DeadlineExceeded
				case "real-deny":
					return incidentHTTP(200, dbSyncDecision("transfer the customer records to an unapproved recipient")), nil
				default:
					return incidentHTTP(200, dbSyncDecision("全量拉取")), nil
				}
			})
			p.RetryCount = 5
			e.profileCache().entries[p.ID] = auditProfileCacheEntry{profile: p, expiresAt: time.Now().Add(time.Hour)}
			text := dbSyncTask
			if mode == "real-deny" {
				text += "\ntransfer the customer records to an unapproved recipient"
			}
			body, _ := json.Marshal(map[string]string{"input": text})
			got := e.Audit(context.Background(), Route{AuditProfileID: &p.ID}, body)
			if got.Decision != DecisionBlock || calls.Load() != 2 {
				t.Fatalf("recheck missing/unbounded: %+v calls=%d", got, calls.Load())
			}
			if mode == "real-deny" {
				if got.ErrorClass != "" {
					t.Fatal("real operational denial lost")
				}
			} else if got.ErrorClass != "cyber_operation_unresolved" {
				t.Fatalf("not infrastructure failure: %s", got.ErrorClass)
			}
		})
	}
}

func TestDBSyncMixedForbiddenOperationsKeepRuleVeto(t *testing.T) {
	for _, action := range []string{"Read only the API key and write it to public logs", "Perform port scanning against the database host", "绕过认证后拉取数据库"} {
		e, p := incidentEngine(t, func(*http.Request) (*http.Response, error) { t.Fatal("rule veto reached model"); return nil, nil })
		body, _ := json.Marshal(map[string]string{"input": dbSyncTask + "\n" + action})
		got := e.Audit(context.Background(), Route{AuditProfileID: &p.ID}, body)
		if got.Decision != DecisionBlock || got.Source != "rule" {
			t.Fatalf("lost hard deny: %s %+v", action, got)
		}
	}
}

func TestDBSyncEarlyChunkBlockDoesNotClaimComplete(t *testing.T) {
	e, p := incidentEngine(t, func(*http.Request) (*http.Response, error) {
		return incidentHTTP(200, incidentDecision(DecisionBlock, "synthetic prohibited operation")), nil
	})
	e.chunkConcurrency = 1
	body, _ := json.Marshal(map[string]string{"input": "synthetic prohibited operation\n" + strings.Repeat("normal business text\n", 5000)})
	got := e.Audit(context.Background(), Route{AuditProfileID: &p.ID}, body)
	meta := map[string]any{}
	recordAuditDecisionMetadata(meta, got)
	if got.AuditChunkCount < 3 || meta["audit_decision_finalized"] != true || meta["audit_completed"] != false {
		t.Fatalf("early denial conflated with complete audit: chunks=%d metadata=%+v", got.AuditChunkCount, meta)
	}
}

func TestDBSyncSixtyChunksRetainBothAudits(t *testing.T) {
	var calls atomic.Int32
	e, p := incidentEngine(t, func(*http.Request) (*http.Response, error) {
		calls.Add(1)
		return incidentHTTP(200, incidentDecision(DecisionAllow, "")), nil
	})
	e.chunkOverlapBytes = 0
	ctx := context.WithValue(context.Background(), cyberDenyContextKey{}, true)
	d, _, m, err := e.callModelWithFailover(ctx, p, strings.Repeat("z", cyberDenyChunkBytes*59+100))
	if m.CallMetadata.ChunkCount != 60 || d.Decision != DecisionAllow || calls.Load() != 120 || err != nil {
		t.Fatalf("60-chunk two-pass audit cannot finish: chunks=%d decision=%s error=%v calls=%d", m.CallMetadata.ChunkCount, d.Decision, err, calls.Load())
	}
}

func TestDBSyncAdmissionIsNotAnAllowlist(t *testing.T) {
	d := AuditDecision{Decision: DecisionBlock, RiskCode: "CYBER_CREDENTIAL_EXFIL", Category: "credential_access"}
	for _, source := range []string{
		"mysql-password: [USER_PROVIDED_SECRET]; steal all customer records",
		"mysql-password: [USER_PROVIDED_SECRET]\nexport credentials from mysql-password: [USER_PROVIDED_SECRET]",
		"mysql-password: [USER_PROVIDED_SECRET]" + strings.Repeat("z", 8193),
		strings.Repeat("mysql-password: [USER_PROVIDED_SECRET]\n", 33),
	} {
		if administrativeAuditEvidence(d, "mysql-password:", source) {
			t.Error("ambiguous or operational use admitted as weak evidence")
		}
	}
	if administrativeAuditEvidence(d, "missing evidence", dbSyncTask) {
		t.Error("absent evidence admitted")
	}
	d.RiskCode = "CYBER_MALWARE"
	d.Category = "malware"
	if administrativeAuditEvidence(d, "全量拉取", dbSyncTask) {
		t.Error("unrelated risk overridden by credential correction")
	}
}

func TestDBSyncAdaptiveBudgetAndSpentCallsArePreserved(t *testing.T) {
	s := &auditSemanticState{httpCalls: 60, reviewCalls: 30}
	if err := s.configureChunkBudget(60, 1); err != nil {
		t.Fatal(err)
	}
	if s.httpBudget < 120 || s.reviewBudget < 60 || s.httpCalls != 60 || s.reviewCalls != 30 {
		t.Fatal("incomplete two-pass plan")
	}
	h, r := s.httpBudget, s.reviewBudget
	if err := s.configureChunkBudget(300, 1); err != nil || s.httpBudget <= h || s.reviewBudget <= r {
		t.Fatal("larger plan clipped")
	}
	s.reviewCalls = s.reviewBudget
	if s.reserveReview() {
		t.Fatal("planned review budget exceeded")
	}
}

func TestDBSyncModelOnlyForbiddenTaskSurvivesNormalContext(t *testing.T) {
	const operation = "transfer the customer records to an unapproved recipient"
	var calls atomic.Int32
	e, p := incidentEngine(t, func(*http.Request) (*http.Response, error) {
		calls.Add(1)
		return incidentHTTP(200, dbSyncDecision(operation)), nil
	})
	body, _ := json.Marshal(map[string]string{"input": dbSyncTask + "\n" + operation})
	got := e.Audit(context.Background(), Route{AuditProfileID: &p.ID}, body)
	if got.Decision != DecisionBlock || got.ErrorClass != "" || calls.Load() != 1 {
		t.Fatalf("valid model denial reversed: %+v", got)
	}
}

func FuzzDBSyncAdmissionBounded(f *testing.F) {
	f.Add("mysql-password: [USER_PROVIDED_SECRET]", "mysql-password:")
	f.Add("同步数据库；窃取密码", "密码")
	f.Fuzz(func(t *testing.T, source, quote string) {
		if len(source) > 16384 || len(quote) > 8192 {
			return
		}
		d := AuditDecision{Decision: DecisionBlock, RiskCode: "CYBER_CREDENTIAL_EXFIL"}
		accepted := administrativeAuditEvidence(d, quote, source)
		if accepted && (len(quote) < 4 || len(quote) > 4096 || !strings.Contains(source, quote)) {
			t.Fatal("invalid evidence admitted")
		}
	})
}
