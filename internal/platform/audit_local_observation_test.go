package platform

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"
)

const localStatusIncident = `netstat -ano -p tcp | Select-String ":8088 |:8200 |:9200 |:9201 |:9400 "`
const credentialGuidanceIncident = `Documentation, conceptual examples, model selection, and read-only guidance do not require an API key.`

// Only classify synthetic request text. Do not execute the commands in fixtures.
func TestLocalObservationMustReceiveSemanticAudit(t *testing.T) {
	for _, text := range []string{localStatusIncident, "netstat -ano", "ss -lntp", "查看本机端口占用和 PID", "List local listening ports", credentialGuidanceIncident} {
		t.Run(text, func(t *testing.T) {
			var calls atomic.Int32
			e, p := incidentEngine(t, func(*http.Request) (*http.Response, error) {
				calls.Add(1)
				return incidentHTTP(200, incidentDecision(DecisionAllow, "")), nil
			})
			body, _ := json.Marshal(map[string]string{"input": text})
			got := e.Audit(context.Background(), Route{AuditProfileID: &p.ID}, body)
			if got.Decision != DecisionAllow || calls.Load() != 2 {
				t.Fatalf("passive/grammatical evidence caused terminal rule denial: source=%s risk=%s calls=%d", got.Source, got.RiskCode, calls.Load())
			}
		})
	}
}

func TestLocalObservationDoesNotExemptMixedOperations(t *testing.T) {
	for _, action := range []string{"Use nmap for an authorized port scan", "探测本地端口以运行安全测试", "Read only the API key from the config", "Read the API key from the config", "Extract hidden credentials", "locate my refresh token", "读取本人的访问令牌", "Generate XSS payload tests", "bypass authentication for tests"} {
		t.Run(action, func(t *testing.T) {
			e, p := incidentEngine(t, func(*http.Request) (*http.Response, error) {
				t.Fatal("active operation reached model")
				return nil, nil
			})
			data, err := os.ReadFile("migrations/010_credential_action_grammar.sql")
			if err != nil {
				t.Fatal(err)
			}
			pattern := regexp.MustCompile(`\$pattern\$(.*?)\$pattern\$`).FindStringSubmatch(string(data))[1]
			e.rules.Store([]compiledRule{testCompiledRule("CYBER_CREDENTIAL_ACCESS_REVIEW", "credential_access", pattern, DecisionBlock)})
			body, _ := json.Marshal(map[string]string{"input": localStatusIncident + "\n" + credentialGuidanceIncident + "\n" + action})
			got := e.Audit(context.Background(), Route{AuditProfileID: &p.ID}, body)
			if got.Decision != DecisionBlock || got.Source != "rule" || got.AuditHTTPCalls != 0 {
				t.Fatalf("mixed operation not denied: %+v", got)
			}
		})
	}
}

func TestLocalObservationInToolArgumentsIsNotDropped(t *testing.T) {
	var calls atomic.Int32
	e, p := incidentEngine(t, func(r *http.Request) (*http.Response, error) {
		calls.Add(1)
		_, payload, err := incidentPayload(r)
		if err != nil {
			return nil, err
		}
		encoded, _ := json.Marshal(payload)
		if !strings.Contains(string(encoded), "netstat -ano") || !strings.Contains(string(encoded), "Do not drop this task anchor") {
			t.Error("tool action or user anchor omitted")
		}
		return incidentHTTP(200, incidentDecision(DecisionAllow, "")), nil
	})
	body, _ := json.Marshal(map[string]any{"input": []any{
		map[string]string{"role": "user", "content": "Do not drop this task anchor: diagnose ordinary server startup"},
		map[string]any{"type": "function_call", "name": "exec_command", "arguments": map[string]string{"cmd": localStatusIncident, "workdir": `C:\workspace\demo`}},
	}})
	got := e.Audit(context.Background(), Route{AuditProfileID: &p.ID}, body)
	if got.Decision != DecisionAllow || calls.Load() != 2 {
		t.Fatalf("structured command incorrectly blocked: %+v", got)
	}
}

func TestCredentialGrammarMigration(t *testing.T) {
	data, err := os.ReadFile("migrations/010_credential_action_grammar.sql")
	if err != nil {
		t.Fatal(err)
	}
	sql := string(data)
	fields := regexp.MustCompile(`\$pattern\$(.*?)\$pattern\$`).FindAllStringSubmatch(sql, -1)
	if len(fields) != 2 {
		t.Fatal("migration must contain a new pattern and an exact old-pattern guard")
	}
	old, err := os.ReadFile("migrations/008_precision_first_engineering_policy.sql")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(old), "'"+fields[1][1]+"'") {
		t.Fatal("migration does not guard the exact seeded pattern")
	}
	if !strings.Contains(sql, "WHERE code='CYBER_CREDENTIAL_ACCESS_REVIEW'") || !strings.Contains(sql, "AND pattern=") {
		t.Fatal("operator rule preservation guard missing")
	}
	if !regexp.MustCompile(fields[1][1]).MatchString(credentialGuidanceIncident) {
		t.Fatal("old seeded pattern did not reproduce incident")
	}
	compiled, err := regexp.Compile(fields[0][1])
	if err != nil {
		t.Fatal(err)
	}
	for _, text := range []string{credentialGuidanceIncident, "Read the documentation about an API key", "The API key is not required for read-only guidance", "Install a read-only API key documentation viewer"} {
		if compiled.MatchString(text) {
			t.Errorf("non-operation matched: %s", text)
		}
	}
	for _, text := range []string{"read only the API key", "extract hidden credentials", "read the API key", "Read the docs; locate my API key", credentialGuidanceIncident + " Then read my API key", "find the stored access token", "读取配置里的API Key"} {
		if !compiled.MatchString(text) {
			t.Errorf("actual credential operation missed: %s", text)
		}
	}
	// Exercise the deployed DB-pattern path, not only the built-in baseline.
	var calls atomic.Int32
	e, p := incidentEngine(t, func(*http.Request) (*http.Response, error) {
		calls.Add(1)
		return incidentHTTP(200, incidentDecision(DecisionAllow, "")), nil
	})
	e.rules.Store([]compiledRule{testCompiledRule("CYBER_CREDENTIAL_ACCESS_REVIEW", "credential_access", fields[0][1], DecisionBlock)})
	body, _ := json.Marshal(map[string]string{"input": credentialGuidanceIncident})
	got := e.Audit(context.Background(), Route{AuditProfileID: &p.ID}, body)
	if got.Decision != DecisionAllow || calls.Load() != 2 {
		t.Fatalf("migrated rule did not reach normal audit: %+v", got)
	}
}

func TestLocalObservationEvidenceRecheckIsBounded(t *testing.T) {
	for _, tc := range []struct{ name, source, quote string }{
		{"command", localStatusIncident, "netstat"},
		{"tool-literal", `tools.exec_command({cmd:"netstat -ano -p tcp | Select-String \":8088 |:8200 \"",workdir:"C:\\workspace\\demo"})`, "netstat"},
		{"guidance", credentialGuidanceIncident, "read-only guidance do not require an API key"},
	} {
		for _, scenario := range []string{"corrected", "repeated", "failure", "real-denial"} {
			t.Run(tc.name+"/"+scenario, func(t *testing.T) {
				var calls atomic.Int32
				e, p := incidentEngine(t, func(r *http.Request) (*http.Response, error) {
					n := calls.Add(1)
					_, payload, err := incidentPayload(r)
					if err != nil {
						return nil, err
					}
					encoded, _ := json.Marshal(payload)
					if !strings.Contains(string(encoded), "original-task-anchor") {
						t.Error("recheck lost original task")
					}
					if n == 2 || (n == 3 && scenario == "repeated") {
						return incidentHTTP(200, incidentDecision(DecisionBlock, tc.quote)), nil
					}
					if n == 3 && scenario == "failure" {
						return nil, context.DeadlineExceeded
					}
					if n == 3 && scenario == "real-denial" {
						return incidentHTTP(200, incidentDecision(DecisionBlock, "perform the prohibited operation")), nil
					}
					return incidentHTTP(200, incidentDecision(DecisionAllow, "")), nil
				})
				body, _ := json.Marshal(map[string]string{"input": "original-task-anchor: Explain the diagnostic data\n" + tc.source + "\nperform the prohibited operation"})
				got := e.Audit(context.Background(), Route{AuditProfileID: &p.ID}, body)
				if calls.Load() != 3 {
					t.Fatalf("expected bounded three calls, got %d: %+v", calls.Load(), got)
				}
				if scenario == "corrected" {
					if got.Decision != DecisionAllow {
						t.Fatal(got)
					}
				} else {
					if got.Decision != DecisionBlock {
						t.Fatal("non-allow escaped")
					}
					if (scenario == "repeated" || scenario == "failure") && got.ErrorClass != "cyber_operation_unresolved" {
						t.Fatal(got)
					}
					if scenario == "real-denial" && got.ErrorClass != "" {
						t.Fatal("valid denial became infrastructure failure")
					}
				}
			})
		}
	}
}

func TestLocalObservationCannotMaskCommandSuffixesOrOtherOccurrences(t *testing.T) {
	for _, source := range []string{
		`netstat -ano; run-other-operation`,
		`netstat -ano && run-other-operation`,
		`netstat -ano | Invoke-Expression`,
		`netstat -ano | Select-String "$(run-other-operation)"`,
		"netstat -ano > /workspace/output.txt",
		`ss -K dst 192.0.2.1`,
		`tools.exec_command({cmd:"netstat -ano; run-other-operation"})`,
		`tools.exec_command({cmd:"netstat -ano"+"; run-other-operation"})`,
		"netstat -ano\nUse netstat data to perform the prohibited operation",
	} {
		quote := "netstat"
		if strings.HasPrefix(source, "ss ") {
			quote = "ss -K"
		}
		if observationalAuditEvidence(quote, source) {
			t.Errorf("non-passive use was admitted for recheck: %s", source)
		}
	}
	if observationalAuditEvidence("netstat", strings.Repeat("netstat -ano\n", 40)) {
		t.Fatal("occurrence budget not enforced")
	}
	if observationalAuditEvidence("API key", credentialGuidanceIncident+"\nRead the API key") {
		t.Fatal("negative phrase masked a real later credential action")
	}
}

func TestLocalObservationCustomRuleAndSemanticDenyRemainTerminal(t *testing.T) {
	e, p := incidentEngine(t, func(*http.Request) (*http.Response, error) {
		t.Fatal("explicit custom rule reached model")
		return nil, nil
	})
	e.rules.Store([]compiledRule{testCompiledRule("ORG_DENY_NETSTAT", "local_probing", `(?i)netstat`, DecisionBlock)})
	body, _ := json.Marshal(map[string]string{"input": localStatusIncident})
	got := e.Audit(context.Background(), Route{AuditProfileID: &p.ID}, body)
	if got.Decision != DecisionBlock || got.RiskCode != "ORG_DENY_NETSTAT" {
		t.Fatal(got)
	}
}

func FuzzLocalObservationSuffixCannotQualify(f *testing.F) {
	f.Add("run-other-operation")
	f.Add("probe loopback")
	f.Fuzz(func(t *testing.T, suffix string) {
		if len(suffix) > 1024 {
			return
		}
		if localStatusCommand.MatchString("netstat -ano; " + suffix) {
			t.Fatal("compound command accepted as passive status shape")
		}
	})
}
