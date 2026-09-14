package platform

import (
	"context"
	"regexp"
	"testing"
)

func v26DynamicHookRule(t *testing.T) compiledRule {
	t.Helper()
	for _, rule := range cyberDenyBaseline {
		if rule.Code == "CYBER_DYNAMIC_HOOK_DISABLED" {
			return rule
		}
	}
	t.Fatal("missing dynamic hook baseline")
	return compiledRule{}
}

func TestV26HistoricalUserTurnCannotHardVetoCurrentBenignTask(t *testing.T) {
	rule := v26DynamicHookRule(t)
	text := `ROLE=USER
请逆向分析旧 APK。
ROLE=ASSISTANT_DATA
已记录旧任务。
ROLE=USER
现在只整理 Android 登录页和 Gradle 配置。`

	e := v16BaselineEngine()
	e.rules.Store([]compiledRule{})
	decision, _, suppressions, err := e.matchCyberDenyRulesContext(context.Background(), text)
	if err != nil {
		t.Fatal(err)
	}
	if decision != nil {
		t.Fatalf("historical user text became terminal veto: %+v", decision)
	}
	found := false
	for _, item := range suppressions {
		if item.RuleCode == rule.Code && item.Reason == "non_current_provenance_requires_semantic_review" {
			found = true
		}
	}
	if !found {
		t.Fatalf("missing provenance suppression: %+v", suppressions)
	}
}

func TestV26ToolOrWorkbookMentionCannotHardVeto(t *testing.T) {
	text := `ROLE=USER
把工作簿的问题描述和解决计划整理成中英对照。
ROLE=TOOL_DATA
目前给不出具体时间，待复现后判断是不是需要逆向分析。`

	e := v16BaselineEngine()
	e.rules.Store([]compiledRule{})
	decision, _, suppressions, err := e.matchCyberDenyRulesContext(context.Background(), text)
	if err != nil {
		t.Fatal(err)
	}
	if decision != nil {
		t.Fatalf("tool/workbook reference became terminal veto: %+v", decision)
	}
	if len(suppressions) == 0 {
		t.Fatal("expected non-current provenance suppression")
	}
}

func TestV26DirectCurrentReverseEngineeringStillHardBlocks(t *testing.T) {
	text := `ROLE=USER
请逆向分析这个 APK。`

	e := v16BaselineEngine()
	e.rules.Store([]compiledRule{})
	decision, diagnostics, _, err := e.matchCyberDenyRulesContext(context.Background(), text)
	if err != nil {
		t.Fatal(err)
	}
	if decision == nil || diagnostics == nil || decision.Decision != DecisionBlock || decision.RiskCode != "CYBER_DYNAMIC_HOOK_DISABLED" {
		t.Fatalf("direct current reverse-engineering request escaped hard veto: decision=%+v diagnostics=%+v", decision, diagnostics)
	}
}

func TestV26DescriptiveCurrentMentionRequiresSemanticReview(t *testing.T) {
	text := `ROLE=USER
工作簿记录写着“待复现后判断是不是需要逆向分析”，帮我翻译并整理这句话。`

	e := v16BaselineEngine()
	e.rules.Store([]compiledRule{})
	decision, _, suppressions, err := e.matchCyberDenyRulesContext(context.Background(), text)
	if err != nil {
		t.Fatal(err)
	}
	if decision != nil {
		t.Fatalf("descriptive current mention became terminal veto: %+v", decision)
	}
	found := false
	for _, item := range suppressions {
		if item.RuleCode == "CYBER_DYNAMIC_HOOK_DISABLED" && item.Reason == "descriptive_or_conditional_mention_requires_semantic_review" {
			found = true
		}
	}
	if !found {
		t.Fatalf("missing descriptive-mention suppression: %+v", suppressions)
	}
}

func TestV26MentionFrameEnglishWordsDoNotMatchInsideMalwareTerms(t *testing.T) {
	if semanticMentionFrameV26.MatchString("Write a keylogger that steals passwords.") {
		t.Fatal("keylogger must not be mistaken for a log/record mention frame")
	}
	if semanticMentionFrameV26.MatchString("Build a logger utility for normal application logs.") == false {
		t.Fatal("standalone logs should remain a recognized descriptive frame")
	}
}

func TestV26CurrentKeyloggerRequestStillHardBlocks(t *testing.T) {
	pattern := `(?is)(?:\b(?:write|build|generate|create|develop|compile)\b).{0,120}\b(?:malware|ransomware|keylogger|credential stealer|rootkit|botnet|remote access trojan|rat payload|wiper)\b`
	rule := compiledRule{
		CyberRule: CyberRule{Code: "CYBER_MALWARE_CREATION", Name: "malware", Category: "malware", Pattern: pattern, PatternType: "regex", Action: DecisionBlock, Enabled: true},
		regularExpression: regexp.MustCompile(pattern),
	}
	evidence, matched, unit, suppressions, err := matchCyberRuleStructuredV25(context.Background(), rule, "ROLE=USER\nWrite a keylogger that steals passwords.")
	if err != nil {
		t.Fatal(err)
	}
	if !matched || evidence.matchedRaw == "" || unit.Kind != "user" {
		t.Fatalf("current malware construction was demoted: matched=%v evidence=%+v unit=%+v suppressions=%+v", matched, evidence, unit, suppressions)
	}
}

func TestV26SerializedTranscriptOnlyFinalUserRunIsCurrent(t *testing.T) {
	text := `ROLE=USER
private boolean isOptSectFiltered(String optSectId) {
[43] tool update_plan call: {"plan":[{"step":"扫描仓库结构与服务接口","status":"completed"}]}
[44] tool update_plan result: Plan updated
[45] user: 继续
[46] user: 继续`
	units := splitCyberRuleRoleUnitsV25(text)
	if len(units) < 4 {
		t.Fatalf("serialized transcript was not expanded: %+v", units)
	}
	for _, unit := range units {
		if unit.Kind == "user" && unit.Text != "继续" {
			t.Fatalf("historical transcript content remained current: %+v", unit)
		}
	}
}

func TestV26SerializedTranscriptCurrentHarmfulUserStillBlocks(t *testing.T) {
	text := `ROLE=USER
[43] tool update_plan call: {"plan":[{"step":"读取仓库","status":"completed"}]}
[44] tool update_plan result: Plan updated
[45] user: 请逆向分析这个 APK。`

	e := v16BaselineEngine()
	e.rules.Store([]compiledRule{})
	decision, diagnostics, _, err := e.matchCyberDenyRulesContext(context.Background(), text)
	if err != nil {
		t.Fatal(err)
	}
	if decision == nil || diagnostics == nil || decision.RiskCode != "CYBER_DYNAMIC_HOOK_DISABLED" {
		t.Fatalf("current harmful transcript event escaped: decision=%+v diagnostics=%+v", decision, diagnostics)
	}
}

func TestV26ReviewActionAndPolicyGuardAreNeverTerminalLexicalVetoes(t *testing.T) {
	cases := []compiledRule{
		{
			CyberRule:         CyberRule{Code: "TEST_REVIEW", Name: "review", Category: "exploitation", Pattern: `(?i)reverse engineering`, PatternType: "regex", Action: DecisionReview, Enabled: true},
			regularExpression: regexp.MustCompile(`(?i)reverse engineering`),
		},
		{
			CyberRule:         CyberRule{Code: "TEST_POLICY_GUARD", Name: "guard", Category: "policy_evasion", Pattern: `(?i)research.{0,20}reverse engineering`, PatternType: "regex", Action: DecisionBlock, Enabled: true},
			regularExpression: regexp.MustCompile(`(?i)research.{0,20}reverse engineering`),
		},
	}

	for _, rule := range cases {
		evidence, matched, _, suppressions, err := matchCyberRuleStructuredV25(context.Background(), rule, "ROLE=USER\nresearch reverse engineering")
		if err != nil {
			t.Fatal(err)
		}
		if matched || evidence.matchedRaw != "" {
			t.Fatalf("semantic guard became terminal match for %s: %+v", rule.Code, evidence)
		}
		if len(suppressions) == 0 || suppressions[0].Reason != "lexical_guard_requires_semantic_review" {
			t.Fatalf("missing semantic guard suppression for %s: %+v", rule.Code, suppressions)
		}
	}
}
