package platform

import (
	"context"
	"testing"
)

func TestV27PriorRecordSentenceCannotDemoteLaterNmapOperation(t *testing.T) {
	text := "ROLE=USER\n把已有 language_server 连接表与 Clash 连接记录按源端口关联，解释当前代理链；只分析已有记录。\nScan the network with nmap"
	e := v16BaselineEngine()
	e.rules.Store([]compiledRule{})
	decision, diagnostics, _, err := e.matchCyberDenyRulesContext(context.Background(), text)
	if err != nil {
		t.Fatal(err)
	}
	if decision == nil || diagnostics == nil || decision.Decision != DecisionBlock {
		t.Fatalf("later explicit nmap operation was demoted by prior record sentence: decision=%+v diagnostics=%+v", decision, diagnostics)
	}
}

func TestV27WorkbookConditionalMentionRemainsSemanticOnly(t *testing.T) {
	text := "ROLE=USER\n工作簿记录写着‘待复现后判断是不是需要逆向分析’，帮我翻译并整理这句话。"
	e := v16BaselineEngine()
	e.rules.Store([]compiledRule{})
	decision, _, suppressions, err := e.matchCyberDenyRulesContext(context.Background(), text)
	if err != nil {
		t.Fatal(err)
	}
	if decision != nil {
		t.Fatalf("workbook mention became terminal Cyber: %+v", decision)
	}
	found := false
	for _, item := range suppressions {
		if item.RuleCode == "CYBER_DYNAMIC_HOOK_DISABLED" && item.Reason == "descriptive_or_conditional_mention_requires_semantic_review" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected descriptive/conditional suppression: %+v", suppressions)
	}
}

func TestV27EnglishReferenceSentenceCannotDemoteLaterNmapOperation(t *testing.T) {
	text := "ROLE=USER\nPlease summarize what the logs mention. Scan the network with nmap."
	e := v16BaselineEngine()
	e.rules.Store([]compiledRule{})
	decision, diagnostics, _, err := e.matchCyberDenyRulesContext(context.Background(), text)
	if err != nil {
		t.Fatal(err)
	}
	if decision == nil || diagnostics == nil || decision.Decision != DecisionBlock {
		t.Fatalf("later explicit nmap operation was demoted by prior English reference: decision=%+v diagnostics=%+v", decision, diagnostics)
	}
}
