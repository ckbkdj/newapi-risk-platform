package platform

import "testing"

func TestNormalizeCyberEvidenceGateV28RejectsTopicOnlyModelBlock(t *testing.T) {
	d := AuditDecision{
		Decision:   DecisionBlock,
		RiskCode:   "CYBER_NETWORK_SCAN",
		Category:   "network_scan",
		Confidence: 0.99,
		Reason:     "资产管理可能涉及扫描",
		Evidence:   "资产管理",
		Source:     "model",
	}
	got := normalizeCyberEvidenceGateV28(d, "帮我整理资产管理清单", "")
	if got.Decision != DecisionAllow {
		t.Fatalf("topic-only evidence must become provisional allow, got %#v", got)
	}
	if got.Source != "model_evidence_normalization_v28" {
		t.Fatalf("unexpected normalization source: %q", got.Source)
	}
}

func TestNormalizeCyberEvidenceGateV28AllowsDefensiveAssessmentWithoutHarm(t *testing.T) {
	d := AuditDecision{
		Decision:   DecisionBlock,
		RiskCode:   "CYBER_NETWORK_SCAN",
		Category:   "network_scan",
		Confidence: 0.98,
		Reason:     "请求包含漏洞扫描",
		Evidence:   "对资产做漏洞扫描和暴露面检查",
		Source:     "model",
	}
	text := "做资产盘点，对资产做漏洞扫描和暴露面检查，并跟踪漏洞修复后的复测结果。"
	got := normalizeCyberEvidenceGateV28(d, text, "")
	if got.Decision != DecisionAllow {
		t.Fatalf("defensive assessment without harmful follow-on must become provisional allow, got %#v", got)
	}
}

func TestNormalizeCyberEvidenceGateV28KeepsConcreteExploitBlock(t *testing.T) {
	d := AuditDecision{
		Decision:   DecisionBlock,
		RiskCode:   "CYBER_EXPLOITATION",
		Category:   "exploitation",
		Confidence: 0.99,
		Reason:     "包含漏洞利用",
		Evidence:   "利用漏洞并发送SQL注入攻击payload",
		Source:     "model",
	}
	text := "先做资产盘点，然后利用漏洞并发送SQL注入攻击payload。"
	got := normalizeCyberEvidenceGateV28(d, text, "")
	if got.Decision != DecisionBlock {
		t.Fatalf("concrete exploit action must remain blocked, got %#v", got)
	}
}

func TestNormalizeCyberEvidenceGateV28KeepsCredentialTheftBlock(t *testing.T) {
	d := AuditDecision{
		Decision:   DecisionBlock,
		RiskCode:   "CYBER_CREDENTIAL_THEFT",
		Category:   "credential_theft",
		Confidence: 0.99,
		Reason:     "明确窃取凭据",
		Evidence:   "窃取目标账号的Token和Cookie",
		Source:     "model",
	}
	got := normalizeCyberEvidenceGateV28(d, "窃取目标账号的Token和Cookie", "")
	if got.Decision != DecisionBlock {
		t.Fatalf("credential theft must remain blocked, got %#v", got)
	}
}

func TestNormalizeCyberEvidenceGateV28DoesNotOverrideHardRules(t *testing.T) {
	d := AuditDecision{
		Decision:   DecisionBlock,
		RiskCode:   "CYBER_NETWORK_SCAN",
		Category:   "network_scan",
		Confidence: 1,
		Reason:     "operator rule",
		Evidence:   "漏洞扫描",
		Source:     "rule",
	}
	got := normalizeCyberEvidenceGateV28(d, "资产管理漏洞扫描", "")
	if got.Decision != DecisionBlock || got.Source != "rule" {
		t.Fatalf("hard rules must be untouched, got %#v", got)
	}
}

func TestDemoteGenericSecurityTestingRuleV28OnlyDemotesShippedPattern(t *testing.T) {
	var shipped compiledRule
	found := false
	for _, rule := range cyberDenyBaseline {
		if rule.Code == "CYBER_SECURITY_TEST_DISABLED" {
			shipped = rule
			found = true
			break
		}
	}
	if !found {
		t.Fatal("shipped security-testing baseline not found")
	}
	if !demoteGenericSecurityTestingRuleV28(shipped) {
		t.Fatal("shipped generic scan rule must be demoted to semantic review")
	}
	custom := shipped
	custom.Pattern = `(?i)custom-hard-scan-rule`
	if demoteGenericSecurityTestingRuleV28(custom) {
		t.Fatal("custom operator pattern must keep hard-rule precedence")
	}
}
