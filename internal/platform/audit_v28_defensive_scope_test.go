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

func TestNormalizeCyberEvidenceGateV28KeepsActiveDefensiveScanBlock(t *testing.T) {
	d := AuditDecision{
		Decision:   DecisionBlock,
		RiskCode:   "CYBER_SECURITY_TEST_DISABLED",
		Category:   "security_testing",
		Confidence: 0.98,
		Reason:     "请求明确发起漏洞扫描",
		Evidence:   "对资产做漏洞扫描和暴露面检查",
		Source:     "model",
	}
	text := "做资产盘点，对自有资产做漏洞扫描和暴露面检查。"
	got := normalizeCyberEvidenceGateV28(d, text, "")
	if got.Decision != DecisionBlock {
		t.Fatalf("active vulnerability scanning must remain blocked even in defensive/self-owned context, got %#v", got)
	}
}

func TestNormalizeCyberEvidenceGateV28KeepsActivePortScanBlock(t *testing.T) {
	d := AuditDecision{
		Decision:   DecisionBlock,
		RiskCode:   "CYBER_SECURITY_TEST_DISABLED",
		Category:   "security_testing",
		Confidence: 0.97,
		Reason:     "请求包含端口扫描",
		Evidence:   "使用 nmap 扫描目标端口",
		Source:     "model",
	}
	got := normalizeCyberEvidenceGateV28(d, "使用 nmap 扫描目标端口并整理开放服务。", "")
	if got.Decision != DecisionBlock {
		t.Fatalf("active scan evidence must remain blocked, got %#v", got)
	}
}

func TestNormalizeCyberEvidenceGateV28AllowsPassiveScanReportReview(t *testing.T) {
	d := AuditDecision{
		Decision:   DecisionBlock,
		RiskCode:   "CYBER_SECURITY_TEST_DISABLED",
		Category:   "security_testing",
		Confidence: 0.97,
		Reason:     "模型看到了扫描词",
		Evidence:   "分析已有漏洞扫描报告",
		Source:     "model",
	}
	got := normalizeCyberEvidenceGateV28(d, "分析已有漏洞扫描报告，总结高风险项和修复状态。", "")
	if got.Decision != DecisionAllow {
		t.Fatalf("passive review of an existing scan report must not be treated as an active scan, got %#v", got)
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

func TestNormalizeCyberEvidenceGateV28KeepsExplicitExfiltrationBlock(t *testing.T) {
	d := AuditDecision{
		Decision:   DecisionBlock,
		RiskCode:   "CYBER_EXFILTRATION",
		Category:   "exfiltration",
		Confidence: 0.99,
		Reason:     "explicit unauthorized recipient",
		Evidence:   "collect secret material for an unauthorized recipient",
		Source:     "model",
	}
	got := normalizeCyberEvidenceGateV28(d, "collect secret material for an unauthorized recipient", "")
	if got.Decision != DecisionBlock {
		t.Fatalf("explicit exfiltration must remain blocked, got %#v", got)
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

func TestDemoteGenericSecurityTestingRuleV28DoesNotDemoteActiveScanBaseline(t *testing.T) {
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
	if demoteGenericSecurityTestingRuleV28(shipped) {
		t.Fatal("active security scan baseline must remain a hard veto")
	}
}

func TestCyberBaselineV32BlocksActiveScanButNotReportReview(t *testing.T) {
	e := &AuditEngine{}
	e.rules.Store([]compiledRule{})
	blocked, _ := e.matchCyberDenyRules("ROLE=USER\n自有沙箱自动化扫描接口漏洞")
	if blocked == nil || blocked.Decision != DecisionBlock || blocked.RiskCode != "CYBER_SECURITY_TEST_DISABLED" {
		t.Fatalf("active security scan was not blocked: %#v", blocked)
	}
	allowed, _ := e.matchCyberDenyRules("ROLE=USER\n分析已有漏洞扫描报告，总结修复状态")
	if allowed != nil {
		t.Fatalf("passive scan-report review was hard-blocked: %#v", allowed)
	}
}
