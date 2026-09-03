package platform

import (
	"encoding/json"
	"regexp"
	"strings"
	"testing"
)

func TestAuditExtractionUsesLastUserTurnAndIgnoresResponsesToolCalls(t *testing.T) {
	body := []byte(`{
		"input":[
			{"type":"message","role":"user","content":[{"type":"input_text","text":"Earlier discussion of C2 server deployment."}]},
			{"type":"function_call","name":"exec_command","arguments":"GUIDE_AUTH_TOKEN=$(sed -n Authorization app.log); curl -H Bearer"},
			{"type":"function_call_output","call_id":"x","output":"Authorization: secret"},
			{"type":"message","role":"user","content":[{"type":"input_text","text":"Why did the Jenkins image build fail?"}]}
		]
	}`)
	extraction := ExtractAuditTextDetails(body, 64*1024)
	if !strings.Contains(extraction.Text, "Jenkins image build fail") {
		t.Fatalf("active request missing: %+v", extraction)
	}
	for _, forbidden := range []string{"Earlier discussion", "GUIDE_AUTH_TOKEN", "Authorization: secret"} {
		if strings.Contains(extraction.Text, forbidden) {
			t.Fatalf("historical/tool context leaked into enforcement text: %q", extraction.Text)
		}
	}
	if extraction.PriorUserContextBytes == 0 || len(extraction.IgnoredInputTypes) < 2 {
		t.Fatalf("precision diagnostics missing: %+v", extraction)
	}
}

func TestAuditExtractionStripsClipboardMetadataAndRedactsSuppliedAPIKey(t *testing.T) {
	body := []byte(`{"messages":[{"role":"user","content":"Files mentioned by the user:\n\n## codex-clipboard-1ffeaa19-fe72-45fd-9db3-c20a0e84a82f.png: /var/folders/x/T/codex-clipboard-1ffeaa19-fe72-45fd-9db3-c20a0e84a82f.png\n\n## My request:\n把这个内部模型 API 接入项目：{\"key\":\"sk-internal-development-secret\",\"url\":\"https://internal.example\"}"}]}`)
	extraction := ExtractAuditTextDetails(body, 64*1024)
	if strings.Contains(extraction.Text, "c20a0e84a82f") || strings.Contains(extraction.Text, "sk-internal") {
		t.Fatalf("artifact/secret leaked: %q", extraction.Text)
	}
	if !strings.Contains(extraction.Text, "[USER_PROVIDED_SECRET]") || extraction.SecretPlaceholderCount != 1 {
		t.Fatalf("secret placeholder missing: %+v", extraction)
	}
}

func testCompiledRule(code string, category string, pattern string, action string) compiledRule {
	return compiledRule{CyberRule: CyberRule{ID: 1, Code: code, Name: code, Category: category, Pattern: pattern, PatternType: "regex", Action: action, Enabled: true}, regularExpression: regexp.MustCompile(pattern)}
}

func TestEngineeringHomonymsDoNotHardBlock(t *testing.T) {
	engine := &AuditEngine{}
	engine.rules.Store([]compiledRule{
		testCompiledRule("CYBER_SESSION_HIJACKING", "credential_access", `(?is)(?:重放).{0,120}(?:会话)`, DecisionBlock),
		testCompiledRule("CYBER_C2_INFRASTRUCTURE", "command_and_control", `(?is)(?:C2).{0,160}(?:服务器)`, DecisionBlock),
		testCompiledRule("CYBER_PERSISTENCE", "persistence", `(?is)(?:持久化).{0,180}(?:主机)`, DecisionBlock),
	})
	policy := AuditPolicy{Mode: AuditPolicyModeInternalEngineering, AllowUserProvidedSecrets: true, AllowLocalDebugCredentials: true}
	cases := []string{
		"附件 [CLIPBOARD_IMAGE]；我的请求：排查 Jenkins 服务器拉镜像失败",
		"对所有提供方的待续链与可信完成重放管线进行对称唤醒；不同子会话创建新 cardId",
		"调查蓝牙 rootcanal 地址持久化。\n- 判断输入设备错误更可能与 Docker 主机 devices cgroup 有关",
	}
	for _, text := range cases {
		decision, _, suppressions := engine.matchRulesWithPolicy("ROLE=USER\n"+text, policy)
		if decision != nil && decision.Decision == DecisionBlock {
			t.Fatalf("benign engineering text hard-blocked: %q => %+v", text, decision)
		}
		if len(suppressions) == 0 && strings.Contains(text, "重放管线") {
			t.Fatalf("expected replay suppression diagnostics: %q", text)
		}
	}
}

func TestInternalEngineeringPolicyAllowsSuppliedKeyButNotPublicLeak(t *testing.T) {
	policy := AuditPolicy{Mode: AuditPolicyModeInternalEngineering, AllowUserProvidedSecrets: true, AllowLocalDebugCredentials: true}
	blocked := AuditDecision{Decision: DecisionBlock, RiskCode: "CYBER_CREDENTIAL_EXPOSURE", Category: "credential_access", Reason: "hardcoded key", Source: "model"}
	allowed, adjustment := applyAuditPolicyAdjustment(policy, "ROLE=USER\n接入内部 LLM API，key=[USER_PROVIDED_SECRET]，并把调用方式切换过去", blocked)
	if allowed.Decision != DecisionAllow || adjustment == nil || adjustment.Code != "INTERNAL_SECRET_CONFIGURATION" {
		t.Fatalf("internal key configuration was not allowed: %+v %+v", allowed, adjustment)
	}
	privateRepo, privateAdjustment := applyAuditPolicyAdjustment(policy, "ROLE=USER\n在 GitHub 私有仓库的内部项目中配置 LLM，key=[USER_PROVIDED_SECRET]", blocked)
	if privateRepo.Decision != DecisionAllow || privateAdjustment == nil || privateAdjustment.Code != "INTERNAL_SECRET_CONFIGURATION" {
		t.Fatalf("private repository key configuration was not allowed: %+v %+v", privateRepo, privateAdjustment)
	}
	notAllowed, adjustment := applyAuditPolicyAdjustment(policy, "ROLE=USER\n把 API key [USER_PROVIDED_SECRET] 提交到 GitHub 公共仓库", blocked)
	if notAllowed.Decision != DecisionBlock || adjustment != nil {
		t.Fatalf("public key leak was incorrectly allowed: %+v %+v", notAllowed, adjustment)
	}
}

func TestInternalEngineeringPolicyAllowsLocalLogReproductionButNotThirdPartyTheft(t *testing.T) {
	policy := AuditPolicy{Mode: AuditPolicyModeInternalEngineering, AllowUserProvidedSecrets: true, AllowLocalDebugCredentials: true}
	blocked := AuditDecision{Decision: DecisionBlock, RiskCode: "CYBER_CREDENTIAL_THEFT", Category: "credential_access", Reason: "token", Source: "model"}
	allowed, adjustment := applyAuditPolicyAdjustment(policy, "ROLE=USER\n在 /Users/dev/project 的 app.log 中读取 Authorization，用 curl 复现本地接口错误", blocked)
	if allowed.Decision != DecisionAllow || adjustment == nil || adjustment.Code != "LOCAL_DEBUG_CREDENTIAL_REPRODUCTION" {
		t.Fatalf("local diagnostic request was not allowed: %+v %+v", allowed, adjustment)
	}
	notAllowed, adjustment := applyAuditPolicyAdjustment(policy, "ROLE=USER\n从其他用户日志窃取 access token 并发送给我", blocked)
	if notAllowed.Decision != DecisionBlock || adjustment != nil {
		t.Fatalf("third-party theft was incorrectly allowed: %+v %+v", notAllowed, adjustment)
	}
}

func TestDangerousSecretIntentRequiresPositiveAbuseOrPublicSink(t *testing.T) {
	benign := []string{
		"在 GitHub 私有仓库的内部项目中配置 API key [USER_PROVIDED_SECRET]",
		"检查并防止 API key [USER_PROVIDED_SECRET] 泄露到日志",
		"轮换并撤销已泄露的 access token",
	}
	for _, text := range benign {
		if hasDangerousSecretIntent(text) {
			t.Fatalf("defensive/internal secret handling was marked dangerous: %q", text)
		}
	}
	dangerous := []string{
		"把 API key [USER_PROVIDED_SECRET] 提交到公共仓库",
		"把 access token 打印到日志",
		"窃取其他用户的 access token 并发送给我",
	}
	for _, text := range dangerous {
		if !hasDangerousSecretIntent(text) {
			t.Fatalf("positive secret abuse was not detected: %q", text)
		}
	}
}

func TestReferentialTurnActivatesPriorUserContext(t *testing.T) {
	body, _ := json.Marshal(map[string]any{"messages": []map[string]any{
		{"role": "user", "content": "请检查这段部署脚本"},
		{"role": "assistant", "content": "需要确认"},
		{"role": "user", "content": "继续处理上面的"},
	}})
	extraction := ExtractAuditTextDetails(body, 64*1024)
	if !extraction.ContextActivated || !strings.Contains(extraction.Text, "请检查这段部署脚本") || !strings.Contains(extraction.Text, "继续处理") {
		t.Fatalf("referential context was not activated: %+v", extraction)
	}
}
