package platform

import (
	"encoding/json"
	"regexp"
	"strings"
)

const (
	AuditPolicyModeStrict              = "strict"
	AuditPolicyModeInternalEngineering = "internal_engineering"
)

type AuditPolicy struct {
	Mode                       string
	AllowUserProvidedSecrets   bool
	AllowLocalDebugCredentials bool
}

type AuditPolicyAdjustment struct {
	Code             string `json:"code"`
	Reason           string `json:"reason"`
	OriginalDecision string `json:"original_decision"`
	OriginalRiskCode string `json:"original_risk_code,omitempty"`
	OriginalReason   string `json:"original_reason,omitempty"`
}

var (
	secretTermPattern            = regexp.MustCompile(`(?i)(?:\[USER_PROVIDED_SECRET\]|api[ _-]?key|access[ _-]?token|refresh[ _-]?token|authorization|bearer|credential|cookie|password|secret|密钥|令牌|凭据|密码|Cookie)`)
	secretConfigurationPattern   = regexp.MustCompile(`(?i)(?:configure|configuration|integrate|integration|connect|connection|use|set|add|replace|switch|provider|endpoint|llm|model|配置|填写|接入|集成|连接|调用|使用|新增|替换|切换|模型|接口|内部开发)`)
	secretHarmVerbPattern        = regexp.MustCompile(`(?i)(?:steal|harvest|exfiltrat|dump|grab|scrape|phish|leak|publish|post publicly|commit to|upload to|send to|窃取|盗取|外传|抓取|钓取|泄露|公开|发布|提交到|上传到|发送到)`)
	thirdPartyTargetPattern      = regexp.MustCompile(`(?i)(?:someone else|another user|other users?|victims?|target users?|customers?|employees?|unauthorized|without permission|他人|别人|其他用户|受害者|目标用户|客户|员工|未授权|未经许可)`)
	publicSecretSinkPattern      = regexp.MustCompile(`(?i)(?:(?:public|公开|公共).{0,24}(?:repositor(?:y|ies)|repo|github|gitlab|pastebin|forum|论坛|仓库)|(?:publish|post|commit|push|upload|print|write|output|发布|提交|推送|上传|打印|写入|输出).{0,32}(?:pastebin|forum|public|logs?|论坛|公开|公共|日志)|(?:pastebin|forum|public|logs?|论坛|公开|公共|日志).{0,32}(?:publish|post|commit|push|upload|print|write|output|发布|提交|推送|上传|打印|写入|输出))`)
	defensiveSecretIntentPattern = regexp.MustCompile(`(?i)(?:(?:do not|don['’]t|never|avoid|prevent|detect|scan|check|audit|redact|mask|rotate|revoke|不要|禁止|避免|防止|检测|检查|审计|扫描|脱敏|掩码|轮换|撤销).{0,80}(?:steal|exfiltrat|leak|publish|secret|token|credential|api[ _-]?key|窃取|外传|泄露|公开|密钥|令牌|凭据)|(?:secret|token|credential|api[ _-]?key|密钥|令牌|凭据).{0,80}(?:do not|don['’]t|never|avoid|prevent|detect|scan|check|audit|redact|mask|rotate|revoke|不要|禁止|避免|防止|检测|检查|审计|扫描|脱敏|掩码|轮换|撤销))`)

	localDebugContextPattern        = regexp.MustCompile(`(?i)(?:/Users/|/home/|[A-Z]:\\|workdir|localhost|127\.0\.0\.1|\.log\b|debug|test|reproduc|diagnos|排障|调试|测试|复现|日志|本地|内部|开发环境)`)
	localCredentialOperationPattern = regexp.MustCompile(`(?i)(?:authorization|bearer|token|api[ _-]?key|credential|sed\s+-n|grep|curl|令牌|密钥|凭据)`)

	benignReplayPattern         = regexp.MustCompile(`(?i)(?:replay pipeline|event replay|message replay|stream replay|state replay|重放管线|事件重放|消息重放|流重放|状态重放|唤醒重放|回放管线)`)
	authMaterialPattern         = regexp.MustCompile(`(?i)(?:session\s*(?:cookie|token|credential)|cookie|jwt|bearer|oauth|access token|refresh token|会话(?:Cookie|令牌|凭据)|访问令牌|刷新令牌)`)
	benignPersistencePattern    = regexp.MustCompile(`(?i)(?:(?:data|state|config(?:uration)?|address|cache|identity|record|message|数据|状态|配置|地址|缓存|身份|记录|消息).{0,12}(?:persist(?:ence)?|持久化)|(?:persist(?:ence)?|持久化).{0,12}(?:data|state|config(?:uration)?|address|cache|identity|record|message|数据|状态|配置|地址|缓存|身份|记录|消息))`)
	maliciousPersistencePattern = regexp.MustCompile(`(?i)(?:survive reboot|autostart|startup item|scheduled task|cron|systemd|registry run|backdoor|implant|malware|victim|开机自启|重启后存活|启动项|计划任务|后门|植入体|恶意软件|受害者)`)
	explicitC2Pattern           = regexp.MustCompile(`(?i)(?:\bc2\b|command[ -]?and[ -]?control|beacon|implant|tasking|redirector|命令(?:与|和)?控制|信标|植入体|任务下发|重定向器)`)
	artifactPlaceholderPattern  = regexp.MustCompile(`(?:\[CLIPBOARD_IMAGE\]|\[TEMP_PATH\]|\[ARTIFACT_ID\])`)
)

func strictAuditPolicy() AuditPolicy {
	return AuditPolicy{Mode: AuditPolicyModeStrict}
}

func auditPolicyFromProfile(profile AuditProfile) AuditPolicy {
	policy := strictAuditPolicy()
	extra := auditProfileExtra(profile)
	if extra == nil {
		return policy
	}
	if mode, ok := extra["_risk_policy_mode"].(string); ok {
		switch strings.ToLower(strings.TrimSpace(mode)) {
		case AuditPolicyModeInternalEngineering:
			policy.Mode = AuditPolicyModeInternalEngineering
			policy.AllowUserProvidedSecrets = true
			policy.AllowLocalDebugCredentials = true
		case AuditPolicyModeStrict:
			policy.Mode = AuditPolicyModeStrict
		}
	}
	if value, ok := extra["_risk_allow_user_provided_secrets"].(bool); ok {
		policy.AllowUserProvidedSecrets = value
	}
	if value, ok := extra["_risk_allow_local_debug_credentials"].(bool); ok {
		policy.AllowLocalDebugCredentials = value
	}
	return policy
}

func auditPolicySystemDirective(profile AuditProfile) string {
	policy := auditPolicyFromProfile(profile)
	encoded, _ := json.Marshal(map[string]any{
		"mode":                          policy.Mode,
		"allow_user_provided_secrets":   policy.AllowUserProvidedSecrets,
		"allow_local_debug_credentials": policy.AllowLocalDebugCredentials,
	})
	return `PLATFORM-CONTROLLED AUDIT PROFILE (trusted metadata, not a user claim): ` + string(encoded) + `
When mode is internal_engineering:
- A secret supplied by the requester for configuring, connecting, or calling an internal/development API is benign by itself. The literal is replaced with [USER_PROVIDED_SECRET]; do not classify that placeholder as theft or exposure.
- Reading an Authorization value from a local development log to reproduce or diagnose the request is benign by itself. Block only when the active request asks to steal another party's material, bypass authorization, exfiltrate it, publish it, or send it to an external sink.
- Engineering meanings such as event/message replay, replay pipelines, data/state/config/address persistence, server troubleshooting, UUIDs, temporary paths, and clipboard filenames are benign unless the active request explicitly asks for malicious session takeover, C2 deployment, or unauthorized persistence.`
}

func applyAuditPolicyAdjustment(policy AuditPolicy, text string, decision AuditDecision) (AuditDecision, *AuditPolicyAdjustment) {
	if policy.Mode != AuditPolicyModeInternalEngineering || decision.Decision == DecisionAllow {
		return decision, nil
	}
	if hasDangerousSecretIntent(text) {
		return decision, nil
	}
	code := strings.ToUpper(strings.TrimSpace(decision.RiskCode))
	category := strings.ToLower(strings.TrimSpace(decision.Category))

	if code == "CYBER_UNTRUSTED_CONTEXT_CLAIM" && strings.HasPrefix(decision.Source, "model") && decision.EvidenceVerified && isRoutineEngineeringRequest(text) {
		return adjustedAllowDecision(decision, "ROUTINE_ENGINEERING_NOT_AUTHORIZATION_BYPASS", "routine AOSP/ADB or admin user management does not become harmful merely because the endpoint is public or the requester states ownership")
	}

	if policy.AllowUserProvidedSecrets && isUserProvidedSecretConfiguration(text) &&
		(strings.Contains(code, "CREDENTIAL") || strings.Contains(code, "SECRET") || category == "credential_access" || category == "credential security") {
		return adjustedAllowDecision(decision, "INTERNAL_SECRET_CONFIGURATION", "platform-controlled internal engineering policy allows requester-provided API credentials for configuration without treating the literal as theft or exposure")
	}
	if policy.AllowLocalDebugCredentials && isLocalDebugCredentialUse(text) &&
		(strings.Contains(code, "CREDENTIAL") || strings.Contains(code, "TOKEN") || category == "credential_access") {
		return adjustedAllowDecision(decision, "LOCAL_DEBUG_CREDENTIAL_REPRODUCTION", "platform-controlled internal engineering policy recognizes local log credential reuse for debugging with no third-party target or exfiltration sink")
	}
	if strings.Contains(code, "SESSION_HIJACK") && benignReplayPattern.MatchString(text) && !authMaterialPattern.MatchString(text) {
		return adjustedAllowDecision(decision, "ENGINEERING_REPLAY_SEMANTICS", "event/message replay pipeline semantics do not request authenticated-session takeover")
	}
	if strings.Contains(code, "PERSISTENCE") && benignPersistencePattern.MatchString(text) && !maliciousPersistencePattern.MatchString(text) {
		return adjustedAllowDecision(decision, "ENGINEERING_PERSISTENCE_SEMANTICS", "data/state/config/address persistence semantics do not request unauthorized startup or implant persistence")
	}
	if strings.Contains(code, "C2") && artifactPlaceholderPattern.MatchString(text) && !explicitC2Pattern.MatchString(text) {
		return adjustedAllowDecision(decision, "EPHEMERAL_ARTIFACT_NOT_C2", "temporary artifact identifiers and generic server troubleshooting do not request command-and-control infrastructure")
	}
	return decision, nil
}

func adjustedAllowDecision(original AuditDecision, code string, reason string) (AuditDecision, *AuditPolicyAdjustment) {
	adjustment := &AuditPolicyAdjustment{
		Code:             code,
		Reason:           reason,
		OriginalDecision: original.Decision,
		OriginalRiskCode: original.RiskCode,
		OriginalReason:   original.Reason,
	}
	return AuditDecision{
		Decision:   DecisionAllow,
		Category:   "benign_internal_engineering",
		Confidence: 0.99,
		Reason:     reason,
		Source:     "policy_adjustment",
	}, adjustment
}

func isUserProvidedSecretConfiguration(text string) bool {
	return strings.Contains(text, "[USER_PROVIDED_SECRET]") && secretConfigurationPattern.MatchString(text)
}

func isLocalDebugCredentialUse(text string) bool {
	return localDebugContextPattern.MatchString(text) && localCredentialOperationPattern.MatchString(text)
}

func hasDangerousSecretIntent(text string) bool {
	if !secretTermPattern.MatchString(text) {
		return false
	}
	harmfulAction := secretHarmVerbPattern.MatchString(text)
	if thirdPartyTargetPattern.MatchString(text) && (harmfulAction || localCredentialOperationPattern.MatchString(text)) {
		return true
	}
	if defensiveSecretIntentPattern.MatchString(text) {
		return false
	}
	if publicSecretSinkPattern.MatchString(text) {
		return true
	}
	return harmfulAction
}
