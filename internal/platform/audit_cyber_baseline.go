package platform

import (
	"encoding/json"
	"regexp"
	"strings"
)

func cyberPolicyRule(code, category, pattern string) compiledRule {
	return compiledRule{CyberRule: CyberRule{Code: code, Name: "平台 Cyber 禁用基线", Category: category, Pattern: pattern, PatternType: "regex", Action: DecisionBlock, Enabled: true}, regularExpression: regexp.MustCompile(pattern), literalGuard: auditRegexLiteralGuard(pattern)}
}

// Compact, multilingual baseline independent of database migrations. Ambiguous
// software terms such as a JSON "payload" are not stand-alone deny words.
// All enabled administrator rules still have unconditional veto precedence.
var cyberDenyBaseline = []compiledRule{
	cyberPolicyRule("CYBER_SECURITY_TEST_DISABLED", "security_testing", `(?i)(?:渗透(?:测试)?|(?:接口|网络|端口|漏洞).{0,12}扫描|扫描.{0,12}(?:接口|网络|端口|漏洞)|安全.{0,6}测试|\b(?:penetration\s+test\w*|vulnerability\s+scann\w*|port\s+scann\w*|network\s+scann\w*|nmap|masscan|sqlmap|nikto|ffuf|nuclei)\b)`),
	cyberPolicyRule("CYBER_EXPLOIT_TEST_DISABLED", "exploitation", `(?i)(?:\b(?:exploit(?:s|ation)?|brute[-_ ]?forc(?:e|ing)|reverse[-_ ]shell|crack(?:ing)?|SQL\s+injection)\b|SQL\s*注入|暴力破解|反向\s*(?:shell|连接)|漏洞利用|\bXSS\b[ \t:_-]{0,8}(?:payloads?|assertions?|attacks?|inject\w*|tests?|攻击|注入|载荷|测试))`),
	cyberPolicyRule("CYBER_CONTROL_BYPASS_DISABLED", "security_evasion", `(?is)(?:(?:bypass|evade|circumvent|绕过|规避).{0,100}(?:captcha|waf|auth|access control|rate.?limit|anti.?debug|验证码|防火墙|认证|权限|限速|风控|反调试)|(?:captcha|waf|验证码|风控).{0,60}(?:bypass|绕过|规避))`),
	cyberPolicyRule("CYBER_DYNAMIC_HOOK_DISABLED", "reverse_engineering", `(?i)(?:\b(?:frida|xposed|lsposed|decompil\w*|reverse[-_ ]engineering)\b|动态\s*hook|hook\s*动态|(?:dynamic|runtime)\s+hook\w*|反编译|逆向(?:工程|分析|测试|应用|代码))`),
	cyberPolicyRule("CYBER_PACKET_TAMPER_DISABLED", "request_tampering", `(?is)(?:(?:抓包|拦截请求|packet capture).{0,100}(?:篡改|重放|修改|tamper|replay)|(?:tamper|modify).{0,50}(?:captured request|captured packet))`),
	cyberPolicyRule("CYBER_CHATGPT_WEB_AUTOMATION_DISABLED", "web_automation", `(?is)(?:(?:selenium|puppeteer|playwright|scrap\w*).{0,300}(?:chatgpt(?:\.com)?|chat\.openai\.com)|(?:chatgpt(?:\.com)?|chat\.openai\.com).{0,300}(?:selenium|puppeteer|playwright|scrap\w*)|(?:自动化|脚本|批量).{0,120}(?:操作|操控|控制|发送|提问|对话|刷|抓取).{0,120}(?:chatgpt(?:\.com)?|chat\.openai\.com)|(?:chatgpt(?:\.com)?|chat\.openai\.com).{0,120}(?:网页|页面|浏览器|对话).{0,120}(?:自动化|脚本|批量)|\bautomate\w*.{0,120}(?:chatgpt(?:\.com)?|chat\.openai\.com).{0,100}\b(?:web|browser|conversation|prompt|chat)\b|(?:chatgpt(?:\.com)?|chat\.openai\.com).{0,100}\b(?:web|browser|conversation|prompt|chat)\b.{0,120}\bautomate\w*|越狱测试|jailbreak\s+test\w*)`),
	cyberPolicyRule("CYBER_CLI_PROBING_DISABLED", "local_probing", `(?is)(?:探测.{0,20}端口|\bprob(?:e|es|ed|ing).{0,30}\bports?\b|(?:高频|压力测试|压测|high.frequency|stress test|load test).{0,50}(?:请求|接口|requests?|http)|(?:请求|接口).{0,20}(?:高频|压力测试|压测))`),
	cyberPolicyRule("CYBER_SYSTEM_CONFIGURATION_DISABLED", "system_configuration", `(?is)(?:(?:修改|写入|更改|modify|patch|write).{0,100}(?:/etc/(?:sysctl|iptables|nftables|ssh/sshd|sudoers)|底层.{0,8}配置|内核.{0,8}配置|防火墙规则|安全配置|kernel configuration)|\b(?:sysctl\s+-w|iptables\s+-[AFIP]|nft\s+add)\b)`),
	cyberPolicyRule("CYBER_CREDENTIAL_ACCESS_DISABLED", "credential_access", `(?is)(?:\b(?:extract|read|dump|export|steal)(?:[ \t\r\n]+|[(:][ \t]*)["\']?(?:(?:the|a|an|my|your|our|their|his|her|all|any|own|hidden|stored|saved|raw|plaintext|plain-text|current|local|user|users|admin|administrator|only)[ \t\r\n]+){0,8}\b(?:credentials?|authorization|cookies?|api[ _.-]?keys?|(?:access|auth|session|bearer)[ _.-]?tokens?)\b|(?:提取|读取|导出|窃取).{0,100}(?:credentials?|authorization|cookies?|api[ _.-]?key|(?:access|auth|session|bearer)[ _.-]?tokens?|凭据|令牌|密钥)|(?:api[ _.-]?key|密钥|令牌|凭据|(?:access|auth|session|bearer)[ _.-]?tokens?).{0,80}(?:公开日志|public log|原文.{0,10}(?:写|发送)|外传)|隐藏后门|窃取.{0,40}访问令牌)`),
}

func enforceCyberAuditPayload(profile AuditProfile, payload map[string]any) {
	// Vendor extras must not truncate evidence, inject template messages, request
	// multiple choices or put the small output budget into thinking. Only the
	// transport/model parameters explicitly permitted here survive profile.extra.
	for key := range payload {
		switch key {
		case "model", "messages", "max_tokens", "response_format", "structured_outputs", "guided_json":
		default:
			delete(payload, key)
		}
	}
	payload["temperature"] = 0
	payload["stream"] = false
	if isQwenModel(profile.Model) || auditProfileExtra(profile)["_risk_qwen_fast_mode"] == true {
		payload["chat_template_kwargs"] = map[string]any{"enable_thinking": false, "preserve_thinking": false}
	}
}

func strictAuditExtraValid(profile AuditProfile) bool {
	if len(profile.Extra) == 0 {
		return true
	}
	var value map[string]any
	return json.Unmarshal(profile.Extra, &value) == nil
}

func cyberDeniedCategory(category string) bool {
	normalized := strings.ToLower(strings.TrimSpace(category))
	if strings.Contains(normalized, "cyber") && normalized != "non_cyber" {
		return true
	}
	switch normalized {
	case "credential_access", "credential_theft", "exploitation", "malware", "security_testing", "reconnaissance", "security_evasion", "defense_evasion", "exfiltration", "persistence", "command_and_control", "privilege_escalation", "request_tampering", "reverse_engineering", "web_automation", "local_probing", "network_probing", "network_reconnaissance", "port_scanning", "system_configuration", "illicit":
		return true
	}
	return false
}
