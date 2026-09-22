package platform

import (
	"regexp"
	"strings"
)

// v28 keeps model-only Cyber decisions grounded in an actual prohibited action.
// It does not weaken custom operator rules. Weak model evidence is provisional
// and v29 turns any resulting uncertainty into fail-open observation.
var defensiveAssetScopeV28 = regexp.MustCompile(`(?is)(?:资产管理|资产盘点|资产清单|暴露面(?:检查|盘点|管理)|攻击面(?:管理|盘点)|漏洞(?:检查|评估|修复|复测|验证)|安全(?:检查|评估|基线)|风险(?:检查|评估)|自有资产|内部资产|已授权资产|asset\s+(?:management|inventory)|attack\s+surface\s+management|exposure\s+(?:management|assessment)|vulnerability\s+(?:assessment|management)|security\s+assessment|remediation\s+(?:check|verification|validation))`)

var scanCapabilityV28 = regexp.MustCompile(`(?is)(?:扫描|探测|枚举端口|端口枚举|漏洞扫描|安全扫描|暴露面检查|资产发现|资产探测|\bscan(?:ning)?\b|\bport\s+(?:scan|enumeration)\b|\bvulnerability\s+(?:scan|scanning|assessment)\b|\basset\s+discovery\b|\bexposure\s+assessment\b|\bnmap\b)`)

var activeSecurityScanV32 = regexp.MustCompile(`(?is)(?:(?:扫描|探测|枚举).{0,32}(?:接口|网络|网段|主机|端口|漏洞|服务)|(?:接口|网络|网段|主机|端口|漏洞|服务).{0,32}(?:扫描|探测|枚举)|(?:安全|漏洞).{0,8}扫描|(?:主动|自动化|批量).{0,24}(?:扫描|探测|枚举)|\b(?:run|use|execute)?\s*(?:nmap|masscan|nuclei|nikto|ffuf|sqlmap)\b|\b(?:security|vulnerability|port|network)\s+scann?\w*\b|\bscan\w*.{0,24}\b(?:network|subnet|host|ports?|vulnerabilit\w*|services?)\b)`)

var passiveSecurityScanReferenceV32 = regexp.MustCompile(`(?is)(?:(?:分析|查看|审阅|复盘|总结|整理|解释|读取).{0,48}(?:扫描报告|扫描结果|扫描日志|扫描输出|nmap\s*输出|scan\s+(?:report|result|log|output))|(?:扫描报告|扫描结果|扫描日志|扫描输出|nmap\s*输出|scan\s+(?:report|result|log|output)).{0,48}(?:分析|查看|审阅|复盘|总结|整理|解释)|(?:修复|整改).{0,32}(?:复测|验证)(?:结果|报告|记录)?)`)

// These are concrete harmful operations rather than topic words. The absence of
// ownership/authorization language is intentionally not included: lack of such
// a statement is not evidence of abuse.
var concreteHarmfulCyberActionV28 = regexp.MustCompile(`(?is)(?:(?:绕过|规避|跳过|破解).{0,32}(?:验证码|waf|认证|鉴权|权限|限速|风控|反调试|安全控制|edr|杀毒)|(?:漏洞利用|利用漏洞|exploit(?:ation)?|0day|zero[- ]day)|(?:sql\s*注入|xss\s*(?:注入|payload)|攻击\s*payload|恶意\s*payload|\b(?:sql\s*injection|xss|attack\s*payload)\b)|(?:暴力破解|密码喷洒|credential\s*stuffing|password\s*spray|brute\s*force)|(?:反向\s*shell|reverse\s*shell|webshell)|(?:窃取|盗取|偷取|越权提取|外传|渗出|exfiltrat\w*|steal).{0,48}(?:凭据|密码|token|cookie|api\s*key|密钥|secret|credential)|(?:凭据|密码|token|cookie|api\s*key|密钥|secret|credential).{0,48}(?:外传|发送|上传|泄露|exfiltrat\w*|send|upload).{0,64}(?:第三方|未授权|外部|无关接收方|third[- ]party|unauthorized|external|unapproved)|(?:收集|发送|上传|公开).{0,48}(?:秘密|敏感数据|客户数据|客户记录|数据库|源代码|凭据|令牌|cookie|api\s*key).{0,64}(?:未授权|无关第三方|外部接收方|接收方)|(?:collect|send|upload|publish|transfer|exfiltrat\w*).{0,48}(?:secret material|sensitive data|customer data|customer records?|database|source code|credentials?|tokens?|cookies?|api\s*keys?).{0,64}(?:unauthorized|unapproved|third[- ]party|external recipient|recipient)|(?:后门|木马|勒索|恶意代码|持久化控制|credential\s*stealer|backdoor|malware|ransomware)|(?:提权|privilege\s*escalation)|(?:删除|破坏|擦除|加密).{0,40}(?:数据|日志|系统|备份|文件|database|logs?|system|backups?|files?)|(?:关闭|禁用|绕过).{0,32}(?:edr|antivirus|防火墙|安全控制|审计|检测)|(?:chatgpt).{0,64}(?:自动化|批量|刷问答|越狱|非官方接口|抓取|bypass|automation|scrap))`)

// The shipped generic security-testing rule historically treated the presence
// of scan/pentest vocabulary as conclusive harm. That is too weak for a hard
// veto. Demote only the unchanged shipped baseline pattern to semantic audit;
// administrator-authored rules with different patterns keep hard precedence.
func demoteGenericSecurityTestingRuleV28(rule compiledRule) bool {
	// v32: the shipped security-scan rule is a hard veto for an active current
	// scan operation. Passive report/history references are filtered earlier by
	// semanticOnlyRuleMatchV26. Keep this function for compatibility with older
	// callers/tests, but never demote an active baseline match.
	return false
}

func normalizeCyberEvidenceGateV28(d AuditDecision, text, source string) AuditDecision {
	if d.Decision == DecisionAllow || !strings.HasPrefix(strings.ToLower(strings.TrimSpace(d.Source)), "model") {
		return d
	}

	evidence := strings.TrimSpace(d.Evidence)
	combined := text + "\n" + source
	hasScanEvidence := scanCapabilityV28.MatchString(evidence)
	hasHarmEvidence := concreteHarmfulCyberActionV28.MatchString(evidence)

	// A block/review whose quoted evidence contains only nouns/context (for
	// example "资产管理", "Token", "认证配置") has not actually proved a
	// prohibited operation.
	if evidence == "" || (!hasScanEvidence && !hasHarmEvidence) {
		return provisionalCyberAllowV28(d, "model block lacked concrete prohibited-action evidence")
	}

	// v32: an explicit active security/vulnerability/network/port scan is itself
	// a governed Cyber capability. Ownership/authorization wording does not turn
	// the operation into an allow. Passive analysis of an already-produced scan
	// report/result remains non-operational and can fail open.
	if hasScanEvidence && activeSecurityScanV32.MatchString(combined) && !passiveSecurityScanReferenceV32.MatchString(evidence) {
		return d
	}
	if hasScanEvidence && !concreteHarmfulCyberActionV28.MatchString(combined) {
		reason := "scan terminology is descriptive or passive rather than an active scan operation"
		if defensiveAssetScopeV28.MatchString(combined) || passiveSecurityScanReferenceV32.MatchString(combined) {
			reason = "asset/security report review does not request an active scan operation"
		}
		return provisionalCyberAllowV28(d, reason)
	}

	return d
}

func provisionalCyberAllowV28(d AuditDecision, reason string) AuditDecision {
	original := d.Decision
	return AuditDecision{
		Decision:               DecisionAllow,
		Category:               "benign_security_operations",
		Confidence:             max(d.Confidence, 0.95),
		ConfidenceKind:         d.ConfidenceKind,
		ConfidenceLabel:        d.ConfidenceLabel,
		Reason:                 reason,
		Source:                 "model_evidence_normalization_v28",
		policyOriginalDecision: original,
	}
}
