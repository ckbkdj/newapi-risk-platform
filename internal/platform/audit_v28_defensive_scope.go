package platform

import (
	"regexp"
	"strings"
)

// v28 keeps model-only Cyber decisions grounded in an actual prohibited action.
// It does not weaken hard operator rules. A normalized allow is not final: the
// existing Cyber path sends allows through the independent verifier pass.
var defensiveAssetScopeV28 = regexp.MustCompile(`(?is)(?:资产管理|资产盘点|资产清单|暴露面(?:检查|盘点|管理)|攻击面(?:管理|盘点)|漏洞(?:扫描|检查|评估|修复|复测|验证)|安全(?:扫描|检查|评估|基线)|风险(?:扫描|检查|评估)|自有资产|内部资产|已授权资产|asset\s+(?:management|inventory|discovery)|attack\s+surface\s+management|exposure\s+(?:management|assessment)|vulnerability\s+(?:scan|scanning|assessment|management)|security\s+(?:scan|assessment)|remediation\s+(?:check|verification|validation))`)

var scanCapabilityV28 = regexp.MustCompile(`(?is)(?:扫描|探测|枚举端口|端口枚举|漏洞扫描|安全扫描|暴露面检查|资产发现|资产探测|\bscan(?:ning)?\b|\bport\s+(?:scan|enumeration)\b|\bvulnerability\s+(?:scan|scanning|assessment)\b|\basset\s+discovery\b|\bexposure\s+assessment\b|\bnmap\b)`)

// These are concrete harmful operations rather than topic words. The absence of
// ownership/authorization language is intentionally not included: lack of such
// a statement is not evidence of abuse.
var concreteHarmfulCyberActionV28 = regexp.MustCompile(`(?is)(?:(?:绕过|规避|跳过|破解).{0,32}(?:验证码|waf|认证|鉴权|权限|限速|风控|反调试|安全控制|edr|杀毒)|(?:漏洞利用|利用漏洞|exploit(?:ation)?|0day|zero[- ]day)|(?:sql\s*注入|xss\s*(?:注入|payload)|攻击\s*payload|恶意\s*payload|\b(?:sql\s*injection|xss|attack\s*payload)\b)|(?:暴力破解|密码喷洒|credential\s*stuffing|password\s*spray|brute\s*force)|(?:反向\s*shell|reverse\s*shell|webshell)|(?:窃取|盗取|偷取|越权提取|外传|渗出|exfiltrat\w*|steal).{0,48}(?:凭据|密码|token|cookie|api\s*key|密钥|secret|credential)|(?:后门|木马|勒索|恶意代码|持久化控制|credential\s*stealer|backdoor|malware|ransomware)|(?:提权|privilege\s*escalation)|(?:删除|破坏|擦除|加密).{0,40}(?:数据|日志|系统|备份|文件|database|logs?|system|backups?|files?)|(?:关闭|禁用|绕过).{0,32}(?:edr|antivirus|防火墙|安全控制|审计|检测)|(?:chatgpt).{0,64}(?:自动化|批量|刷问答|越狱|非官方接口|抓取|bypass|automation|scrap))`)

func normalizeCyberEvidenceGateV28(d AuditDecision, text, source string) AuditDecision {
	if d.Decision == DecisionAllow || !strings.HasPrefix(strings.ToLower(strings.TrimSpace(d.Source)), "model") {
		return d
	}

	evidence := strings.TrimSpace(d.Evidence)
	combined := text + "\n" + source
	label := d.RiskCode + " " + d.Category + " " + d.Reason
	hasConcreteEvidence := scanCapabilityV28.MatchString(evidence) || concreteHarmfulCyberActionV28.MatchString(evidence)

	// A block/review whose quoted evidence contains only nouns/context (for
	// example "资产管理", "Token", "认证配置") has not actually proved a
	// prohibited operation. Downgrade it to a provisional allow so the existing
	// independent verifier must classify the full request again from scratch.
	if evidence == "" || !hasConcreteEvidence {
		return provisionalCyberAllowV28(d, "model block lacked concrete prohibited-action evidence")
	}

	// Defensive asset inventory, exposure assessment and vulnerability
	// remediation are not prohibited merely because they contain scan/security
	// vocabulary. Only keep the denial when the request itself contains a
	// concrete harmful follow-on action such as exploitation, bypass, credential
	// theft, destructive impact or security-control evasion.
	if defensiveAssetScopeV28.MatchString(combined) && scanCapabilityV28.MatchString(evidence+" "+label) && !concreteHarmfulCyberActionV28.MatchString(combined) {
		return provisionalCyberAllowV28(d, "defensive asset/security assessment lacks a concrete harmful action")
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
