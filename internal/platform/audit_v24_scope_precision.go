package platform

import (
	"regexp"
	"strings"
)

// v24: visual/design artifact export is not data exfiltration. The shipped
// exfiltration seed is intentionally broad and can otherwise join a plan item
// such as "导出/校验图表" with a later tool command containing `--files` and a
// build-directory glob such as `!target`. Extend the existing routine-export
// precision guard rather than weakening the administrator rule or the generic
// exfiltration deny boundary.
var routineArtifactExportContextV24 = regexp.MustCompile(`(?is:(?:导出|export).{0,32}(?:图表|架构图|流程图|设计图|draw\.io|diagram|chart|svg|pdf|png|预览|校验|检查)|(?:图表|架构图|流程图|设计图|draw\.io|diagram|chart).{0,32}(?:导出|export|预览|校验|检查))`)

func init() {
	// All package variables have completed initialization before init runs.
	// Preserve the earlier v20 routine-data-export patterns and add only this
	// narrow visual-artifact family. This remains a candidate suppression: the
	// complete request still proceeds to semantic audit.
	routineDataExportContext = regexp.MustCompile(`(?:` + routineDataExportContext.String() + `)|(?:` + routineArtifactExportContextV24.String() + `)`)
}

var nonCyberGitHistoryScopeLabelV24 = regexp.MustCompile(`(?i)(?:\bCYBER_(?:DATA_TAMPERING|FRAUD)\b|\bCYBER_MALICIOUS\b.{0,80}(?:git|commit|history)|git[ _-]?history|git\s*历史|提交历史|版本控制|工时|作者信息|commit author|commit date)`)
var gitHistoryOperationV24 = regexp.MustCompile(`(?is)(?:(?:git|commit|提交).{0,160}(?:作者|author|email|邮箱|时间|date|月份|历史|history|rebase|filter-repo|amend|改写|修改|重写)|(?:作者|author|提交时间|commit date).{0,120}(?:git|commit|提交|历史|history))`)
var gitHistoryEvidenceV24 = regexp.MustCompile(`(?is)(?:(?:提交|commit).{0,120}(?:作者|author|时间|date|月份|历史|history|信息)|(?:作者信息|提交时间|commit author|commit date).{0,120}(?:修改|改成|rewrite|change|提交|commit))`)

// These are concrete Cyber purposes for a Git-history operation. General HR,
// attribution, timesheet, policy or honesty concerns are deliberately absent:
// this gateway enforces Cyber capability, not every form of misconduct.
var gitHistoryCyberPurposeV24 = regexp.MustCompile(`(?is)(?:
	(?:隐藏|掩盖|清除|删除).{0,48}(?:入侵|攻击痕迹|后门|恶意(?:代码|提交|载荷)|取证证据|安全审计证据|安全日志)
	|(?:植入|加入|注入).{0,48}(?:后门|木马|恶意代码|窃密|凭据窃取)
	|(?:窃取|盗取|外传|偷运).{0,64}(?:凭据|密码|令牌|token|cookie|api.?key|客户数据|数据库|源代码)
	|(?:绕过|规避|关闭|禁用).{0,48}(?:认证|权限|风控|审计|检测|安全控制|edr|antivirus)
	|\b(?:cover\s+tracks?|conceal|hide|erase|remove)\b.{0,64}\b(?:intrusion|attack traces?|backdoor|malware|malicious commit|forensic evidence|security audit evidence|security logs?)\b
	|\b(?:implant|inject|insert)\b.{0,64}\b(?:backdoor|malware|trojan|credential stealer)\b
	|\b(?:steal|exfiltrat\w*|smuggl\w*)\b.{0,64}\b(?:credentials?|passwords?|tokens?|cookies?|api keys?|customer data|database|source code)\b
	|\b(?:bypass|evade|disable)\b.{0,48}\b(?:authentication|authorization|security controls?|audit|detection|edr|antivirus)\b
)`)

// Qwen can drift from the Cyber-only taxonomy into generic fraud/compliance
// judgements. Normalize only a very narrow class: a non-allow model verdict
// labelled as generic Git-history/fraud/tampering, whose verified evidence and
// request are about version-control metadata/history, with no concrete Cyber
// purpose. The normalized allow is NOT final authorization: callCyberDenyModel
// still sends it through the independent verifier pass.
func normalizeCyberOnlyScopeV24(d AuditDecision, text, source string) AuditDecision {
	if d.Decision == DecisionAllow || !strings.HasPrefix(strings.ToLower(strings.TrimSpace(d.Source)), "model") {
		return d
	}
	label := d.RiskCode + " " + d.Category + " " + d.Reason
	if !nonCyberGitHistoryScopeLabelV24.MatchString(label) {
		return d
	}
	if !gitHistoryOperationV24.MatchString(text) && !gitHistoryOperationV24.MatchString(source) {
		return d
	}
	if strings.TrimSpace(d.Evidence) != "" && !gitHistoryEvidenceV24.MatchString(d.Evidence) {
		return d
	}
	if gitHistoryCyberPurposeV24.MatchString(text) || gitHistoryCyberPurposeV24.MatchString(source) {
		return d
	}

	original := d.Decision
	return AuditDecision{
		Decision:               DecisionAllow,
		Category:               "normal_dev",
		Confidence:             max(d.Confidence, 0.95),
		ConfidenceKind:         d.ConfidenceKind,
		ConfidenceLabel:        d.ConfidenceLabel,
		Reason:                 "Git history/metadata changes are outside Cyber-only scope absent a concrete security harm",
		Source:                 "model_scope_normalization",
		policyOriginalDecision: original,
	}
}
