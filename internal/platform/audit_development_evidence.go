package platform

import (
	"regexp"
	"strings"
)

const shippedSystemPromptPattern = `(?is)(?:\b(?:reveal|extract|print|leak|show)\b|(?:显示|提取|打印|泄露|展示)).{0,120}(?:\b(?:system prompt|developer prompt|hidden instructions|internal prompt)\b|(?:系统提示词|开发者提示词|隐藏指令|内部提示词))`

var interactiveCredentialInput = regexp.MustCompile(`(?i)(?:(?:只?在|从)(?:终端|命令行|控制台)[ \t]*(?:的)?(?:隐藏提示|隐藏输入提示|交互式提示|用户输入提示)(?:中|里)?[ \t]*读取[ \t]*(?:token|密码|凭据|访问令牌)|read[ \t]+(?:the[ \t]+)?(?:token|password|credentials?)[ \t]+from[ \t]+(?:an?[ \t]+)?(?:interactive|hidden)[ \t]+(?:terminal[ \t]+)?prompt)`)
var devPromptCategory = regexp.MustCompile(`(?i)(system.prompt|prompt.extraction|ai.exfiltration|提示词)`)
var refusalTableExpectation = regexp.MustCompile(`(?i)\|[ \t]*(?:不(?:要)?(?:泄露|提供|显示|执行)|拒绝(?:提供|执行)|must not|refuse)`)
var devRiskCategory = regexp.MustCompile(`(?i)(auth|bypass|credential|exfil|凭据|认证|外传)`)
var devAuthTransport = regexp.MustCompile(`(?i)(请求头|headers?|作为.{0,12}认证|(?:token|jwt|session).{0,20}authentication)`)
var devAuthMaterial = regexp.MustCompile(`(?i)(\b(?:token|jwt|session)\b|会话|令牌)`)
var devExplicitOperation = regexp.MustCompile(`(?i)(窃取|盗取|绕过|伪造|冒用|跳过.{0,12}(?:验证|认证|校验|验签)|关闭.{0,12}(?:验证|认证|校验|验签)|他人.{0,12}(?:凭据|令牌|token)|公开.{0,12}(?:token|凭据|密钥)|外传|后门|\b(?:steal|stolen|bypass|forge|forged|exfil\w*|harvest|victim|unauthorized)\b|(?:disable|skip|ignore).{0,24}(?:auth|verification|signature))`)
var markdownRuleBoundary = regexp.MustCompile(`\|[ \t]*(?:\r?\n|\\n)[ \t]*\|`)
var policyNegationSuffix = regexp.MustCompile(`(?i)(?:不要|不得|禁止|不应|不能|拒绝|避免|不|do not |don't |must not |never )[ \t]*$`)

func precisionRule(r compiledRule) bool {
	if r.PatternType != "regex" {
		return false
	}
	if r.Code == "CYBER_SYSTEM_PROMPT_EXTRACTION" {
		return r.Pattern == shippedSystemPromptPattern
	}
	if r.Code == "CYBER_CREDENTIAL_ACCESS_DISABLED" && r.ID == 0 {
		for _, b := range cyberDenyBaseline {
			if b.Code == r.Code {
				return b.Pattern == r.Pattern
			}
		}
	}
	return false
}

// Recognize the *object of a read*, not the environment or a claimed permission.
// The returned admission is not allow: all text still reaches both model passes.
func interactiveCredentialEvidence(source string, start, end int) bool {
	lo, hi := max(0, start-180), min(len(source), end+100)
	around := source[lo:hi]
	for _, m := range interactiveCredentialInput.FindAllStringIndex(around, -1) {
		if lo+m[0] <= start && lo+m[1] >= end {
			return true
		}
	}
	return false
}

func weakDevelopmentRuleEvidence(r compiledRule, text string, ev cyberRuleEvidence) string {
	if !precisionRule(r) {
		return ""
	}
	if r.Code == "CYBER_CREDENTIAL_ACCESS_DISABLED" && interactiveCredentialEvidence(text, ev.start, ev.end) {
		return "interactive_supplied_credential_input"
	}
	if r.Code == "CYBER_SYSTEM_PROMPT_EXTRACTION" {
		// A seeded dot-all pattern can join a refusal to another table row. This
		// invalid relationship is re-audited, not interpreted as a final rule veto.
		if markdownRuleBoundary.MatchString(ev.matchedRaw) {
			return "cross_boundary_system_prompt_terms"
		}
		if policyNegationSuffix.MatchString(text[max(0, ev.start-60):ev.start]) {
			return "negated_system_prompt_disclosure"
		}
	}
	return ""
}

func developmentAuditEvidence(d AuditDecision, quote, source string) bool {
	if !(devRiskCategory.MatchString(d.RiskCode+" "+d.Category) || devPromptCategory.MatchString(d.RiskCode+" "+d.Category)) || len(quote) < 4 || len(quote) > 4096 {
		return false
	}
	offset, found := 0, false
	for i := 0; i < 32; i++ {
		rel := strings.Index(source[offset:], quote)
		if rel < 0 {
			return found
		}
		start, end := offset+rel, offset+rel+len(quote)
		lo := strings.LastIndex(source[:start], "\n") + 1
		hi := len(source)
		if n := strings.IndexByte(source[end:], '\n'); n >= 0 {
			hi = end + n
		}
		if hi-lo > 8192 {
			return false
		}
		line := source[lo:hi]
		if devExplicitOperation.MatchString(line) {
			return false
		}
		input := interactiveCredentialEvidence(source, start, end)
		design := devAuthMaterial.MatchString(quote) && devAuthTransport.MatchString(line)
		// An expected-refusal test row is an artifact, not evidence that its
		// sample instruction has been adopted. The whole task is still rechecked.
		refusalTest := devPromptCategory.MatchString(d.RiskCode+" "+d.Category) && strings.Count(line, "|") >= 4 && refusalTableExpectation.MatchString(line)
		if !input && !design && !refusalTest {
			return false
		}
		found = true
		offset = start + 1
	}
	return false
}
