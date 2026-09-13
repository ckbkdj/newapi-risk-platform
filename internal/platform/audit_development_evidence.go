package platform

import (
	"regexp"
	"strings"
)

const shippedSystemPromptPattern = `(?is)(?:\b(?:reveal|extract|print|leak|show)\b|(?:显示|提取|打印|泄露|展示)).{0,120}(?:\b(?:system prompt|developer prompt|hidden instructions|internal prompt)\b|(?:系统提示词|开发者提示词|隐藏指令|内部提示词))`

const shippedSecurityEvasionPattern = `(?is)(?:\b(?:bypass|disable|evade|blind|tamper with)\b|(?:绕过|关闭|规避|致盲|篡改)).{0,120}(?:\b(?:edr|antivirus|endpoint protection|defender|siem|security controls?|xdr|ids|ips)\b|(?:EDR|杀毒|终端防护|Defender|SIEM|安全控制|XDR|IDS|IPS))`

const shippedDataExfiltrationPattern = `(?is)(?:\b(?:exfiltrate|steal|smuggle|extract)\b|(?:外传|窃取|偷运|导出)).{0,160}(?:\b(?:database|customer data|source code|documents|secrets|files|records)\b|(?:数据库|客户数据|源代码|文档|秘密|文件|记录)).{0,160}(?:\b(?:target|victim|company|tenant|server)\b|(?:目标|受害者|公司|租户|服务器))`

var interactiveCredentialInput = regexp.MustCompile(`(?i)(?:(?:只?在|从)(?:终端|命令行|控制台)[ \t]*(?:的)?(?:隐藏提示|隐藏输入提示|交互式提示|用户输入提示)(?:中|里)?[ \t]*读取[ \t]*(?:token|密码|凭据|访问令牌)|read[ \t]+(?:the[ \t]+)?(?:token|password|credentials?)[ \t]+from[ \t]+(?:an?[ \t]+)?(?:interactive|hidden)[ \t]+(?:terminal[ \t]+)?prompt)`)
var devPromptCategory = regexp.MustCompile(`(?i)(system.prompt|prompt.extraction|ai.exfiltration|提示词)`)
var refusalTableExpectation = regexp.MustCompile(`(?i)\|[ \t]*(?:不(?:要)?(?:泄露|提供|显示|执行)|拒绝(?:提供|执行)|must not|refuse)`)
var devRiskCategory = regexp.MustCompile(`(?i)(auth|bypass|credential|exfil|凭据|认证|外传)`)
var devAuthTransport = regexp.MustCompile(`(?i)(请求头|headers?|作为.{0,12}认证|(?:token|jwt|session).{0,20}authentication)`)
var devAuthMaterial = regexp.MustCompile(`(?i)(\b(?:token|jwt|session)\b|会话|令牌)`)
var devExplicitOperation = regexp.MustCompile(`(?i)(窃取|盗取|绕过|伪造|冒用|跳过.{0,12}(?:验证|认证|校验|验签)|关闭.{0,12}(?:验证|认证|校验|验签)|他人.{0,12}(?:凭据|令牌|token)|公开.{0,12}(?:token|凭据|密钥)|外传|后门|\b(?:steal|stolen|bypass|forge|forged|exfil\w*|harvest|victim|unauthorized)\b|(?:disable|skip|ignore).{0,24}(?:auth|verification|signature))`)
var markdownRuleBoundary = regexp.MustCompile(`\|[ \t]*(?:\r?\n|\\n)[ \t]*\|`)
var defensiveXSSContext = regexp.MustCompile(`(?i)(?:(?:防(?:止|范|御)?|预防|避免|拦截|过滤|清洗|转义|编码|净化|修复|防护).{0,32}\bXSS\b|\bXSS\b.{0,32}(?:防护|过滤|清洗|转义|编码|净化|修复)|\b(?:sanitize|escape|filter|clean|prevent|protect|mitigat\w*|block)\b.{0,48}\bXSS\b|\bXSS\b.{0,48}\b(?:sanitiz\w*|escap\w*|filter\w*|clean\w*|prevent\w*|protect\w*|mitigat\w*)\b)`)
var routineDataExportContext = regexp.MustCompile(`(?is)(?:异步.{0,24}导出|分页.{0,24}导出|批量.{0,24}导出|报表.{0,24}导出|归档.{0,24}导出|导出.{0,28}(?:限制|任务|接口|功能|报表|CSV|Excel|分页|批次|最大行数|最大条数|数据库连接|JVM内存)|单任务.{0,24}(?:最大行数|最大条数)|容量(?:目标|规划|估算)|数据库连接|JVM\s*内存|\b(?:async|paged|paginated|batch|report|csv|excel|archive)\s+export\b|\bexport\b.{0,48}\b(?:row limit|max(?:imum)? rows?|pagination|batch size|database connections?|jvm memory|capacity planning)\b)`)
var harmfulDataExportContext = regexp.MustCompile(`(?is)(?:未授权|未经授权|无权限|越权|他人|其他租户|其他用户|受害者|目标(?:系统|服务器|租户|公司|数据库|仓库)|窃取|盗取|外传|偷运|凭据|密码|令牌|密钥|Cookie|API.?Key|\b(?:unauthori[sz]ed|victim|other users?|another tenant|target (?:system|server|tenant|company|database|repository)|steal|stolen|exfiltrat\w*|smuggl\w*|credentials?|passwords?|tokens?|cookies?|private keys?|api keys?|bypass|compromise)\b)`)

// Scope negation to the matched action, never the whole request. Double
// negatives and quoted "local/authorized" claims are not permissions.
var policyNegationSuffix = regexp.MustCompile(`(?i)(?:不要|不得|禁止|不应(?:该)?|不能|拒绝|避免|无需|不会|没有|不再|未|不|\bdo not |\bdon't |\bmust not |\bnever )[ \t]*$`)
var doubleNegationSuffix = regexp.MustCompile(`(?:不得|不能|不可|不会|不是|并非|没有|禁止|不要|不应|无法|无需|不需要|不必|未尝)[ \t]*(?:不(?:要|得|能|应(?:该)?|会|再|必|需要)?|没有|未|禁止|拒绝|避免|无需)[ \t]*$|(?i:\b(?:not|never)[ \t]+(?:never|not)[ \t]+$)`)
var completeSecurityTarget = regexp.MustCompile(strings.Replace(shippedSecurityEvasionPattern, `(?:EDR|杀毒|终端防护|Defender|SIEM|安全控制|XDR|IDS|IPS)`, `(?:杀毒|终端防护|安全控制)`, 1))

func negatedAuditAction(source string, at int) bool {
	if at < 0 || at > len(source) {
		return false
	}
	prefix := source[max(0, at-128):at]
	return policyNegationSuffix.MatchString(prefix) && !doubleNegationSuffix.MatchString(prefix)
}

func precisionRule(r compiledRule) bool {
	if r.PatternType != "regex" {
		return false
	}
	if r.Code == "CYBER_CREDENTIAL_ACCESS_REVIEW" {
		return r.Pattern == shippedCredentialAccessPattern
	}
	if r.Code == "CYBER_SECURITY_EVASION" {
		return r.Pattern == shippedSecurityEvasionPattern
	}
	if r.Code == "CYBER_DATA_EXFILTRATION" {
		return r.Pattern == shippedDataExfiltrationPattern
	}
	if r.Code == "CYBER_SYSTEM_PROMPT_EXTRACTION" {
		return r.Pattern == shippedSystemPromptPattern
	}
	if r.Code == "CYBER_PROMPT_INJECTION" {
		return r.Pattern == shippedPromptInjectionPattern
	}
	if r.ID == 0 {
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

// Defensive source comments and sanitization code may literally contain phrases
// such as "防 XSS攻击". That phrase describes the threat being mitigated, not an
// operation to perform. Suppress only this individual shipped-baseline candidate;
// later XSS payload/injection candidates in the same request are still scanned.
func defensiveXSSEvidence(source string, ev cyberRuleEvidence) bool {
	if ev.start < 0 || ev.end <= ev.start || ev.end > len(source) || !strings.Contains(strings.ToLower(ev.matchedRaw), "xss") {
		return false
	}
	lineStart := strings.LastIndex(source[:ev.start], "\n") + 1
	lineEnd := len(source)
	if next := strings.IndexByte(source[ev.end:], '\n'); next >= 0 {
		lineEnd = ev.end + next
	}
	if lineEnd-lineStart > 4096 {
		return false
	}
	return defensiveXSSContext.MatchString(source[lineStart:lineEnd])
}

// A routine product/data-platform export can contain the same three nouns as the
// generic exfiltration seed rule: "导出 ... 数据库 ... 目标". Examples include
// async export row limits, report/CSV export, archive jobs and capacity targets.
// Downgrade only the individual shipped-rule candidate to semantic review, and
// never when the local window contains an unauthorized/third-party/secret signal.
func routineDataExportEvidence(source string, ev cyberRuleEvidence) bool {
	if ev.start < 0 || ev.end <= ev.start || ev.end > len(source) {
		return false
	}
	matchedLower := strings.ToLower(ev.matchedRaw)
	if strings.Contains(matchedLower, "exfiltrat") || strings.Contains(matchedLower, "steal") || strings.Contains(matchedLower, "smuggl") ||
		strings.Contains(ev.matchedRaw, "外传") || strings.Contains(ev.matchedRaw, "窃取") || strings.Contains(ev.matchedRaw, "偷运") || strings.Contains(ev.matchedRaw, "盗取") {
		return false
	}
	if !strings.Contains(matchedLower, "export") && !strings.Contains(matchedLower, "extract") && !strings.Contains(ev.matchedRaw, "导出") && !strings.Contains(ev.matchedRaw, "提取") {
		return false
	}
	lo, hi := max(0, ev.start-320), min(len(source), ev.end+320)
	around := source[lo:hi]
	if harmfulDataExportContext.MatchString(around) {
		return false
	}
	return routineDataExportContext.MatchString(around)
}

func weakDevelopmentRuleEvidence(r compiledRule, text string, ev cyberRuleEvidence) string {
	if !precisionRule(r) {
		return ""
	}
	if reason := scriptDevelopmentRuleEvidence(r, text, ev); reason != "" {
		return reason
	}
	if (r.Code == "CYBER_CREDENTIAL_ACCESS_DISABLED" || r.Code == "CYBER_CREDENTIAL_ACCESS_REVIEW") && stateObjectNotCredential(text, ev) {
		return "read_object_is_state_not_cross_clause_credential"
	}
	if routineCredentialRuleEvidence(r, text, ev) {
		return "local_credential_loading_requires_semantic_audit"
	}
	if r.Code == "CYBER_SECURITY_TEST_DISABLED" && escapedMountMapCandidate(text, ev) {
		return "escaped_linebreak_filesystem_row"
	}
	if r.Code == "CYBER_EXPLOIT_TEST_DISABLED" && defensiveXSSEvidence(text, ev) {
		return "defensive_xss_mitigation_requires_semantic_audit"
	}
	if r.Code == "CYBER_DATA_EXFILTRATION" && routineDataExportEvidence(text, ev) {
		return "routine_data_export_requires_semantic_audit"
	}
	// A reference inside a complete plain-source search is not execution of the
	// tool named in the search expression. All other text and rules still run.
	if r.ID == 0 && (r.Category == "security_testing" || r.Category == "reverse_engineering" || r.Category == "exploitation" || r.Category == "system_configuration") && (engineeringEvidenceAt(text, ev.start, ev.end) || developmentDataEvidenceAt(text, ev.start, ev.end)) {
		return "ordinary_engineering_command_requires_semantic_audit"
	}
	if (r.Code == "CYBER_CREDENTIAL_ACCESS_DISABLED" || r.Code == "CYBER_SYSTEM_PROMPT_EXTRACTION" || r.Code == "CYBER_DATA_EXFILTRATION" || r.Code == "CYBER_SECURITY_EVASION") && negatedAuditAction(text, ev.start) {
		return "locally_negated_action"
	}
	if r.Code == "CYBER_DATA_EXFILTRATION" && strings.HasPrefix(text[ev.start:], "导出器") {
		return "exporter_noun_not_exfiltration_action"
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
		if negatedAuditAction(text, ev.start) {
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

// A quote of one simple action may have lost its immediately preceding
// negation. Every occurrence must be locally negated before one fresh check.
var simpleCredentialActionQuote = regexp.MustCompile(`(?i)^(?:读取|提取|导出|窃取|read|extract|dump|export|steal)[ \t]+(?:tokens?|credentials?|cookies?|api[_ -]?keys?)$|^(?:读取|提取|导出|窃取)[ \t]*(?:凭据|密钥|令牌)$`)

func negatedCredentialAuditEvidence(quote, source string) bool {
	if !simpleCredentialActionQuote.MatchString(quote) {
		return false
	}
	offset, found := 0, false
	for i := 0; i < 32; i++ {
		n := strings.Index(source[offset:], quote)
		if n < 0 {
			return found
		}
		at := offset + n
		if !negatedAuditAction(source, at) {
			return false
		}
		found = true
		offset = at + len(quote)
	}
	return false
}
