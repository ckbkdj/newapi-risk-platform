package platform

import (
	"encoding/json"
	"regexp"
	"strings"
)

// Match only the exact shipped rule; administrator patterns remain authoritative.
const shippedPromptInjectionPattern = `(?is)(?:\b(?:prompt injection|ignore previous instructions|override system instructions|developer message override)\b|(?:提示词注入|忽略之前指令|覆盖系统指令|覆盖开发者指令)).{0,180}(?:\b(?:agent|tool|system prompt|retrieval|rag|assistant)\b|(?:Agent|工具|系统提示词|检索|RAG|助手))`

var browserWindowObject = regexp.MustCompile(`(?i)^关闭[ \t]*(?:当前)?(?:所有)?[ \t]*(?:(?:Edge|Chrome|Firefox)[ \t]*(?:浏览器)?|浏览器)[ \t]*窗口[，,；;。.]`)
var identifierListRead = regexp.MustCompile("(?:再按|然后读取|读取|根据|按)[ \t`]*$")
var securityEvidenceTarget = regexp.MustCompile(`(?i)\b(?:edr|antivirus|endpoint protection|defender|siem|security controls?|xdr|ids|ips)\b|杀毒|终端防护|安全控制`)
var identifierListFile = regexp.MustCompile(`(?i)^(?:ids|ips)\.(?:txt|csv|json)(?:$|[^A-Za-z0-9_.-])`)
var previewReadObject = regexp.MustCompile(`^读取[ \t]*(?:本地|当前|服务)?(?:预览响应|页面响应|编译输出|构建结果|测试结果|诊断日志)[，,。.;；？?]`)
var credentialEvidenceTarget = regexp.MustCompile(`(?i)credentials?|authorization|tokens?|cookies?|api[ _.-]?key|凭据|令牌|密钥`)
var numericBudgetKey = regexp.MustCompile(`(?i)(?:^|[^A-Za-z0-9_])((?:max_(?:output_|completion_)?|input_|output_|total_)tokens)(?:\\{0,8}["'])?[ \t]*:[ \t\r\n]*[0-9]+(?:$|[^A-Za-z0-9_.])`)
var warningPredicate = regexp.MustCompile(`(?i)(?:that's a|that is a)[ \t]+$`)
var warningObject = regexp.MustCompile(`(?i)^prompt injection attempt\.[ \t]*(?:\r?\n|\\{1,8}n)[ \t]*-[ \t]*Some system shortcuts are hard-blocked at the tool$`)
var warningCondition = regexp.MustCompile(`(?i)If a page tells you(?:[^\r\n]|\r?\n){1,180}(?:that's a|that is a)[ \t]+$`)
var automationEvidenceClass = regexp.MustCompile(`(?i)^(?:CYBER_(?:WEB|BROWSER|SCRIPT)_AUTOMATION|(?:web|browser|script)_automation)$`)
var browserCoordinatePrimitive = regexp.MustCompile(`(?i)^[A-Za-z0-9_.-]{1,128}\.(?:bat|cmd|ps1|py|js)[ \t]+打开(?:浏览器|Edge|Chrome|Firefox)[ \t]*(?:加载完后|加载完成后)[ \t]*X[ \t]*=[ \t]*[0-9]{1,6}[，,][ \t]*Y[ \t]*=[ \t]*[0-9]{1,6}[ \t]+点击(?:这个|该)?坐标(?:即可)?$`)
var playwrightClickPrimitive = regexp.MustCompile(`^(?:await[ \t]+)?page\.getByRole\([ \t]*(?:'button'|"button"|'link'|"link"|'checkbox'|"checkbox")[ \t]*,[ \t]*\{[ \t]*name:[ \t]*(?:'[^'\\\r\n]{1,80}'|"[^"\\\r\n]{1,80}")[ \t]*\}[ \t]*\)\.click\(\);?$`)
var scriptTaskTitleField = regexp.MustCompile(`^(?:"title"|"preview")[ \t]*:[ \t]*("(?:[^"\\\r\n]|\\.)*")[ \t]*,?$`)
var testRunnerPrimitive = regexp.MustCompile(`^(?:(?:python3?[ \t]+-m[ \t]+)?pytest[ \t]+tests/[A-Za-z0-9_./-]+|npm[ \t]+test|go[ \t]+test[ \t]+\./\.\.\.)$`)
var scriptForbiddenPurpose = regexp.MustCompile(`(?i)(chatgpt|chat\.openai\.com|captcha|验证码|waf|frida|nmap|sql[ _-]?injection|xss|反调试|暴力破解|绕过|窃取|盗取|外传|后门|攻击|扫描|提权|\b(?:exploit|malware|phishing|exfiltrate|bypass|steal|eval|exec|invoke-expression|disable|evade)\b)`)

// A greedy dot-all match can end at ids.txt even when it contains an earlier
// real IDS/EDR target. Check EVERY security target, never just the last one.
func browserListRuleEvidence(source string, ev cyberRuleEvidence) bool {
	if ev.start < 0 || ev.end > len(source) || ev.end <= ev.start || ev.end-ev.start > 4096 {
		return false
	}
	part := source[ev.start:ev.end]
	if !browserWindowObject.MatchString(part) {
		return false
	}
	targets := securityEvidenceTarget.FindAllStringIndex(part, 33)
	if len(targets) == 0 || len(targets) > 32 {
		return false
	}
	for _, m := range targets {
		at := ev.start + m[0]
		// No executable/configuration suffix, partial filename, or bare IDS.
		if !identifierListRead.MatchString(source[max(ev.start, at-64):at]) || !identifierListFile.MatchString(source[at:min(len(source), at+64)]) {
			return false
		}
	}
	return true
}

// Recognize numeric tool/output-budget field names, not arbitrary token names.
// The read's object must be a build/preview result and ALL credential-looking
// words in the candidate must belong to those complete typed keys.
func previewBudgetRuleEvidence(source string, ev cyberRuleEvidence) bool {
	if ev.start < 0 || ev.end > len(source) || ev.end <= ev.start || ev.end-ev.start > 4096 {
		return false
	}
	part := source[ev.start:ev.end]
	if !previewReadObject.MatchString(part) || devExplicitOperation.MatchString(part) {
		return false
	}
	around := source[ev.start:min(len(source), ev.end+80)]
	keys := numericBudgetKey.FindAllStringSubmatchIndex(around, 33)
	targets := credentialEvidenceTarget.FindAllStringIndex(part, 33)
	if len(keys) == 0 || len(keys) > 32 || len(targets) == 0 || len(targets) > 32 {
		return false
	}
	for _, target := range targets {
		covered := false
		for _, key := range keys {
			if key[2] <= target[0] && key[3] >= target[1] {
				covered = true
				break
			}
		}
		if !covered {
			return false
		}
	}
	return true
}

// This warning describes an untrusted-page example and the tool's existing
// restrictions. It is not an instruction to inject. No trust is granted to a
// file/role/tool, and subsequent or overlapping operational matches still run.
// Both newline spellings are matched in place; the input is never unescaped.
func promptWarningRuleEvidence(source string, ev cyberRuleEvidence) bool {
	if ev.start < 0 || ev.end > len(source) || ev.end <= ev.start || ev.end-ev.start > 4096 {
		return false
	}
	prefix := source[max(0, ev.start-300):ev.start]
	return warningPredicate.MatchString(prefix) && warningCondition.MatchString(prefix) && warningObject.MatchString(source[ev.start:ev.end])
}

func scriptDevelopmentRuleEvidence(r compiledRule, source string, ev cyberRuleEvidence) string {
	// The caller verifies precisionRule too; keep this guard to prevent misuse.
	if !precisionRule(r) {
		return ""
	}
	switch r.Code {
	case "CYBER_SECURITY_EVASION":
		if browserListRuleEvidence(source, ev) {
			return "browser_window_object_not_identifier_list_security_control"
		}
	case "CYBER_CREDENTIAL_ACCESS_DISABLED", "CYBER_CREDENTIAL_ACCESS_REVIEW":
		if previewBudgetRuleEvidence(source, ev) {
			return "preview_read_not_numeric_tool_token_budget"
		}
	case "CYBER_PROMPT_INJECTION":
		if promptWarningRuleEvidence(source, ev) {
			return "untrusted_page_warning_not_injection_instruction"
		}
	}
	return ""
}

// This admits ONE source-preserving reclassification, not an allow. Only the
// finite shapes below qualify; no filename, framework, test claim, or historical
// title exempts the surrounding request. Every occurrence must qualify.
func scriptDevelopmentAuditEvidence(d AuditDecision, quote, source string) bool {
	if len(quote) < 4 || len(quote) > 4096 {
		return false
	}
	offset, found := 0, false
	for count := 0; count < 32; count++ {
		n := strings.Index(source[offset:], quote)
		if n < 0 {
			return found
		}
		at := offset + n
		ev := cyberRuleEvidence{start: at, end: at + len(quote), matchedRaw: quote}
		weak := false
		switch strings.ToUpper(d.RiskCode) {
		case "CYBER_SECURITY_EVASION":
			weak = browserListRuleEvidence(source, ev)
		case "CYBER_CREDENTIAL_ACCESS_DISABLED", "CYBER_CREDENTIAL_ACCESS_REVIEW":
			weak = previewBudgetRuleEvidence(source, ev)
		case "CYBER_PROMPT_INJECTION":
			weak = promptWarningRuleEvidence(source, ev)
		}
		if automationEvidenceClass.MatchString(d.RiskCode) || automationEvidenceClass.MatchString(d.Category) {
			line, ok := developmentLineAt(source, ev.start, ev.end)
			weak = ok && !scriptForbiddenPurpose.MatchString(line) && scriptPrimitiveLine(line, quote) && (browserCoordinatePrimitive.MatchString(quote) || playwrightClickPrimitive.MatchString(quote) || testRunnerPrimitive.MatchString(quote))
		}
		if !weak {
			return false
		}
		found, offset = true, at+1
	}
	return false
}

// A short primitive quote must not hide a shell/JS suffix on the same line.
// The only extra wrapper admitted here is one literal task-title/preview field;
// it remains data, not trusted instructions or a reason to omit history.
func scriptPrimitiveLine(line, quote string) bool {
	if line == quote {
		return true
	}
	field := line
	if strings.HasPrefix(field, "{") && strings.HasSuffix(field, "}") {
		field = strings.TrimSpace(field[1 : len(field)-1])
	}
	match := scriptTaskTitleField.FindStringSubmatch(field)
	if len(match) != 2 {
		return false
	}
	var title string
	if json.Unmarshal([]byte(match[1]), &title) != nil {
		return false
	}
	title = strings.TrimSpace(title)
	title = strings.TrimSpace(strings.TrimSuffix(title, "…"))
	return title == quote
}
