package platform

import (
	"regexp"
	"strings"
	"unicode/utf8"
)

// This is the exact shipped DB expression from migration 010, not an operator
// override. We correct evidence admission without rewriting enabled/action or
// mutating persisted policy. The raw and decoded tool views both use this gate.
const shippedCredentialAccessPattern = `(?is)(?:\b(?:extract|read|locate|find|recover|parse)(?:[ \t\r\n]+|[(:][ \t]*)["\']?(?:(?:the|a|an|my|your|our|their|his|her|all|any|own|hidden|stored|saved|raw|plaintext|plain-text|current|local|user|users|admin|administrator|only)[ \t\r\n]+){0,8}\b(?:credentials?|access[ _-]tokens?|refresh[ _-]tokens?|api[ _.-]?keys?|authorization|bearer|cookies?)\b|(?:提取|读取|定位|查找|恢复|解析).{0,80}(?:凭据|访问令牌|刷新令牌|API[ _.-]?Key|Authorization|Bearer|Cookie))`

var routineCredentialMaterial = regexp.MustCompile(`(?i)(key|token|credential|password|secret|authorization|bearer|cookie|密钥|私钥|令牌|凭据|密码|口令)`)
var routineCredentialSource = regexp.MustCompile(`(?i)(\b(?:config(?:uration)?|environment|env|keystoreProperties|printenv)\b|\.env\b|(?:keystore|local|gradle|key)\.properties\b|/run/secrets/|\.(?:pk8|jks|keystore)\b|\b(?:os\.(?:getenv|environ)|process\.env|system\.getenv|providers\.environmentVariable|Environment\.GetEnvironmentVariable)\b|(?:本地|本项目|项目|应用|程序|构建|签名).{0,20}(?:配置|开发|凭据|密钥|私钥|令牌|Key)|环境变量)`)
var routineCredentialRead = regexp.MustCompile(`(?i)(\b(?:read|load|locate|find|parse|getenv|getProperty|environmentVariable|GetEnvironmentVariable|load_dotenv)\b|os\.environ\b|process\.env\b|(?:读取|加载|解析|查找|定位)|\b(?:apksigner[ \t]+sign|keytool[ \t]+-list)\b)`)
var routineCredentialExtract = regexp.MustCompile(`(?i)(?:\bextract\b|提取).{0,100}(?:\bconfig(?:uration)?\b|\.env\b|环境变量|项目配置)`)
var credentialSensitiveOrigin = regexp.MustCompile(`(?i)(\b(?:hidden|stolen|victim|unauthorized|other users?|another user|browser cookies?|lsass|ntds|mimikatz)\b|他人|其他用户|别人的|隐藏凭据|隐藏密钥|隐藏令牌|浏览器.{0,12}(?:会话|Cookie|密码)|/etc/shadow|/proc/[0-9]+/environ|Login Data)`)
var credentialHazard = regexp.MustCompile(`(?i)(窃取|盗取|偷取|外传|公开|泄露|泄漏|上传|发送|回显|打印|输出|绕过|伪造|冒用|后门|恶意|\b(?:steal|stolen|dump|exfil\w*|harvest|bypass|forge|leak|disclose|expose|publish|upload|send|print|printf|echo|Write-Host|Write-Output|Out-File|Set-Content|eval|exec|execSync|spawn|subprocess|Invoke-Expression|Start-Process|curl|wget|nc)\b|\b(?:disable|skip|ignore)\b.{0,30}\b(?:auth\w*|signature|verification)\b|\bwrite\b.{0,80}\b(?:public|logs?|external|stdout)\b|\b(?:console\.(?:log|error)|log(?:ger)?\.(?:info|debug|warn|error)|requests?\.(?:post|put)|fetch[ \t]*\())`)
var credentialNegatedClause = regexp.MustCompile(`(?i)(?:不要|不应(?:该)?|不会|不得|禁止|避免|无需|不再|不(?:把|将|写入|记录)|\b(?:do not|don't|must not|never|without)[ \t]+)`)
var credentialDoubleNegative = regexp.MustCompile(`(?:不得不|不能不|不会不|不是不|并非不|不要不|不应不|不需要不|无法不)|(?i:\b(?:not|never)[ \t]+(?:not|never)\b)`)
var credentialAffirmativeJoin = regexp.MustCompile(`(?i)(但是|然而|而是|然后|但|却|不但|不仅|不光|不止|\b(?:but|then|instead|however)\b)`)

func credentialHazardNegated(line string, at int) bool {
	if negatedAuditAction(line, at) {
		return true
	}
	// Object-first safety requirements ("不要将密钥写入公开日志") cannot
	// become positive sinks simply because the object intervenes. Do not carry
	// negation across clauses or an affirmative contrast. Never infer permission.
	start := 0
	if sep := strings.LastIndexAny(line[:at], "，,；;。\n\r"); sep >= 0 {
		_, width := utf8.DecodeRuneInString(line[sep:])
		start = sep + width
	}
	if at-start > 180 {
		return false
	}
	prefix := line[start:at]
	return credentialNegatedClause.MatchString(prefix) && !credentialAffirmativeJoin.MatchString(prefix) && !credentialDoubleNegative.MatchString(prefix) && !doubleNegationSuffix.MatchString(prefix)
}

func hasAffirmativeCredentialHazard(line string) bool {
	if credentialSensitiveOrigin.MatchString(line) {
		return true
	}
	matches := credentialHazard.FindAllStringIndex(line, 64)
	if len(matches) >= 64 {
		return true
	}
	for _, m := range matches {
		if !credentialHazardNegated(line, m[0]) {
			return true
		}
	}
	return false
}

// Reading a selected local configuration file or named environment value is not
// by itself disclosure. A full command is required; pipes, redirections and
// arbitrary compound suffixes cannot inherit this evidence shape.
var credentialReadCommandHead = regexp.MustCompile(`(?i)^(?:cat|head|Get-Content|Get-Item|printenv|apksigner|keytool)\b`)
var credentialReadCommand = regexp.MustCompile(`(?i)^(?:(?:cat|Get-Content(?:[ \t]+-(?:Raw|LiteralPath))?)[ \t]+(?:[A-Za-z0-9_./:\\-]+|"[A-Za-z0-9_./:\\ -]+")|head(?:[ \t]+-n[ \t]+[0-9]+)?[ \t]+[A-Za-z0-9_./:\\-]+|printenv[ \t]+[A-Za-z_][A-Za-z0-9_]*|Get-Item[ \t]+Env:[A-Za-z_][A-Za-z0-9_]*|keytool[ \t]+-list[ \t]+-keystore[ \t]+[A-Za-z0-9_./:\\-]+|apksigner[ \t]+sign[ \t]+--ks[ \t]+[A-Za-z0-9_./:\\-]+[ \t]+--ks-pass[ \t]+env:[A-Za-z_][A-Za-z0-9_]*[ \t]+[A-Za-z0-9_./:\\-]+)$`)

// An already-masked configuration value proves that a value was present, not
// that it was stolen or published. Recheck its use in the full task; do not
// bless suffixes or infer authorization from the placeholder.
var maskedCredentialAssignment = regexp.MustCompile(`^[ \t]*["']?[A-Za-z_][A-Za-z0-9_.-]*["']?[ \t]*[:=][ \t]*["']?\[(?:USER_PROVIDED_SECRET|REDACTED)\]["']?[ \t]*[,;]?[ \t]*$`)

func routineCredentialLine(line string) bool {
	if len(line) <= 1024 && routineCredentialMaterial.MatchString(line) && maskedCredentialAssignment.MatchString(line) {
		return true
	}
	// The local/project label alone is never an allow condition. This identifies
	// ordinary access evidence for a fresh full-context classification, not trust.
	if len(line) == 0 || len(line) > 8192 || (!routineCredentialMaterial.MatchString(line) && !strings.Contains(line, ".env")) || !routineCredentialSource.MatchString(line) {
		return false
	}
	if hasAffirmativeCredentialHazard(line) {
		return false
	}
	trimmed := strings.TrimSpace(line)
	if credentialReadCommandHead.MatchString(trimmed) {
		return credentialReadCommand.MatchString(trimmed)
	}
	return routineCredentialRead.MatchString(line) || routineCredentialExtract.MatchString(line)
}

func localCredentialEvidenceAt(source string, start, end int) bool {
	if start < 0 || end <= start || end > len(source) {
		return false
	}
	lo := strings.LastIndexByte(source[:start], '\n') + 1
	hi := len(source)
	if n := strings.IndexByte(source[end:], '\n'); n >= 0 {
		hi = end + n
	}
	if hi-lo > 8192 {
		return false
	}
	return routineCredentialLine(source[lo:hi])
}

func routineCredentialRuleEvidence(r compiledRule, source string, ev cyberRuleEvidence) bool {
	if r.Code != "CYBER_CREDENTIAL_ACCESS_DISABLED" && r.Code != "CYBER_CREDENTIAL_ACCESS_REVIEW" {
		return false
	}
	if !precisionRule(r) || !localCredentialEvidenceAt(source, ev.start, ev.end) {
		return false
	}
	// A complete matched read/extract in a normal configuration-loading statement
	// does not prove disclosure. Other same/overlapping matches still run.
	return true
}

func routineCredentialAuditEvidence(quote, source string) bool {
	if len(quote) < 3 || len(quote) > 4096 || (!routineCredentialMaterial.MatchString(quote) && !routineCredentialRead.MatchString(quote) && !credentialReadCommandHead.MatchString(strings.TrimSpace(quote)) && !strings.Contains(quote, ".env")) {
		return false
	}
	offset, found := 0, false
	for count := 0; count < 32; count++ {
		rel := strings.Index(source[offset:], quote)
		if rel < 0 {
			return found
		}
		start := offset + rel
		if !localCredentialEvidenceAt(source, start, start+len(quote)) {
			return false
		}
		found = true
		offset = start + 1
	}
	return false
}
