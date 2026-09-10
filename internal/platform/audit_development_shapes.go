package platform

import (
	"encoding/xml"
	"io"
	"regexp"
	"strings"
)

// Bounded evidence admission, not a request/domain allowlist. These shapes
// cannot authorize execution, skip other rules, or override a valid deny.
var credentialDocumentationRow = regexp.MustCompile("^[ \\t|`+*-]*(?:~?/|[A-Za-z]:\\\\)?[A-Za-z0-9_./\\\\<>-]+\\.(?:json|ya?ml|toml|ini|properties|env|conf|xml|gradle|kts)[` \\t]*(?:[ \\t]{2,}|[ \\t]*\\|[ \\t]*)(?:[A-Za-z][A-Za-z0-9_ /(),.:-]*|[\\p{Han}A-Za-z0-9_ /(),，、.:-]+)[ \\t|`]*$")
var documentationOperation = regexp.MustCompile(`(?i)(\b(?:read|extract|steal|dump|export|find|locate|recover|cat|copy|open|send|upload|print|execute|run|bypass|harvest|publish|fetch)\b|读取|提取|窃取|导出|发送|上传|执行|绕过|公开|泄露)`)
var nonCredentialStateRead = regexp.MustCompile(`^(?:读取|查询|查看|获取)[ \t]*\x60?(?:当前|本地|服务|应用)?(?:运行)?(?:状态|配置状态|状态信息|布尔值|配置是否存在|文件是否存在)`)
var currentSessionSource = regexp.MustCompile(`(?i)(当前(?:已)?登录(?:的)?(?:账号|账户|用户)|当前(?:会话|登录态)|\bcurrent(?:ly)?[ -](?:logged[ -]in[ -](?:user|account)|session)\b)`)
var normalSessionUse = regexp.MustCompile(`(?i)(请求头|认证|客户端|业务[ \t]*SDK|\b(?:SDK|authentication|authorization header)\b)`)
var configurationAssignment = regexp.MustCompile(`(?i)^(?:[+*-][ \t]*)?(?:(?:val|var|const|final|String)[ \t]+)?(?:[A-Za-z_][A-Za-z0-9_.]*)[ \t]*[:=][ \t]*(?:"\[(?:USER_PROVIDED_SECRET|REDACTED)\]"|'\[(?:USER_PROVIDED_SECRET|REDACTED)\]'|\[(?:USER_PROVIDED_SECRET|REDACTED)\]|"[A-Za-z0-9_.@/-]{0,80}"|'[A-Za-z0-9_.@/-]{0,80}')[ \t]*[,;]?$`)
var developmentQuotedLiteral = regexp.MustCompile(`"(?:[^"\\\r\n]|\\.)*"|'(?:[^'\\\r\n]|\\.)*'`)
var repositoryDSL = regexp.MustCompile(`^(?:[ \t{}():=;,]|(?:repositories|maven|mavenCentral|google|gradlePluginPortal|credentials|PasswordCredentials|username|password|url|uri|name|STRING)\b)+$`)
var repositoryArtifactURL = regexp.MustCompile(`https://[A-Za-z0-9.-]+(?::[0-9]+)?/[A-Za-z0-9_./+%-]+\.(?:pom|jar|aar|module|xml|zip)(?:\b|$)`)
var packageReadCommand = regexp.MustCompile(`^(?:curl(?:[ \t]+(?:-I|--head|-f|-s|-S|-L|--fail|--silent|--show-error|--location|--max-time[ \t]+[0-9]+))*|Invoke-WebRequest[ \t]+-Method[ \t]+(?:Get|Head)[ \t]+-Uri)[ \t]+https://[A-Za-z0-9./:_+%~-]+$`)
var packageDownloadRecord = regexp.MustCompile(`(?i)^(?:Downloading(?: from [A-Za-z0-9_.-]+)?|Downloaded(?: from [A-Za-z0-9_.-]+)?|Could not (?:GET|HEAD)|Resource missing)[ :]+['"]?https://[A-Za-z0-9./:_+%~-]+['"]?[ .]*$`)

func developmentLineAt(source string, start, end int) (string, bool) {
	if start < 0 || end <= start || end > len(source) {
		return "", false
	}
	a := strings.LastIndexByte(source[:start], '\n') + 1
	b := len(source)
	if n := strings.IndexByte(source[end:], '\n'); n >= 0 {
		b = end + n
	}
	if b-a > 8192 {
		return "", false
	}
	return strings.TrimSpace(source[a:b]), true
}

func stateObjectNotCredential(source string, ev cyberRuleEvidence) bool {
	if ev.start < 0 || ev.end > len(source) || ev.end <= ev.start {
		return false
	}
	quote := source[ev.start:ev.end]
	if !nonCredentialStateRead.MatchString(quote) {
		return false
	}
	boundary := strings.IndexAny(quote, "，,；;。\n\r|")
	return boundary > 0 && !routineCredentialMaterial.MatchString(quote[:boundary])
}

func currentSessionCredentialLine(line string) bool {
	return currentSessionSource.MatchString(line) && routineCredentialRead.MatchString(line) && routineCredentialMaterial.MatchString(line) && normalSessionUse.MatchString(line) && !hasAffirmativeCredentialHazard(line)
}

func repositoryConfigurationLine(line string) bool {
	if len(line) > 2048 || strings.ContainsAny(line, "$`") {
		return false
	}
	// A bare assignment is data, not a disclosure operation. Other uses of the
	// value elsewhere in the unchanged request still require classification.
	if configurationAssignment.MatchString(line) && routineCredentialMaterial.MatchString(line) {
		return true
	}
	if !strings.Contains(line, "{") || !strings.Contains(line, "}") {
		return false
	}
	stripped := developmentQuotedLiteral.ReplaceAllString(line, "STRING")
	return repositoryDSL.MatchString(stripped) && (strings.Contains(stripped, "maven") || strings.Contains(stripped, "credentials"))
}

func developmentEvidenceLine(line string) bool {
	// The decoded tool projection can wrap a complete scalar in double quotes.
	// Remove that pair only; the complete body still must match a finite shape.
	if len(line) >= 2 && line[0] == '"' && line[len(line)-1] == '"' {
		line = strings.TrimSpace(line[1 : len(line)-1])
	}
	if credentialDocumentationRow.MatchString(line) && routineCredentialMaterial.MatchString(line) && !documentationOperation.MatchString(line) {
		return true
	}
	if repositoryConfigurationLine(line) || mavenConfigurationXML(line) || currentSessionCredentialLine(line) || routineBuildCommand(line) {
		return true
	}
	if repositoryArtifactURL.MatchString(line) && (packageReadCommand.MatchString(line) || packageDownloadRecord.MatchString(line)) {
		return true
	}
	return credentialPresenceDiagnostic(line)
}

func normalDevelopmentAuditEvidence(quote, source string) bool {
	if len(quote) < 3 || len(quote) > 4096 {
		return false
	}
	offset, found := 0, false
	for count := 0; count < 32; count++ {
		rel := strings.Index(source[offset:], quote)
		if rel < 0 {
			return found
		}
		at := offset + rel
		line, ok := developmentLineAt(source, at, at+len(quote))
		if !ok || !developmentEvidenceLine(line) {
			return false
		}
		found = true
		offset = at + 1
	}
	return false
}

// Split simple expression containers without evaluating Python or shell. All
// scanning is bounded by the containing source line, with a nesting ceiling.
func splitDevelopmentExpr(s string, sep byte) ([]string, bool) {
	var parts []string
	var stack []byte
	var quote byte
	escaped, last := false, 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		if quote != 0 {
			if escaped {
				escaped = false
				continue
			}
			if c == '\\' {
				escaped = true
				continue
			}
			if c == quote {
				quote = 0
			}
			continue
		}
		if c == '\'' || c == '"' {
			quote = c
			continue
		}
		switch c {
		case '(', '[', '{':
			stack = append(stack, c)
			if len(stack) > 16 {
				return nil, false
			}
		case ')', ']', '}':
			if len(stack) == 0 {
				return nil, false
			}
			open := stack[len(stack)-1]
			if (c == ')' && open != '(') || (c == ']' && open != '[') || (c == '}' && open != '{') {
				return nil, false
			}
			stack = stack[:len(stack)-1]
		default:
			if c == sep && len(stack) == 0 {
				parts = append(parts, strings.TrimSpace(s[last:i]))
				last = i + 1
			}
		}
	}
	if quote != 0 || len(stack) != 0 || escaped {
		return nil, false
	}
	return append(parts, strings.TrimSpace(s[last:])), true
}

var presenceCalls = regexp.MustCompile(`([A-Za-z_][A-Za-z0-9_.]*)[ \t]*\(`)
var presenceKey = regexp.MustCompile(`^['"][A-Za-z_]*(?:exists|present|configured|enabled|ready)['"]$`)
var existsExpression = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*\.exists\(\)$`)
var presenceComprehension = regexp.MustCompile(`(?s)^\{[A-Za-z_][A-Za-z0-9_]*[ \t]*:[ \t]*any\(.+\)[ \t]+for[ \t]+[A-Za-z_][A-Za-z0-9_]*[ \t]+in[ \t]+[A-Za-z_][A-Za-z0-9_]*\}$`)
var enabledMetadata = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*\.get\(['"]enabled['"]\)(?: if isinstance\([A-Za-z_][A-Za-z0-9_]*,[ \t]*dict\) else None)?$`)

func credentialPresenceDiagnostic(line string) bool {
	if len(line) > 8192 || !strings.Contains(line, ".env") || credentialSensitiveOrigin.MatchString(line) || devExplicitOperation.MatchString(line) {
		return false
	}
	at := strings.Index(line, "print(")
	if at < 0 || strings.Count(line, "print(") != 1 {
		return false
	}
	suffix := strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(line[at:]), ";"))
	if !strings.HasPrefix(suffix, "print({") || !strings.HasSuffix(suffix, "})") {
		return false
	}
	// Reject unknown/effectful calls anywhere, not just in the displayed fields.
	stripped := developmentQuotedLiteral.ReplaceAllString(line, "STRING")
	if strings.ContainsAny(stripped, "`$|>&") || strings.Contains(stripped, "__") || presenceNetworkCall.MatchString(stripped) {
		return false
	}
	allowed := map[string]bool{"Path": true, "home": true, "read_text": true, "exists": true, "safe_load": true, "get": true, "isinstance": true, "bool": true, "any": true, "startswith": true, "split": true, "strip": true, "splitlines": true, "print": true}
	for _, m := range presenceCalls.FindAllStringSubmatch(stripped, 64) {
		name := m[1]
		if n := strings.LastIndexByte(name, '.'); n >= 0 {
			name = name[n+1:]
		}
		if !allowed[name] {
			return false
		}
	}
	// Remove just the known observational sink before testing the rest for other
	// sinks. A second print, network send, logger or command suffix never inherits.
	if hasAffirmativeCredentialHazard(line[:at]) {
		return false
	}
	fields, ok := splitDevelopmentExpr(suffix[len("print({"):len(suffix)-2], ',')
	if !ok || len(fields) == 0 || len(fields) > 16 {
		return false
	}
	for _, field := range fields {
		pair, ok := splitDevelopmentExpr(field, ':')
		if !ok || len(pair) != 2 || !presenceKey.MatchString(pair[0]) {
			return false
		}
		v := pair[1]
		if existsExpression.MatchString(v) || enabledMetadata.MatchString(v) || presenceComprehension.MatchString(v) {
			continue
		}
		if (strings.HasPrefix(v, "bool(") || strings.HasPrefix(v, "any(")) && strings.HasSuffix(v, ")") {
			if _, ok := splitDevelopmentExpr(v, ','); ok {
				continue
			}
		}
		return false
	}
	return true
}

// No external entities, directives, unknown elements, or surrounding executable
// text. A Maven settings/repository fragment is configuration, not extraction.
func mavenConfigurationXML(line string) bool {
	if len(line) > 4096 || !strings.HasPrefix(line, "<") {
		return false
	}
	decoder := xml.NewDecoder(strings.NewReader(line))
	allowed := map[string]bool{"settings": true, "servers": true, "server": true, "id": true, "username": true, "password": true, "privateKey": true, "passphrase": true, "repositories": true, "repository": true, "name": true, "url": true, "releases": true, "snapshots": true, "enabled": true}
	depth, roots := 0, 0
	relevant := false
	for count := 0; count < 256; count++ {
		token, err := decoder.Token()
		if err == io.EOF {
			return depth == 0 && roots == 1 && relevant
		}
		if err != nil {
			return false
		}
		switch v := token.(type) {
		case xml.StartElement:
			if !allowed[v.Name.Local] {
				return false
			}
			if depth == 0 {
				roots++
			}
			depth++
			if depth > 16 {
				return false
			}
			relevant = relevant || v.Name.Local == "server" || v.Name.Local == "repository"
		case xml.EndElement:
			depth--
		case xml.CharData:
			if depth == 0 && strings.TrimSpace(string(v)) != "" {
				return false
			}
		default:
			return false
		}
	}
	return false
}

var developmentBuildCommand = regexp.MustCompile(`^(?:(?:\./|\.\\)?gradlew(?:\.bat)?(?:[ \t]+(?::?[A-Za-z0-9_.:-]*(?:assembleDebug|assembleRelease|compileDebugJavaWithJavac|testDebugUnitTest|lintDebug)|dependencies|dependencyInsight|build|clean|test|lint|tasks|help|projects|--stacktrace|--info|--refresh-dependencies|--offline|--no-daemon|-q))+|(?:mvn|mvnw|\./mvnw)(?:[ \t]+(?:clean|compile|package|verify|test|install|dependency:tree|dependency:resolve|--offline|-q|-DskipTests))+)$`)
var presenceNetworkCall = regexp.MustCompile(`(?i)\b(?:requests?|httpx|urllib|socket|subprocess)\.`)

func routineBuildCommand(line string) bool {
	return developmentBuildCommand.MatchString(line) && !engineeringUnsafeBuildTarget.MatchString(line)
}

func developmentDataEvidenceAt(source string, start, end int) bool {
	line, ok := developmentLineAt(source, start, end)
	return ok && developmentEvidenceLine(line)
}
