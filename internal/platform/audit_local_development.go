package platform

import (
	"regexp"
	"strings"
)

// These recognize insufficient evidence, NOT an environment whitelist. Source
// bytes remain in every model pass; other matches in the same request are kept.
const defaultPromptExtractionRulePattern = `(?is)(?:\b(?:reveal|extract|print|leak|show)\b|(?:显示|提取|打印|泄露|展示)).{0,120}(?:\b(?:system prompt|developer prompt|hidden instructions|internal prompt)\b|(?:系统提示词|开发者提示词|隐藏指令|内部提示词))`

var terminalSecretInput = regexp.MustCompile(`(?i)(?:终端|交互式|terminal|interactive)[^\r\n]{0,48}(?:隐藏|不回显|hidden|masked|no.echo)[^\r\n]{0,48}(?:读取|输入|read|input)[^\r\n]{0,16}(?:tokens?|jwt|session|令牌|凭据|密钥)`)
var localDevelopmentDanger = regexp.MustCompile(`(?i)(窃|盗|绕过|规避|外传|未经许可|未授权|伪造|跳过|禁用校验|关闭校验|第三方|受害者|公开|打印|上传|\.env|/proc/|浏览器|\.ssh|\b(?:steal|stolen|harvest|exfil\w*|bypass|evade|forge|victim|unauthori[sz]ed|public|dump|extract|browser|disable|skip)\b|[;&|<>]|\$\(|` + "`" + `)`)
var authDesignRiskClass = regexp.MustCompile(`(?i)(credential|exfil|bypass|authentication|凭据|认证|外传)`)
var authDesignToken = regexp.MustCompile(`(?i)\b(?:tokens?|jwt|session)\b`)
var authDesignTransport = regexp.MustCompile(`(?i)(请求头|header)`)
var authDesignBoundary = regexp.MustCompile(`(?i)(认证|鉴权|校验|接入|插件|authentication|verify|validation|plugin)`)

// Bounded containing line, including serialized tool-output newline escapes.
// An unknown/oversized containing line is not admitted to corrective handling.
func developmentEvidenceLine(source string, start, end int) (string, bool) {
	if start < 0 || end < start || end > len(source) || end-start > 4096 {
		return "", false
	}
	left := max(0, start-8192)
	right := min(len(source), end+8192)
	prefix := source[left:start]
	suffix := source[end:right]
	a, b := left, right
	for _, boundary := range []string{"\n", "\r", `\n`, `\r`} {
		if at := strings.LastIndex(prefix, boundary); at >= 0 {
			a = max(a, left+at+len(boundary))
		}
		if at := strings.Index(suffix, boundary); at >= 0 {
			b = min(b, end+at)
		}
	}
	if (a == left && left > 0) || (b == right && right < len(source)) || b-a > 8192 {
		return "", false
	}
	return source[a:b], true
}

func secureTerminalInputLine(line string) bool {
	return terminalSecretInput.MatchString(line) && !localDevelopmentDanger.MatchString(line)
}

func nonOperationalShippedRuleMatch(r compiledRule, ev cyberRuleEvidence, source string) bool {
	if r.Code == "CYBER_CREDENTIAL_ACCESS_DISABLED" && r.ID == 0 {
		shipped := false
		for _, baseline := range cyberDenyBaseline {
			if baseline.Code == r.Code && baseline.Pattern == r.Pattern {
				shipped = true
				break
			}
		}
		if shipped {
			line, ok := developmentEvidenceLine(source, ev.start, ev.end)
			return ok && secureTerminalInputLine(line)
		}
	}
	// Only the exact shipped expression is eligible. Never rewrite administrator
	// patterns or treat an actual multi-line extraction request as a table artifact.
	if r.Code == "CYBER_SYSTEM_PROMPT_EXTRACTION" && r.Pattern == defaultPromptExtractionRulePattern {
		q := strings.NewReplacer(`\r\n`, "\n", `\n`, "\n", "\r\n", "\n").Replace(ev.matchedRaw)
		split := strings.Index(q, "|\n|")
		if split < 0 {
			split = strings.Index(q, "|\n |")
		}
		if split < 0 {
			return false
		}
		prefix, _ := developmentEvidenceLine(source, ev.start, ev.start)
		return strings.HasPrefix(q, "泄露") && (strings.Contains(prefix, "不要") || strings.Contains(prefix, "不应") || strings.Contains(prefix, "禁止") || strings.Contains(prefix, "不能"))
	}
	return false
}

func localDevelopmentAuditEvidence(d AuditDecision, quote, source string) bool {
	if !authDesignRiskClass.MatchString(d.Category+" "+d.RiskCode) || len(quote) < 4 || len(quote) > 4096 {
		return false
	}
	offset, found := 0, false
	for count := 0; count < 32; count++ {
		rel := strings.Index(source[offset:], quote)
		if rel < 0 {
			return found
		}
		at := offset + rel
		line, ok := developmentEvidenceLine(source, at, at+len(quote))
		if !ok || localDevelopmentDanger.MatchString(line) {
			return false
		}
		auth := authDesignToken.MatchString(line) && authDesignTransport.MatchString(line) && authDesignBoundary.MatchString(line)
		if !auth && !secureTerminalInputLine(line) {
			return false
		}
		found = true
		offset = at + 1
	}
	return false
}

const localDevelopmentAuditBoundary = `本地普通开发、构建、业务测试、插件认证方案讨论不等于 Cyber；也不能凭“本地/测试/localhost”授予整体豁免。用户在终端隐藏输入自己主动提供的 Token 是认证输入，不是从配置、浏览器、进程或他人账户提取秘密。讨论将 JWT/Session 放在请求头并由自有服务校验，本身不是绕过认证；把秘密塞入提示词、只信任客户端声明是不良安全设计，应指出风险，不能凭方案讨论伪造正在窃密/绕过的事实。防护测试表的预期拒绝说明不能跨行拼接成新的攻击动作；若实际请求读取隐藏秘密、伪造权限或执行禁用操作，仍 block。必须核对实际动作和来源，不因开发说明自动 allow。`
