package platform

import (
	"regexp"
	"regexp/syntax"
	"sort"
	"strings"
	"unicode/utf8"
)

const cyberRuleContextRunes = 180

var (
	traceSensitivePatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)\bBearer\s+[A-Za-z0-9._~+/-]{8,}`),
		regexp.MustCompile(`(?i)(authorization|api[_ -]?key|access[_ -]?token|refresh[_ -]?token|password|secret|cookie)\s*[:=]\s*[^\s,;]{4,}`),
		regexp.MustCompile(`\bsk-[A-Za-z0-9_-]{8,}\b`),
		regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`),
		regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b`),
		regexp.MustCompile(`(?is)-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----`),
	}
	credentialSelfServicePattern = regexp.MustCompile(`(?is)(?:(?:\b(?:my|our|own)\b|(?:我的|我们(?:自己)?的|自己的)).{0,100}(?:\b(?:api[ _-]?keys?|access tokens?|refresh tokens?|passwords?|credentials?|cookies?|private keys?|secrets?)\b|(?:API.?Key|访问令牌|刷新令牌|密码|凭据|Cookie|私钥|密钥|Secret)).{0,180}(?:\b(?:check|inspect|find|locate|view|read|recover|rotate|revoke|redact|mask|replace|delete|remove|secure|store|manage|audit|verify|leak(?:ed)?|exposed|compromised)\b|(?:检查|查看|查找|定位|读取|找回|恢复|轮换|撤销|脱敏|掩码|替换|删除|移除|保护|保存|管理|审计|验证|泄露|暴露|失窃)))|(?:(?:\b(?:check|inspect|find|locate|view|read|recover|rotate|revoke|redact|mask|replace|delete|remove|secure|store|manage|audit|verify)\b|(?:检查|查看|查找|定位|读取|找回|恢复|轮换|撤销|脱敏|掩码|替换|删除|移除|保护|保存|管理|审计|验证)).{0,180}(?:\b(?:my|our|own)\b|(?:我的|我们(?:自己)?的|自己的)).{0,100}(?:\b(?:api[ _-]?keys?|access tokens?|refresh tokens?|passwords?|credentials?|cookies?|private keys?|secrets?)\b|(?:API.?Key|访问令牌|刷新令牌|密码|凭据|Cookie|私钥|密钥|Secret)))`)
	credentialThirdPartyTargetPattern = regexp.MustCompile(`(?is)(?:\b(?:someone else(?:'s)?|another user(?:'s)?|other users?|victims?|target users?|customers?|employees?)\b|(?:他人的|别人的|其他用户|受害者|目标用户|客户的|员工的)).{0,160}(?:\b(?:passwords?|credentials?|tokens?|cookies?|keys?|secrets?)\b|(?:密码|凭据|令牌|Cookie|密钥|Secret))`)
)

type RuleMatchDiagnostics struct {
	RuleID          int64    `json:"rule_id"`
	RulePosition    int      `json:"rule_position"`
	RuleCode        string   `json:"rule_code"`
	RuleName        string   `json:"rule_name"`
	RuleDescription string   `json:"rule_description,omitempty"`
	Category        string   `json:"category"`
	Action          string   `json:"action"`
	Priority        int      `json:"priority"`
	PatternType     string   `json:"pattern_type"`
	Pattern         string   `json:"pattern,omitempty"`
	Indicators      []string `json:"indicators,omitempty"`
	MatchedText     string   `json:"matched_text,omitempty"`
	Context         string   `json:"context,omitempty"`
	UserGuidance    string   `json:"user_guidance,omitempty"`
	Downgraded      bool     `json:"downgraded_to_review,omitempty"`
	DowngradeReason string   `json:"downgrade_reason,omitempty"`
}

type cyberRuleEvidence struct {
	start      int
	end        int
	matchedRaw string
}

func matchCyberRuleEvidence(rule compiledRule, text string, lowerText string) (cyberRuleEvidence, bool) {
	var start, end int
	switch rule.PatternType {
	case "regex":
		if rule.regularExpression == nil {
			return cyberRuleEvidence{}, false
		}
		location := rule.regularExpression.FindStringIndex(text)
		if location == nil {
			return cyberRuleEvidence{}, false
		}
		start, end = location[0], location[1]
	case "contains":
		start = strings.Index(lowerText, rule.lowerPattern)
		if start < 0 {
			return cyberRuleEvidence{}, false
		}
		end = start + len(rule.lowerPattern)
	case "exact":
		if !strings.EqualFold(strings.TrimSpace(text), rule.lowerPattern) {
			return cyberRuleEvidence{}, false
		}
		trimmed := strings.TrimSpace(text)
		start = strings.Index(text, trimmed)
		if start < 0 {
			start = 0
		}
		end = start + len(trimmed)
	default:
		return cyberRuleEvidence{}, false
	}
	if start < 0 || end < start || end > len(text) {
		return cyberRuleEvidence{}, false
	}
	return cyberRuleEvidence{start: start, end: end, matchedRaw: text[start:end]}, true
}

func buildRuleMatchDiagnostics(rule compiledRule, position int, text string, evidence cyberRuleEvidence) RuleMatchDiagnostics {
	return RuleMatchDiagnostics{
		RuleID:          rule.ID,
		RulePosition:    position,
		RuleCode:        rule.Code,
		RuleName:        rule.Name,
		RuleDescription: rule.Description,
		Category:        rule.Category,
		Action:          rule.Action,
		Priority:        rule.Priority,
		PatternType:     rule.PatternType,
		Pattern:         rule.Pattern,
		Indicators:      extractCyberRuleIndicators(rule.CyberRule, evidence.matchedRaw),
		MatchedText:     redactCyberTraceText(evidence.matchedRaw),
		Context:         cyberRuleContext(text, evidence.start, evidence.end),
		UserGuidance:    cyberRuleUserGuidance(rule.CyberRule),
	}
}

func shouldReviewCredentialSelfService(rule CyberRule, text string) (bool, string) {
	if rule.Action != DecisionBlock {
		return false, ""
	}
	if rule.Code != "CYBER_CREDENTIAL_THEFT" && rule.Code != "CYBER_CLOUD_SECRET_THEFT" && rule.Category != "credential_access" {
		return false, ""
	}
	if !credentialSelfServicePattern.MatchString(text) {
		return false, ""
	}
	if credentialThirdPartyTargetPattern.MatchString(text) {
		return false, ""
	}
	return true, "检测到本人/自有凭据的检查、找回、轮换、撤销、脱敏或泄露处置语义；不直接放行，改由审计模型结合完整上下文复核"
}

func cyberRuleUserGuidance(rule CyberRule) string {
	switch rule.Category {
	case "credential_access", "credential_theft":
		return "如果是在处理自己的密钥、Token 或密码，请明确描述检查泄露、定位本人凭据、轮换、撤销、脱敏、恢复或安全存储目的；不要请求获取、导出或接管他人凭据。"
	case "malware", "command_and_control", "persistence":
		return "如果目的是防御或分析，请改为描述样本分析、IOC 提取、检测、隔离、清理、修复或阻断目标，不要要求生成、部署或维持恶意载荷。"
	case "defense_evasion":
		return "如果是在做兼容性或防御测试，请描述检测反调试/防护兼容问题、日志分析或修复目标，不要要求关闭、绕过或规避真实安全控制。"
	case "execution", "privilege_escalation":
		return "如果是在排障或授权测试，请描述漏洞验证、修复、缓解和最小复现范围，避免要求面向真实目标的可直接利用或提权能力。"
	case "reconnaissance":
		return "如果是资产管理或防御扫描，请明确说明自有资产、资产盘点、暴露面检查或漏洞修复目标，并限制在必要的验证范围。"
	case "exfiltration":
		return "如果是在排查数据泄露，请改为描述检测、审计、阻断、取证或验证数据流向，不要要求导出他人或未授权数据。"
	default:
		return "请把请求改写为防御、检测、审计、修复、取证、合规或明确的安全处置目标，避免要求可直接用于未授权攻击的操作能力。"
	}
}

func redactCyberTraceText(value string) string {
	value = strings.ToValidUTF8(value, "")
	for _, expression := range traceSensitivePatterns {
		value = expression.ReplaceAllStringFunc(value, func(match string) string {
			lower := strings.ToLower(match)
			for _, separator := range []string{":", "="} {
				if index := strings.Index(lower, separator); index >= 0 {
					return match[:index+1] + "[REDACTED]"
				}
			}
			if strings.HasPrefix(lower, "bearer ") {
				return match[:7] + "[REDACTED]"
			}
			if strings.HasPrefix(match, "-----BEGIN") {
				return "[REDACTED PRIVATE KEY]"
			}
			return "[REDACTED SECRET]"
		})
	}
	value = strings.Map(func(r rune) rune {
		if r == '\n' || r == '\r' || r == '\t' || r >= 0x20 {
			return r
		}
		return ' '
	}, value)
	return truncateString(strings.TrimSpace(value), 1200)
}

func cyberRuleContext(text string, start int, end int) string {
	if start < 0 || end < start || end > len(text) {
		return ""
	}
	beforeRunes := utf8.RuneCountInString(text[:start])
	matchRunes := utf8.RuneCountInString(text[start:end])
	allRunes := []rune(text)
	left := beforeRunes - cyberRuleContextRunes
	if left < 0 {
		left = 0
	}
	right := beforeRunes + matchRunes + cyberRuleContextRunes
	if right > len(allRunes) {
		right = len(allRunes)
	}
	prefix := redactCyberTraceText(string(allRunes[left:beforeRunes]))
	matched := redactCyberTraceText(string(allRunes[beforeRunes : beforeRunes+matchRunes]))
	suffix := redactCyberTraceText(string(allRunes[beforeRunes+matchRunes : right]))
	var builder strings.Builder
	if left > 0 {
		builder.WriteString("…")
	}
	builder.WriteString(prefix)
	builder.WriteString(" ⟦")
	builder.WriteString(matched)
	builder.WriteString("⟧ ")
	builder.WriteString(suffix)
	if right < len(allRunes) {
		builder.WriteString("…")
	}
	return truncateString(strings.TrimSpace(builder.String()), 1600)
}

func extractCyberRuleIndicators(rule CyberRule, matchedText string) []string {
	if rule.PatternType == "contains" || rule.PatternType == "exact" {
		indicator := strings.TrimSpace(rule.Pattern)
		if indicator == "" {
			return nil
		}
		return []string{redactCyberTraceText(indicator)}
	}
	parsed, err := syntax.Parse(rule.Pattern, syntax.Perl)
	if err != nil {
		return nil
	}
	candidates := make([]string, 0, 16)
	var walk func(*syntax.Regexp)
	walk = func(node *syntax.Regexp) {
		if node == nil {
			return
		}
		if node.Op == syntax.OpLiteral {
			literal := strings.TrimSpace(string(node.Rune))
			if usefulCyberRuleLiteral(literal) && strings.Contains(strings.ToLower(matchedText), strings.ToLower(literal)) {
				candidates = append(candidates, literal)
			}
		}
		for _, child := range node.Sub {
			walk(child)
		}
	}
	walk(parsed)
	seen := map[string]struct{}{}
	unique := make([]string, 0, len(candidates))
	for _, candidate := range candidates {
		key := strings.ToLower(candidate)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		unique = append(unique, candidate)
	}
	lowerMatched := strings.ToLower(matchedText)
	sort.SliceStable(unique, func(i, j int) bool {
		left := strings.Index(lowerMatched, strings.ToLower(unique[i]))
		right := strings.Index(lowerMatched, strings.ToLower(unique[j]))
		if left == right {
			return len(unique[i]) > len(unique[j])
		}
		return left < right
	})
	if len(unique) > 8 {
		unique = unique[:8]
	}
	for index := range unique {
		unique[index] = redactCyberTraceText(unique[index])
	}
	return unique
}

func usefulCyberRuleLiteral(value string) bool {
	if value == "" {
		return false
	}
	runes := utf8.RuneCountInString(value)
	if isASCIIText(value) {
		return runes >= 3
	}
	return runes >= 2
}
