from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def replace_once(text: str, old: str, new: str, label: str) -> str:
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected exactly one match, found {count}")
    return text.replace(old, new, 1)


# ---------------------------------------------------------------------------
# Role/type/current-turn aware extraction with privacy-preserving normalization
# ---------------------------------------------------------------------------
(ROOT / "internal/platform/audit_input_scope.go").write_text(
    r'''package platform

import (
	"encoding/json"
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"
)

const (
	auditInputScopeEndUserIntent = "end_user_intent_only"
	auditInputScopeContextOnly   = "context_only"
	auditInputScopeRawFallback   = "raw_request_fallback"

	auditReferenceContextLimitBytes = 64 * 1024
)

type AuditTextExtraction struct {
	Text                   string
	Scope                  string
	IntentBytes            int
	RawIntentBytes         int
	IgnoredContextBytes    int
	IgnoredRoles           []string
	PriorUserContextBytes  int
	ActiveUserMessages     int
	ContextActivated       bool
	IgnoredInputTypes      []string
	EphemeralArtifactCount int
	SecretPlaceholderCount int
}

type auditUserUnit struct {
	Text     string
	Position int
}

type auditTextCollector struct {
	maximumBytes        int
	userUnits           []auditUserUnit
	position            int
	ignoredContextBytes int
	ignoredRoles        map[string]struct{}
	ignoredInputTypes   map[string]struct{}
}

var (
	myRequestMarkerPattern = regexp.MustCompile(`(?im)^\s*##\s*(?:my|user)\s+request\s*:\s*`)
	myRequestZHPattern     = regexp.MustCompile(`(?m)^\s*##\s*我的请求\s*[：:]\s*`)
	fileHeaderPattern      = regexp.MustCompile(`(?im)^\s*files mentioned by the user\s*:\s*$`)
	clipboardArtifactPattern = regexp.MustCompile(`(?i)codex-clipboard-[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}\.(?:png|jpe?g|webp|gif|bmp)`)
	temporaryPathPattern = regexp.MustCompile(`(?i)(?:/private)?/var/folders/[^\s"']+|/tmp/[^\s"']+|[a-z]:\\[^\r\n"']*\\(?:temp|tmp)\\[^\s"']+`)
	bareUUIDInPathPattern = regexp.MustCompile(`(?i)([/\\._-])[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}(?=\.[a-z0-9]{1,8}\b)`)

	secretAssignmentPattern = regexp.MustCompile(`(?i)(["']?(?:api[_ -]?key|access[_ -]?token|refresh[_ -]?token|authorization|password|secret|token|key)["']?\s*[:=]\s*["']?)([A-Za-z0-9._~+\-/=]{8,})`)
	bearerSecretPattern     = regexp.MustCompile(`(?i)(\bBearer\s+)([A-Za-z0-9._~+\-/=]{8,})`)
	openAISecretPattern     = regexp.MustCompile(`\bsk-[A-Za-z0-9_-]{8,}\b`)
	awsSecretPattern        = regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`)

	referentialIntentPattern = regexp.MustCompile(`(?i)^\s*(?:继续|继续处理|继续上面|按上面|按照上面|按前面|执行上述|照做|开始吧|确认|是的|可以|做吧|修复它|处理它|continue|go ahead|proceed|do it|yes|same as above|carry on)(?:\s|[，。,.!！?？]|$)`)
	newTopicPattern          = regexp.MustCompile(`(?i)(?:忽略上面|不要继续|这是新问题|另一个问题|new question|ignore the above|do not continue)`)
)

func ExtractAuditTextDetails(body []byte, maximumBytes int) AuditTextExtraction {
	if maximumBytes <= 0 {
		maximumBytes = 256 * 1024
	}
	var root any
	if err := json.Unmarshal(body, &root); err != nil {
		if len(body) > maximumBytes {
			body = body[:maximumBytes]
		}
		normalized, artifacts, secrets, _ := normalizeAuditUserText(strings.ToValidUTF8(string(body), "�"))
		return AuditTextExtraction{
			Text:                   normalized,
			Scope:                  auditInputScopeRawFallback,
			IntentBytes:            len(normalized),
			RawIntentBytes:         len(body),
			EphemeralArtifactCount: artifacts,
			SecretPlaceholderCount: secrets,
		}
	}

	collector := &auditTextCollector{
		maximumBytes:      maximumBytes,
		ignoredRoles:      map[string]struct{}{},
		ignoredInputTypes: map[string]struct{}{},
	}
	collector.collectRoot(root)
	selected, contextActivated := selectActiveAuditUnits(collector.userUnits)
	selectedSet := make(map[int]struct{}, len(selected))
	for _, index := range selected {
		selectedSet[index] = struct{}{}
	}

	var builder strings.Builder
	result := AuditTextExtraction{
		Scope:            auditInputScopeEndUserIntent,
		ContextActivated: contextActivated,
	}
	for index, unit := range collector.userUnits {
		if _, active := selectedSet[index]; !active {
			result.PriorUserContextBytes += len(unit.Text)
			continue
		}
		normalized, artifacts, secrets, removed := normalizeAuditUserText(unit.Text)
		result.RawIntentBytes += len(unit.Text)
		result.EphemeralArtifactCount += artifacts
		result.SecretPlaceholderCount += secrets
		result.IgnoredContextBytes += removed
		if strings.TrimSpace(normalized) == "" {
			continue
		}
		role := "ROLE=USER"
		if contextActivated && index != selected[len(selected)-1] {
			role = "ROLE=USER_REFERENCED"
		}
		appendAuditLine(&builder, role, maximumBytes)
		appendAuditLine(&builder, normalized, maximumBytes)
		result.ActiveUserMessages++
	}
	result.Text = builder.String()
	result.IntentBytes = len(result.Text)
	result.IgnoredContextBytes += collector.ignoredContextBytes + result.PriorUserContextBytes
	result.IgnoredRoles = sortedSetKeys(collector.ignoredRoles)
	result.IgnoredInputTypes = sortedSetKeys(collector.ignoredInputTypes)
	if strings.TrimSpace(result.Text) == "" && result.IgnoredContextBytes > 0 {
		result.Scope = auditInputScopeContextOnly
	}
	return result
}

func (collector *auditTextCollector) collectRoot(value any) {
	switch typed := value.(type) {
	case string:
		collector.addUserUnit(typed)
	case []any:
		collector.collectInput(typed)
	case map[string]any:
		if messages, ok := typed["messages"]; ok {
			collector.collectMessages(messages)
			collector.ignoreKnownRootContext(typed, "messages")
			return
		}
		if input, ok := typed["input"]; ok {
			collector.collectInput(input)
			collector.ignoreKnownRootContext(typed, "input")
			return
		}
		for _, key := range []string{"prompt", "query"} {
			if child, ok := typed[key]; ok {
				collector.addUserUnit(eligibleText(child, collector.maximumBytes))
				collector.ignoreKnownRootContext(typed, key)
				return
			}
		}
		for _, key := range []string{"content", "text"} {
			if child, ok := typed[key]; ok {
				collector.addUserUnit(eligibleText(child, collector.maximumBytes))
				collector.ignoreKnownRootContext(typed, key)
				return
			}
		}
		collector.ignoreContext("UNKNOWN_ROOT", typed)
	}
}

func (collector *auditTextCollector) ignoreKnownRootContext(values map[string]any, activeKey string) {
	for key, child := range values {
		if key == activeKey || strings.EqualFold(key, "model") || strings.EqualFold(key, "stream") {
			continue
		}
		switch strings.ToLower(key) {
		case "instructions", "system", "system_instruction", "developer", "tools", "functions", "tool_choice", "response_format":
			collector.ignoreContext(strings.ToUpper(key), child)
		}
	}
}

func (collector *auditTextCollector) collectMessages(value any) {
	items, ok := value.([]any)
	if !ok {
		collector.ignoreContext("MESSAGES", value)
		return
	}
	for _, item := range items {
		collector.position++
		object, ok := item.(map[string]any)
		if !ok {
			collector.ignoreContext("INVALID_MESSAGE", item)
			continue
		}
		collector.collectRoleObject(object)
	}
}

func (collector *auditTextCollector) collectInput(value any) {
	switch typed := value.(type) {
	case string:
		collector.position++
		collector.addUserUnitAt(typed, collector.position)
	case []any:
		for _, item := range typed {
			collector.position++
			switch child := item.(type) {
			case string:
				collector.addUserUnitAt(child, collector.position)
			case map[string]any:
				if _, hasRole := child["role"]; hasRole {
					collector.collectRoleObject(child)
					continue
				}
				kind, _ := child["type"].(string)
				normalizedKind := strings.ToLower(strings.TrimSpace(kind))
				switch normalizedKind {
				case "input_text", "text":
					collector.addUserUnitAt(eligibleText(child, collector.maximumBytes), collector.position)
				case "message":
					collector.collectRoleObject(child)
				default:
					collector.ignoreInputType(normalizedKind, child)
				}
			default:
				collector.ignoreContext("UNKNOWN_INPUT", item)
			}
		}
	case map[string]any:
		collector.position++
		if _, hasRole := typed["role"]; hasRole {
			collector.collectRoleObject(typed)
			return
		}
		kind, _ := typed["type"].(string)
		if normalized := strings.ToLower(strings.TrimSpace(kind)); normalized == "input_text" || normalized == "text" {
			collector.addUserUnitAt(eligibleText(typed, collector.maximumBytes), collector.position)
			return
		}
		collector.ignoreInputType(strings.ToLower(strings.TrimSpace(kind)), typed)
	default:
		collector.ignoreContext("INPUT", typed)
	}
}

func (collector *auditTextCollector) collectRoleObject(object map[string]any) {
	role, _ := object["role"].(string)
	normalizedRole := strings.ToLower(strings.TrimSpace(role))
	if !isEndUserRole(normalizedRole) {
		if normalizedRole == "" {
			kind, _ := object["type"].(string)
			collector.ignoreInputType(strings.ToLower(strings.TrimSpace(kind)), object)
			return
		}
		collector.ignoreContext(strings.ToUpper(normalizedRole), object)
		return
	}
	content := make(map[string]any)
	for _, key := range []string{"content", "text", "input", "prompt", "query", "arguments", "description"} {
		if value, exists := object[key]; exists {
			content[key] = value
		}
	}
	collector.addUserUnitAt(eligibleText(content, collector.maximumBytes), collector.position)
}

func (collector *auditTextCollector) addUserUnit(value string) {
	collector.position++
	collector.addUserUnitAt(value, collector.position)
}

func (collector *auditTextCollector) addUserUnitAt(value string, position int) {
	value = strings.TrimSpace(strings.ToValidUTF8(value, "�"))
	if value == "" {
		return
	}
	collector.userUnits = append(collector.userUnits, auditUserUnit{Text: value, Position: position})
}

func (collector *auditTextCollector) ignoreInputType(kind string, value any) {
	if kind == "" {
		kind = "unknown_input_type"
	}
	collector.ignoredInputTypes[strings.ToUpper(kind)] = struct{}{}
	collector.ignoreContext("INPUT_"+strings.ToUpper(kind), value)
}

func (collector *auditTextCollector) ignoreContext(role string, value any) {
	collector.ignoredContextBytes += countContextTextBytes(value, "")
	role = strings.TrimSpace(role)
	if role != "" {
		collector.ignoredRoles[role] = struct{}{}
	}
}

func selectActiveAuditUnits(units []auditUserUnit) ([]int, bool) {
	if len(units) == 0 {
		return nil, false
	}
	last := len(units) - 1
	selected := map[int]struct{}{last: {}}
	// Consecutive user items in one request are one active turn.
	for index := last - 1; index >= 0 && units[index].Position+1 == units[index+1].Position; index-- {
		selected[index] = struct{}{}
	}
	contextActivated := false
	lastText := strings.TrimSpace(units[last].Text)
	if needsPriorUserContext(lastText) {
		contextActivated = true
		bytes := len(lastText)
		added := 0
		for index := last - 1; index >= 0 && added < 2 && bytes < auditReferenceContextLimitBytes; index-- {
			selected[index] = struct{}{}
			bytes += len(units[index].Text)
			added++
		}
	}
	indices := make([]int, 0, len(selected))
	for index := range selected {
		indices = append(indices, index)
	}
	sort.Ints(indices)
	return indices, contextActivated
}

func needsPriorUserContext(text string) bool {
	if text == "" || newTopicPattern.MatchString(text) {
		return false
	}
	if referentialIntentPattern.MatchString(text) {
		return true
	}
	return utf8.RuneCountInString(text) <= 12 && regexp.MustCompile(`(?i)(?:这个|那个|它|上述|上面|前面|that|it|above|same)`).MatchString(text)
}

func normalizeAuditUserText(value string) (string, int, int, int) {
	value = strings.ToValidUTF8(value, "�")
	originalLength := len(value)
	if matches := myRequestMarkerPattern.FindAllStringIndex(value, -1); len(matches) > 0 {
		value = value[matches[len(matches)-1][1]:]
	} else if matches := myRequestZHPattern.FindAllStringIndex(value, -1); len(matches) > 0 {
		value = value[matches[len(matches)-1][1]:]
	}
	value = fileHeaderPattern.ReplaceAllString(value, "[ATTACHMENT_METADATA]")

	artifacts := 0
	for _, expression := range []*regexp.Regexp{clipboardArtifactPattern, temporaryPathPattern, bareUUIDInPathPattern} {
		matches := expression.FindAllStringIndex(value, -1)
		artifacts += len(matches)
		replacement := "[TEMP_PATH]"
		if expression == clipboardArtifactPattern {
			replacement = "[CLIPBOARD_IMAGE]"
		} else if expression == bareUUIDInPathPattern {
			replacement = "${1}[ARTIFACT_ID]"
		}
		value = expression.ReplaceAllString(value, replacement)
	}

	secretCount := 0
	for _, expression := range []*regexp.Regexp{secretAssignmentPattern, bearerSecretPattern} {
		secretCount += len(expression.FindAllStringIndex(value, -1))
		value = expression.ReplaceAllString(value, "${1}[USER_PROVIDED_SECRET]")
	}
	for _, expression := range []*regexp.Regexp{openAISecretPattern, awsSecretPattern} {
		secretCount += len(expression.FindAllStringIndex(value, -1))
		value = expression.ReplaceAllString(value, "[USER_PROVIDED_SECRET]")
	}
	value = strings.TrimSpace(value)
	removed := originalLength - len(value)
	if removed < 0 {
		removed = 0
	}
	return value, artifacts, secretCount, removed
}

func appendAuditLine(builder *strings.Builder, value string, maximumBytes int) {
	value = strings.ToValidUTF8(value, "�")
	if value == "" || builder.Len() >= maximumBytes {
		return
	}
	separator := 0
	if builder.Len() > 0 {
		separator = 1
	}
	remaining := maximumBytes - builder.Len() - separator
	if remaining <= 0 {
		return
	}
	if len(value) > remaining {
		value = strings.ToValidUTF8(value[:remaining], "�")
	}
	if builder.Len() > 0 {
		builder.WriteByte('\n')
	}
	builder.WriteString(value)
}

func eligibleText(value any, maximumBytes int) string {
	if maximumBytes <= 0 {
		return ""
	}
	var builder strings.Builder
	var walk func(any, string)
	appendValue := func(text string) {
		appendAuditLine(&builder, text, maximumBytes)
	}
	walk = func(current any, key string) {
		if builder.Len() >= maximumBytes || isIgnoredContentKey(key) {
			return
		}
		switch typed := current.(type) {
		case string:
			if key == "" || isEligibleTextKey(key) {
				appendValue(typed)
			}
		case []any:
			for _, child := range typed {
				walk(child, key)
			}
		case map[string]any:
			kind, _ := typed["type"].(string)
			if isIgnoredContentType(kind) || isNonUserInputType(kind) {
				return
			}
			for _, childKey := range sortedMapKeys(typed) {
				if strings.EqualFold(childKey, "role") || strings.EqualFold(childKey, "type") || strings.EqualFold(childKey, "name") {
					continue
				}
				if isEligibleTextKey(childKey) || strings.EqualFold(childKey, "content") || strings.EqualFold(childKey, "input") {
					walk(typed[childKey], childKey)
				}
			}
		}
	}
	walk(value, "")
	return builder.String()
}

func countContextTextBytes(value any, key string) int {
	if isIgnoredContentKey(key) {
		return 0
	}
	switch typed := value.(type) {
	case string:
		return len(typed)
	case []any:
		total := 0
		for _, child := range typed {
			total += countContextTextBytes(child, key)
		}
		return total
	case map[string]any:
		if kind, _ := typed["type"].(string); isIgnoredContentType(kind) {
			return 0
		}
		total := 0
		for childKey, child := range typed {
			total += countContextTextBytes(child, childKey)
		}
		return total
	default:
		return 0
	}
}

func sortedMapKeys(values map[string]any) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func sortedSetKeys(values map[string]struct{}) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func isEndUserRole(role string) bool {
	switch role {
	case "user", "end_user", "end-user", "human", "customer", "client":
		return true
	default:
		return false
	}
}

func isEligibleTextKey(key string) bool {
	switch strings.ToLower(strings.TrimSpace(key)) {
	case "content", "text", "input", "input_text", "prompt", "query", "arguments", "description":
		return true
	default:
		return false
	}
}

func isIgnoredContentKey(key string) bool {
	switch strings.ToLower(strings.TrimSpace(key)) {
	case "image_url", "url", "audio", "file", "data", "image", "video", "base64", "api_key", "authorization", "password", "secret":
		return true
	default:
		return false
	}
}

func isIgnoredContentType(kind string) bool {
	kind = strings.ToLower(strings.TrimSpace(kind))
	return strings.Contains(kind, "image") || strings.Contains(kind, "audio") ||
		strings.Contains(kind, "video") || strings.Contains(kind, "file")
}

func isNonUserInputType(kind string) bool {
	kind = strings.ToLower(strings.TrimSpace(kind))
	if kind == "" || kind == "message" || kind == "input_text" || kind == "text" {
		return false
	}
	return strings.Contains(kind, "tool") || strings.Contains(kind, "function") ||
		strings.Contains(kind, "computer") || strings.Contains(kind, "reasoning") ||
		strings.Contains(kind, "search") || strings.Contains(kind, "output") ||
		strings.Contains(kind, "approval") || strings.Contains(kind, "reference") ||
		strings.HasSuffix(kind, "_call") || strings.HasSuffix(kind, "_result") ||
		strings.HasSuffix(kind, "_output")
}
''',
    encoding="utf-8",
)

# ---------------------------------------------------------------------------
# Platform-controlled audit policy and deterministic false-positive correction
# ---------------------------------------------------------------------------
(ROOT / "internal/platform/audit_policy.go").write_text(
    r'''package platform

import (
	"encoding/json"
	"regexp"
	"strings"
)

const (
	AuditPolicyModeStrict              = "strict"
	AuditPolicyModeInternalEngineering = "internal_engineering"
)

type AuditPolicy struct {
	Mode                       string
	AllowUserProvidedSecrets   bool
	AllowLocalDebugCredentials bool
}

type AuditPolicyAdjustment struct {
	Code             string `json:"code"`
	Reason           string `json:"reason"`
	OriginalDecision string `json:"original_decision"`
	OriginalRiskCode string `json:"original_risk_code,omitempty"`
	OriginalReason   string `json:"original_reason,omitempty"`
}

var (
	secretTermPattern = regexp.MustCompile(`(?i)(?:\[USER_PROVIDED_SECRET\]|api[ _-]?key|access[ _-]?token|refresh[ _-]?token|authorization|bearer|credential|cookie|password|secret|密钥|令牌|凭据|密码|Cookie)`)
	secretConfigurationPattern = regexp.MustCompile(`(?i)(?:configure|configuration|integrate|integration|connect|connection|use|set|add|replace|switch|provider|endpoint|llm|model|配置|填写|接入|集成|连接|调用|使用|新增|替换|切换|模型|接口|内部开发)`)
	secretHarmVerbPattern = regexp.MustCompile(`(?i)(?:steal|harvest|exfiltrat|dump|grab|scrape|phish|leak|publish|post publicly|commit to|upload to|send to|窃取|盗取|外传|抓取|钓取|泄露|公开|发布|提交到|上传到|发送到)`)
	thirdPartyTargetPattern = regexp.MustCompile(`(?i)(?:someone else|another user|other users?|victims?|target users?|customers?|employees?|unauthorized|without permission|他人|别人|其他用户|受害者|目标用户|客户|员工|未授权|未经许可)`)
	publicSecretSinkPattern = regexp.MustCompile(`(?i)(?:public repo|public repository|github|gitlab|pastebin|论坛|公开仓库|公共仓库|日志输出|打印到日志|提交到仓库)`)

	localDebugContextPattern = regexp.MustCompile(`(?i)(?:/Users/|/home/|[A-Z]:\\|workdir|localhost|127\.0\.0\.1|\.log\b|debug|test|reproduc|diagnos|排障|调试|测试|复现|日志|本地|内部|开发环境)`)
	localCredentialOperationPattern = regexp.MustCompile(`(?i)(?:authorization|bearer|token|api[ _-]?key|credential|sed\s+-n|grep|curl|令牌|密钥|凭据)`)

	benignReplayPattern = regexp.MustCompile(`(?i)(?:replay pipeline|event replay|message replay|stream replay|state replay|重放管线|事件重放|消息重放|流重放|状态重放|唤醒重放|回放管线)`)
	authMaterialPattern = regexp.MustCompile(`(?i)(?:session\s*(?:cookie|token|credential)|cookie|jwt|bearer|oauth|access token|refresh token|会话(?:Cookie|令牌|凭据)|访问令牌|刷新令牌)`)
	benignPersistencePattern = regexp.MustCompile(`(?i)(?:(?:data|state|config(?:uration)?|address|cache|identity|record|message|数据|状态|配置|地址|缓存|身份|记录|消息).{0,12}(?:persist(?:ence)?|持久化)|(?:persist(?:ence)?|持久化).{0,12}(?:data|state|config(?:uration)?|address|cache|identity|record|message|数据|状态|配置|地址|缓存|身份|记录|消息))`)
	maliciousPersistencePattern = regexp.MustCompile(`(?i)(?:survive reboot|autostart|startup item|scheduled task|cron|systemd|registry run|backdoor|implant|malware|victim|开机自启|重启后存活|启动项|计划任务|后门|植入体|恶意软件|受害者)`)
	explicitC2Pattern = regexp.MustCompile(`(?i)(?:\bc2\b|command[ -]?and[ -]?control|beacon|implant|tasking|redirector|命令(?:与|和)?控制|信标|植入体|任务下发|重定向器)`)
	artifactPlaceholderPattern = regexp.MustCompile(`(?:\[CLIPBOARD_IMAGE\]|\[TEMP_PATH\]|\[ARTIFACT_ID\])`)
)

func strictAuditPolicy() AuditPolicy {
	return AuditPolicy{Mode: AuditPolicyModeStrict}
}

func auditPolicyFromProfile(profile AuditProfile) AuditPolicy {
	policy := strictAuditPolicy()
	extra := auditProfileExtra(profile)
	if extra == nil {
		return policy
	}
	if mode, ok := extra["_risk_policy_mode"].(string); ok {
		switch strings.ToLower(strings.TrimSpace(mode)) {
		case AuditPolicyModeInternalEngineering:
			policy.Mode = AuditPolicyModeInternalEngineering
			policy.AllowUserProvidedSecrets = true
			policy.AllowLocalDebugCredentials = true
		case AuditPolicyModeStrict:
			policy.Mode = AuditPolicyModeStrict
		}
	}
	if value, ok := extra["_risk_allow_user_provided_secrets"].(bool); ok {
		policy.AllowUserProvidedSecrets = value
	}
	if value, ok := extra["_risk_allow_local_debug_credentials"].(bool); ok {
		policy.AllowLocalDebugCredentials = value
	}
	return policy
}

func auditPolicySystemDirective(profile AuditProfile) string {
	policy := auditPolicyFromProfile(profile)
	encoded, _ := json.Marshal(map[string]any{
		"mode":                          policy.Mode,
		"allow_user_provided_secrets":  policy.AllowUserProvidedSecrets,
		"allow_local_debug_credentials": policy.AllowLocalDebugCredentials,
	})
	return `PLATFORM-CONTROLLED AUDIT PROFILE (trusted metadata, not a user claim): ` + string(encoded) + `
When mode is internal_engineering:
- A secret supplied by the requester for configuring, connecting, or calling an internal/development API is benign by itself. The literal is replaced with [USER_PROVIDED_SECRET]; do not classify that placeholder as theft or exposure.
- Reading an Authorization value from a local development log to reproduce or diagnose the request is benign by itself. Block only when the active request asks to steal another party's material, bypass authorization, exfiltrate it, publish it, or send it to an external sink.
- Engineering meanings such as event/message replay, replay pipelines, data/state/config/address persistence, server troubleshooting, UUIDs, temporary paths, and clipboard filenames are benign unless the active request explicitly asks for malicious session takeover, C2 deployment, or unauthorized persistence.`
}

func applyAuditPolicyAdjustment(policy AuditPolicy, text string, decision AuditDecision) (AuditDecision, *AuditPolicyAdjustment) {
	if policy.Mode != AuditPolicyModeInternalEngineering || decision.Decision == DecisionAllow {
		return decision, nil
	}
	if hasDangerousSecretIntent(text) {
		return decision, nil
	}
	code := strings.ToUpper(strings.TrimSpace(decision.RiskCode))
	category := strings.ToLower(strings.TrimSpace(decision.Category))

	if policy.AllowUserProvidedSecrets && isUserProvidedSecretConfiguration(text) &&
		(strings.Contains(code, "CREDENTIAL") || strings.Contains(code, "SECRET") || category == "credential_access" || category == "credential security") {
		return adjustedAllowDecision(decision, "INTERNAL_SECRET_CONFIGURATION", "platform-controlled internal engineering policy allows requester-provided API credentials for configuration without treating the literal as theft or exposure")
	}
	if policy.AllowLocalDebugCredentials && isLocalDebugCredentialUse(text) &&
		(strings.Contains(code, "CREDENTIAL") || strings.Contains(code, "TOKEN") || category == "credential_access") {
		return adjustedAllowDecision(decision, "LOCAL_DEBUG_CREDENTIAL_REPRODUCTION", "platform-controlled internal engineering policy recognizes local log credential reuse for debugging with no third-party target or exfiltration sink")
	}
	if strings.Contains(code, "SESSION_HIJACK") && benignReplayPattern.MatchString(text) && !authMaterialPattern.MatchString(text) {
		return adjustedAllowDecision(decision, "ENGINEERING_REPLAY_SEMANTICS", "event/message replay pipeline semantics do not request authenticated-session takeover")
	}
	if strings.Contains(code, "PERSISTENCE") && benignPersistencePattern.MatchString(text) && !maliciousPersistencePattern.MatchString(text) {
		return adjustedAllowDecision(decision, "ENGINEERING_PERSISTENCE_SEMANTICS", "data/state/config/address persistence semantics do not request unauthorized startup or implant persistence")
	}
	if strings.Contains(code, "C2") && artifactPlaceholderPattern.MatchString(text) && !explicitC2Pattern.MatchString(text) {
		return adjustedAllowDecision(decision, "EPHEMERAL_ARTIFACT_NOT_C2", "temporary artifact identifiers and generic server troubleshooting do not request command-and-control infrastructure")
	}
	return decision, nil
}

func adjustedAllowDecision(original AuditDecision, code string, reason string) (AuditDecision, *AuditPolicyAdjustment) {
	adjustment := &AuditPolicyAdjustment{
		Code:             code,
		Reason:           reason,
		OriginalDecision: original.Decision,
		OriginalRiskCode: original.RiskCode,
		OriginalReason:   original.Reason,
	}
	return AuditDecision{
		Decision:   DecisionAllow,
		Category:   "benign_internal_engineering",
		Confidence: 0.99,
		Reason:     reason,
		Source:     "policy_adjustment",
	}, adjustment
}

func isUserProvidedSecretConfiguration(text string) bool {
	return secretTermPattern.MatchString(text) && secretConfigurationPattern.MatchString(text)
}

func isLocalDebugCredentialUse(text string) bool {
	return localDebugContextPattern.MatchString(text) && localCredentialOperationPattern.MatchString(text)
}

func hasDangerousSecretIntent(text string) bool {
	if !secretTermPattern.MatchString(text) {
		return false
	}
	return secretHarmVerbPattern.MatchString(text) || thirdPartyTargetPattern.MatchString(text) || publicSecretSinkPattern.MatchString(text)
}
''',
    encoding="utf-8",
)

# ---------------------------------------------------------------------------
# Semantic rule units and code-specific suppression diagnostics
# ---------------------------------------------------------------------------
(ROOT / "internal/platform/audit_rule_units.go").write_text(
    r'''package platform

import (
	"regexp"
	"strings"
)

const auditRuleUnitMaxBytes = 8192

type auditRuleUnit struct {
	Index int
	Kind  string
	Text  string
}

type RuleSuppressionDiagnostic struct {
	RuleCode    string `json:"rule_code"`
	UnitIndex   int    `json:"unit_index"`
	Reason      string `json:"reason"`
	MatchedText string `json:"matched_text,omitempty"`
}

var (
	markdownListPattern = regexp.MustCompile(`^\s*(?:[-*+]\s+|\d+[.)]\s+)`)
	artifactC2FragmentPattern = regexp.MustCompile(`(?i)(?:codex-clipboard|[cC][0-9a-f]{8,}|\[CLIPBOARD_IMAGE\]|\[ARTIFACT_ID\]|\[TEMP_PATH\])`)
)

func splitAuditRuleUnits(text string) []auditRuleUnit {
	lines := strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n")
	units := make([]auditRuleUnit, 0, len(lines)/2+1)
	var builder strings.Builder
	kind := "paragraph"
	inFence := false
	flush := func() {
		value := strings.TrimSpace(builder.String())
		builder.Reset()
		if value == "" {
			return
		}
		appendAuditRuleUnit(&units, kind, value)
	}
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "ROLE=") {
			flush()
			continue
		}
		if strings.HasPrefix(trimmed, "```") {
			if !inFence {
				flush()
				kind = "code"
				inFence = true
			} else {
				if builder.Len() > 0 {
					builder.WriteByte('\n')
				}
				builder.WriteString(line)
				flush()
				kind = "paragraph"
				inFence = false
				continue
			}
		}
		if !inFence && (trimmed == "" || markdownListPattern.MatchString(line) || strings.HasPrefix(trimmed, "#")) {
			flush()
			if trimmed == "" {
				continue
			}
			kind = map[bool]string{true: "list_item", false: "heading"}[markdownListPattern.MatchString(line)]
			builder.WriteString(line)
			flush()
			kind = "paragraph"
			continue
		}
		if builder.Len() > 0 {
			builder.WriteByte('\n')
		}
		builder.WriteString(line)
	}
	flush()
	return units
}

func appendAuditRuleUnit(units *[]auditRuleUnit, kind string, value string) {
	for len(value) > auditRuleUnitMaxBytes {
		end := auditRuleUnitMaxBytes
		for end > 0 && (value[end]&0xC0) == 0x80 {
			end--
		}
		if end <= 0 {
			end = auditRuleUnitMaxBytes
		}
		*units = append(*units, auditRuleUnit{Index: len(*units) + 1, Kind: kind, Text: value[:end]})
		next := end - 256
		if next < 0 {
			next = end
		}
		value = value[next:]
	}
	if strings.TrimSpace(value) != "" {
		*units = append(*units, auditRuleUnit{Index: len(*units) + 1, Kind: kind, Text: value})
	}
}

func shouldSuppressEngineeringRuleMatch(policy AuditPolicy, rule CyberRule, unit string, evidence cyberRuleEvidence) (bool, string) {
	code := strings.ToUpper(strings.TrimSpace(rule.Code))
	matched := unit
	if evidence.start >= 0 && evidence.end >= evidence.start && evidence.end <= len(unit) {
		matched = unit[evidence.start:evidence.end]
	}
	switch code {
	case "CYBER_C2_INFRASTRUCTURE":
		if artifactC2FragmentPattern.MatchString(matched) && !explicitC2Pattern.MatchString(matched) {
			return true, "artifact_or_hex_fragment_without_standalone_c2_semantics"
		}
		if !explicitC2Pattern.MatchString(matched) {
			return true, "generic_server_text_without_c2_semantics"
		}
	case "CYBER_SESSION_HIJACKING":
		if benignReplayPattern.MatchString(matched) && !authMaterialPattern.MatchString(matched) {
			return true, "engineering_replay_without_authentication_material"
		}
	case "CYBER_PERSISTENCE":
		if benignPersistencePattern.MatchString(matched) && !maliciousPersistencePattern.MatchString(matched) {
			return true, "application_data_persistence_without_startup_or_implant_semantics"
		}
	case "CYBER_CREDENTIAL_THEFT", "CYBER_CLOUD_SECRET_THEFT", "CYBER_CREDENTIAL_ACCESS_REVIEW":
		if policy.Mode == AuditPolicyModeInternalEngineering && !hasDangerousSecretIntent(unit) {
			if policy.AllowUserProvidedSecrets && isUserProvidedSecretConfiguration(unit) {
				return true, "requester_provided_secret_configuration_requires_semantic_policy_not_hard_block"
			}
			if policy.AllowLocalDebugCredentials && isLocalDebugCredentialUse(unit) {
				return true, "local_debug_credential_use_requires_semantic_policy_not_hard_block"
			}
		}
	}
	return false, ""
}
''',
    encoding="utf-8",
)

# ---------------------------------------------------------------------------
# Type surface for diagnostics
# ---------------------------------------------------------------------------
types_path = ROOT / "internal/platform/types.go"
types = types_path.read_text(encoding="utf-8")
types = replace_once(
    types,
    "\tAuditIgnoredRoles        []string              `json:\"audit_ignored_roles,omitempty\"`\n"
    "\tAuditTextLimitMode       string                `json:\"audit_text_limit_mode,omitempty\"`\n"
    "\tAuditTextLimitBytes      int                   `json:\"audit_text_limit_bytes,omitempty\"`\n",
    "\tAuditIgnoredRoles           []string                    `json:\"audit_ignored_roles,omitempty\"`\n"
    "\tAuditIgnoredInputTypes      []string                    `json:\"audit_ignored_input_types,omitempty\"`\n"
    "\tAuditTextLimitMode          string                      `json:\"audit_text_limit_mode,omitempty\"`\n"
    "\tAuditTextLimitBytes         int                         `json:\"audit_text_limit_bytes,omitempty\"`\n"
    "\tAuditRawIntentBytes         int                         `json:\"audit_raw_intent_bytes,omitempty\"`\n"
    "\tAuditPriorUserContextBytes  int                         `json:\"audit_prior_user_context_bytes,omitempty\"`\n"
    "\tAuditActiveUserMessages     int                         `json:\"audit_active_user_messages,omitempty\"`\n"
    "\tAuditContextActivated       bool                        `json:\"audit_context_activated,omitempty\"`\n"
    "\tAuditEphemeralArtifactCount int                         `json:\"audit_ephemeral_artifact_count,omitempty\"`\n"
    "\tAuditSecretPlaceholderCount int                         `json:\"audit_secret_placeholder_count,omitempty\"`\n"
    "\tAuditRuleSuppressions       []RuleSuppressionDiagnostic `json:\"audit_rule_suppressions,omitempty\"`\n"
    "\tAuditPolicyMode             string                      `json:\"audit_policy_mode,omitempty\"`\n"
    "\tAuditPolicyAdjustment       *AuditPolicyAdjustment      `json:\"audit_policy_adjustment,omitempty\"`\n",
    "audit result precision fields",
)
types_path.write_text(types, encoding="utf-8")

# ---------------------------------------------------------------------------
# Audit engine: semantic units, early profile policy, and adjustment pass
# ---------------------------------------------------------------------------
audit_path = ROOT / "internal/platform/audit.go"
audit = audit_path.read_text(encoding="utf-8")
start = audit.index("func (e *AuditEngine) matchRules(text string)")
end = audit.index("func (e *AuditEngine) Audit(", start)
new_match = r'''func (e *AuditEngine) matchRules(text string, policy AuditPolicy) (*AuditDecision, *RuleMatchDiagnostics, []RuleSuppressionDiagnostic) {
	rules, _ := e.rules.Load().([]compiledRule)
	units := splitAuditRuleUnits(text)
	var review *AuditDecision
	var reviewDiagnostics *RuleMatchDiagnostics
	suppressions := make([]RuleSuppressionDiagnostic, 0, 4)
	for ruleIndex, rule := range rules {
		for _, unit := range units {
			evidence, matched := matchCyberRuleEvidence(rule, unit.Text, strings.ToLower(unit.Text))
			if !matched {
				continue
			}
			if suppressed, suppressionReason := shouldSuppressEngineeringRuleMatch(policy, rule.CyberRule, unit.Text, evidence); suppressed {
				if len(suppressions) < 16 {
					suppressions = append(suppressions, RuleSuppressionDiagnostic{
						RuleCode:    rule.Code,
						UnitIndex:   unit.Index,
						Reason:      suppressionReason,
						MatchedText: redactCyberTraceText(evidence.matchedRaw),
					})
				}
				continue
			}
			diagnostics := buildRuleMatchDiagnostics(rule, ruleIndex+1, unit.Text, evidence)
			diagnostics.UnitIndex = unit.Index
			diagnostics.UnitKind = unit.Kind
			action := rule.Action
			reason := fmt.Sprintf("matched cyber rule #%d (%s)", rule.ID, rule.Code)
			if len(diagnostics.Indicators) > 0 {
				reason += ": " + strings.Join(diagnostics.Indicators, ", ")
			}
			if downgrade, downgradeReason := shouldReviewCredentialSelfService(rule.CyberRule, unit.Text); downgrade {
				action = DecisionReview
				diagnostics.Downgraded = true
				diagnostics.DowngradeReason = downgradeReason
				reason = fmt.Sprintf("matched cyber rule #%d (%s), but credential self-service context requires semantic review", rule.ID, rule.Code)
			}
			decision := AuditDecision{
				Decision:   action,
				RiskCode:   rule.Code,
				Category:   rule.Category,
				Confidence: 1,
				Reason:     reason,
				Source:     "rule",
				RuleID:     rule.ID,
			}
			if action == DecisionReview {
				if review == nil {
					copyOfDecision := decision
					copyOfDiagnostics := diagnostics
					review = &copyOfDecision
					reviewDiagnostics = &copyOfDiagnostics
				}
				continue
			}
			return &decision, &diagnostics, suppressions
		}
	}
	return review, reviewDiagnostics, suppressions
}

'''
audit = audit[:start] + new_match + audit[end:]
# Extraction diagnostics in result.
audit = replace_once(
    audit,
    "\t\tAuditIgnoredRoles:        append([]string(nil), extraction.IgnoredRoles...),\n"
    "\t\tAuditTextLimitMode:       e.textLimitMode,\n"
    "\t\tAuditTextLimitBytes:      e.maxTextBytes,\n",
    "\t\tAuditIgnoredRoles:           append([]string(nil), extraction.IgnoredRoles...),\n"
    "\t\tAuditIgnoredInputTypes:      append([]string(nil), extraction.IgnoredInputTypes...),\n"
    "\t\tAuditTextLimitMode:          e.textLimitMode,\n"
    "\t\tAuditTextLimitBytes:         e.maxTextBytes,\n"
    "\t\tAuditRawIntentBytes:         extraction.RawIntentBytes,\n"
    "\t\tAuditPriorUserContextBytes:  extraction.PriorUserContextBytes,\n"
    "\t\tAuditActiveUserMessages:     extraction.ActiveUserMessages,\n"
    "\t\tAuditContextActivated:       extraction.ContextActivated,\n"
    "\t\tAuditEphemeralArtifactCount: extraction.EphemeralArtifactCount,\n"
    "\t\tAuditSecretPlaceholderCount: extraction.SecretPlaceholderCount,\n",
    "audit extraction precision diagnostics",
)
old_flow = """\tmatched, ruleMatch := e.matchRules(text)\n\tresult.RuleMatch = ruleMatch\n\tif matched != nil && (matched.Decision == DecisionBlock || matched.Decision == DecisionAllow) {\n\t\tresult.AuditDecision = *matched\n\t\treturn result\n\t}\n\n\tprofile, err := e.getAuditProfile(ctx, route.AuditProfileID)\n\tif err != nil || !profile.Enabled {\n"""
new_flow = """\tprofile, profileErr := e.getAuditProfile(ctx, route.AuditProfileID)\n\tpolicy := strictAuditPolicy()\n\tif profileErr == nil && profile.Enabled {\n\t\tpolicy = auditPolicyFromProfile(profile)\n\t}\n\tresult.AuditPolicyMode = policy.Mode\n\tmatched, ruleMatch, suppressions := e.matchRules(text, policy)\n\tresult.RuleMatch = ruleMatch\n\tresult.AuditRuleSuppressions = append([]RuleSuppressionDiagnostic(nil), suppressions...)\n\tif matched != nil && (matched.Decision == DecisionBlock || matched.Decision == DecisionAllow) {\n\t\tadjusted, adjustment := applyAuditPolicyAdjustment(policy, text, *matched)\n\t\tresult.AuditDecision = adjusted\n\t\tresult.AuditPolicyAdjustment = adjustment\n\t\treturn result\n\t}\n\n\tif profileErr != nil || !profile.Enabled {\n"""
audit = replace_once(audit, old_flow, new_flow, "audit policy before rules")
# Ensure stale err identifier isn't used in unavailable branch condition. That branch doesn't use err itself.
# Policy adjustment before fail-closed review conversion.
audit = replace_once(
    audit,
    "\tif decision.Decision == DecisionReview && (route.FailClosed || usedProfile.FailClosed) {\n",
    "\tdecision, result.AuditPolicyAdjustment = applyAuditPolicyAdjustment(policy, text, decision)\n"
    "\tif decision.Decision == DecisionReview && (route.FailClosed || usedProfile.FailClosed) {\n",
    "audit model policy adjustment",
)
audit_path.write_text(audit, encoding="utf-8")

# Rule diagnostics unit fields.
explain_path = ROOT / "internal/platform/cyber_rule_explainability.go"
explain = explain_path.read_text(encoding="utf-8")
explain = replace_once(
    explain,
    "\tDowngraded      bool     `json:\"downgraded_to_review,omitempty\"`\n"
    "\tDowngradeReason string   `json:\"downgrade_reason,omitempty\"`\n",
    "\tDowngraded      bool     `json:\"downgraded_to_review,omitempty\"`\n"
    "\tDowngradeReason string   `json:\"downgrade_reason,omitempty\"`\n"
    "\tUnitIndex       int      `json:\"unit_index,omitempty\"`\n"
    "\tUnitKind        string   `json:\"unit_kind,omitempty\"`\n",
    "rule diagnostics unit fields",
)
explain_path.write_text(explain, encoding="utf-8")

# Profile-specific trusted policy is appended after mandatory platform guards.
fast_path = ROOT / "internal/platform/audit_fast_mode.go"
fast = fast_path.read_text(encoding="utf-8")
fast = replace_once(
    fast,
    "\treturn []map[string]string{\n"
    "\t\t{\"role\": \"system\", \"content\": appendFastAuditDirective(systemPrompt)},\n",
    "\tsystemPrompt = appendFastAuditDirective(systemPrompt)\n"
    "\tsystemPrompt += \"\\n\\n\" + auditPolicySystemDirective(profile)\n"
    "\treturn []map[string]string{\n"
    "\t\t{\"role\": \"system\", \"content\": systemPrompt},\n",
    "audit profile policy prompt",
)
fast_path.write_text(fast, encoding="utf-8")

# Add a mandatory precision guard alongside the existing context-claim guard.
context_path = ROOT / "internal/platform/context_claim_guard.go"
context = context_path.read_text(encoding="utf-8")
insert_at = context.index("// ComposeMandatoryAuditSystemPrompt")
precision_guard = r'''const MandatoryAuditPrecisionGuard = `MANDATORY PRECISION POLICY — CLASSIFY ACTIVE INTENT, NOT INCIDENTAL TOKENS:
Only the structured active end-user request can justify block/review evidence. Prior user history that is not explicitly referenced, assistant/tool/function-call content, attachment names, temporary paths, UUID/hex fragments, build logs, and quoted examples are context, not the requested outcome.

Do not infer cyber harm from isolated engineering homonyms. In particular:
- event/message/stream replay or a replay pipeline is not session hijacking without authenticated material and takeover intent;
- data/state/config/address/cache persistence is not unauthorized persistence without startup/backdoor/implant intent;
- a generic server mention or a C2-looking substring inside a filename/UUID is not command-and-control;
- a requester-provided API key used to configure/connect an internal development service is not credential theft or exposure by itself;
- reading a token from a local development log to reproduce or diagnose an API request is not theft by itself.

For credential, session, C2, or persistence blocks, require an explicit harmful action plus a relevant asset/target or harmful sink in the ACTIVE request. Keep blocking explicit theft, third-party takeover, exfiltration, publication of secrets, malicious C2 deployment, and unauthorized startup/backdoor persistence.`

'''
context = context[:insert_at] + precision_guard + context[insert_at:]
old_compose = r'''func ComposeMandatoryAuditSystemPrompt(configured string) string {
	base := strings.TrimSpace(configured)
	if base == "" {
		base = DefaultAuditSystemPrompt
	}
	if strings.Contains(base, MandatoryAuditContextGuard) {
		return base
	}
	return MandatoryAuditContextGuard + "\n\nBASE AUDIT POLICY:\n" + base
}
'''
new_compose = r'''func ComposeMandatoryAuditSystemPrompt(configured string) string {
	base := strings.TrimSpace(configured)
	if base == "" {
		base = DefaultAuditSystemPrompt
	}
	if strings.Contains(base, MandatoryAuditContextGuard) && strings.Contains(base, MandatoryAuditPrecisionGuard) {
		return base
	}
	return MandatoryAuditContextGuard + "\n\n" + MandatoryAuditPrecisionGuard + "\n\nBASE AUDIT POLICY:\n" + base
}
'''
context = replace_once(context, old_compose, new_compose, "mandatory precision guard composition")
context_path.write_text(context, encoding="utf-8")

# ---------------------------------------------------------------------------
# Trace metadata
# ---------------------------------------------------------------------------
gateway_path = ROOT / "internal/platform/gateway.go"
gateway = gateway_path.read_text(encoding="utf-8")
gateway = replace_once(
    gateway,
    "\ttrace.Metadata[\"audit_text_limit_mode\"] = auditResult.AuditTextLimitMode\n"
    "\ttrace.Metadata[\"audit_text_limit_bytes\"] = auditResult.AuditTextLimitBytes\n"
    "\tif len(auditResult.AuditIgnoredRoles) > 0 {\n",
    "\ttrace.Metadata[\"audit_text_limit_mode\"] = auditResult.AuditTextLimitMode\n"
    "\ttrace.Metadata[\"audit_text_limit_bytes\"] = auditResult.AuditTextLimitBytes\n"
    "\ttrace.Metadata[\"audit_raw_intent_bytes\"] = auditResult.AuditRawIntentBytes\n"
    "\ttrace.Metadata[\"audit_prior_user_context_bytes\"] = auditResult.AuditPriorUserContextBytes\n"
    "\ttrace.Metadata[\"audit_active_user_messages\"] = auditResult.AuditActiveUserMessages\n"
    "\ttrace.Metadata[\"audit_context_activated\"] = auditResult.AuditContextActivated\n"
    "\ttrace.Metadata[\"audit_ephemeral_artifact_count\"] = auditResult.AuditEphemeralArtifactCount\n"
    "\ttrace.Metadata[\"audit_secret_placeholder_count\"] = auditResult.AuditSecretPlaceholderCount\n"
    "\ttrace.Metadata[\"audit_policy_mode\"] = auditResult.AuditPolicyMode\n"
    "\tif len(auditResult.AuditIgnoredInputTypes) > 0 {\n"
    "\t\ttrace.Metadata[\"audit_ignored_input_types\"] = auditResult.AuditIgnoredInputTypes\n"
    "\t}\n"
    "\tif len(auditResult.AuditRuleSuppressions) > 0 {\n"
    "\t\ttrace.Metadata[\"audit_rule_suppressions\"] = auditResult.AuditRuleSuppressions\n"
    "\t}\n"
    "\tif auditResult.AuditPolicyAdjustment != nil {\n"
    "\t\ttrace.Metadata[\"audit_policy_adjustment\"] = auditResult.AuditPolicyAdjustment\n"
    "\t}\n"
    "\tif len(auditResult.AuditIgnoredRoles) > 0 {\n",
    "gateway precision metadata",
)
gateway_path.write_text(gateway, encoding="utf-8")

# ---------------------------------------------------------------------------
# Database rule tiers, trusted default profile, and adaptive shadow-only mode
# ---------------------------------------------------------------------------
migration = r'''-- Precision-first policy for engineering traffic.
UPDATE cyber_rules SET
    pattern='(?is)(?:\b(?:steal|dump|exfiltrat(?:e|ing)|harvest|grab)\b|(?:窃取|盗取|外传|偷取)).{0,80}(?:\b(?:passwords?|credentials?|session cookies?|access tokens?|refresh tokens?|api keys?|private keys?|seed phrases?|mnemonics?)\b|(?:密码|凭据|会话(?:Cookie|令牌)|访问令牌|刷新令牌|API.?Key|私钥|助记词))',
    action='block',
    description='Explicit theft, harvesting, dumping, or exfiltration of authentication material.'
WHERE code='CYBER_CREDENTIAL_THEFT';
-- statement-breakpoint
INSERT INTO cyber_rules
(code,name,description,category,pattern,pattern_type,action,priority,enabled)
VALUES
('CYBER_CREDENTIAL_ACCESS_REVIEW','Ambiguous credential access for semantic review','Reading, extracting, or locating credentials can be legitimate debugging or harmful access; require semantic review.','credential_access','(?is)(?:\b(?:extract|read|locate|find|recover|parse)\b|(?:提取|读取|定位|查找|恢复|解析)).{0,80}(?:\b(?:credentials?|access tokens?|refresh tokens?|api keys?|authorization|bearer|cookies?)\b|(?:凭据|访问令牌|刷新令牌|API.?Key|Authorization|Bearer|Cookie))','regex','review',1998,TRUE),
('CYBER_EXPLICIT_C2_DEPLOYMENT','Explicit C2 deployment','Explicitly building, deploying, hosting, or configuring command-and-control infrastructure.','command_and_control','(?is)(?:\b(?:build|deploy|host|configure|stand up)\b|(?:构建|搭建|部署|托管|配置)).{0,48}(?:\b(?:c2|command[ -]?and[ -]?control|beacon|implant)\b|(?:命令(?:与|和)?控制|信标|植入体)).{0,64}(?:\b(?:server|framework|channel|callback|tasking|redirector)\b|(?:服务器|框架|通道|回连|任务下发|重定向器))','regex','block',1952,TRUE),
('CYBER_EXPLICIT_SESSION_TAKEOVER','Explicit session-token takeover','Using stolen cookies or session tokens to authenticate as another party.','credential_access','(?is)(?:\b(?:steal|replay|use|inject)\b|(?:窃取|重放|使用|注入)).{0,64}(?:\b(?:session cookies?|session tokens?|jwt|bearer token|oauth token)\b|(?:会话(?:Cookie|令牌)|JWT|Bearer|OAuth令牌)).{0,80}(?:\b(?:take over|login as|impersonate|bypass authentication)\b|(?:接管|冒充|登录他人|绕过认证))','regex','block',1996,TRUE),
('CYBER_EXPLICIT_MALICIOUS_PERSISTENCE','Explicit malicious persistence','Installing a backdoor, implant, or malware startup mechanism on a target.','persistence','(?is)(?:\b(?:install|deploy|create|configure)\b|(?:安装|部署|创建|配置)).{0,64}(?:\b(?:backdoor|implant|malware|webshell|trojan)\b|(?:后门|植入体|恶意软件|WebShell|木马)).{0,80}(?:\b(?:autostart|survive reboot|startup|scheduled task|cron|systemd|registry run)\b|(?:开机自启|重启后存活|启动项|计划任务))','regex','block',1956,TRUE)
ON CONFLICT(code) DO UPDATE SET
    name=EXCLUDED.name,description=EXCLUDED.description,category=EXCLUDED.category,
    pattern=EXCLUDED.pattern,pattern_type=EXCLUDED.pattern_type,action=EXCLUDED.action,
    priority=EXCLUDED.priority,enabled=TRUE,updated_at=now();
-- statement-breakpoint
UPDATE cyber_rules SET
    pattern='(?is)(?:\b(?:command[ -]?and[ -]?control|c2|beacon|implant)\b|(?:命令(?:与|和)?控制|信标|植入体))[^\r\n]{0,64}(?:\b(?:server|framework|channel|callback|tasking|redirector)\b|(?:服务器|框架|通道|回连|任务下发|重定向器))',
    action='review',
    description='C2 terminology with nearby infrastructure terminology; semantic model must confirm operational malicious intent.'
WHERE code='CYBER_C2_INFRASTRUCTURE';
-- statement-breakpoint
UPDATE cyber_rules SET
    pattern='(?is)(?:\b(?:hijack|take over|steal|replay)\b|(?:劫持|接管|窃取|重放))[^\r\n]{0,64}(?:\b(?:session cookies?|session tokens?|jwt|bearer token|oauth token)\b|(?:会话(?:Cookie|令牌|凭据)|Cookie|JWT|Bearer|OAuth令牌))',
    action='review',
    description='Potential authenticated-session takeover; generic event/message replay is excluded and semantic review is required.'
WHERE code='CYBER_SESSION_HIJACKING';
-- statement-breakpoint
UPDATE cyber_rules SET
    pattern='(?is)(?:\b(?:survive reboot|autostart|startup persistence|scheduled task persistence|startup item|registry run)\b|(?:开机自启|重启后存活|计划任务持久化|启动项|注册表Run键))[^\r\n]{0,96}(?:\b(?:target|host|victim|implant|backdoor|malware)\b|(?:目标|主机|受害者|植入体|后门|恶意软件))?',
    action='review',
    description='Startup or implant persistence semantics; ordinary data/state/config/address persistence is excluded.'
WHERE code='CYBER_PERSISTENCE';
-- statement-breakpoint
UPDATE settings SET value='false'::jsonb,updated_at=now()
WHERE key IN ('cyber_adaptive_auto_promote','cyber_adaptive_auto_block');
-- statement-breakpoint
UPDATE audit_profiles SET extra=
    jsonb_set(
      jsonb_set(
        jsonb_set(COALESCE(extra,'{}'::jsonb),'{_risk_policy_mode}','"internal_engineering"'::jsonb,TRUE),
        '{_risk_allow_user_provided_secrets}','true'::jsonb,TRUE),
      '{_risk_allow_local_debug_credentials}','true'::jsonb,TRUE),
    updated_at=now()
WHERE is_default=TRUE AND NOT (COALESCE(extra,'{}'::jsonb) ? '_risk_policy_mode');
'''
(ROOT / "internal/platform/migrations/008_precision_first_engineering_policy.sql").write_text(migration, encoding="utf-8")

adaptive_path = ROOT / "internal/platform/adaptive_rules.go"
adaptive = adaptive_path.read_text(encoding="utf-8")
adaptive = replace_once(adaptive, "\t\tAutoPromote:      true,\n", "\t\tAutoPromote:      false,\n", "adaptive default shadow-only")
adaptive_path.write_text(adaptive, encoding="utf-8")

# Bootstrap fresh deployments with the platform-controlled engineering profile.
store_path = ROOT / "internal/platform/store.go"
store = store_path.read_text(encoding="utf-8")
store = replace_once(
    store,
    "\t\t_, err = s.pool.Exec(ctx, `INSERT INTO audit_profiles\n"
    "\t\t\t(name,endpoint,model,api_key_ciphertext,system_prompt,timeout_ms,block_threshold,enabled,fail_closed,is_default)\n"
    "\t\t\tVALUES($1,$2,$3,$4,$5,$6,$7,TRUE,TRUE,$8)\n"
    "\t\t\tON CONFLICT(name) DO NOTHING`,\n"
    "\t\t\t\"Default small-model audit\", cfg.DefaultAuditEndpoint, cfg.DefaultAuditModel, ciphertext,\n"
    "\t\t\tDefaultAuditSystemPrompt, int(cfg.DefaultAuditTimeout.Milliseconds()),\n"
    "\t\t\tcfg.DefaultAuditBlockThreshold, !defaultExists)\n",
    "\t\tdefaultExtra := json.RawMessage(`{\"_risk_policy_mode\":\"internal_engineering\",\"_risk_allow_user_provided_secrets\":true,\"_risk_allow_local_debug_credentials\":true}`)\n"
    "\t\t_, err = s.pool.Exec(ctx, `INSERT INTO audit_profiles\n"
    "\t\t\t(name,endpoint,model,api_key_ciphertext,system_prompt,timeout_ms,block_threshold,enabled,fail_closed,is_default,extra)\n"
    "\t\t\tVALUES($1,$2,$3,$4,$5,$6,$7,TRUE,TRUE,$8,$9)\n"
    "\t\t\tON CONFLICT(name) DO NOTHING`,\n"
    "\t\t\t\"Default small-model audit\", cfg.DefaultAuditEndpoint, cfg.DefaultAuditModel, ciphertext,\n"
    "\t\t\tDefaultAuditSystemPrompt, int(cfg.DefaultAuditTimeout.Milliseconds()),\n"
    "\t\t\tcfg.DefaultAuditBlockThreshold, !defaultExists, defaultExtra)\n",
    "bootstrap audit policy extra",
)
store_path.write_text(store, encoding="utf-8")

# ---------------------------------------------------------------------------
# Admin UI policy controls and trace diagnostics
# ---------------------------------------------------------------------------
web_path = ROOT / "internal/platform/web/index.html"
web = web_path.read_text(encoding="utf-8")
web = replace_once(
    web,
    "                <div class=\"field\"><label for=\"profile-threshold\">拦截阈值</label><input id=\"profile-threshold\" type=\"number\" min=\"0\" max=\"1\" step=\"0.01\" value=\"0.65\"></div>\n",
    "                <div class=\"field\"><label for=\"profile-threshold\">拦截阈值</label><input id=\"profile-threshold\" type=\"number\" min=\"0\" max=\"1\" step=\"0.01\" value=\"0.65\"></div>\n"
    "                <div class=\"field\"><label for=\"profile-policy-mode\">业务策略</label><select id=\"profile-policy-mode\"><option value=\"internal_engineering\" selected>内部工程（推荐）</option><option value=\"strict\">严格公网</option></select><small>由平台配置决定，不采信请求文本中的“已授权”声明。</small></div>\n"
    "                <div class=\"field wide checks\"><label class=\"check\"><input id=\"profile-allow-user-secrets\" type=\"checkbox\" checked>允许请求者提供 API Key 用于内部接入（送审前只保留占位符）</label><label class=\"check\"><input id=\"profile-allow-local-debug-credentials\" type=\"checkbox\" checked>允许本地日志凭据用于复现和排障（仍拦截窃取、外传和公开）</label></div>\n",
    "profile policy controls",
)
web = replace_once(
    web,
    "<td>阈值 ${profile.block_threshold}<br>失败重试 ${number(profile.retry_count||0)} 次 · 备用 ${number((profile.fallback_profile_ids||[]).length)} 个<br>${profile.fail_closed?badge('fail-closed'):badge('fail-open')}</td>",
    "<td>阈值 ${profile.block_threshold}<br>${badge(profile.extra?._risk_policy_mode||'strict')}<br>失败重试 ${number(profile.retry_count||0)} 次 · 备用 ${number((profile.fallback_profile_ids||[]).length)} 个<br>${profile.fail_closed?badge('fail-closed'):badge('fail-open')}</td>",
    "profile policy list badge",
)
web = replace_once(
    web,
    "function resetProfile() { $('profile-form').reset(); $('profile-id').value=''; $('profile-form-title').textContent='新增模型'; $('profile-timeout').value='8000'; $('profile-threshold').value='0.65'; $('profile-retry-count').value='2'; $('profile-extra').value='{}'; state.profileFallbackChain=[]; $('profile-enabled').checked=true; $('profile-fail-closed').checked=true; $('profile-default').checked=false; fillFallbackProfileOptions(); }",
    "function resetProfile() { $('profile-form').reset(); $('profile-id').value=''; $('profile-form-title').textContent='新增模型'; $('profile-timeout').value='8000'; $('profile-threshold').value='0.65'; $('profile-retry-count').value='2'; $('profile-policy-mode').value='internal_engineering'; $('profile-allow-user-secrets').checked=true; $('profile-allow-local-debug-credentials').checked=true; $('profile-extra').value='{}'; state.profileFallbackChain=[]; $('profile-enabled').checked=true; $('profile-fail-closed').checked=true; $('profile-default').checked=false; fillFallbackProfileOptions(); }",
    "reset profile policy",
)
old_edit = "function editProfile(id) { const profile=state.profiles.find(item=>item.id===Number(id));if(!profile)return;$('profile-id').value=profile.id;$('profile-name').value=profile.name;$('profile-endpoint').value=profile.endpoint;$('profile-model').value=profile.model;$('profile-api-key').value='';$('profile-system-prompt').value=profile.system_prompt||'';$('profile-timeout').value=profile.timeout_ms;$('profile-threshold').value=profile.block_threshold;$('profile-retry-count').value=profile.retry_count??2;$('profile-extra').value=JSON.stringify(profile.extra||{},null,2);state.profileFallbackChain=(profile.fallback_profile_ids||[]).map(Number);$('profile-enabled').checked=profile.enabled;$('profile-fail-closed').checked=profile.fail_closed;$('profile-default').checked=profile.is_default;$('profile-form-title').textContent=`编辑模型 #${profile.id}`;fillFallbackProfileOptions();$('profile-form').scrollIntoView({behavior:'smooth',block:'start'}); }"
new_edit = "function editProfile(id) { const profile=state.profiles.find(item=>item.id===Number(id));if(!profile)return;const extra=profile.extra||{};$('profile-id').value=profile.id;$('profile-name').value=profile.name;$('profile-endpoint').value=profile.endpoint;$('profile-model').value=profile.model;$('profile-api-key').value='';$('profile-system-prompt').value=profile.system_prompt||'';$('profile-timeout').value=profile.timeout_ms;$('profile-threshold').value=profile.block_threshold;$('profile-retry-count').value=profile.retry_count??2;$('profile-policy-mode').value=extra._risk_policy_mode||'strict';$('profile-allow-user-secrets').checked=extra._risk_allow_user_provided_secrets===true;$('profile-allow-local-debug-credentials').checked=extra._risk_allow_local_debug_credentials===true;$('profile-extra').value=JSON.stringify(extra,null,2);state.profileFallbackChain=(profile.fallback_profile_ids||[]).map(Number);$('profile-enabled').checked=profile.enabled;$('profile-fail-closed').checked=profile.fail_closed;$('profile-default').checked=profile.is_default;$('profile-form-title').textContent=`编辑模型 #${profile.id}`;fillFallbackProfileOptions();$('profile-form').scrollIntoView({behavior:'smooth',block:'start'}); }"
web = replace_once(web, old_edit, new_edit, "edit profile policy")
old_save = "async function saveProfile(event) { event.preventDefault();let extra;try{extra=JSON.parse($('profile-extra').value||'{}');}catch{toast('额外参数不是合法 JSON','error');return;}const payload={id:Number($('profile-id').value||0),name:$('profile-name').value,endpoint:$('profile-endpoint').value,model:$('profile-model').value,api_key:$('profile-api-key').value,system_prompt:$('profile-system-prompt').value,timeout_ms:Number($('profile-timeout').value),block_threshold:Number($('profile-threshold').value),retry_count:Number($('profile-retry-count').value||0),fallback_profile_ids:[...state.profileFallbackChain],enabled:$('profile-enabled').checked,fail_closed:$('profile-fail-closed').checked,is_default:$('profile-default').checked,extra};"
new_save = "async function saveProfile(event) { event.preventDefault();let extra;try{extra=JSON.parse($('profile-extra').value||'{}');}catch{toast('额外参数不是合法 JSON','error');return;}extra._risk_policy_mode=$('profile-policy-mode').value||'strict';extra._risk_allow_user_provided_secrets=$('profile-allow-user-secrets').checked;extra._risk_allow_local_debug_credentials=$('profile-allow-local-debug-credentials').checked;const payload={id:Number($('profile-id').value||0),name:$('profile-name').value,endpoint:$('profile-endpoint').value,model:$('profile-model').value,api_key:$('profile-api-key').value,system_prompt:$('profile-system-prompt').value,timeout_ms:Number($('profile-timeout').value),block_threshold:Number($('profile-threshold').value),retry_count:Number($('profile-retry-count').value||0),fallback_profile_ids:[...state.profileFallbackChain],enabled:$('profile-enabled').checked,fail_closed:$('profile-fail-closed').checked,is_default:$('profile-default').checked,extra};"
web = replace_once(web, old_save, new_save, "save profile policy")
web = replace_once(
    web,
    "['审计延迟',`${number(item.audit_latency_ms)} ms`], ['审计输入范围',item.metadata?.audit_input_scope||'-'], ['审计用户意图字节',item.metadata?.audit_intent_bytes??'-'], ['审计文本上限模式',item.metadata?.audit_text_limit_mode||'-'], ['本次审计文本容量',byteText(item.metadata?.audit_text_limit_bytes)], ['忽略的系统/工具上下文字节',item.metadata?.audit_ignored_context_bytes??0], ['忽略的上下文角色',(item.metadata?.audit_ignored_roles||[]).join(', ')||'-'],",
    "['审计延迟',`${number(item.audit_latency_ms)} ms`], ['审计输入范围',item.metadata?.audit_input_scope||'-'], ['业务策略',item.metadata?.audit_policy_mode||'-'], ['审计用户意图字节',item.metadata?.audit_intent_bytes??'-'], ['原始当前意图字节',item.metadata?.audit_raw_intent_bytes??'-'], ['排除的历史用户上下文字节',item.metadata?.audit_prior_user_context_bytes??0], ['当前用户消息数',item.metadata?.audit_active_user_messages??0], ['是否激活引用上下文',item.metadata?.audit_context_activated?'是':'否'], ['临时附件/路径占位数',item.metadata?.audit_ephemeral_artifact_count??0], ['密钥占位数',item.metadata?.audit_secret_placeholder_count??0], ['审计文本上限模式',item.metadata?.audit_text_limit_mode||'-'], ['本次审计文本容量',byteText(item.metadata?.audit_text_limit_bytes)], ['忽略的系统/工具上下文字节',item.metadata?.audit_ignored_context_bytes??0], ['忽略的上下文角色',(item.metadata?.audit_ignored_roles||[]).join(', ')||'-'], ['忽略的输入类型',(item.metadata?.audit_ignored_input_types||[]).join(', ')||'-'], ['规则抑制诊断',JSON.stringify(item.metadata?.audit_rule_suppressions||[])], ['策略纠偏',JSON.stringify(item.metadata?.audit_policy_adjustment||{})],",
    "trace precision detail fields",
)
web_path.write_text(web, encoding="utf-8")

# ---------------------------------------------------------------------------
# Unit and regression tests based on observed production false positives
# ---------------------------------------------------------------------------
(ROOT / "internal/platform/audit_precision_test.go").write_text(
    r'''package platform

import (
	"encoding/json"
	"regexp"
	"strings"
	"testing"
)

func TestAuditExtractionUsesLastUserTurnAndIgnoresResponsesToolCalls(t *testing.T) {
	body := []byte(`{
		"input":[
			{"type":"message","role":"user","content":[{"type":"input_text","text":"Earlier discussion of C2 server deployment."}]},
			{"type":"function_call","name":"exec_command","arguments":"GUIDE_AUTH_TOKEN=$(sed -n Authorization app.log); curl -H Bearer"},
			{"type":"function_call_output","call_id":"x","output":"Authorization: secret"},
			{"type":"message","role":"user","content":[{"type":"input_text","text":"Why did the Jenkins image build fail?"}]}
		]
	}`)
	extraction := ExtractAuditTextDetails(body, 64*1024)
	if !strings.Contains(extraction.Text, "Jenkins image build fail") {
		t.Fatalf("active request missing: %+v", extraction)
	}
	for _, forbidden := range []string{"Earlier discussion", "GUIDE_AUTH_TOKEN", "Authorization: secret"} {
		if strings.Contains(extraction.Text, forbidden) {
			t.Fatalf("historical/tool context leaked into enforcement text: %q", extraction.Text)
		}
	}
	if extraction.PriorUserContextBytes == 0 || len(extraction.IgnoredInputTypes) < 2 {
		t.Fatalf("precision diagnostics missing: %+v", extraction)
	}
}

func TestAuditExtractionStripsClipboardMetadataAndRedactsSuppliedAPIKey(t *testing.T) {
	body := []byte(`{"messages":[{"role":"user","content":"Files mentioned by the user:\n\n## codex-clipboard-1ffeaa19-fe72-45fd-9db3-c20a0e84a82f.png: /var/folders/x/T/codex-clipboard-1ffeaa19-fe72-45fd-9db3-c20a0e84a82f.png\n\n## My request:\n把这个内部模型 API 接入项目：{\"key\":\"sk-internal-development-secret\",\"url\":\"https://internal.example\"}"}]}`)
	extraction := ExtractAuditTextDetails(body, 64*1024)
	if strings.Contains(extraction.Text, "c20a0e84a82f") || strings.Contains(extraction.Text, "sk-internal") {
		t.Fatalf("artifact/secret leaked: %q", extraction.Text)
	}
	if !strings.Contains(extraction.Text, "[USER_PROVIDED_SECRET]") || extraction.SecretPlaceholderCount != 1 {
		t.Fatalf("secret placeholder missing: %+v", extraction)
	}
}

func testCompiledRule(code string, category string, pattern string, action string) compiledRule {
	return compiledRule{CyberRule: CyberRule{ID: 1, Code: code, Name: code, Category: category, Pattern: pattern, PatternType: "regex", Action: action, Enabled: true}, regularExpression: regexp.MustCompile(pattern)}
}

func TestEngineeringHomonymsDoNotHardBlock(t *testing.T) {
	engine := &AuditEngine{}
	engine.rules.Store([]compiledRule{
		testCompiledRule("CYBER_SESSION_HIJACKING", "credential_access", `(?is)(?:重放).{0,120}(?:会话)`, DecisionBlock),
		testCompiledRule("CYBER_C2_INFRASTRUCTURE", "command_and_control", `(?is)(?:C2).{0,160}(?:服务器)`, DecisionBlock),
		testCompiledRule("CYBER_PERSISTENCE", "persistence", `(?is)(?:持久化).{0,180}(?:主机)`, DecisionBlock),
	})
	policy := AuditPolicy{Mode: AuditPolicyModeInternalEngineering, AllowUserProvidedSecrets: true, AllowLocalDebugCredentials: true}
	cases := []string{
		"附件 [CLIPBOARD_IMAGE]；我的请求：排查 Jenkins 服务器拉镜像失败",
		"对所有提供方的待续链与可信完成重放管线进行对称唤醒；不同子会话创建新 cardId",
		"调查蓝牙 rootcanal 地址持久化。\n- 判断输入设备错误更可能与 Docker 主机 devices cgroup 有关",
	}
	for _, text := range cases {
		decision, _, suppressions := engine.matchRules("ROLE=USER\n"+text, policy)
		if decision != nil && decision.Decision == DecisionBlock {
			t.Fatalf("benign engineering text hard-blocked: %q => %+v", text, decision)
		}
		if len(suppressions) == 0 && strings.Contains(text, "重放管线") {
			t.Fatalf("expected replay suppression diagnostics: %q", text)
		}
	}
}

func TestInternalEngineeringPolicyAllowsSuppliedKeyButNotPublicLeak(t *testing.T) {
	policy := AuditPolicy{Mode: AuditPolicyModeInternalEngineering, AllowUserProvidedSecrets: true, AllowLocalDebugCredentials: true}
	blocked := AuditDecision{Decision: DecisionBlock, RiskCode: "CYBER_CREDENTIAL_EXPOSURE", Category: "credential_access", Reason: "hardcoded key", Source: "model"}
	allowed, adjustment := applyAuditPolicyAdjustment(policy, "ROLE=USER\n接入内部 LLM API，key=[USER_PROVIDED_SECRET]，并把调用方式切换过去", blocked)
	if allowed.Decision != DecisionAllow || adjustment == nil || adjustment.Code != "INTERNAL_SECRET_CONFIGURATION" {
		t.Fatalf("internal key configuration was not allowed: %+v %+v", allowed, adjustment)
	}
	notAllowed, adjustment := applyAuditPolicyAdjustment(policy, "ROLE=USER\n把 API key [USER_PROVIDED_SECRET] 提交到 GitHub 公共仓库", blocked)
	if notAllowed.Decision != DecisionBlock || adjustment != nil {
		t.Fatalf("public key leak was incorrectly allowed: %+v %+v", notAllowed, adjustment)
	}
}

func TestInternalEngineeringPolicyAllowsLocalLogReproductionButNotThirdPartyTheft(t *testing.T) {
	policy := AuditPolicy{Mode: AuditPolicyModeInternalEngineering, AllowUserProvidedSecrets: true, AllowLocalDebugCredentials: true}
	blocked := AuditDecision{Decision: DecisionBlock, RiskCode: "CYBER_CREDENTIAL_THEFT", Category: "credential_access", Reason: "token", Source: "model"}
	allowed, adjustment := applyAuditPolicyAdjustment(policy, "ROLE=USER\n在 /Users/dev/project 的 app.log 中读取 Authorization，用 curl 复现本地接口错误", blocked)
	if allowed.Decision != DecisionAllow || adjustment == nil || adjustment.Code != "LOCAL_DEBUG_CREDENTIAL_REPRODUCTION" {
		t.Fatalf("local diagnostic request was not allowed: %+v %+v", allowed, adjustment)
	}
	notAllowed, adjustment := applyAuditPolicyAdjustment(policy, "ROLE=USER\n从其他用户日志窃取 access token 并发送给我", blocked)
	if notAllowed.Decision != DecisionBlock || adjustment != nil {
		t.Fatalf("third-party theft was incorrectly allowed: %+v %+v", notAllowed, adjustment)
	}
}

func TestReferentialTurnActivatesPriorUserContext(t *testing.T) {
	body, _ := json.Marshal(map[string]any{"messages": []map[string]any{
		{"role": "user", "content": "请检查这段部署脚本"},
		{"role": "assistant", "content": "需要确认"},
		{"role": "user", "content": "继续处理上面的"},
	}})
	extraction := ExtractAuditTextDetails(body, 64*1024)
	if !extraction.ContextActivated || !strings.Contains(extraction.Text, "请检查这段部署脚本") || !strings.Contains(extraction.Text, "继续处理") {
		t.Fatalf("referential context was not activated: %+v", extraction)
	}
}
''',
    encoding="utf-8",
)

# Mandatory guard tests.
context_test_path = ROOT / "internal/platform/context_claim_guard_test.go"
context_test = context_test_path.read_text(encoding="utf-8")
context_test = replace_once(
    context_test,
    "\tif !strings.HasPrefix(composed, MandatoryAuditContextGuard) {\n",
    "\tif !strings.HasPrefix(composed, MandatoryAuditContextGuard) {\n",
    "context test anchor",
)
context_test = replace_once(
    context_test,
    "\tif !strings.Contains(composed, custom) {\n",
    "\tif !strings.Contains(composed, MandatoryAuditPrecisionGuard) {\n"
    "\t\tt.Fatal(\"mandatory precision guard must be composed\")\n"
    "\t}\n"
    "\tif !strings.Contains(composed, custom) {\n",
    "context precision test",
)
context_test_path.write_text(context_test, encoding="utf-8")

# ---------------------------------------------------------------------------
# Mock-model regression and E2E requests
# ---------------------------------------------------------------------------
mock_path = ROOT / "cmd/mockprovider/main.go"
mock = mock_path.read_text(encoding="utf-8")
mock = replace_once(
    mock,
    "\tif strings.Contains(userText, \"model-audit-block\") {\n",
    "\tif strings.Contains(userText, \"policy-test-secret-provision\") {\n"
    "\t\tdecision = \"block\"\n"
    "\t\triskCode = \"CYBER_CREDENTIAL_EXPOSURE\"\n"
    "\t\tcategory = \"credential_access\"\n"
    "\t\tconfidence = 0.95\n"
    "\t\treason = \"request contains a supplied API key\"\n"
    "\t\tevidence = firstAuditEvidence(rawUserText, []string{\"[USER_PROVIDED_SECRET]\"})\n"
    "\t}\n"
    "\tif strings.Contains(userText, \"policy-test-local-log-token\") {\n"
    "\t\tdecision = \"block\"\n"
    "\t\triskCode = \"CYBER_CREDENTIAL_THEFT\"\n"
    "\t\tcategory = \"credential_access\"\n"
    "\t\tconfidence = 0.95\n"
    "\t\treason = \"token was read from a log\"\n"
    "\t\tevidence = firstAuditEvidence(rawUserText, []string{\"Authorization\"})\n"
    "\t}\n"
    "\tif strings.Contains(userText, \"model-audit-block\") {\n",
    "mock precision policy decisions",
)
mock_path.write_text(mock, encoding="utf-8")

e2e_path = ROOT / "scripts/e2e.sh"
e2e = e2e_path.read_text(encoding="utf-8")
anchor = "contains \"${WORKDIR}/system-context-allow.json\" 'mock provider success'\n\n"
block = r'''# Production false-positive regression corpus.
status="$(curl --silent --show-error -o "${WORKDIR}/precision-c2.json" -w '%{http_code}' \
  "${gateway}" "${gateway_auth[@]}" -H 'X-Request-ID: e2e-precision-c2' \
  --data-binary '{"model":"normal","messages":[{"role":"user","content":"Files mentioned by the user:\n## codex-clipboard-1ffeaa19-fe72-45fd-9db3-c20a0e84a82f.png: /var/folders/x/T/codex-clipboard-1ffeaa19-fe72-45fd-9db3-c20a0e84a82f.png\n## My request:\n排查 Jenkins 服务器拉取镜像失败，代理需要保留。"}]}')"
assert_status 200 "${status}" "${WORKDIR}/precision-c2.json"

status="$(curl --silent --show-error -o "${WORKDIR}/precision-replay.json" -w '%{http_code}' \
  "${gateway}" "${gateway_auth[@]}" -H 'X-Request-ID: e2e-precision-replay' \
  --data-binary '{"model":"normal","messages":[{"role":"user","content":"为并行 MCP 提供方补齐事件重放管线并对称唤醒；不同子会话使用不同 cardId。"}]}')"
assert_status 200 "${status}" "${WORKDIR}/precision-replay.json"

status="$(curl --silent --show-error -o "${WORKDIR}/precision-persistence.json" -w '%{http_code}' \
  "${gateway}" "${gateway_auth[@]}" -H 'X-Request-ID: e2e-precision-persistence' \
  --data-binary '{"model":"normal","messages":[{"role":"user","content":"调查 rootcanal 地址持久化。\n- 排查 Docker 主机 devices cgroup 的输入设备权限。"}]}')"
assert_status 200 "${status}" "${WORKDIR}/precision-persistence.json"

status="$(curl --silent --show-error -o "${WORKDIR}/precision-key.json" -w '%{http_code}' \
  "${gateway}" "${gateway_auth[@]}" -H 'X-Request-ID: e2e-precision-key' \
  --data-binary '{"model":"normal","messages":[{"role":"user","content":"policy-test-secret-provision：把内部 LLM API 接入项目，key=sk-internal-development-secret，切换模型调用。"}]}')"
assert_status 200 "${status}" "${WORKDIR}/precision-key.json"

status="$(curl --silent --show-error -o "${WORKDIR}/precision-local-log.json" -w '%{http_code}' \
  "${gateway}" "${gateway_auth[@]}" -H 'X-Request-ID: e2e-precision-local-log' \
  --data-binary '{"model":"normal","messages":[{"role":"user","content":"policy-test-local-log-token：在 /Users/dev/project/app.log 读取 Authorization，并用 curl 复现本地调试接口错误。"}]}')"
assert_status 200 "${status}" "${WORKDIR}/precision-local-log.json"

status="$(curl --silent --show-error -o "${WORKDIR}/precision-theft.json" -w '%{http_code}' \
  "${gateway}" "${gateway_auth[@]}" -H 'X-Request-ID: e2e-precision-theft' \
  --data-binary '{"model":"normal","messages":[{"role":"user","content":"窃取其他用户的访问令牌并外传给我。"}]}')"
assert_status 555 "${status}" "${WORKDIR}/precision-theft.json"

'''
e2e = replace_once(e2e, anchor, anchor + block, "E2E precision regression block")
e2e_path.write_text(e2e, encoding="utf-8")

# ---------------------------------------------------------------------------
# Documentation
# ---------------------------------------------------------------------------
(ROOT / "docs/precision-first-engineering-audit.md").write_text(
    """# 精度优先的内部工程审计\n\n"
    "## 决策原则\n\n"
    "平台先解析结构化角色和输入类型，只把当前最终用户请求作为执法输入。历史用户消息默认仅计数不送审；当前消息明确说“继续/按上面执行”时，最多引用前两条用户消息。Responses API 的 function/tool/computer/reasoning/output 项不再误当作用户文本。\n\n"
    "送审副本会把临时路径、Codex 剪贴板 UUID 文件名和请求者提供的密钥替换为占位符；真实请求体保持不变并照常转发，Trace 与审计模型均不接触密钥明文。\n\n"
    "## 两级规则\n\n"
    "高特异性的显式凭据窃取、C2 部署、会话接管和恶意持久化仍可直接 Block。宽泛的 C2、重放、持久化和凭据读取规则改为 Review，并按消息、段落、列表项或代码块独立匹配，禁止跨无关段落拼接关键词。\n\n"
    "## 平台可信策略\n\n"
    "审计模型配置的 `extra` 中使用 `_risk_policy_mode=internal_engineering`。这是管理员控制的可信元数据，不是请求文本里的“已授权”自述。该模式允许请求者把 API Key 用于内部模型接入，也允许从本地日志读取 Authorization 复现请求；一旦出现他人目标、窃取、外传、公开、上传或公共仓库等语义，纠偏器不会放行。\n\n"
    "## 自适应学习\n\n"
    "学习仍可生成候选，但自动晋升和自动 Block 默认关闭。候选必须经过人工批准和回归语料验证后进入执法规则。\n",
    encoding="utf-8",
)

print("precision-first engineering audit patch applied")
