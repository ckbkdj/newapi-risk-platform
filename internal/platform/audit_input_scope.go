package platform

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
	myRequestMarkerPattern   = regexp.MustCompile(`(?im)^\s*##\s*(?:my|user)\s+request\s*:\s*`)
	myRequestZHPattern       = regexp.MustCompile(`(?m)^\s*##\s*我的请求\s*[：:]\s*`)
	fileHeaderPattern        = regexp.MustCompile(`(?im)^\s*files mentioned by the user\s*:\s*$`)
	clipboardArtifactPattern = regexp.MustCompile(`(?i)codex-clipboard-[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}\.(?:png|jpe?g|webp|gif|bmp)`)
	temporaryPathPattern     = regexp.MustCompile(`(?i)(?:/private)?/var/folders/[^\s"']+|/tmp/[^\s"']+|[a-z]:\\[^\r\n"']*\\(?:temp|tmp)\\[^\s"']+`)
	bareUUIDInPathPattern    = regexp.MustCompile(`(?i)([/\\._-])[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}(\.[a-z0-9]{1,8}\b)`)

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
	// A user-controlled "## My request" heading is not a trusted boundary.
	// Preserve preceding material for intent/adoption assessment; never let a
	// fabricated heading hide a harmful prefix or erase quoted context.
	value = fileHeaderPattern.ReplaceAllString(value, "[ATTACHMENT_METADATA]")

	artifacts := 0
	for _, expression := range []*regexp.Regexp{clipboardArtifactPattern, temporaryPathPattern, bareUUIDInPathPattern} {
		matches := expression.FindAllStringIndex(value, -1)
		artifacts += len(matches)
		replacement := "[TEMP_PATH]"
		if expression == clipboardArtifactPattern {
			replacement = "[CLIPBOARD_IMAGE]"
		} else if expression == bareUUIDInPathPattern {
			replacement = "${1}[ARTIFACT_ID]${2}"
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
