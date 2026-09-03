package platform

import (
	"encoding/json"
	"sort"
	"strings"
)

const (
	auditInputScopeEndUserIntent = "end_user_intent_only"
	auditInputScopeContextOnly   = "context_only"
	auditInputScopeRawFallback   = "raw_request_fallback"
)

type AuditTextExtraction struct {
	Text                string
	Scope               string
	IntentBytes         int
	IgnoredContextBytes int
	IgnoredRoles        []string
}

type auditTextCollector struct {
	maximumBytes        int
	builder             strings.Builder
	ignoredContextBytes int
	ignoredRoles        map[string]struct{}
}

func ExtractAuditTextDetails(body []byte, maximumBytes int) AuditTextExtraction {
	if maximumBytes <= 0 {
		maximumBytes = 256 * 1024
	}
	var root any
	if err := json.Unmarshal(body, &root); err != nil {
		if len(body) > maximumBytes {
			body = body[:maximumBytes]
		}
		text := strings.ToValidUTF8(string(body), "�")
		return AuditTextExtraction{
			Text:        text,
			Scope:       auditInputScopeRawFallback,
			IntentBytes: len(text),
		}
	}
	collector := &auditTextCollector{
		maximumBytes: maximumBytes,
		ignoredRoles: map[string]struct{}{},
	}
	collector.collectRoot(root)
	roles := make([]string, 0, len(collector.ignoredRoles))
	for role := range collector.ignoredRoles {
		roles = append(roles, role)
	}
	sort.Strings(roles)
	text := collector.builder.String()
	scope := auditInputScopeEndUserIntent
	if strings.TrimSpace(text) == "" && collector.ignoredContextBytes > 0 {
		scope = auditInputScopeContextOnly
	}
	return AuditTextExtraction{
		Text:                text,
		Scope:               scope,
		IntentBytes:         len(text),
		IgnoredContextBytes: collector.ignoredContextBytes,
		IgnoredRoles:        roles,
	}
}

func (collector *auditTextCollector) collectRoot(value any) {
	switch typed := value.(type) {
	case string:
		collector.appendUserBlock("USER", typed)
	case []any:
		collector.collectInput(typed)
	case map[string]any:
		_, hasMessages := typed["messages"]
		_, hasInput := typed["input"]
		_, hasPrompt := typed["prompt"]
		_, hasQuery := typed["query"]
		keys := sortedMapKeys(typed)
		for _, key := range keys {
			child := typed[key]
			switch strings.ToLower(key) {
			case "messages":
				collector.collectMessages(child)
			case "input":
				collector.collectInput(child)
			case "prompt", "query":
				collector.appendUserBlock("USER", child)
			case "content", "text":
				if !hasMessages && !hasInput && !hasPrompt && !hasQuery {
					collector.appendUserBlock("USER", child)
				}
			case "instructions", "system", "system_instruction", "developer", "tools", "functions", "tool_choice", "response_format":
				collector.ignoreContext(strings.ToUpper(key), child)
			}
		}
	}
}

func (collector *auditTextCollector) collectMessages(value any) {
	items, ok := value.([]any)
	if !ok {
		collector.collectInput(value)
		return
	}
	for _, item := range items {
		object, ok := item.(map[string]any)
		if !ok {
			collector.appendUserBlock("USER", item)
			continue
		}
		collector.collectRoleObject(object)
	}
}

func (collector *auditTextCollector) collectInput(value any) {
	switch typed := value.(type) {
	case string:
		collector.appendUserBlock("USER", typed)
	case []any:
		for _, item := range typed {
			if object, ok := item.(map[string]any); ok {
				if _, hasRole := object["role"]; hasRole {
					collector.collectRoleObject(object)
					continue
				}
				if kind, _ := object["type"].(string); isIgnoredContentType(kind) {
					collector.ignoreContext(strings.ToUpper(kind), object)
					continue
				}
			}
			collector.appendUserBlock("USER", item)
		}
	case map[string]any:
		if _, hasRole := typed["role"]; hasRole {
			collector.collectRoleObject(typed)
			return
		}
		collector.appendUserBlock("USER", typed)
	default:
		collector.appendUserBlock("USER", typed)
	}
}

func (collector *auditTextCollector) collectRoleObject(object map[string]any) {
	role, _ := object["role"].(string)
	normalizedRole := strings.ToLower(strings.TrimSpace(role))
	if !isEndUserRole(normalizedRole) {
		if normalizedRole == "" {
			normalizedRole = "unknown_role"
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
	collector.appendUserBlock("USER", content)
}

func (collector *auditTextCollector) appendUserBlock(role string, value any) {
	if collector.builder.Len() >= collector.maximumBytes {
		return
	}
	remaining := collector.maximumBytes - collector.builder.Len()
	text := eligibleText(value, remaining)
	if strings.TrimSpace(text) == "" {
		return
	}
	collector.appendLine("ROLE=" + role)
	collector.appendLine(text)
}

func (collector *auditTextCollector) appendLine(value string) {
	value = strings.ToValidUTF8(value, "�")
	if value == "" || collector.builder.Len() >= collector.maximumBytes {
		return
	}
	separator := 0
	if collector.builder.Len() > 0 {
		separator = 1
	}
	remaining := collector.maximumBytes - collector.builder.Len() - separator
	if remaining <= 0 {
		return
	}
	if len(value) > remaining {
		value = strings.ToValidUTF8(value[:remaining], "�")
	}
	if collector.builder.Len() > 0 {
		collector.builder.WriteByte('\n')
	}
	collector.builder.WriteString(value)
}

func (collector *auditTextCollector) ignoreContext(role string, value any) {
	collector.ignoredContextBytes += countContextTextBytes(value, "")
	role = strings.TrimSpace(role)
	if role != "" {
		collector.ignoredRoles[role] = struct{}{}
	}
}

func eligibleText(value any, maximumBytes int) string {
	if maximumBytes <= 0 {
		return ""
	}
	var builder strings.Builder
	var walk func(any, string)
	appendValue := func(text string) {
		text = strings.ToValidUTF8(text, "�")
		if text == "" || builder.Len() >= maximumBytes {
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
		if len(text) > remaining {
			text = strings.ToValidUTF8(text[:remaining], "�")
		}
		if builder.Len() > 0 {
			builder.WriteByte('\n')
		}
		builder.WriteString(text)
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
			if kind, _ := typed["type"].(string); isIgnoredContentType(kind) {
				return
			}
			for _, childKey := range sortedMapKeys(typed) {
				if strings.EqualFold(childKey, "role") || strings.EqualFold(childKey, "type") || strings.EqualFold(childKey, "name") {
					continue
				}
				if isEligibleTextKey(childKey) || childKey == "content" || childKey == "input" {
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
