package platform

import (
	"encoding/json"
	"strings"
)

// recordUpstreamFailureMetadata records only bounded, sanitized diagnostics.
// It never stores the full upstream response body or stream.
func recordUpstreamFailureMetadata(
	trace *TraceEvent,
	riskCode string,
	upstreamStatus int,
	evidence []byte,
	stage string,
) {
	if trace == nil {
		return
	}
	if trace.Metadata == nil {
		trace.Metadata = map[string]any{}
	}
	stage = strings.TrimSpace(stage)
	if stage != "" {
		trace.Metadata["failure_stage"] = stage
	}
	if strings.TrimSpace(riskCode) != "" {
		trace.Metadata["upstream_error_class"] = strings.TrimSpace(riskCode)
	}
	if upstreamStatus > 0 {
		trace.Metadata["upstream_error_http_status"] = upstreamStatus
	}
	if reason := extractUpstreamFailureReason(evidence); reason != "" {
		trace.Metadata["upstream_error_reason"] = reason
	}
}

func extractUpstreamFailureReason(evidence []byte) string {
	if len(evidence) == 0 {
		return ""
	}
	text := strings.ToValidUTF8(string(evidence), "")
	for _, rawLine := range strings.Split(text, "\n") {
		line := strings.TrimSpace(rawLine)
		if !strings.HasPrefix(line, "data:") {
			continue
		}
		data := strings.TrimSpace(strings.TrimPrefix(line, "data:"))
		if data == "" || data == "[DONE]" {
			continue
		}
		if reason := jsonFailureReason([]byte(data)); reason != "" {
			return reason
		}
	}
	if reason := jsonFailureReason(evidence); reason != "" {
		return reason
	}
	return sanitizeAuditDiagnostic(text)
}

func jsonFailureReason(body []byte) string {
	var payload map[string]any
	if json.Unmarshal(body, &payload) != nil {
		return ""
	}
	for _, path := range [][]string{
		{"error", "message"},
		{"error", "detail"},
		{"message"},
		{"detail"},
	} {
		value := any(payload)
		for _, key := range path {
			object, ok := value.(map[string]any)
			if !ok {
				value = nil
				break
			}
			value = object[key]
		}
		if text, ok := value.(string); ok && strings.TrimSpace(text) != "" {
			return sanitizeAuditDiagnostic(text)
		}
	}
	if value, ok := payload["error"].(string); ok && strings.TrimSpace(value) != "" {
		return sanitizeAuditDiagnostic(value)
	}
	return ""
}
