package platform

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strings"
)

const auditDiagnosticTextLimit = 700

type AuditModelCallError struct {
	Class      string
	HTTPStatus int
	Message    string
	Cause      error
}

func (e *AuditModelCallError) Error() string {
	if e == nil {
		return ""
	}
	message := strings.TrimSpace(e.Message)
	if message == "" {
		message = "audit model call failed"
	}
	if e.Cause != nil {
		return message + ": " + e.Cause.Error()
	}
	return message
}

func (e *AuditModelCallError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Cause
}

func newAuditModelCallError(class string, httpStatus int, message string, cause error) error {
	return &AuditModelCallError{
		Class:      strings.TrimSpace(class),
		HTTPStatus: httpStatus,
		Message:    sanitizeAuditDiagnostic(message),
		Cause:      cause,
	}
}

func classifyAuditTransportError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return newAuditModelCallError("timeout", 0, "audit model request timed out", nil)
	}
	var networkError net.Error
	if errors.As(err, &networkError) && networkError.Timeout() {
		return newAuditModelCallError("timeout", 0, "audit model request timed out", nil)
	}
	return newAuditModelCallError("connection", 0, "audit model connection failed", err)
}

func auditHTTPStatusError(status int, body []byte) error {
	class := "http_status"
	switch {
	case status == 401 || status == 403:
		class = "authentication"
	case status == 404:
		class = "endpoint_or_model_not_found"
	case status == 408:
		class = "timeout"
	case status == 429:
		class = "rate_limited"
	case status >= 500:
		class = "audit_server_error"
	}
	message := fmt.Sprintf("audit model returned HTTP %d", status)
	if detail := auditHTTPErrorDetail(body); detail != "" {
		message += ": " + detail
	}
	return newAuditModelCallError(class, status, message, nil)
}

func auditHTTPErrorDetail(body []byte) string {
	if len(body) == 0 {
		return ""
	}
	var envelope map[string]any
	if json.Unmarshal(body, &envelope) == nil {
		for _, path := range [][]string{{"error", "message"}, {"error", "detail"}, {"message"}, {"detail"}} {
			value := any(envelope)
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
	}
	return sanitizeAuditDiagnostic(string(body))
}

func auditModelErrorDetails(err error) (class string, httpStatus int, reason string) {
	if err == nil {
		return "", 0, ""
	}
	var callError *AuditModelCallError
	if errors.As(err, &callError) {
		class = strings.TrimSpace(callError.Class)
		httpStatus = callError.HTTPStatus
		reason = sanitizeAuditDiagnostic(callError.Error())
		if class == "" {
			class = "unknown"
		}
		return class, httpStatus, reason
	}
	return "unknown", 0, sanitizeAuditDiagnostic(err.Error())
}

func sanitizeAuditDiagnostic(value string) string {
	value = sanitizeAdaptiveProviderError([]byte(value))
	value = strings.Join(strings.Fields(value), " ")
	return truncateString(value, auditDiagnosticTextLimit)
}

func parseAuditModelResponseContent(content string) (modelAuditResponse, error) {
	content = strings.TrimSpace(strings.ToValidUTF8(content, ""))
	if content == "" {
		return modelAuditResponse{}, newAuditModelCallError("empty_response", 0, "audit model returned empty content", nil)
	}

	var direct modelAuditResponse
	if json.Unmarshal([]byte(content), &direct) == nil && strings.TrimSpace(direct.Decision) != "" {
		return validateAuditModelResponse(direct)
	}

	candidates := balancedJSONObjects(content)
	for index := len(candidates) - 1; index >= 0; index-- {
		var candidate modelAuditResponse
		if json.Unmarshal([]byte(candidates[index]), &candidate) != nil || strings.TrimSpace(candidate.Decision) == "" {
			continue
		}
		return validateAuditModelResponse(candidate)
	}
	return modelAuditResponse{}, newAuditModelCallError(
		"invalid_json",
		0,
		"audit model output did not contain a valid policy JSON object",
		nil,
	)
}

func validateAuditModelResponse(result modelAuditResponse) (modelAuditResponse, error) {
	result.Decision = strings.ToLower(strings.TrimSpace(result.Decision))
	switch result.Decision {
	case DecisionAllow, DecisionBlock, DecisionReview:
	default:
		return modelAuditResponse{}, newAuditModelCallError(
			"invalid_decision",
			0,
			fmt.Sprintf("audit model returned invalid decision %q", result.Decision),
			nil,
		)
	}
	result.Confidence = clampConfidence(result.Confidence)
	result.RiskCode = strings.TrimSpace(result.RiskCode)
	result.Category = strings.TrimSpace(result.Category)
	result.Reason = truncateString(strings.TrimSpace(result.Reason), 500)
	return result, nil
}

func balancedJSONObjects(value string) []string {
	objects := make([]string, 0, 4)
	start := -1
	depth := 0
	inString := false
	escaped := false
	for index, character := range value {
		if start < 0 {
			if character == '{' {
				start = index
				depth = 1
				inString = false
				escaped = false
			}
			continue
		}
		if inString {
			if escaped {
				escaped = false
				continue
			}
			if character == '\\' {
				escaped = true
				continue
			}
			if character == '"' {
				inString = false
			}
			continue
		}
		switch character {
		case '"':
			inString = true
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				objects = append(objects, value[start:index+1])
				start = -1
			}
		}
	}
	return objects
}

func traceFailureReason(riskCode string, upstreamStatus int, metadata map[string]any) string {
	if metadata != nil {
		if reason, ok := metadata["audit_reason"].(string); ok && strings.TrimSpace(reason) != "" {
			return truncateString(reason, auditDiagnosticTextLimit)
		}
		if reason, ok := metadata["error_reason"].(string); ok && strings.TrimSpace(reason) != "" {
			return truncateString(reason, auditDiagnosticTextLimit)
		}
	}
	switch riskCode {
	case "ROUTE_NOT_FOUND":
		return "渠道路由不存在或已禁用"
	case "GATEWAY_AUTH_FAILED":
		return "New API 渠道 Key 校验失败"
	case "RATE_LIMITED":
		return "请求触发网关限流"
	case "GATEWAY_OVERLOADED":
		return "网关全局并发已满"
	case "REQUEST_TOO_LARGE":
		return "请求体超过网关限制"
	case "AUDIT_MODEL_UNAVAILABLE":
		return "没有可用的审计模型"
	case "AUDIT_MODEL_ERROR":
		return "审计模型调用或返回格式异常"
	case "AUDIT_REVIEW_REQUIRED":
		return "审计模型要求进一步复核"
	case "ROUTE_CONCURRENCY_LIMITED":
		return "该渠道路由并发已满"
	case "GATEWAY_CONFIG_ERROR":
		return "渠道路由配置无效"
	case "UPSTREAM_CONNECTION_ERROR":
		return "无法连接真实上游模型"
	case "UPSTREAM_TIMEOUT":
		return "真实上游模型请求超时"
	case "UPSTREAM_MODEL_ERROR":
		if upstreamStatus > 0 {
			return fmt.Sprintf("真实上游模型返回 HTTP %d", upstreamStatus)
		}
		return "真实上游模型返回错误"
	case "UPSTREAM_STREAM_ERROR":
		return "真实上游流式响应中断或返回错误事件"
	}
	if strings.HasPrefix(riskCode, "CYBER_") {
		return "请求命中 Cyber 风控规则或语义审计"
	}
	return strings.TrimSpace(riskCode)
}
