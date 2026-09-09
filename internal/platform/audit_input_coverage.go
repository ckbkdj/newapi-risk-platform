package platform

import (
	"regexp"
	"strings"
)

// Continuation language need not be at the beginning or shorter than 12 runes.
// This is bounded selection, not proof of safety: selected but unavailable or
// oversized context produces an explicit coverage failure.
var naturalContinuationPattern = regexp.MustCompile(`(?i)(?:继续|补齐|剩余|未完成|最终版本|前面讨论|上面讨论|前述|上述|按(?:照)?(?:上面|前面|之前)|照(?:刚才|之前)|修复(?:它|这个)|完善(?:它|这个)|完成(?:它|这个)|\b(?:continue|remaining|finish it|finish the|complete it|complete the|implement the (?:plan|proposal)|as discussed|as above|previous (?:plan|steps|task)|final version|go ahead|do it|proceed)\b)`)

// Only an explicitly dependent standalone request without any local context
// is failed for missing history. Merely mentioning a final version in a full
// task specification is not evidence of missing input.
var standaloneContinuationPattern = regexp.MustCompile(`(?i)^\s*(?:请\s*)?(?:继续(?:处理)?(?:[。！!\s]|$)|补齐剩余|按(?:照)?(?:之前|前面|上面)|照做|执行上述|修复它|处理它|完成它|(?:continue|go ahead|do it|proceed|finish it|complete it)(?:[.!?\s]|$))`)

func auditActiveTurnStart(units []auditUserUnit) int {
	if len(units) == 0 {
		return 0
	}
	start := len(units) - 1
	for start > 0 && units[start-1].Position+1 == units[start].Position {
		start--
	}
	return start
}

func (r *AuditTextExtraction) addCoverageIssue(issue string) {
	r.CoverageStatus = "incomplete"
	for _, existing := range r.CoverageIssues {
		if existing == issue {
			return
		}
	}
	r.CoverageIssues = append(r.CoverageIssues, issue)
}

func auditContainsUnsupportedContent(value any) bool {
	switch v := value.(type) {
	case []any:
		for _, child := range v {
			if auditContainsUnsupportedContent(child) {
				return true
			}
		}
	case map[string]any:
		if kind, _ := v["type"].(string); kind != "" {
			switch strings.ToLower(strings.TrimSpace(kind)) {
			case "text", "input_text", "output_text":
			default:
				return true
			}
		}
		for key, child := range v {
			switch strings.ToLower(key) {
			case "image_url", "input_audio", "audio", "video", "file", "file_id", "file_data":
				return true
			case "content", "input":
				if auditContainsUnsupportedContent(child) {
					return true
				}
			}
		}
	}
	return false
}

func auditIncompleteInputDecision(failClosed bool, issues []string) AuditDecision {
	reason := "audit input coverage is incomplete: " + strings.Join(issues, ", ")
	if failClosed {
		return AuditDecision{Decision: DecisionBlock, RiskCode: "AUDIT_INPUT_COVERAGE_INCOMPLETE", Category: "audit_infrastructure", Reason: reason, Source: "platform"}
	}
	// An explicitly configured fail-open is not a successful safety assessment.
	return AuditDecision{Decision: DecisionAllow, Category: "audit_infrastructure", Reason: reason, Source: "fail_open"}
}
