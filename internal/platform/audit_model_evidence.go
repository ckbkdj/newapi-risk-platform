package platform

import (
	"fmt"
	"strings"
	"unicode/utf8"
)

const (
	auditModelEvidenceMaxRunes = 120
	auditModelEvidenceMaxBytes = 512
)

// validateAuditDecisionEvidence makes model blocks explainable and prevents a
// hallucinated explanation from being persisted as if it came from the user's
// request. Every block/review must quote a contiguous piece of the audited
// request. The stored quote and context are always redacted.
func validateAuditDecisionEvidence(decision AuditDecision, sourceText string) (AuditDecision, error) {
	if decision.Decision == DecisionAllow {
		decision.Evidence = ""
		decision.EvidenceContext = ""
		decision.EvidenceVerified = false
		decision.EvidenceMatchMode = ""
		decision.EvidenceChunkIndex = 0
		decision.EvidenceChunkCount = 0
		return decision, nil
	}
	if decision.Decision != DecisionBlock && decision.Decision != DecisionReview {
		return decision, nil
	}

	candidate := normalizeAuditEvidenceQuote(decision.Evidence)
	if candidate == "" {
		return AuditDecision{}, newAuditModelCallError(
			"invalid_evidence",
			0,
			"audit model returned block/review without an exact request evidence quote",
			nil,
		)
	}
	if len(candidate) > auditModelEvidenceMaxBytes || utf8.RuneCountInString(candidate) > auditModelEvidenceMaxRunes {
		return AuditDecision{}, newAuditModelCallError(
			"invalid_evidence",
			0,
			fmt.Sprintf("audit model evidence exceeds the %d-character safety limit", auditModelEvidenceMaxRunes),
			nil,
		)
	}

	start := strings.Index(sourceText, candidate)
	matchMode := "exact"
	if start < 0 && isASCIIText(candidate) {
		start = indexASCIIEqualFold(sourceText, candidate)
		if start >= 0 {
			matchMode = "ascii_case_insensitive"
		}
	}
	if start < 0 {
		return AuditDecision{}, newAuditModelCallError(
			"invalid_evidence",
			0,
			"audit model block/review evidence was not found in the audited request",
			nil,
		)
	}
	end := start + len(candidate)
	if end > len(sourceText) {
		return AuditDecision{}, newAuditModelCallError(
			"invalid_evidence",
			0,
			"audit model evidence location is outside the audited request",
			nil,
		)
	}

	decision.Evidence = redactCyberTraceText(sourceText[start:end])
	decision.EvidenceContext = cyberRuleContext(sourceText, start, end)
	decision.EvidenceVerified = true
	decision.EvidenceMatchMode = matchMode
	return decision, nil
}

func normalizeAuditEvidenceQuote(value string) string {
	value = strings.TrimSpace(strings.ToValidUTF8(value, ""))
	for {
		changed := false
		for _, pair := range [][2]string{
			{"```", "```"},
			{"`", "`"},
			{"\"", "\""},
			{"'", "'"},
			{"“", "”"},
			{"‘", "’"},
			{"《", "》"},
		} {
			if strings.HasPrefix(value, pair[0]) && strings.HasSuffix(value, pair[1]) && len(value) >= len(pair[0])+len(pair[1]) {
				value = strings.TrimSpace(value[len(pair[0]) : len(value)-len(pair[1])])
				changed = true
				break
			}
		}
		if !changed {
			break
		}
	}
	value = strings.TrimPrefix(value, "…")
	value = strings.TrimSuffix(value, "…")
	value = strings.TrimPrefix(value, "...")
	value = strings.TrimSuffix(value, "...")
	return strings.TrimSpace(value)
}

func indexASCIIEqualFold(haystack string, needle string) int {
	if needle == "" || len(needle) > len(haystack) || !isASCIIText(needle) {
		return -1
	}
	for start := 0; start+len(needle) <= len(haystack); start++ {
		matched := true
		for index := range needle {
			left := haystack[start+index]
			right := needle[index]
			if left >= 'A' && left <= 'Z' {
				left += 'a' - 'A'
			}
			if right >= 'A' && right <= 'Z' {
				right += 'a' - 'A'
			}
			if left != right {
				matched = false
				break
			}
		}
		if matched {
			return start
		}
	}
	return -1
}

func auditModelUserGuidance(category string) string {
	return cyberRuleUserGuidance(CyberRule{Category: strings.TrimSpace(category)})
}
