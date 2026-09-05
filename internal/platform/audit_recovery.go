package platform

import (
	"context"
	"errors"
	"regexp"
)

type auditOriginalTextBytesKey struct{}
type auditResumeChunksKey struct{}

var auditInputLowerBoundPattern = regexp.MustCompile(`(?i)at\s+least\s+[0-9][0-9,]*\s+input\s+tokens`)
var auditOutputTokenCountPattern = regexp.MustCompile(`(?i)requested\s+([0-9][0-9,]*)\s+output\s+tokens`)

func auditObservedOutputTokens(message string) int {
	// Only add a completion budget to a known INPUT count, never to a count
	// parsed from a provider's combined "total tokens" message.
	if !auditRequestedTokenPatterns[0].MatchString(message) && !auditRequestedTokenPatterns[1].MatchString(message) {
		return 0
	}
	if match := auditOutputTokenCountPattern.FindStringSubmatch(message); len(match) == 2 {
		return parseAuditTokenNumber(match[1])
	}
	return 0
}

func observeAuditContextError(metadata auditCallMetadata, err error) auditCallMetadata {
	var callError *AuditModelCallError
	if errors.As(err, &callError) && callError.RequestedTokens >= metadata.RequestedTokens {
		metadata.ContextWindowTokens = callError.MaxContextTokens
		metadata.RequestedTokens = callError.RequestedTokens
		metadata.RequestedTokensLowerBound = callError.RequestedTokensLowerBound
		metadata.ObservedOutputTokens = callError.ObservedOutputTokens
	}
	return metadata
}

func (e *AuditEngine) recoveryAuditChunkBytes(ctx context.Context, textBytes int, err error) int {
	maxTokens, inputTokens := auditContextTokenCounts(err)
	outputTokens := auditOutputPlanFromContext(ctx).MaxTokens
	var observed *AuditModelCallError
	if errors.As(err, &observed) && observed.OutputMaxTokens > outputTokens {
		outputTokens = observed.OutputMaxTokens
	}
	size := e.auditChunkBytesForOutput(textBytes, inputTokens, maxTokens, outputTokens)
	var callError *AuditModelCallError
	if errors.As(err, &callError) && callError.RequestedTokensLowerBound {
		// "At least" is a lower bound (often from early-stop tokenization), NOT
		// the actual prompt size. A byte/token ratio based on it is unsound.
		capBytes := e.fallbackChunkBytes
		if capBytes <= 0 {
			capBytes = 192 * 1024
		}
		if budget := maxTokens - outputTokens - 2048; budget > 0 && budget < capBytes {
			capBytes = budget
		}
		if size > capBytes {
			size = capBytes
		}
	}
	if size < 1 {
		size = 1
	}
	return size
}

func auditDiagnosticsFromError(plan auditOutputPlan, err error) auditOutputDiagnostics {
	result := auditOutputDiagnostics{Mode: plan.Mode, MaxTokens: plan.MaxTokens, Failed: true}
	var callError *AuditModelCallError
	if !errors.As(err, &callError) {
		return result
	}
	if callError.OutputMode != "" {
		result.Mode = callError.OutputMode
	}
	if callError.OutputMaxTokens > 0 {
		result.MaxTokens = callError.OutputMaxTokens
	}
	// These fields are attached at the failing HTTP call. Never fall back to
	// shared lastFailure: it may belong to a different chunk/response.
	result.FinishReason = callError.FinishReason
	result.ResponseContentBytes = callError.ResponseContentBytes
	result.ResponseSource = callError.ResponseSource
	result.ResponsePreview = sanitizeAuditResponsePreview(callError.ResponsePreview)
	result.ResponseID = callError.ResponseID
	return result
}

func auditErrorNeedsOutputRecovery(err error) bool {
	class, _, _ := auditModelErrorDetails(err)
	switch class {
	case "response_format", "empty_response", "invalid_json", "output_truncated", "structured_output_unsupported", "invalid_decision":
		return true
	default:
		return false
	}
}

func recordAuditDecisionMetadata(metadata map[string]any, result AuditResult) {
	if metadata == nil {
		return
	}
	metadata["audit_effective_decision"] = result.Decision
	metadata["audit_input_contract"] = auditInputContractVersion
	metadata["audit_embedded_reference_count"] = result.AuditEmbeddedReferenceCount
	metadata["audit_completed"] = result.ErrorClass == "" && result.Source != "platform" && result.Source != "fail_open"
	metadata["audit_semantic_reviews_truncated"] = result.AuditSemanticReviewCount > len(result.AuditSemanticReviews)
	metadata["audit_http_calls"] = result.AuditHTTPCalls
	metadata["audit_semantic_review_calls"] = result.AuditSemanticReviewCalls
	metadata["audit_semantic_review_count"] = result.AuditSemanticReviewCount
	if len(result.AuditSemanticReviews) > 0 {
		metadata["audit_semantic_reviews"] = result.AuditSemanticReviews
	}
	if result.SemanticReview != nil {
		metadata["audit_semantic_review_status"] = result.SemanticReview.Status
	} else if result.AuditSemanticReviewCount > 0 {
		if result.ErrorClass != "" {
			metadata["audit_semantic_review_status"] = "error"
		} else {
			metadata["audit_semantic_review_status"] = "see_attempts"
		}
	}
	if result.RequestEvidence != "" {
		metadata["audit_current_request_evidence"] = result.RequestEvidence
	}
	if result.EvidenceRelation != "" {
		metadata["audit_evidence_relation"] = result.EvidenceRelation
	}
	if result.HarmType != "" {
		metadata["audit_harm_type"] = result.HarmType
	}
	raw := result.AuditModelDecision
	if raw == nil {
		return
	}
	metadata["audit_model_decision"] = raw.Decision
	metadata["audit_model_risk_code"] = raw.RiskCode
	metadata["audit_model_confidence"] = raw.Confidence
	metadata["audit_model_original_reason"] = truncateString(raw.Reason, auditDiagnosticTextLimit)
	if raw.EvidenceVerified {
		metadata["audit_model_original_evidence"] = truncateString(raw.Evidence, 1200)
	}
	if raw.Decision != result.Decision {
		metadata["audit_decision_adjusted"] = true
	}
}
