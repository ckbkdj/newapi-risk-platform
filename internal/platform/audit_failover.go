package platform

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

const (
	maxAuditFallbackProfiles = 8
	maxAuditRetryCount       = 5
	maxAuditTotalAttempts    = 24
)

type auditFailoverMetadata struct {
	ModelInputs         []AuditModelInputDiagnostics
	HTTPCalls           int
	HTTPBudget          int
	ReviewBudget        int
	SemanticReviewCalls int
	SemanticReviewCount int
	SemanticReviews     []AuditSemanticReview
	CallMetadata        auditCallMetadata
	AttemptCount        int
	ModelRetryCount     int
	FallbackCount       int
	Attempts            []AuditAttempt
	OutputDiagnostics   auditOutputDiagnostics
}

func (e *AuditEngine) callModelWithFailover(
	ctx context.Context,
	root AuditProfile,
	text string,
) (AuditDecision, AuditProfile, auditFailoverMetadata, error) {
	ctx, semanticState := withAuditSemanticState(ctx)
	metadata := auditFailoverMetadata{
		Attempts: make([]AuditAttempt, 0, 1+root.RetryCount),
	}
	profiles := []AuditProfile{root}
	seen := map[int64]struct{}{root.ID: {}}
	for _, fallbackID := range root.FallbackProfileIDs {
		if fallbackID <= 0 || len(profiles) >= maxAuditFallbackProfiles+1 {
			continue
		}
		if _, exists := seen[fallbackID]; exists {
			continue
		}
		seen[fallbackID] = struct{}{}
		id := fallbackID
		profile, err := e.getAuditProfile(ctx, &id)
		if err != nil || !profile.Enabled {
			continue
		}
		profiles = append(profiles, profile)
	}

	usedProfile := root
	var lastErr error
	for profileIndex, profile := range profiles {
		if ctx.Err() != nil {
			return AuditDecision{}, usedProfile, semanticState.metadata(metadata), ctx.Err()
		}
		if metadata.AttemptCount >= maxAuditTotalAttempts {
			lastErr = newAuditModelCallError(
				"retry_budget_exhausted",
				0,
				fmt.Sprintf("audit retry/fallback budget exhausted after %d model calls", metadata.AttemptCount),
				nil,
			)
			break
		}
		if profileIndex > 0 {
			metadata.FallbackCount++
		}
		if cyberDenyActive(ctx) {
			// Fallback can repair infrastructure, never relax the root's required
			// panel/verifier policy or recover by bypassing a failed verification.
			extra := auditProfileExtra(profile)
			if extra == nil {
				extra = map[string]any{}
			}
			for _, key := range []string{"_risk_fusion_profile_ids", "_risk_fusion_adjudicator_profile_id", "_risk_verifier_profile_id"} {
				delete(extra, key)
				if v, ok := auditProfileExtra(root)[key]; ok {
					extra[key] = v
				}
			}
			profile.Extra, _ = json.Marshal(extra)
			profile = cyberDenyProfile(profile)
		}
		usedProfile = profile
		retries := profile.RetryCount
		if retries < 0 {
			retries = 0
		}
		if retries > maxAuditRetryCount {
			retries = maxAuditRetryCount
		}

		formatAttempt := 0
		var profileChunks auditCallMetadata
		for attempt := 0; attempt <= retries; attempt++ {
			if ctx.Err() != nil {
				return AuditDecision{}, usedProfile, semanticState.metadata(metadata), ctx.Err()
			}
			if metadata.AttemptCount >= maxAuditTotalAttempts {
				lastErr = newAuditModelCallError(
					"retry_budget_exhausted",
					0,
					fmt.Sprintf("audit retry/fallback budget exhausted after %d model calls", metadata.AttemptCount),
					nil,
				)
				break
			}

			outputPlan := e.auditOutputPlan(profile, formatAttempt)
			attemptContext, outputState := withAuditOutputAttempt(ctx, outputPlan)
			attemptContext = context.WithValue(attemptContext, auditResumeChunksKey{}, profileChunks)
			decision, callMetadata, err := e.callModel(attemptContext, profile, text)
			profileChunks = callMetadata
			outputDiagnostics := outputState.snapshot(false)
			if err != nil {
				// A previous HTTP 400 in another chunk is not the response to a
				// later transport timeout. Correlate diagnostics to this error.
				outputDiagnostics = auditDiagnosticsFromError(outputPlan, err)
			}
			metadata.OutputDiagnostics = outputDiagnostics
			metadata.CallMetadata = mergeAuditCallMetadata(metadata.CallMetadata, callMetadata)
			metadata.AttemptCount++
			attemptRecord := AuditAttempt{
				ProfileID:            profile.ID,
				ProfileName:          profile.Name,
				Model:                profile.Model,
				Attempt:              attempt + 1,
				Success:              err == nil,
				OutputMode:           outputDiagnostics.Mode,
				OutputMaxTokens:      outputDiagnostics.MaxTokens,
				FinishReason:         outputDiagnostics.FinishReason,
				ResponseContentBytes: outputDiagnostics.ResponseContentBytes,
				ResponseSource:       outputDiagnostics.ResponseSource,
				ResponsePreview:      outputDiagnostics.ResponsePreview,
				ResponseID:           outputDiagnostics.ResponseID,
			}
			if err == nil {
				attemptRecord.ConfidenceKind, attemptRecord.ConfidenceLabel, attemptRecord.OutputNormalizations = decision.ConfidenceKind, decision.ConfidenceLabel, decision.OutputNormalizations
				attemptRecord.Decision = decision.Decision
				attemptRecord.RiskCode = decision.RiskCode
				attemptRecord.Confidence = decision.Confidence
				attemptRecord.Reason = decision.Reason
				attemptRecord.Evidence = decision.Evidence
				metadata.Attempts = append(metadata.Attempts, attemptRecord)
				return decision, profile, semanticState.metadata(metadata), nil
			}

			err = annotateAuditOutputError(err, outputDiagnostics)
			lastErr = err
			attemptRecord.ErrorClass, attemptRecord.HTTPStatus, attemptRecord.Reason = auditModelErrorDetails(err)
			metadata.Attempts = append(metadata.Attempts, attemptRecord)
			// A required fusion panel cannot be bypassed by a fallback profile
			// that has no panel configured. Missing assessments are unresolved.
			if strings.HasPrefix(attemptRecord.ErrorClass, "cyber_") || strings.HasPrefix(attemptRecord.ErrorClass, "fusion_") || (cyberDenyActive(ctx) && (strings.HasPrefix(attemptRecord.ErrorClass, "semantic_verifier_") || attemptRecord.ErrorClass == "audit_capacity_exceeded" || attemptRecord.ErrorClass == "audit_http_budget" || attemptRecord.ErrorClass == "semantic_review_budget")) {
				return AuditDecision{}, usedProfile, semanticState.metadata(metadata), err
			}
			if attempt >= retries || !auditErrorRetryableOnSameProfile(err) {
				break
			}
			if auditErrorNeedsOutputRecovery(err) {
				formatAttempt++
			}
			metadata.ModelRetryCount++
			if err := waitAuditRetry(ctx, attempt); err != nil {
				return AuditDecision{}, usedProfile, semanticState.metadata(metadata), err
			}
		}
	}

	if lastErr == nil {
		lastErr = newAuditModelCallError("fallback_unavailable", 0, "no enabled audit fallback model is available", nil)
	}
	return AuditDecision{}, usedProfile, semanticState.metadata(metadata), lastErr
}

func mergeAuditCallMetadata(existing auditCallMetadata, current auditCallMetadata) auditCallMetadata {
	result := current
	if result.Mode == "" {
		result.Mode = existing.Mode
	}
	if result.ChunkCount == 0 {
		result.ChunkCount = existing.ChunkCount
	}
	if result.ChunkBytes == 0 {
		result.ChunkBytes = existing.ChunkBytes
	}
	if result.RetryCount < existing.RetryCount {
		result.RetryCount = existing.RetryCount
	}
	// Preserve the largest over-limit observation across failed primary and
	// fallback models so a later successful fallback cannot erase the user's
	// actual token diagnostics from the trace.
	if existing.RequestedTokens > result.RequestedTokens {
		result.RequestedTokens = existing.RequestedTokens
		result.ContextWindowTokens = existing.ContextWindowTokens
		result.RequestedTokensLowerBound = existing.RequestedTokensLowerBound
		result.ObservedOutputTokens = existing.ObservedOutputTokens
	} else if result.RequestedTokens == 0 && existing.RequestedTokens > 0 {
		result.RequestedTokens = existing.RequestedTokens
		result.ContextWindowTokens = existing.ContextWindowTokens
	} else if result.ContextWindowTokens == 0 {
		result.ContextWindowTokens = existing.ContextWindowTokens
	}
	return result
}

func auditErrorRetryableOnSameProfile(err error) bool {
	var callError *AuditModelCallError
	if !errors.As(err, &callError) {
		return false
	}
	switch callError.Class {
	case "connection",
		"timeout",
		"rate_limited",
		"audit_server_error",
		"response_read",
		"response_format",
		"empty_response",
		"invalid_json",
		"invalid_schema",
		"ambiguous_output",
		"output_truncated",
		"structured_output_unsupported",
		"invalid_decision",
		"invalid_evidence":
		return true
	default:
		// Authentication, model/endpoint-not-found, generic 4xx, credential
		// decryption, and context-size failures are deterministic. Retrying the
		// same profile only adds latency; the ordered fallback chain may still
		// recover them on another profile.
		return false
	}
}

func waitAuditRetry(ctx context.Context, retryIndex int) error {
	delay := 75 * time.Millisecond
	for index := 0; index < retryIndex && delay < 300*time.Millisecond; index++ {
		delay *= 2
		if delay > 300*time.Millisecond {
			delay = 300 * time.Millisecond
		}
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
