package platform

import (
	"context"
	"errors"
	"fmt"
	"time"
)

const (
	maxAuditFallbackProfiles = 8
	maxAuditRetryCount       = 5
	maxAuditTotalAttempts    = 24
)

type auditFailoverMetadata struct {
	CallMetadata      auditCallMetadata
	AttemptCount      int
	ModelRetryCount   int
	FallbackCount     int
	Attempts          []AuditAttempt
	OutputDiagnostics auditOutputDiagnostics
}

func (e *AuditEngine) callModelWithFailover(
	ctx context.Context,
	root AuditProfile,
	text string,
) (AuditDecision, AuditProfile, auditFailoverMetadata, error) {
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
			return AuditDecision{}, usedProfile, metadata, ctx.Err()
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
		usedProfile = profile
		retries := profile.RetryCount
		if retries < 0 {
			retries = 0
		}
		if retries > maxAuditRetryCount {
			retries = maxAuditRetryCount
		}

		for attempt := 0; attempt <= retries; attempt++ {
			if ctx.Err() != nil {
				return AuditDecision{}, usedProfile, metadata, ctx.Err()
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

			outputPlan := e.auditOutputPlan(profile, attempt)
			attemptContext, outputState := withAuditOutputAttempt(ctx, outputPlan)
			decision, callMetadata, err := e.callModel(attemptContext, profile, text)
			outputDiagnostics := outputState.snapshot(err != nil)
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
				attemptRecord.Decision = decision.Decision
				attemptRecord.RiskCode = decision.RiskCode
				attemptRecord.Confidence = decision.Confidence
				attemptRecord.Reason = decision.Reason
				attemptRecord.Evidence = decision.Evidence
				metadata.Attempts = append(metadata.Attempts, attemptRecord)
				return decision, profile, metadata, nil
			}

			err = annotateAuditOutputError(err, outputDiagnostics)
			lastErr = err
			attemptRecord.ErrorClass, attemptRecord.HTTPStatus, attemptRecord.Reason = auditModelErrorDetails(err)
			metadata.Attempts = append(metadata.Attempts, attemptRecord)
			if attempt >= retries || !auditErrorRetryableOnSameProfile(err) {
				break
			}
			metadata.ModelRetryCount++
			if err := waitAuditRetry(ctx, attempt); err != nil {
				return AuditDecision{}, usedProfile, metadata, err
			}
		}
	}

	if lastErr == nil {
		lastErr = newAuditModelCallError("fallback_unavailable", 0, "no enabled audit fallback model is available", nil)
	}
	return AuditDecision{}, usedProfile, metadata, lastErr
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
