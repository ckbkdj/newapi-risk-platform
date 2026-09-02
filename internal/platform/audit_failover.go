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
	CallMetadata   auditCallMetadata
	AttemptCount   int
	ModelRetryCount int
	FallbackCount  int
	Attempts       []AuditAttempt
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
	for _, fallbackID := range root.FallbackProfileIDs {
		if fallbackID <= 0 || fallbackID == root.ID || len(profiles) >= maxAuditFallbackProfiles+1 {
			continue
		}
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

			decision, callMetadata, err := e.callModel(ctx, profile, text)
			metadata.CallMetadata = callMetadata
			metadata.AttemptCount++
			attemptRecord := AuditAttempt{
				ProfileID:   profile.ID,
				ProfileName: profile.Name,
				Model:       profile.Model,
				Attempt:     attempt + 1,
				Success:     err == nil,
			}
			if err == nil {
				metadata.Attempts = append(metadata.Attempts, attemptRecord)
				return decision, profile, metadata, nil
			}

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
		"http_status",
		"response_read",
		"response_format",
		"empty_response",
		"invalid_json",
		"invalid_decision":
		return true
	default:
		return false
	}
}

func waitAuditRetry(ctx context.Context, retryIndex int) error {
	delay := 100 * time.Millisecond
	for index := 0; index < retryIndex && delay < time.Second; index++ {
		delay *= 2
		if delay > time.Second {
			delay = time.Second
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
