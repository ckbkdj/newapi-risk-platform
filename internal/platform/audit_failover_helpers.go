package platform

import (
	"context"
	"fmt"
)

func (s *Store) ValidateAuditFallbackProfiles(ctx context.Context, profileID int64, ids []int64) error {
	if len(ids) > maxAuditFallbackProfiles {
		return fmt.Errorf("at most %d fallback audit models may be configured", maxAuditFallbackProfiles)
	}
	seen := make(map[int64]struct{}, len(ids))
	for position, id := range ids {
		if id <= 0 {
			return fmt.Errorf("fallback audit model #%d has an invalid id", position+1)
		}
		if profileID > 0 && id == profileID {
			return fmt.Errorf("an audit model cannot fall back to itself")
		}
		if _, exists := seen[id]; exists {
			return fmt.Errorf("fallback audit model id %d is duplicated", id)
		}
		seen[id] = struct{}{}
		var exists bool
		if err := s.pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM audit_profiles WHERE id=$1)`, id).Scan(&exists); err != nil {
			return fmt.Errorf("validate fallback audit model %d: %w", id, err)
		}
		if !exists {
			return fmt.Errorf("fallback audit model id %d does not exist", id)
		}
	}
	return nil
}

func auditAttemptModelNames(attempts []AuditAttempt) []string {
	result := make([]string, 0, len(attempts))
	seen := make(map[string]struct{}, len(attempts))
	for _, attempt := range attempts {
		name := attempt.Model
		if name == "" {
			name = attempt.ProfileName
		}
		if name == "" {
			continue
		}
		if _, exists := seen[name]; exists {
			continue
		}
		seen[name] = struct{}{}
		result = append(result, name)
	}
	return result
}
