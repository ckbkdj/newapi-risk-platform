package platform

// All retry/fallback and re-chunk loops remain finite. A context failure can
// consume one single-call plan plus the existing bounded re-chunk attempts.
const maxAuditChunkPlans = maxAuditTotalAttempts * (auditChunkRetryLimit + 1)

// Reserve the complete plan (primary and verifiers, each with at most one
// existing repair), without resetting calls already spent on earlier plans.
// Production reserves the maximum validated three-verifier panel. A smaller
// plan is useful for explicit internal tests. This is NOT permission to allow.
func (s *auditSemanticState) configureChunkBudget(chunks int, votes ...int) error {
	reviewers := 3
	if len(votes) == 1 {
		reviewers = votes[0]
	}
	invalid := func() error {
		return newAuditModelCallError("cyber_plan_budget", 0, "invalid or exhausted finite audit work plan; forwarding denied", nil)
	}
	if chunks <= 0 || len(votes) > 1 || reviewers < 1 || reviewers > 3 {
		return invalid()
	}
	httpPerChunk, reviewPerChunk := 2*(1+reviewers), 1+2*reviewers
	maxInt := int(^uint(0) >> 1)
	if chunks > maxInt/httpPerChunk || chunks > maxInt/reviewPerChunk {
		return invalid()
	}
	httpWork, reviewWork := chunks*httpPerChunk, chunks*reviewPerChunk
	s.mu.Lock()
	defer s.mu.Unlock()
	baseHTTP, baseReview := max(cyberDenyHTTPBudget, s.httpBudget), max(maxAuditSemanticCalls, s.reviewBudget)
	if s.budgetPlans >= maxAuditChunkPlans || httpWork > maxInt-baseHTTP || reviewWork > maxInt-baseReview {
		return invalid()
	}
	s.httpBudget, s.reviewBudget = baseHTTP+httpWork, baseReview+reviewWork
	s.budgetPlans++
	return nil
}
