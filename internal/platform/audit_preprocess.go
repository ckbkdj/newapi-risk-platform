package platform

import (
	"context"
	"errors"
	"io"
)

type auditContextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (r auditContextReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.reader.Read(p)
}

// This is an optimistic upper bound, not a claim that every request below it
// fits. Overlap, task boundaries, repairs and Fusion can require more calls.
// Above it no two-pass full-content allow can fit the existing hard budgets.
func (e *AuditEngine) auditCapacityTextLimit() int {
	chunks := min(cyberDenyMaxHTTPBudget/2, cyberDenyMaxReviewBudget)
	if e.maxAuditChunks > 0 {
		chunks = min(chunks, e.maxAuditChunks)
	}
	return chunks * cyberDenyChunkBytes
}

func auditProfileFailure(ctx context.Context, p AuditProfile, err error) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return newAuditModelCallError("audit_profile_lookup_timeout", 0, "audit profile lookup timed out; model enabled state is unknown", nil)
	case errors.Is(err, context.Canceled):
		return newAuditModelCallError("audit_cancelled", 0, "audit profile lookup cancelled", nil)
	case errors.Is(err, ErrNotFound):
		return newAuditModelCallError("audit_profile_not_found", 0, "selected or default audit profile does not exist", nil)
	case err != nil:
		// Do not expose a DSN, password or private endpoint embedded in driver errors.
		return newAuditModelCallError("audit_profile_lookup_failed", 0, "audit profile storage lookup failed; model enabled state is unknown", nil)
	case !p.Enabled:
		return newAuditModelCallError("audit_profile_disabled", 0, "selected audit profile is disabled", nil)
	}
	return nil
}
