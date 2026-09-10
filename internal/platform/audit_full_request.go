package platform

import "context"

const defaultAuditModelConcurrency = 16

// The caller retains cancellation ownership. A zero total timeout permits the
// finite complete plan, not unbounded retries or work after disconnection.
func (e *AuditEngine) fullAuditContext(parent context.Context) (context.Context, context.CancelFunc) {
	if e.requestTimeout > 0 {
		return context.WithTimeout(parent, e.requestTimeout)
	}
	return context.WithCancel(parent)
}

// Limit physical model calls across requests. Release in the raw-call frame,
// before a verifier or repair is invoked, so a one-slot engine cannot deadlock.
func (e *AuditEngine) acquireAuditModelSlot(ctx context.Context) (func(), error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if e.modelSlots == nil {
		return func() {}, nil
	} // Explicit internal test engine.
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case e.modelSlots <- struct{}{}:
		if err := ctx.Err(); err != nil {
			<-e.modelSlots
			return nil, err
		}
		return func() { <-e.modelSlots }, nil
	}
}
