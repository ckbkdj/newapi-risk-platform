package platform

// Base budgets are retained for small requests. Long requests reserve enough
// space for two-pass auditing plus a bounded recovery margin. Never reset spent
// calls on retries/fallback; concurrency and the 120s request deadline are unchanged.
const cyberDenyMaxHTTPBudget = 256
const cyberDenyMaxReviewBudget = 128

func (s *auditSemanticState) configureChunkBudget(chunks int) {
 if chunks < 1 { return }
 chunks=min(chunks,256)
 margin:=2*min(chunks,16)
 httpLimit:=min(cyberDenyMaxHTTPBudget,max(cyberDenyHTTPBudget,2*chunks+margin))
 reviewLimit:=min(cyberDenyMaxReviewBudget,max(maxAuditSemanticCalls,chunks+margin))
 s.mu.Lock()
 defer s.mu.Unlock()
 s.httpBudget=max(s.httpBudget,httpLimit)
 s.reviewBudget=max(s.reviewBudget,reviewLimit)
}
