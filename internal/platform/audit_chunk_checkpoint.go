package platform

import (
	"context"
	"crypto/sha256"
	"sync/atomic"
)

type auditChunkCheckpointKey struct{}
type auditChunkReuseKey struct{}

// Lifetime is ONE request and ONE fixed primary/self-verifier profile. It never
// persists or shares an allow across users, fallback profiles or policy panels.
// The collector alone writes; cached entries are read before workers start.
type auditChunkCheckpoint struct {
	allows map[[32]byte]AuditDecision
}

func newAuditChunkCheckpoint(ctx context.Context, profile AuditProfile) *auditChunkCheckpoint {
	if !cyberDenyActive(ctx) {
		return nil
	}
	extra := auditProfileExtra(profile)
	// Independently configured reviewers may change while a request is running.
	// Without a pinned panel snapshot, do not reuse assessments for these modes.
	for _, key := range []string{"_risk_fusion_profile_ids", "_risk_verifier_profile_id"} {
		if _, configured := extra[key]; configured {
			return nil
		}
	}
	return &auditChunkCheckpoint{allows: make(map[[32]byte]AuditDecision)}
}

func auditChunkCheckpointID(scope auditSourceScope, chunk string, index, total int) [32]byte {
	ctx := context.WithValue(context.Background(), auditSourceScopeKey{}, scope)
	// Includes exact source bytes, chunk index/total, task anchors AND provenance.
	// Rechunking or a changed source/context therefore cannot borrow an old allow.
	document := encodeAuditScopedDocument(ctx, decorateAuditChunk(chunk, index, total), chunk)
	return sha256.Sum256([]byte(document))
}
func (c *auditChunkCheckpoint) put(id [32]byte, d AuditDecision, err error) {
	if c == nil || err != nil || d.Decision != DecisionAllow || len(c.allows) >= cyberDenyMaxReviewBudget {
		return
	}
	// Called only after callModelOnceWithEvidenceSource, which completes BOTH
	// primary and required verification. Never store a primary-only candidate.
	c.allows[id] = d
}
func recordAuditChunkReuse(ctx context.Context) {
	if p, ok := ctx.Value(auditChunkReuseKey{}).(*atomic.Int32); ok {
		p.Add(1)
	}
}
