package platform

import (
	"context"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"
)

const auditProfileLookupTimeout = 5 * time.Second

// No database messages, DSNs, request text or secrets are written here.
// Stage timings distinguish CPU preprocessing from storage and model requests.
type AuditPreflightDiagnostics struct {
	StageMS                   map[string]int64 `json:"stage_ms"`
	FailureStage              string           `json:"failure_stage,omitempty"`
	ProfileSelection          string           `json:"profile_selection"`
	RequestedProfileID        int64            `json:"requested_profile_id,omitempty"`
	SelectedProfileID         int64            `json:"selected_profile_id,omitempty"`
	ProfileErrorKind          string           `json:"profile_error_kind,omitempty"`
	RequiredChunks            int              `json:"required_chunks,omitempty"`
	MinimumHTTPCalls          int              `json:"minimum_http_calls,omitempty"`
	NonOperationalRuleMatches int              `json:"non_operational_rule_matches,omitempty"`
}

func failAuditPreflight(result *AuditResult, stage, class, code, reason string) {
	result.ErrorClass = class
	result.AuditDecision = AuditDecision{Decision: DecisionBlock, Source: "platform", Category: "audit_infrastructure", RiskCode: code, Reason: reason}
	if result.AuditPreflight != nil {
		result.AuditPreflight.FailureStage = stage
	}
}

func auditPreflightInterrupted(ctx context.Context, result *AuditResult, stage string) bool {
	err := ctx.Err()
	if err == nil {
		return false
	}
	class, reason := "audit_cancelled", "audit cancelled during "+stage+"; no complete assessment"
	if errors.Is(err, context.DeadlineExceeded) {
		class = "audit_deadline"
		reason = "audit deadline exceeded during " + stage + "; no complete assessment"
	}
	failAuditPreflight(result, stage, class, "AUDIT_MODEL_ERROR", reason)
	return true
}

func auditProfileFailure(ctx context.Context, p AuditProfile, err error) (class, reason, kind string) {
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return "audit_deadline", "audit deadline exceeded before profile selection completed", "context_deadline"
	}
	if errors.Is(ctx.Err(), context.Canceled) {
		return "audit_cancelled", "audit cancelled before profile selection completed", "context_cancelled"
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return "audit_profile_lookup_timeout", "audit profile lookup timed out; model availability is unknown", "lookup_deadline"
	}
	if errors.Is(err, context.Canceled) {
		return "audit_cancelled", "audit profile lookup cancelled; model availability is unknown", "lookup_cancelled"
	}
	if errors.Is(err, ErrNotFound) {
		return "audit_profile_not_found", "selected/default audit profile does not exist", "not_found"
	}
	if err != nil {
		// Error types are diagnostic; error strings can contain connection secrets.
		return "audit_profile_lookup_error", "audit profile storage lookup failed; model availability is unknown", fmt.Sprintf("%T", err)
	}
	if !p.Enabled {
		return "audit_profile_disabled", "selected/default audit profile is disabled", "disabled"
	}
	return "", "", ""
}

// This is capacity admission, NOT a safe-content shortcut. Refuse before costly
// rule/model work when complete mandatory two-pass coverage cannot fit. Never
// drop history, increase concurrency or claim partial content was audited.
func (e *AuditEngine) rejectImpossibleAuditCapacity(ctx context.Context, text string, result *AuditResult) bool {
	if len(text) <= cyberDenyChunkBytes {
		return false
	}
	chunks, _ := splitAuditTextWithOffsets(text, cyberDenyChunkBytes, e.chunkOverlapBytes)
	if auditPreflightInterrupted(ctx, result, "capacity") {
		return true
	}
	count := len(chunks)
	if result.AuditPreflight != nil {
		result.AuditPreflight.RequiredChunks = count
		result.AuditPreflight.MinimumHTTPCalls = 2 * count
	}
	if (e.maxAuditChunks <= 0 || count <= e.maxAuditChunks) && 2*count <= cyberDenyMaxHTTPBudget && count <= cyberDenyMaxReviewBudget {
		return false
	}
	result.AuditChunkCount = count
	result.AuditChunkBytes = cyberDenyChunkBytes
	result.AuditMode = "preflight_capacity"
	result.AuditHTTPBudget = cyberDenyMaxHTTPBudget
	result.AuditReviewBudget = cyberDenyMaxReviewBudget
	failAuditPreflight(result, "capacity", "input_too_large", "AUDIT_CONTEXT_TOO_LARGE", fmt.Sprintf("complete audit requires %d chunks and at least %d model calls; limits are %d chunks, %d HTTP calls and %d reviews; no content verdict", count, 2*count, e.maxAuditChunks, cyberDenyMaxHTTPBudget, cyberDenyMaxReviewBudget))
	return true
}

// Bound decoder reads and make cancellation visible while ingesting a large
// JSON string. Cancellation is checked again after parsing/collection; it is
// never turned into an empty/allow request.
type auditContextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (r *auditContextReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	if len(p) > 32*1024 {
		p = p[:32*1024]
	}
	return r.reader.Read(p)
}

// Regexp's reader API has the same byte offsets as FindStringIndex. A cancelled
// stream can look like EOF to regexp, so the caller MUST discard its outcome
// when ctx.Err()!=nil. No worker goroutine is left computing after cancellation.
type auditContextRuneReader struct {
	ctx       context.Context
	reader    *strings.Reader
	remaining int
}

func (r *auditContextRuneReader) ReadRune() (rune, int, error) {
	if r.remaining <= 0 {
		if err := r.ctx.Err(); err != nil {
			return 0, 0, err
		}
		r.remaining = 4096
	}
	c, n, err := r.reader.ReadRune()
	r.remaining -= n
	return c, n, err
}
func findAuditRegex(ctx context.Context, expression *regexp.Regexp, text string) ([]int, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	var location []int
	if len(text) < 64*1024 {
		location = expression.FindStringIndex(text)
	} else {
		location = expression.FindReaderIndex(&auditContextRuneReader{ctx: ctx, reader: strings.NewReader(text)})
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return location, nil
}

func matchCyberRuleWithContext(ctx context.Context, r compiledRule, text, lower string, pre *AuditPreflightDiagnostics) (cyberRuleEvidence, bool, error) {
	if r.PatternType != "regex" || r.regularExpression == nil {
		ev, hit := matchCyberRuleEvidence(r, text, lower)
		return ev, hit, ctx.Err()
	}
	for from, skipped := 0, 0; from < len(text); {
		loc, err := findAuditRegex(ctx, r.regularExpression, text[from:])
		if err != nil {
			return cyberRuleEvidence{}, false, err
		}
		if loc == nil {
			return cyberRuleEvidence{}, false, nil
		}
		ev := cyberRuleEvidence{start: from + loc[0], end: from + loc[1], matchedRaw: text[from+loc[0] : from+loc[1]]}
		if !nonOperationalShippedRuleMatch(r, ev, text) {
			return ev, true, nil
		}
		if pre != nil {
			pre.NonOperationalRuleMatches++
		}
		skipped++
		if skipped > 128 {
			return cyberRuleEvidence{}, false, errors.New("non-operational rule evidence inspection budget exhausted")
		}
		_, size := utf8.DecodeRuneInString(text[ev.start:])
		if size == 0 {
			break
		}
		from = ev.start + size
	}
	return cyberRuleEvidence{}, false, nil
}
