package platform

import (
	"context"
	"encoding/json"
	"slices"
	"strings"
)

type auditAdmissionPhaseKey struct{}

const maxAuditModelInputRecords = 32

// Proof of what the gateway DISPATCHED, not proof of what a remote provider
// tokenized or what a model attended to. No plaintext, endpoint or secret is logged.
type AuditModelInputDiagnostics struct {
	Call                     int    `json:"call"`
	ProfileID                int64  `json:"profile_id"`
	Phase                    string `json:"phase"`
	RequestTextBytes         int    `json:"request_text_bytes"`
	EvidenceSourceBytes      int    `json:"evidence_source_bytes"`
	RequestContextBytes      int    `json:"request_context_bytes"`
	RequestContextCount      int    `json:"request_context_count"`
	PayloadBytes             int    `json:"payload_bytes"`
	SourceMatchesRequestText bool   `json:"source_matches_request_text"`
	RequestTextHMAC          string `json:"request_text_hmac,omitempty"`
	DocumentHMAC             string `json:"document_hmac,omitempty"`
}

// Verify the actual protected user-message document before dispatch. Compare
// decoded bytes, not their JSON escapes. Context remains interpretation-only;
// evidence is still checked against the very same request_text, not system text.
func (e *AuditEngine) auditModelInputDiagnostics(ctx context.Context, p AuditProfile, messages []map[string]string, source string, payloadBytes int) (AuditModelInputDiagnostics, error) {
	invalid := func() (AuditModelInputDiagnostics, error) {
		return AuditModelInputDiagnostics{}, newAuditModelCallError("cyber_input_integrity", 0, "audit user document is empty, changed, or inconsistent with the evidence source", nil)
	}
	if len(messages) != 2 || messages[0]["role"] != "system" || messages[1]["role"] != "user" || strings.TrimSpace(source) == "" {
		return invalid()
	}
	var doc auditRequestDocument
	if json.Unmarshal([]byte(messages[1]["content"]), &doc) != nil || doc.Schema != auditInputContractVersion || doc.RequestText != source {
		return invalid()
	}
	scope := auditScopeFromContext(ctx, source)
	if !slices.Equal(doc.RequestContext, scope.Anchors) {
		return invalid()
	}
	phase := "primary"
	if second, _ := ctx.Value(cyberDenySecondPassKey{}).(bool); second {
		phase = "verifier"
	}
	if repair, _ := ctx.Value(auditAdmissionPhaseKey{}).(string); repair == "evidence_repair" || repair == "grounding" {
		phase = repair
	}
	d := AuditModelInputDiagnostics{ProfileID: p.ID, Phase: phase, RequestTextBytes: len(doc.RequestText), EvidenceSourceBytes: len(source), RequestContextCount: len(doc.RequestContext), PayloadBytes: payloadBytes, SourceMatchesRequestText: true}
	for _, s := range doc.RequestContext {
		d.RequestContextBytes += len(s)
	}
	if e.security != nil {
		d.RequestTextHMAC = e.security.PromptHMAC("audit-request-text-v1\x00" + doc.RequestText)
		d.DocumentHMAC = e.security.PromptHMAC("audit-request-document-v1\x00" + messages[1]["content"])
	}
	return d, nil
}
