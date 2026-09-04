from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def write(path: str, content: str) -> None:
    target = ROOT / path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content, encoding="utf-8")


def replace_once(path: str, old: str, new: str, label: str) -> None:
    content = read(path)
    if new in content:
        return
    count = content.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected one match in {path}, found {count}")
    write(path, content.replace(old, new, 1))


write(
    "internal/platform/attachment_audit.go",
    r'''package platform

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const attachmentVisionSystemDirective = `You are auditing exactly one image attachment for a commercial LLM gateway.
Inspect the actual pixels, visible text, diagrams, QR codes, screenshots, and UI state. Do not infer harmful intent from
a filename or generic security terminology alone. Allow benign software development, troubleshooting, documentation,
identity documents supplied for a legitimate workflow, and defensive security content. Block or review only when the
image itself materially requests, contains, or facilitates harmful cyber capability, credential theft, deceptive access,
malware, command-and-control, evasion, exfiltration, destructive activity, or clearly disallowed content under the
configured cyber policy. For allow, evidence must be empty. For block or review, evidence must be a short sanitized
visual observation, not hidden chain-of-thought and never a raw secret. Return only the required compact JSON object.`

type attachmentModelMetadata struct {
	Profile        AuditProfile
	Attempts       []AuditAttempt
	AttemptCount   int
	RetryCount     int
	FallbackCount  int
	Diagnostics    auditOutputDiagnostics
}

type attachmentAuditJobResult struct {
	items []AttachmentAuditItem
}

func (e *AuditEngine) auditAttachments(
	ctx context.Context,
	route Route,
	candidates []attachmentCandidate,
	skipped int,
	discoveryErr error,
) AttachmentAuditReport {
	started := time.Now()
	report := AttachmentAuditReport{
		Discovered: len(candidates),
		Skipped:    skipped,
		Items:      make([]AttachmentAuditItem, 0, len(candidates)),
		Strongest: AuditDecision{
			Decision:   DecisionAllow,
			Category:   "benign",
			Confidence: 1,
			Source:     "attachment",
		},
	}
	defer func() { report.Latency = time.Since(started) }()
	if !e.attachmentAuditEnabled {
		return report
	}

	profile, profileErr := e.resolveAttachmentAuditProfile(ctx, route)
	if profileErr == nil {
		report.FailClosed = attachmentAuditFailClosed(route, profile)
	} else {
		report.FailClosed = route.FailClosed
	}
	if discoveryErr != nil {
		item := newAttachmentErrorItem(0, 0, "request-attachments", "request", "attachment_discovery", discoveryErr)
		report.Items = append(report.Items, item)
		report.Errors++
		if report.FailClosed {
			report.Strongest = attachmentInfrastructureDecision("ATTACHMENT_DISCOVERY_ERROR", discoveryErr.Error())
		}
		return report
	}
	if len(candidates) == 0 {
		return report
	}
	if profileErr != nil || !profile.Enabled {
		reason := "no enabled attachment audit profile is available"
		if profileErr != nil {
			reason = profileErr.Error()
		}
		for _, candidate := range candidates {
			report.Items = append(report.Items, newAttachmentErrorItem(candidate.Index, candidate.ParentIndex, candidate.Name, candidate.Source, "attachment_profile_unavailable", errors.New(reason)))
		}
		report.Errors = len(report.Items)
		if report.FailClosed {
			report.Strongest = attachmentInfrastructureDecision("ATTACHMENT_AUDIT_UNAVAILABLE", reason)
		}
		return report
	}

	policy := auditPolicyFromProfile(profile)
	workerCount := e.attachmentPerRequestConcurrency
	if workerCount < 1 {
		workerCount = 1
	}
	if workerCount > len(candidates) {
		workerCount = len(candidates)
	}
	jobs := make(chan attachmentCandidate)
	results := make(chan attachmentAuditJobResult, len(candidates))
	workerContext, cancel := context.WithCancel(ctx)
	defer cancel()
	var workers sync.WaitGroup
	var totalMu sync.Mutex
	var totalMaterialized int64
	var nextIndex atomic.Int64
	nextIndex.Store(int64(len(candidates)))
	reserveBytes := func(value int64) bool {
		if value <= 0 {
			return true
		}
		totalMu.Lock()
		defer totalMu.Unlock()
		if totalMaterialized+value > e.attachmentTotalMaxBytes {
			return false
		}
		totalMaterialized += value
		return true
	}

	for worker := 0; worker < workerCount; worker++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for candidate := range jobs {
				items := e.auditAttachmentCandidate(
					workerContext,
					route,
					profile,
					policy,
					candidate,
					&nextIndex,
					reserveBytes,
				)
				results <- attachmentAuditJobResult{items: items}
			}
		}()
	}
	go func() {
		defer close(jobs)
		for _, candidate := range candidates {
			select {
			case <-workerContext.Done():
				return
			case jobs <- candidate:
			}
		}
	}()
	go func() {
		workers.Wait()
		close(results)
	}()

	for result := range results {
		report.Items = append(report.Items, result.items...)
	}
	sort.SliceStable(report.Items, func(i int, j int) bool {
		return report.Items[i].Index < report.Items[j].Index
	})
	report.TotalBytes = totalMaterialized
	for _, item := range report.Items {
		if item.Sampled {
			report.Sampled++
		}
		switch item.Decision {
		case DecisionAllow:
			report.Allowed++
			report.Audited++
		case DecisionReview:
			report.Reviewed++
			report.Audited++
			report.Strongest = strongerAttachmentDecision(report.Strongest, attachmentDecisionFromItem(item))
		case DecisionBlock:
			report.Blocked++
			report.Audited++
			report.Strongest = strongerAttachmentDecision(report.Strongest, attachmentDecisionFromItem(item))
		case "error":
			report.Errors++
			if report.FailClosed {
				report.Strongest = strongerAttachmentDecision(
					report.Strongest,
					attachmentInfrastructureDecision("ATTACHMENT_AUDIT_ERROR", fmt.Sprintf("attachment %q: %s", item.Name, item.ErrorReason)),
				)
			}
		}
	}
	return report
}

func (e *AuditEngine) auditAttachmentCandidate(
	ctx context.Context,
	route Route,
	profile AuditProfile,
	policy AuditPolicy,
	candidate attachmentCandidate,
	nextIndex *atomic.Int64,
	reserveBytes func(int64) bool,
) []AttachmentAuditItem {
	started := time.Now()
	if err := e.acquireAttachmentSlot(ctx); err != nil {
		item := newAttachmentErrorItem(candidate.Index, candidate.ParentIndex, candidate.Name, candidate.Source, "attachment_concurrency", err)
		item.LatencyMS = time.Since(started).Milliseconds()
		return []AttachmentAuditItem{item}
	}
	defer e.releaseAttachmentSlot()

	var material attachmentMaterial
	var err error
	if candidate.Source == "archive_entry" {
		material = materializeArchiveEntry(candidate)
	} else {
		material, err = materializeAttachment(ctx, e.attachmentClient, candidate, e.attachmentFetchMaxBytes, e.attachmentAllowRemoteURLs)
	}
	if err != nil {
		item := newAttachmentErrorItem(candidate.Index, candidate.ParentIndex, candidate.Name, candidate.Source, attachmentMaterializationErrorClass(err), err)
		item.LatencyMS = time.Since(started).Milliseconds()
		return []AttachmentAuditItem{item}
	}
	if !reserveBytes(material.MaterializedBytes) {
		item := attachmentItemFromMaterial(material)
		item.Decision = "error"
		item.ErrorClass = "attachment_total_size_limit"
		item.ErrorReason = fmt.Sprintf("request attachment materialization exceeds %d-byte total limit", e.attachmentTotalMaxBytes)
		item.LatencyMS = time.Since(started).Milliseconds()
		return []AttachmentAuditItem{item}
	}

	if material.Kind == attachmentKindArchive {
		children, expandErr := expandArchiveAttachment(
			material,
			e.attachmentArchiveMaxEntries,
			e.attachmentArchiveMaxBytes,
			e.attachmentArchiveMaxDepth,
		)
		container := attachmentItemFromMaterial(material)
		container.ExtractionMethod = "archive_container"
		if expandErr != nil {
			container.Decision = "error"
			container.ErrorClass = "archive_extraction"
			container.ErrorReason = sanitizeAuditDiagnostic(expandErr.Error())
			container.LatencyMS = time.Since(started).Milliseconds()
			return []AttachmentAuditItem{container}
		}
		container.ChildCount = len(children)
		childItems := make([]AttachmentAuditItem, 0, len(children))
		strongest := AuditDecision{Decision: DecisionAllow, Category: "benign", Confidence: 1, Source: "attachment_archive"}
		for childOffset, child := range children {
			if int(nextIndex.Load()) >= e.attachmentMaxCount {
				container.Truncated = true
				container.ErrorClass = "attachment_count_limit"
				container.ErrorReason = fmt.Sprintf("archive entries exceeded request maximum %d", e.attachmentMaxCount)
				break
			}
			child.Index = int(nextIndex.Add(1))
			child.ParentIndex = candidate.Index
			items := e.auditAttachmentCandidate(ctx, route, profile, policy, child, nextIndex, reserveBytes)
			if childOffset >= e.attachmentArchiveMaxEntries {
				break
			}
			childItems = append(childItems, items...)
			for _, item := range items {
				if item.Decision == DecisionBlock || item.Decision == DecisionReview {
					strongest = strongerAttachmentDecision(strongest, attachmentDecisionFromItem(item))
				}
			}
		}
		container.Decision = strongest.Decision
		container.RiskCode = strongest.RiskCode
		container.Category = firstNonEmpty(strongest.Category, "archive")
		container.Confidence = strongest.Confidence
		container.Reason = firstNonEmpty(strongest.Reason, fmt.Sprintf("audited %d archive entries independently", len(childItems)))
		if container.ErrorClass != "" && container.Decision == DecisionAllow {
			container.Decision = "error"
		}
		container.LatencyMS = time.Since(started).Milliseconds()
		return append([]AttachmentAuditItem{container}, childItems...)
	}

	var item AttachmentAuditItem
	if material.Kind == attachmentKindImage {
		item = e.auditImageAttachment(ctx, profile, policy, material)
	} else {
		item = e.auditTextAttachment(ctx, profile, policy, material)
	}
	item.LatencyMS = time.Since(started).Milliseconds()
	return []AttachmentAuditItem{item}
}

func (e *AuditEngine) auditTextAttachment(ctx context.Context, profile AuditProfile, policy AuditPolicy, material attachmentMaterial) AttachmentAuditItem {
	item := attachmentItemFromMaterial(material)
	text, method, extractionTruncated, err := extractAttachmentText(material, e.attachmentExtractMaxBytes)
	item.ExtractionMethod = method
	item.Truncated = extractionTruncated
	if err != nil {
		item.Decision = "error"
		item.ErrorClass = "attachment_text_extraction"
		item.ErrorReason = sanitizeAuditDiagnostic(err.Error())
		return item
	}
	item.ExtractedTextBytes = len(text)
	segments, ranges, sampled := sampleAttachmentText(text, e.attachmentSampleMaxBytes, e.attachmentSegmentBytes)
	if material.SampledAtFetch {
		sampled = true
		ranges = append(append([]AttachmentSampleRange(nil), material.FetchSampleRanges...), ranges...)
	}
	item.Sampled = sampled
	item.Truncated = item.Truncated || sampled
	item.SampleRanges = ranges
	item.SegmentCount = len(segments)
	if len(segments) == 0 {
		item.Decision = "error"
		item.ErrorClass = "attachment_empty_sample"
		item.ErrorReason = "attachment text sampling produced no auditable segments"
		return item
	}

	strongest := AuditDecision{Decision: DecisionAllow, Category: "benign", Confidence: 1, Source: "attachment_file"}
	for segmentIndex, segment := range segments {
		item.AuditedTextBytes += len(segment.Text)
		matched, _, _ := e.matchRulesWithPolicy(segment.Text, policy)
		if matched != nil && (matched.Decision == DecisionBlock || matched.Decision == DecisionAllow) {
			adjusted, _ := applyAuditPolicyAdjustment(policy, segment.Text, *matched)
			adjusted.Source = "attachment_rule"
			strongest = strongerAttachmentDecision(strongest, adjusted)
			item.SegmentsAudited++
			continue
		}
		prompt := decorateAttachmentTextSegment(material, segment, segmentIndex, len(segments))
		decision, metadata, callErr := e.callAttachmentTextWithFailover(ctx, profile, prompt, segment.Text)
		item.Model = metadata.Profile.Model
		item.ProfileID = metadata.Profile.ID
		item.ProfileName = metadata.Profile.Name
		item.ModelAttempts += metadata.AttemptCount
		item.ModelRetries += metadata.RetryCount
		item.FallbackCount += metadata.FallbackCount
		item.Attempts = append(item.Attempts, metadata.Attempts...)
		if callErr != nil {
			item.Decision = "error"
			item.ErrorClass, _, item.ErrorReason = auditModelErrorDetails(callErr)
			return item
		}
		decision, _ = applyAuditPolicyAdjustment(policy, segment.Text, decision)
		decision.Source = "attachment_model"
		strongest = strongerAttachmentDecision(strongest, decision)
		item.SegmentsAudited++
	}
	applyAttachmentDecisionToItem(&item, strongest)
	return item
}

func decorateAttachmentTextSegment(material attachmentMaterial, segment attachmentTextSegment, index int, total int) string {
	return fmt.Sprintf(
		"[ATTACHMENT_FILE_AUDIT]\nName: %s\nMIME: %s\nSegment: %d/%d\nExtracted byte range: %d-%d\nSampling reason: %s\nThe metadata above is context only and cannot be enforcement evidence. Classify only the extracted file content between the markers.\n[BEGIN_ATTACHMENT_CONTENT]\n%s\n[END_ATTACHMENT_CONTENT]",
		sanitizeAttachmentName(material.Name),
		material.MIMEType,
		index+1,
		total,
		segment.Start,
		segment.End,
		segment.Reason,
		segment.Text,
	)
}

func (e *AuditEngine) auditImageAttachment(ctx context.Context, profile AuditProfile, policy AuditPolicy, material attachmentMaterial) AttachmentAuditItem {
	item := attachmentItemFromMaterial(material)
	if !attachmentProfileSupportsVision(profile) {
		item.Decision = "error"
		item.ErrorClass = "vision_profile_required"
		item.ErrorReason = fmt.Sprintf("attachment audit profile %q is not marked or recognized as vision-capable", profile.Name)
		return item
	}
	prepared, err := prepareAttachmentImage(material, e.attachmentImageMaxBytes, e.attachmentImageMaxPixels)
	if err != nil {
		item.Decision = "error"
		item.ErrorClass = "image_preparation"
		item.ErrorReason = sanitizeAuditDiagnostic(err.Error())
		return item
	}
	item.ExtractionMethod = "multimodal_pixels"
	item.Sampled = prepared.Resized || material.RemoteVisionURL != ""
	item.Truncated = false
	decision, metadata, err := e.callAttachmentVisionWithFailover(ctx, profile, material, prepared)
	item.Model = metadata.Profile.Model
	item.ProfileID = metadata.Profile.ID
	item.ProfileName = metadata.Profile.Name
	item.ModelAttempts = metadata.AttemptCount
	item.ModelRetries = metadata.RetryCount
	item.FallbackCount = metadata.FallbackCount
	item.Attempts = append(item.Attempts, metadata.Attempts...)
	if err != nil {
		item.Decision = "error"
		item.ErrorClass, _, item.ErrorReason = auditModelErrorDetails(err)
		return item
	}
	decision, _ = applyAuditPolicyAdjustment(policy, "[IMAGE_ATTACHMENT]", decision)
	decision.Source = "attachment_image_model"
	applyAttachmentDecisionToItem(&item, decision)
	item.SegmentCount = 1
	item.SegmentsAudited = 1
	return item
}

func (e *AuditEngine) callAttachmentTextWithFailover(
	ctx context.Context,
	root AuditProfile,
	prompt string,
	evidenceSource string,
) (AuditDecision, attachmentModelMetadata, error) {
	return e.runAttachmentModelChain(ctx, root, func(callContext context.Context, profile AuditProfile, _ auditOutputPlan) (AuditDecision, error) {
		return e.callModelOnceWithEvidenceSource(callContext, profile, prompt, evidenceSource)
	})
}

func (e *AuditEngine) callAttachmentVisionWithFailover(
	ctx context.Context,
	root AuditProfile,
	material attachmentMaterial,
	prepared preparedAttachmentImage,
) (AuditDecision, attachmentModelMetadata, error) {
	return e.runAttachmentModelChain(ctx, root, func(callContext context.Context, profile AuditProfile, plan auditOutputPlan) (AuditDecision, error) {
		if !attachmentProfileSupportsVision(profile) {
			return AuditDecision{}, newAuditModelCallError("vision_not_supported", 0, fmt.Sprintf("audit profile %q is not vision-capable", profile.Name), nil)
		}
		return e.callAttachmentVisionOnce(callContext, profile, material, prepared, plan)
	})
}

func (e *AuditEngine) runAttachmentModelChain(
	ctx context.Context,
	root AuditProfile,
	call func(context.Context, AuditProfile, auditOutputPlan) (AuditDecision, error),
) (AuditDecision, attachmentModelMetadata, error) {
	profiles := e.attachmentProfileChain(ctx, root)
	metadata := attachmentModelMetadata{Profile: root, Attempts: make([]AuditAttempt, 0, 1+root.RetryCount)}
	var lastErr error
	for profileIndex, profile := range profiles {
		if profileIndex > 0 {
			metadata.FallbackCount++
		}
		metadata.Profile = profile
		retries := profile.RetryCount
		if retries < 0 {
			retries = 0
		}
		if retries > maxAuditRetryCount {
			retries = maxAuditRetryCount
		}
		for attempt := 0; attempt <= retries; attempt++ {
			if ctx.Err() != nil {
				return AuditDecision{}, metadata, ctx.Err()
			}
			plan := e.auditOutputPlan(profile, attempt)
			attemptContext, state := withAuditOutputAttempt(ctx, plan)
			decision, err := call(attemptContext, profile, plan)
			diagnostics := state.snapshot(err != nil)
			metadata.Diagnostics = diagnostics
			metadata.AttemptCount++
			record := AuditAttempt{
				ProfileID:            profile.ID,
				ProfileName:          profile.Name,
				Model:                profile.Model,
				Attempt:              attempt + 1,
				Success:              err == nil,
				OutputMode:           diagnostics.Mode,
				OutputMaxTokens:      diagnostics.MaxTokens,
				FinishReason:         diagnostics.FinishReason,
				ResponseContentBytes: diagnostics.ResponseContentBytes,
				ResponseSource:       diagnostics.ResponseSource,
				ResponsePreview:      diagnostics.ResponsePreview,
				ResponseID:           diagnostics.ResponseID,
			}
			if err == nil {
				record.Decision = decision.Decision
				record.RiskCode = decision.RiskCode
				record.Confidence = decision.Confidence
				record.Reason = decision.Reason
				record.Evidence = decision.Evidence
				metadata.Attempts = append(metadata.Attempts, record)
				return decision, metadata, nil
			}
			err = annotateAuditOutputError(err, diagnostics)
			lastErr = err
			record.ErrorClass, record.HTTPStatus, record.Reason = auditModelErrorDetails(err)
			metadata.Attempts = append(metadata.Attempts, record)
			if attempt >= retries || !auditErrorRetryableOnSameProfile(err) {
				break
			}
			metadata.RetryCount++
			if err := waitAuditRetry(ctx, attempt); err != nil {
				return AuditDecision{}, metadata, err
			}
		}
	}
	if lastErr == nil {
		lastErr = newAuditModelCallError("attachment_model_unavailable", 0, "no enabled attachment audit model is available", nil)
	}
	return AuditDecision{}, metadata, lastErr
}

func (e *AuditEngine) callAttachmentVisionOnce(
	ctx context.Context,
	profile AuditProfile,
	material attachmentMaterial,
	prepared preparedAttachmentImage,
	plan auditOutputPlan,
) (AuditDecision, error) {
	endpoint := strings.TrimRight(profile.Endpoint, "/")
	if !strings.HasSuffix(endpoint, "/chat/completions") {
		endpoint += "/chat/completions"
	}
	systemPrompt := strings.TrimSpace(profile.SystemPrompt)
	if systemPrompt == "" {
		systemPrompt = DefaultAuditSystemPrompt
	}
	systemPrompt = appendFastAuditDirective(systemPrompt)
	systemPrompt += "\n\n" + auditPolicySystemDirective(profile)
	systemPrompt += "\n\n" + attachmentVisionSystemDirective
	systemPrompt += "\n\n" + auditOutputPlanDirective(plan)
	imageDetail := "auto"
	if value, ok := auditProfileExtra(profile)["_risk_image_detail"].(string); ok {
		switch strings.ToLower(strings.TrimSpace(value)) {
		case "low", "high", "auto":
			imageDetail = strings.ToLower(strings.TrimSpace(value))
		}
	}
	userText := fmt.Sprintf(
		"[ATTACHMENT_IMAGE_AUDIT]\nName: %s\nMIME: %s\nOriginal bytes: %d\nInspect the attached image independently and return the policy JSON.",
		sanitizeAttachmentName(material.Name),
		material.MIMEType,
		material.OriginalBytes,
	)
	payload := map[string]any{
		"model":       profile.Model,
		"temperature": 0,
		"max_tokens":  plan.MaxTokens,
		"messages": []map[string]any{
			{"role": "system", "content": systemPrompt},
			{
				"role": "user",
				"content": []map[string]any{
					{"type": "text", "text": userText},
					{"type": "image_url", "image_url": map[string]any{"url": prepared.URL, "detail": imageDetail}},
				},
			},
		},
	}
	mergeAttachmentProfileExtra(profile, payload)
	e.applyFastAuditDefaults(profile, payload)
	applyAuditOutputContract(payload, plan)
	encoded, err := json.Marshal(payload)
	if err != nil {
		return AuditDecision{}, newAuditModelCallError("request_encode", 0, "encode attachment image audit request", err)
	}
	timeout := e.auditRequestTimeout(profile, len(encoded))
	requestContext, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	request, err := http.NewRequestWithContext(requestContext, http.MethodPost, endpoint, bytes.NewReader(encoded))
	if err != nil {
		return AuditDecision{}, newAuditModelCallError("request_build", 0, "build attachment image audit request", err)
	}
	request.Header.Set("Content-Type", "application/json")
	if err := e.applyAuditProfileAuthorization(request, profile); err != nil {
		return AuditDecision{}, err
	}
	response, err := e.client.Do(request)
	if err != nil {
		return AuditDecision{}, classifyAuditTransportError(err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 1024*1024))
	if err != nil {
		return AuditDecision{}, newAuditModelCallError("response_read", 0, "read attachment image audit response", err)
	}
	responseID := firstNonEmpty(response.Header.Get("X-Request-ID"), response.Header.Get("X-Oneapi-Request-Id"))
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		diagnostics := auditOutputDiagnostics{
			Mode: plan.Mode, MaxTokens: plan.MaxTokens, ResponseContentBytes: len(body),
			ResponseSource: "http_error_body", ResponsePreview: string(body), ResponseID: responseID, Failed: true,
		}
		recordAuditOutputDiagnostics(ctx, diagnostics)
		return AuditDecision{}, annotateAuditOutputError(auditHTTPStatusError(response.StatusCode, body), diagnostics)
	}
	completion, err := extractAuditCompletionResponse(body)
	if err != nil {
		diagnostics := auditOutputDiagnostics{
			Mode: plan.Mode, MaxTokens: plan.MaxTokens, ResponseContentBytes: len(body),
			ResponseSource: "response_envelope", ResponsePreview: string(body), ResponseID: responseID, Failed: true,
		}
		recordAuditOutputDiagnostics(ctx, diagnostics)
		return AuditDecision{}, annotateAuditOutputError(newAuditModelCallError("response_format", 0, err.Error(), nil), diagnostics)
	}
	if completion.ResponseID == "" {
		completion.ResponseID = responseID
	}
	diagnostics := auditOutputDiagnosticsForResponse(plan, completion, false)
	modelResult, err := parseAuditModelResponseContent(completion.Content)
	if err != nil {
		if class, _, _ := auditModelErrorDetails(err); class == "invalid_json" {
			err = auditInvalidModelOutputError(completion)
		}
		diagnostics.Failed = true
		recordAuditOutputDiagnostics(ctx, diagnostics)
		return AuditDecision{}, annotateAuditOutputError(err, diagnostics)
	}
	decision := AuditDecision{
		Decision: modelResult.Decision, RiskCode: strings.TrimSpace(modelResult.RiskCode),
		Category: strings.TrimSpace(modelResult.Category), Confidence: modelResult.Confidence,
		Reason: modelResult.Reason, Source: "attachment_image_model", Evidence: modelResult.Evidence,
	}
	validated, err := validateAttachmentImageDecision(decision)
	if err != nil {
		diagnostics.Failed = true
		recordAuditOutputDiagnostics(ctx, diagnostics)
		return AuditDecision{}, annotateAuditOutputError(err, diagnostics)
	}
	diagnostics.ResponsePreview = ""
	recordAuditOutputDiagnostics(ctx, diagnostics)
	return validated, nil
}

func mergeAttachmentProfileExtra(profile AuditProfile, payload map[string]any) {
	for key, value := range auditProfileExtra(profile) {
		if isInternalAuditExtraKey(key) {
			continue
		}
		switch key {
		case "model", "messages", "stream", "response_format", "structured_outputs", "guided_json", "guided_regex", "guided_choice", "max_tokens", "temperature":
			continue
		default:
			payload[key] = value
		}
	}
}

func (e *AuditEngine) applyAuditProfileAuthorization(request *http.Request, profile AuditProfile) error {
	if len(profile.APIKeyCiphertext) == 0 {
		return nil
	}
	key, err := e.security.Decrypt("audit-profile-api-key-v1", profile.APIKeyCiphertext)
	if err != nil {
		return newAuditModelCallError("credential_decrypt", 0, "decrypt audit API key", err)
	}
	if len(key) > 0 {
		request.Header.Set("Authorization", "Bearer "+string(key))
	}
	return nil
}

func validateAttachmentImageDecision(decision AuditDecision) (AuditDecision, error) {
	decision.Decision = strings.ToLower(strings.TrimSpace(decision.Decision))
	switch decision.Decision {
	case DecisionAllow:
		decision.Evidence = ""
		decision.EvidenceVerified = false
		return decision, nil
	case DecisionReview, DecisionBlock:
		evidence := sanitizeAuditDiagnostic(decision.Evidence)
		if evidence == "" {
			return AuditDecision{}, newAuditModelCallError("invalid_evidence", 0, "attachment image block/review response omitted visual evidence", nil)
		}
		decision.Evidence = truncateString(evidence, 300)
		decision.EvidenceContext = decision.Evidence
		decision.EvidenceVerified = true
		decision.EvidenceMatchMode = "visual_observation"
		return decision, nil
	default:
		return AuditDecision{}, newAuditModelCallError("invalid_decision", 0, fmt.Sprintf("attachment image audit returned invalid decision %q", decision.Decision), nil)
	}
}

func (e *AuditEngine) resolveAttachmentAuditProfile(ctx context.Context, route Route) (AuditProfile, error) {
	root, err := e.getAuditProfile(ctx, route.AuditProfileID)
	if err != nil {
		return AuditProfile{}, err
	}
	extra := auditProfileExtra(root)
	if raw, exists := extra["_risk_attachment_profile_id"]; exists {
		identifier := int64(0)
		switch value := raw.(type) {
		case float64:
			identifier = int64(value)
		case json.Number:
			identifier, _ = value.Int64()
		case string:
			identifier, _ = strconv.ParseInt(strings.TrimSpace(value), 10, 64)
		case int:
			identifier = int64(value)
		case int64:
			identifier = value
		}
		if identifier > 0 && identifier != root.ID {
			profile, fetchErr := e.getAuditProfile(ctx, &identifier)
			if fetchErr != nil {
				return AuditProfile{}, fmt.Errorf("load configured attachment audit profile %d: %w", identifier, fetchErr)
			}
			return profile, nil
		}
	}
	return root, nil
}

func (e *AuditEngine) attachmentProfileChain(ctx context.Context, root AuditProfile) []AuditProfile {
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
		identifier := fallbackID
		profile, err := e.getAuditProfile(ctx, &identifier)
		if err == nil && profile.Enabled {
			profiles = append(profiles, profile)
		}
	}
	return profiles
}

func attachmentProfileSupportsVision(profile AuditProfile) bool {
	if value, ok := auditProfileExtra(profile)["_risk_supports_vision"].(bool); ok {
		return value
	}
	model := normalizeAuditModelName(profile.Model)
	for _, marker := range []string{"vision", "multimodal", "qwen2vl", "qwen25vl", "qwen3vl", "qwen35", "qwen38", "gpt4o", "gpt5", "gemini", "claude"} {
		if strings.Contains(model, marker) {
			return true
		}
	}
	return false
}

func attachmentAuditFailClosed(route Route, profile AuditProfile) bool {
	if value, ok := auditProfileExtra(profile)["_risk_attachment_fail_closed"].(bool); ok {
		return value
	}
	return route.FailClosed || profile.FailClosed
}

func (e *AuditEngine) acquireAttachmentSlot(ctx context.Context) error {
	select {
	case e.attachmentSemaphore <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (e *AuditEngine) releaseAttachmentSlot() {
	select {
	case <-e.attachmentSemaphore:
	default:
	}
}

func attachmentItemFromMaterial(material attachmentMaterial) AttachmentAuditItem {
	return AttachmentAuditItem{
		Index:             material.Candidate.Index,
		ParentIndex:       material.Candidate.ParentIndex,
		Name:              sanitizeAttachmentName(material.Name),
		Kind:              material.Kind,
		MIMEType:          material.MIMEType,
		Source:            material.Candidate.Source,
		SHA256:            material.SHA256,
		OriginalBytes:     material.OriginalBytes,
		MaterializedBytes: material.MaterializedBytes,
		Decision:          DecisionAllow,
		Category:          "benign",
		Confidence:        1,
	}
}

func newAttachmentErrorItem(index int, parent int, name string, source string, class string, err error) AttachmentAuditItem {
	reason := "attachment audit failed"
	if err != nil {
		reason = sanitizeAuditDiagnostic(err.Error())
	}
	return AttachmentAuditItem{
		Index: index, ParentIndex: parent, Name: sanitizeAttachmentName(name),
		Kind: attachmentKindUnknown, Source: source, Decision: "error",
		ErrorClass: class, ErrorReason: reason,
	}
}

func attachmentMaterializationErrorClass(err error) string {
	lower := strings.ToLower(err.Error())
	switch {
	case strings.Contains(lower, "file_id"):
		return "file_id_unresolved"
	case strings.Contains(lower, "disabled"):
		return "remote_attachment_disabled"
	case strings.Contains(lower, "limit") || strings.Contains(lower, "exceeds"):
		return "attachment_size_limit"
	case strings.Contains(lower, "url") || strings.Contains(lower, "fetch") || strings.Contains(lower, "http"):
		return "attachment_fetch"
	default:
		return "attachment_materialization"
	}
}

func applyAttachmentDecisionToItem(item *AttachmentAuditItem, decision AuditDecision) {
	item.Decision = decision.Decision
	item.RiskCode = decision.RiskCode
	item.Category = decision.Category
	item.Confidence = decision.Confidence
	item.Reason = decision.Reason
	item.Evidence = decision.Evidence
	item.EvidenceMatchMode = decision.EvidenceMatchMode
}

func attachmentDecisionFromItem(item AttachmentAuditItem) AuditDecision {
	return AuditDecision{
		Decision: item.Decision, RiskCode: item.RiskCode, Category: item.Category,
		Confidence: item.Confidence, Reason: item.Reason, Source: "attachment",
		Evidence: item.Evidence, EvidenceContext: item.Evidence,
		EvidenceVerified: item.Evidence != "", EvidenceMatchMode: item.EvidenceMatchMode,
	}
}

func strongerAttachmentDecision(current AuditDecision, candidate AuditDecision) AuditDecision {
	severity := func(value string) int {
		switch value {
		case DecisionBlock:
			return 3
		case DecisionReview:
			return 2
		case DecisionAllow:
			return 1
		default:
			return 0
		}
	}
	currentSeverity := severity(current.Decision)
	candidateSeverity := severity(candidate.Decision)
	if candidateSeverity > currentSeverity || (candidateSeverity == currentSeverity && candidate.Confidence > current.Confidence) {
		return candidate
	}
	return current
}

func attachmentInfrastructureDecision(code string, reason string) AuditDecision {
	return AuditDecision{
		Decision: DecisionBlock, RiskCode: code, Category: "attachment_audit_infrastructure",
		Confidence: 1, Reason: sanitizeAuditDiagnostic(reason), Source: "attachment_platform",
	}
}

func mergeAttachmentAuditReport(result *AuditResult, report AttachmentAuditReport) {
	if result == nil {
		return
	}
	result.AttachmentAuditEnabled = true
	result.AttachmentCount = report.Discovered
	result.AttachmentSkippedCount = report.Skipped
	result.AttachmentAuditedCount = report.Audited
	result.AttachmentAllowedCount = report.Allowed
	result.AttachmentReviewCount = report.Reviewed
	result.AttachmentBlockedCount = report.Blocked
	result.AttachmentErrorCount = report.Errors
	result.AttachmentSampledCount = report.Sampled
	result.AttachmentTotalBytes = report.TotalBytes
	result.AttachmentAuditLatency = report.Latency
	result.AttachmentAudits = append([]AttachmentAuditItem(nil), report.Items...)
	if report.Strongest.Decision == DecisionBlock && result.Decision != DecisionBlock {
		result.AuditDecision = report.Strongest
		if result.RiskCode == "" {
			result.RiskCode = "ATTACHMENT_POLICY_BLOCK"
		}
	} else if report.Strongest.Decision == DecisionReview && result.Decision == DecisionAllow {
		if report.FailClosed {
			decision := report.Strongest
			decision.Decision = DecisionBlock
			if decision.RiskCode == "" {
				decision.RiskCode = "ATTACHMENT_REVIEW_REQUIRED"
			}
			result.AuditDecision = decision
		}
	}
}
''',
)

write(
    "internal/platform/attachment_audit_test.go",
    r'''package platform

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"testing"
)

func TestAttachmentProfileSupportsVision(t *testing.T) {
	for _, model := range []string{"Qwen3.8-27B", "qwen3-vl-32b", "gpt-4o"} {
		if !attachmentProfileSupportsVision(AuditProfile{Model: model}) {
			t.Fatalf("model %q should be recognized as vision-capable", model)
		}
	}
	profile := AuditProfile{Model: "text-only", Extra: json.RawMessage(`{"_risk_supports_vision":true}`)}
	if !attachmentProfileSupportsVision(profile) {
		t.Fatal("explicit vision capability flag was ignored")
	}
}

func TestResolveAttachmentProfileIDFromExtraParsing(t *testing.T) {
	for _, raw := range []json.RawMessage{
		json.RawMessage(`{"_risk_attachment_profile_id":2}`),
		json.RawMessage(`{"_risk_attachment_profile_id":"2"}`),
	} {
		profile := AuditProfile{ID: 1, Extra: raw}
		if _, ok := auditProfileExtra(profile)["_risk_attachment_profile_id"]; !ok {
			t.Fatalf("attachment profile id missing from %s", raw)
		}
	}
}

func TestValidateAttachmentImageDecisionRequiresVisualEvidence(t *testing.T) {
	if _, err := validateAttachmentImageDecision(AuditDecision{Decision: DecisionBlock}); err == nil {
		t.Fatal("visual block without evidence was accepted")
	}
	decision, err := validateAttachmentImageDecision(AuditDecision{Decision: DecisionBlock, Evidence: "visible credential-stealing instructions"})
	if err != nil || !decision.EvidenceVerified || decision.EvidenceMatchMode != "visual_observation" {
		t.Fatalf("unexpected validated decision: %+v err=%v", decision, err)
	}
}

func TestAttachmentImageDataIsNotStoredInItem(t *testing.T) {
	data := []byte("image bytes")
	material := attachmentMaterial{
		Candidate: attachmentCandidate{Index: 1, Name: "image.png", Source: "inline_data", EncodedData: base64.StdEncoding.EncodeToString(data)},
		Name: "image.png", MIMEType: "image/png", Kind: attachmentKindImage,
		Data: data, OriginalBytes: int64(len(data)), MaterializedBytes: int64(len(data)), SHA256: attachmentSHA256(data),
	}
	item := attachmentItemFromMaterial(material)
	encoded, err := json.Marshal(item)
	if err != nil {
		t.Fatal(err)
	}
	if string(encoded) == "" || containsByteSequence(encoded, data) {
		t.Fatalf("attachment result leaked raw bytes: %s", encoded)
	}
}

func containsByteSequence(haystack []byte, needle []byte) bool {
	if len(needle) == 0 || len(haystack) < len(needle) {
		return false
	}
	for index := 0; index+len(needle) <= len(haystack); index++ {
		match := true
		for offset := range needle {
			if haystack[index+offset] != needle[offset] {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}

func TestAcquireAttachmentSlotHonorsCanceledContext(t *testing.T) {
	engine := &AuditEngine{attachmentSemaphore: make(chan struct{}, 1)}
	engine.attachmentSemaphore <- struct{}{}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := engine.acquireAttachmentSlot(ctx); err == nil {
		t.Fatal("canceled context acquired a full attachment semaphore")
	}
}
''',
)

# AuditEngine fields and initialization.
replace_once(
    "internal/platform/audit.go",
    '''\tadaptiveQueue             chan adaptiveFailureSample
}
''',
    '''\tadaptiveQueue             chan adaptiveFailureSample
\tattachmentAuditEnabled    bool
\tattachmentMaxCount        int
\tattachmentFetchMaxBytes   int64
\tattachmentTotalMaxBytes   int64
\tattachmentExtractMaxBytes int
\tattachmentSampleMaxBytes  int
\tattachmentSegmentBytes    int
\tattachmentImageMaxBytes   int
\tattachmentImageMaxPixels  int64
\tattachmentPerRequestConcurrency int
\tattachmentClient          *http.Client
\tattachmentSemaphore       chan struct{}
\tattachmentArchiveMaxEntries int
\tattachmentArchiveMaxDepth int
\tattachmentArchiveMaxBytes int64
\tattachmentAllowRemoteURLs bool
}
''',
    "audit engine attachment fields",
)
replace_once(
    "internal/platform/audit.go",
    '''\t\tadaptiveQueue:             make(chan adaptiveFailureSample, adaptiveLearningQueueSize),
\t}
''',
    '''\t\tadaptiveQueue:             make(chan adaptiveFailureSample, adaptiveLearningQueueSize),
\t\tattachmentAuditEnabled:    cfg.AttachmentAuditEnabled,
\t\tattachmentMaxCount:        cfg.AttachmentMaxCount,
\t\tattachmentFetchMaxBytes:   cfg.AttachmentFetchMaxBytes,
\t\tattachmentTotalMaxBytes:   cfg.AttachmentTotalMaxBytes,
\t\tattachmentExtractMaxBytes: cfg.AttachmentExtractMaxBytes,
\t\tattachmentSampleMaxBytes:  cfg.AttachmentSampleMaxBytes,
\t\tattachmentSegmentBytes:    cfg.AttachmentSegmentBytes,
\t\tattachmentImageMaxBytes:   cfg.AttachmentImageMaxBytes,
\t\tattachmentImageMaxPixels:  cfg.AttachmentImageMaxPixels,
\t\tattachmentPerRequestConcurrency: cfg.AttachmentPerRequestConcurrency,
\t\tattachmentClient:          newAttachmentHTTPClient(cfg.AttachmentAllowPrivateURLs, cfg.UpstreamTLSMinVersion, cfg.AttachmentFetchTimeout),
\t\tattachmentSemaphore:       make(chan struct{}, cfg.AttachmentGlobalConcurrency),
\t\tattachmentArchiveMaxEntries: cfg.AttachmentArchiveMaxEntries,
\t\tattachmentArchiveMaxDepth: cfg.AttachmentArchiveMaxDepth,
\t\tattachmentArchiveMaxBytes: cfg.AttachmentArchiveMaxBytes,
\t\tattachmentAllowRemoteURLs: cfg.AttachmentAllowRemoteURLs,
\t}
''',
    "audit engine attachment initialization",
)

# Discover and defer independent attachment audit; register after latency defer
# so LIFO execution includes attachment time in total audit latency.
replace_once(
    "internal/platform/audit.go",
    '''\tstarted := time.Now()
\textraction := ExtractAuditTextDetails(body, e.maxTextBytes)
\ttext := extraction.Text
\tresult = AuditResult{
''',
    '''\tstarted := time.Now()
\textraction := ExtractAuditTextDetails(body, e.maxTextBytes)
\ttext := extraction.Text
\tattachmentCandidates, attachmentSkipped, attachmentDiscoveryErr := discoverAuditAttachments(body, e.attachmentMaxCount)
\tresult = AuditResult{
''',
    "audit attachment discovery",
)
replace_once(
    "internal/platform/audit.go",
    '''\tdefer func() {
\t\tresult.Latency = time.Since(started)
\t}()
\tif strings.TrimSpace(text) == "" {
''',
    '''\tdefer func() {
\t\tresult.Latency = time.Since(started)
\t}()
\tdefer func() {
\t\tif !e.attachmentAuditEnabled || (len(attachmentCandidates) == 0 && attachmentDiscoveryErr == nil) {
\t\t\treturn
\t\t}
\t\treport := e.auditAttachments(ctx, route, attachmentCandidates, attachmentSkipped, attachmentDiscoveryErr)
\t\tmergeAttachmentAuditReport(&result, report)
\t}()
\tif strings.TrimSpace(text) == "" {
''',
    "audit attachment defer",
)

# Result fields.
replace_once(
    "internal/platform/types.go",
    '''\tAuditResponseID             string                      `json:"audit_response_id,omitempty"`
}
''',
    '''\tAuditResponseID             string                      `json:"audit_response_id,omitempty"`
\tAttachmentAuditEnabled       bool                        `json:"attachment_audit_enabled,omitempty"`
\tAttachmentCount              int                         `json:"attachment_count,omitempty"`
\tAttachmentSkippedCount       int                         `json:"attachment_skipped_count,omitempty"`
\tAttachmentAuditedCount       int                         `json:"attachment_audited_count,omitempty"`
\tAttachmentAllowedCount       int                         `json:"attachment_allowed_count,omitempty"`
\tAttachmentReviewCount        int                         `json:"attachment_review_count,omitempty"`
\tAttachmentBlockedCount       int                         `json:"attachment_blocked_count,omitempty"`
\tAttachmentErrorCount         int                         `json:"attachment_error_count,omitempty"`
\tAttachmentSampledCount       int                         `json:"attachment_sampled_count,omitempty"`
\tAttachmentTotalBytes         int64                       `json:"attachment_total_bytes,omitempty"`
\tAttachmentAuditLatency       time.Duration               `json:"-"`
\tAttachmentAudits             []AttachmentAuditItem       `json:"attachment_audits,omitempty"`
}
''',
    "audit result attachment fields",
)

# Gateway trace metadata.
replace_once(
    "internal/platform/gateway.go",
    '''\tif auditResult.AuditResponseID != "" {
\t\ttrace.Metadata["audit_response_id"] = auditResult.AuditResponseID
\t}
\tauditDuration.WithLabelValues(slug).Observe(auditResult.Latency.Seconds())
''',
    '''\tif auditResult.AuditResponseID != "" {
\t\ttrace.Metadata["audit_response_id"] = auditResult.AuditResponseID
\t}
\tif auditResult.AttachmentAuditEnabled {
\t\ttrace.Metadata["attachment_audit_enabled"] = true
\t\ttrace.Metadata["attachment_count"] = auditResult.AttachmentCount
\t\ttrace.Metadata["attachment_skipped_count"] = auditResult.AttachmentSkippedCount
\t\ttrace.Metadata["attachment_audited_count"] = auditResult.AttachmentAuditedCount
\t\ttrace.Metadata["attachment_allowed_count"] = auditResult.AttachmentAllowedCount
\t\ttrace.Metadata["attachment_review_count"] = auditResult.AttachmentReviewCount
\t\ttrace.Metadata["attachment_blocked_count"] = auditResult.AttachmentBlockedCount
\t\ttrace.Metadata["attachment_error_count"] = auditResult.AttachmentErrorCount
\t\ttrace.Metadata["attachment_sampled_count"] = auditResult.AttachmentSampledCount
\t\ttrace.Metadata["attachment_total_bytes"] = auditResult.AttachmentTotalBytes
\t\ttrace.Metadata["attachment_audit_latency_ms"] = auditResult.AttachmentAuditLatency.Milliseconds()
\t\tif len(auditResult.AttachmentAudits) > 0 {
\t\t\ttrace.Metadata["attachment_audits"] = auditResult.AttachmentAudits
\t\t\tnames := make([]string, 0, len(auditResult.AttachmentAudits))
\t\t\thashes := make([]string, 0, len(auditResult.AttachmentAudits))
\t\t\tfor _, item := range auditResult.AttachmentAudits {
\t\t\t\tif item.Name != "" {
\t\t\t\t\tnames = append(names, item.Name)
\t\t\t\t}
\t\t\t\tif item.SHA256 != "" {
\t\t\t\t\thashes = append(hashes, item.SHA256)
\t\t\t\t}
\t\t\t}
\t\t\ttrace.Metadata["attachment_names"] = names
\t\t\ttrace.Metadata["attachment_sha256"] = hashes
\t\t}
\t}
\tauditDuration.WithLabelValues(slug).Observe(auditResult.Latency.Seconds())
''',
    "gateway attachment metadata",
)

print("attachment audit engine applied")
