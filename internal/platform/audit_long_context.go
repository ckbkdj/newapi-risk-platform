package platform

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"unicode/utf8"
)

const auditChunkRetryLimit = 4

type auditCallMetadata struct {
	Mode                      string
	ChunkCount                int
	ChunkBytes                int
	RequestedTokens           int
	RequestedTokensLowerBound bool
	ObservedOutputTokens      int
	ContextWindowTokens       int
	RetryCount                int
}

type auditChunkResult struct {
	index    int
	decision AuditDecision
	err      error
}

// callModel keeps the common path fast: it first sends the complete request
// once. Only an explicit context-length rejection causes request-side
// segmentation. No vLLM truncate_prompt_tokens option is used, because silent
// truncation can hide harmful text from the auditor.
func (e *AuditEngine) callModel(
	ctx context.Context,
	profile AuditProfile,
	text string,
) (AuditDecision, auditCallMetadata, error) {
	metadata := auditCallMetadata{
		Mode:       "single",
		ChunkCount: 1,
		ChunkBytes: len(text),
	}

	// Every chunk, including a short tail, inherits the full request's prefill
	// timeout. The caller's own deadline is still an absolute upper bound.
	ctx = context.WithValue(ctx, auditOriginalTextBytesKey{}, len(text))
	resume, _ := ctx.Value(auditResumeChunksKey{}).(auditCallMetadata)
	var lastContextError error
	chunkBytes := resume.ChunkBytes
	if resume.Mode == "chunked_after_context_limit" && chunkBytes > 0 {
		metadata = resume
	} else {
		decision, err := e.callModelOnce(ctx, profile, text)
		if err == nil || !isAuditContextLengthError(err) {
			return decision, metadata, err
		}
		metadata.Mode = "chunked_after_context_limit"
		metadata = observeAuditContextError(metadata, err)
		chunkBytes = e.recoveryAuditChunkBytes(ctx, len(text), err)
		lastContextError = err
	}

	for retry := 0; retry < auditChunkRetryLimit; retry++ {
		chunks := splitAuditTextByBytes(text, chunkBytes, e.chunkOverlapBytes)
		metadata.ChunkCount = len(chunks)
		metadata.ChunkBytes = chunkBytes
		metadata.RetryCount = retry + 1
		if len(chunks) > e.maxAuditChunks {
			return AuditDecision{}, metadata, newAuditModelCallError(
				"input_too_large",
				0,
				fmt.Sprintf(
					"audit input requires %d chunks, exceeding configured maximum %d",
					len(chunks),
					e.maxAuditChunks,
				),
				nil,
			)
		}

		decision, chunkErr := e.callModelChunks(ctx, profile, chunks)
		if chunkErr == nil {
			return decision, metadata, nil
		}
		if !isAuditContextLengthError(chunkErr) {
			return AuditDecision{}, metadata, chunkErr
		}
		lastContextError = chunkErr
		metadata = observeAuditContextError(metadata, chunkErr)
		if chunkBytes <= 1024 {
			break
		}
		chunkBytes /= 2
		if chunkBytes < 1024 {
			chunkBytes = 1024
		}
	}

	return AuditDecision{}, metadata, lastContextError
}

func (e *AuditEngine) initialAuditChunkBytes(
	textBytes int,
	requestedTokens int,
	contextWindowTokens int,
) int {
	if textBytes <= 1 {
		return 1
	}

	return e.auditChunkBytesForOutput(textBytes, requestedTokens, contextWindowTokens, e.outputMaxTokens)
}

func (e *AuditEngine) auditChunkBytesForOutput(textBytes, requestedTokens, contextWindowTokens, outputTokens int) int {
	targetTokens := e.contextTargetTokens
	if contextWindowTokens > 0 {
		modelTarget := contextWindowTokens - outputTokens - 2048
		if modelTarget > 0 && (targetTokens <= 0 || modelTarget < targetTokens) {
			targetTokens = modelTarget
		}
	}

	chunkBytes := e.fallbackChunkBytes
	if chunkBytes <= 0 {
		chunkBytes = 192 * 1024
	}
	if requestedTokens > 0 && targetTokens > 0 && requestedTokens > targetTokens {
		// A 10% safety margin covers system/template overhead and token-density
		// variation between portions of the request.
		ratio := float64(targetTokens) / float64(requestedTokens)
		chunkBytes = int(float64(textBytes) * ratio * 0.90)
	}
	if chunkBytes < 1024 {
		chunkBytes = 1024
	}
	if chunkBytes >= textBytes {
		chunkBytes = textBytes / 2
	}
	if chunkBytes < 1 {
		chunkBytes = 1
	}
	return chunkBytes
}

func (e *AuditEngine) callModelChunks(
	ctx context.Context,
	profile AuditProfile,
	chunks []string,
) (AuditDecision, error) {
	if len(chunks) == 0 {
		return AuditDecision{}, newAuditModelCallError(
			"input_too_large",
			0,
			"audit input produced no chunks",
			nil,
		)
	}
	if len(chunks) == 1 {
		return e.callModelOnceWithEvidenceSource(ctx, profile, decorateAuditChunk(chunks[0], 0, 1), chunks[0])
	}

	workerCount := e.chunkConcurrency
	if workerCount < 1 {
		workerCount = 1
	}
	if workerCount > len(chunks) {
		workerCount = len(chunks)
	}

	workerContext, cancel := context.WithCancel(ctx)
	defer cancel()
	jobs := make(chan int)
	results := make(chan auditChunkResult, len(chunks))
	var waitGroup sync.WaitGroup

	for worker := 0; worker < workerCount; worker++ {
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			for {
				select {
				case <-workerContext.Done():
					return
				case index, ok := <-jobs:
					if !ok {
						return
					}
					decision, err := e.callModelOnceWithEvidenceSource(
						workerContext,
						profile,
						decorateAuditChunk(chunks[index], index, len(chunks)),
						chunks[index],
					)
					results <- auditChunkResult{index: index, decision: decision, err: err}
				}
			}
		}()
	}

	go func() {
		defer close(jobs)
		for index := range chunks {
			select {
			case <-workerContext.Done():
				return
			case jobs <- index:
			}
		}
	}()
	go func() {
		waitGroup.Wait()
		close(results)
	}()

	var firstBlock *auditChunkResult
	var strongestReview *auditChunkResult
	var firstError error
	allowConfidence := 1.0
	completed := 0

	for result := range results {
		completed++
		if result.err != nil {
			if firstBlock == nil && firstError == nil {
				firstError = result.err
				cancel()
			}
			continue
		}
		switch result.decision.Decision {
		case DecisionBlock:
			if firstBlock == nil {
				copyResult := result
				firstBlock = &copyResult
				cancel()
			}
		case DecisionReview:
			if strongestReview == nil || result.decision.Confidence > strongestReview.decision.Confidence {
				copyResult := result
				strongestReview = &copyResult
			}
		case DecisionAllow:
			if result.decision.Confidence < allowConfidence {
				allowConfidence = result.decision.Confidence
			}
		default:
			if firstError == nil {
				firstError = newAuditModelCallError(
					"invalid_decision",
					0,
					fmt.Sprintf("audit chunk returned invalid decision %q", result.decision.Decision),
					nil,
				)
				cancel()
			}
		}
	}

	if firstBlock != nil {
		return decorateChunkDecision(firstBlock.decision, firstBlock.index, len(chunks)), nil
	}
	if firstError != nil {
		return AuditDecision{}, firstError
	}
	// Never return review/allow until every chunk has produced a decision.
	// A client disconnect or deadline must not turn a partially audited request
	// into a result that a fail-open route could forward.
	if completed < len(chunks) {
		return AuditDecision{}, newAuditModelCallError("connection", 0, "chunked audit was canceled before every chunk completed", ctx.Err())
	}
	if strongestReview != nil {
		return decorateChunkDecision(strongestReview.decision, strongestReview.index, len(chunks)), nil
	}
	return AuditDecision{
		Decision:   DecisionAllow,
		Category:   "benign",
		Confidence: allowConfidence,
		Reason:     fmt.Sprintf("all %d long-context chunks allowed", len(chunks)),
		Source:     "model_chunked",
	}, nil
}

func decorateAuditChunk(text string, index int, total int) string {
	return fmt.Sprintf(
		"[LONG_CONTEXT_AUDIT_CHUNK %d/%d]\nThis chunk is part of one request. Classify the capability in this chunk; do not assume other chunks are safe.\n%s",
		index+1,
		total,
		text,
	)
}

func decorateChunkDecision(decision AuditDecision, index int, total int) AuditDecision {
	decision.Source = "model_chunked"
	if decision.EvidenceVerified {
		decision.EvidenceChunkIndex = index + 1
		decision.EvidenceChunkCount = total
	}
	reason := strings.TrimSpace(decision.Reason)
	if reason == "" {
		reason = "chunk decision"
	}
	decision.Reason = truncateString(
		fmt.Sprintf("chunk %d/%d: %s", index+1, total, reason),
		500,
	)
	return decision
}

func splitAuditTextByBytes(text string, maxBytes int, overlapBytes int) []string {
	if text == "" {
		return nil
	}
	if maxBytes <= 0 || len(text) <= maxBytes {
		return []string{text}
	}
	if overlapBytes < 0 {
		overlapBytes = 0
	}
	if overlapBytes >= maxBytes/2 {
		overlapBytes = maxBytes / 4
	}

	chunks := make([]string, 0, len(text)/maxBytes+2)
	for start := 0; start < len(text); {
		end := start + maxBytes
		if end >= len(text) {
			end = len(text)
		} else {
			for end > start && !utf8.RuneStart(text[end]) {
				end--
			}
			floor := start + maxBytes*3/4
			if floor < end {
				if relative := strings.LastIndexByte(text[floor:end], '\n'); relative >= 0 {
					candidate := floor + relative + 1
					if candidate > start {
						end = candidate
					}
				}
			}
		}
		if end <= start {
			end = start + 1
			for end < len(text) && !utf8.RuneStart(text[end]) {
				end++
			}
		}
		chunks = append(chunks, text[start:end])
		if end >= len(text) {
			break
		}

		next := end - overlapBytes
		if next <= start {
			next = end
		}
		for next < len(text) && !utf8.RuneStart(text[next]) {
			next++
		}
		start = next
	}
	return chunks
}
