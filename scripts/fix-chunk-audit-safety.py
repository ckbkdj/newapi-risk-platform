from pathlib import Path

root = Path(__file__).resolve().parents[1]

long_path = root / "internal/platform/audit_long_context.go"
text = long_path.read_text(encoding="utf-8")
old = '''	for retry := 0; retry < auditChunkRetryLimit; retry++ {
		chunks := splitAuditTextByBytes(text, chunkBytes, e.chunkOverlapBytes)
		if len(chunks) > e.maxAuditChunks {
			return AuditDecision{}, metadata, newAuditModelCallError(
'''
new = '''	for retry := 0; retry < auditChunkRetryLimit; retry++ {
		chunks := splitAuditTextByBytes(text, chunkBytes, e.chunkOverlapBytes)
		metadata.ChunkCount = len(chunks)
		metadata.ChunkBytes = chunkBytes
		metadata.RetryCount = retry + 1
		if len(chunks) > e.maxAuditChunks {
			return AuditDecision{}, metadata, newAuditModelCallError(
'''
if text.count(old) != 1:
    raise SystemExit("chunk metadata precheck anchor not found")
text = text.replace(old, new, 1)
old = '''
		metadata.ChunkCount = len(chunks)
		metadata.ChunkBytes = chunkBytes
		metadata.RetryCount = retry + 1
		decision, chunkErr := e.callModelChunks(ctx, profile, chunks)
'''
new = '''
		decision, chunkErr := e.callModelChunks(ctx, profile, chunks)
'''
if text.count(old) != 1:
    raise SystemExit("duplicate chunk metadata anchor not found")
text = text.replace(old, new, 1)
old = '''	if firstError != nil {
		return AuditDecision{}, firstError
	}
	if strongestReview != nil {
		return decorateChunkDecision(strongestReview.decision, strongestReview.index, len(chunks)), nil
	}
	if completed < len(chunks) {
		return AuditDecision{}, newAuditModelCallError("connection", 0, "chunked audit was canceled before every chunk completed", ctx.Err())
	}
'''
new = '''	if firstError != nil {
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
'''
if text.count(old) != 1:
    raise SystemExit("chunk completion ordering anchor not found")
long_path.write_text(text.replace(old, new, 1), encoding="utf-8")

init_path = root / "scripts/init-env.sh"
text = init_path.read_text(encoding="utf-8")
old = "# default to 2 MiB.\n"
new = "# default to 8 MiB so the request layer can segment the complete input.\n"
if text.count(old) != 1:
    raise SystemExit("init-env comment anchor not found")
init_path.write_text(text.replace(old, new, 1), encoding="utf-8")

print("chunk audit safety cleanup applied")
