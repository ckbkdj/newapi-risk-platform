package platform

import (
	"context"
	"regexp"
	"strings"
)

// These are evidence-shape checks, NEVER request allowlists. They identify
// quotations that do not establish an operation, before a Cyber verdict locks.
// The entire request and its task anchors still go through fresh classification.
var opaqueOperationEvidence = regexp.MustCompile(`^[A-Za-z0-9+/_=-]{64,}$`)

var dependencyVersionEvidence = regexp.MustCompile(`"[A-Za-z0-9@_./-]+"\s*:\s*"[~^<>=*v0-9][0-9A-Za-z.*+~^<>=| -]*"`)
var numberedPathEvidence = regexp.MustCompile(`^\s*[0-9]+[\t ]+(?:/|[A-Za-z]:\\)[A-Za-z0-9_./\\@:+~-]+\s*$`)
var sensitiveSearchEvidence = regexp.MustCompile(`(?i)(credentials?|passwords?|secrets?|api[_ .?-]*key|access[_ .?-]*token|authorization|cookies?|\.env|\.ssh|凭据|密码|密钥|令牌)`)

func nonOperationalAuditEvidence(d AuditDecision, source string) bool {
	if d.Decision != DecisionBlock && d.Decision != DecisionReview {
		return false
	}
	q := normalizeAuditEvidenceQuote(d.Evidence)
	// Display redaction can replace USER_PROVIDED_SECRET with REDACTED.
	// Use validated offsets, not a lossy log quote, for source-shape admission.
	if d.evidenceSourceMatched && d.evidenceSourceStart >= 0 && d.evidenceSourceEnd <= len(source) && d.evidenceSourceEnd > d.evidenceSourceStart {
		raw := source[d.evidenceSourceStart:d.evidenceSourceEnd]
		if redactCyberTraceText(raw) == d.Evidence {
			q = raw
		}
	}
	if q == "" {
		return false
	}
	if opaqueOperationEvidence.MatchString(q) && strings.Contains(source, q) {
		return true
	}
	if normalDevelopmentAuditEvidence(q, source) || routineCredentialAuditEvidence(q, source) || negatedCredentialAuditEvidence(q, source) || developmentAuditEvidence(d, q, source) || administrativeAuditEvidence(d, q, source) || observationalAuditEvidence(q, source) {
		return true
	}
	at := strings.Index(source, q)
	if at < 0 && isASCIIText(q) {
		at = indexASCIIEqualFold(source, q)
	}
	if at < 0 {
		return false
	}
	// Limit auxiliary inspection even when the request contains a huge JSON line.
	lo, hi := at-512, at+len(q)+512
	if lo < 0 {
		lo = 0
	}
	if hi > len(source) {
		hi = len(source)
	}
	around := source[lo:hi]
	for _, m := range dependencyVersionEvidence.FindAllStringIndex(around, -1) {
		if lo+m[0] <= at && lo+m[1] >= at+len(q) {
			return true
		}
	}
	// Restore line boundaries so a quote beginning mid-path is still recognized.
	start := strings.LastIndex(source[:at], "\n") + 1
	end := at + len(q)
	if n := strings.Index(source[end:], "\n"); n >= 0 {
		end += n
	} else {
		end = len(source)
	}
	if end-start > 8192 {
		return false
	}
	lines := strings.Split(source[start:end], "\n")
	paths := 0
	for _, line := range lines {
		if !numberedPathEvidence.MatchString(line) {
			paths = -1
			break
		}
		paths++
	}
	if paths > 0 {
		// Require inventory context, not a lone path that might be a command.
		if paths >= 2 {
			return true
		}
		if start > 0 {
			prevEnd := start - 1
			prevStart := strings.LastIndex(source[:prevEnd], "\n") + 1
			if numberedPathEvidence.MatchString(source[prevStart:prevEnd]) {
				return true
			}
		}
		if end < len(source) {
			next := source[end+1:]
			if n := strings.Index(next, "\n"); n >= 0 {
				next = next[:n]
			}
			if len(next) <= 4096 && numberedPathEvidence.MatchString(next) {
				return true
			}
		}
	}
	// A short quote may omit a pipeline, credential target or closing quote.
	// Inspect the complete containing source line, not a cherry-picked prefix.
	return len(lines) == 1 && readOnlySearchEvidence(strings.TrimSpace(lines[0]))
}

// Recognize only the shape of a plain text-search quotation. Shell compounds,
// substitution, rg preprocessors, credential targets and multiline commands
// must not qualify. Even a recognized search is reclassified, never auto-allowed.
func readOnlySearchEvidence(q string) bool {
	if !(strings.HasPrefix(q, "rg ") || strings.HasPrefix(q, "grep ")) || sensitiveSearchEvidence.MatchString(q) {
		return false
	}
	if strings.Contains(q, "--pre") || strings.ContainsAny(q, "\n\r") {
		return false
	}
	var quote rune
	escaped := false
	for _, c := range q {
		if escaped {
			escaped = false
			continue
		}
		if quote == '\'' {
			if c == '\'' {
				quote = 0
			}
			continue
		}
		if c == '\\' {
			escaped = true
			continue
		}
		if c == '$' || c == '`' {
			return false
		}
		if quote == '"' {
			if c == '"' {
				quote = 0
			}
			continue
		}
		if c == '\'' || c == '"' {
			quote = c
			continue
		}
		if strings.ContainsRune(";|&<>", c) {
			return false
		}
	}
	return quote == 0 && !escaped
}

const auditOperationGroundingFeedback = `OPERATION EVIDENCE CHECK v1: 前一候选只证明资料、配置或正常操作的存在，尚未证明禁用动作。这不是放行要求。仅有一次重新审计机会；使用相同完整 request_text 和 request_context，不沿用上一类别或猜测。查找真正要求执行/生成/采纳的禁用操作：存在则 block，引用包含该操作的一处连续原文；确无禁用操作才 allow，实际风险未解则 review。依赖名称/版本、文件目录、只读检索、本机状态、配置加载不是操作性攻击证据。不能用本地/授权声明豁免其他禁用动作。不要省略其他片段，不得删除否定词。保持六字段输出和80字短证据。` + "\n" + normalDevelopmentPolicy

// Repair only an unadmitted candidate. A valid operational denial never reaches
// this path. Evidence and operation repairs share ONE extra call per candidate;
// the raw call below cannot recursively start another repair.
func (e *AuditEngine) callCyberGroundedModel(ctx context.Context, profile AuditProfile, text, source string) (AuditDecision, error) {
	d, err := e.callModelRawWithEvidenceSource(ctx, profile, text, source)
	class, _, _ := auditModelErrorDetails(err)
	invalidQuote := class == "invalid_evidence" && (d.Decision == DecisionBlock || d.Decision == DecisionReview)
	if err != nil && !invalidQuote {
		return d, err
	}
	if !invalidQuote && !nonOperationalAuditEvidence(d, source) {
		return d, nil
	}
	ctx, state := withAuditSemanticState(ctx)
	kind, failureClass, feedback := "grounding", "cyber_operation_unresolved", auditOperationGroundingFeedback
	candidateError := "non_operational_evidence"
	if invalidQuote {
		kind, failureClass, feedback = "evidence_repair", "cyber_evidence_unresolved", auditEvidenceRepairFeedback
		candidateError = "invalid_evidence"
	}
	review := AuditSemanticReview{Status: kind + "_error", Candidate: cleanSemanticDecision(d), CandidateError: candidateError, ProfileID: profile.ID, Model: profile.Model}
	if invalidQuote {
		// The original malformed quote is not promoted into verified evidence. Keep
		// the failed response diagnostics separate from the recovery response.
		diag := auditDiagnosticsFromError(auditOutputPlanFromContext(ctx), err)
		attempt := auditAdmissionAttempt(profile, 1, diag, d, err)
		review.Attempts = append(review.Attempts, attempt)
	}
	defer func() { state.record(review) }()
	if !state.reserveReview() {
		return AuditDecision{}, newAuditModelCallError(failureClass, 0, "candidate repair review budget exhausted", nil)
	}
	if ctx.Err() != nil {
		return AuditDecision{}, newAuditModelCallError(failureClass, 0, "candidate repair cancelled before dispatch", ctx.Err())
	}
	plan := auditOutputPlanFromContext(ctx)
	plan.VerifyIntent = false
	plan.Feedback = feedback
	checkCtx, output := withAuditOutputAttempt(ctx, plan)
	checkCtx = context.WithValue(checkCtx, auditAdmissionPhaseKey{}, kind)
	checked, checkErr := e.callModelRawWithEvidenceSource(checkCtx, profile, text, source)
	if checkErr == nil && nonOperationalAuditEvidence(checked, source) {
		checkErr = newAuditModelCallError(failureClass, 0, "repair still cites only non-operational evidence", nil)
	}
	if checkErr == nil {
		checked, checkErr = cyberDenyVerdict(checked)
	}
	diag := output.snapshot(checkErr != nil)
	diag.Failed = checkErr != nil
	recordAuditOutputDiagnostics(ctx, diag)
	number := 1
	if invalidQuote {
		number = 2
	}
	review.Attempts = append(review.Attempts, auditAdmissionAttempt(profile, number, diag, checked, checkErr))
	if checkErr != nil {
		return AuditDecision{}, annotateAuditOutputError(newAuditModelCallError(failureClass, 0, "candidate evidence unresolved after one bounded repair; forwarding denied", checkErr), diag)
	}
	clean := cleanSemanticDecision(checked)
	review.Outcome = &clean
	review.Status = kind + "_confirmed"
	if checked.Decision == DecisionAllow {
		review.Status = kind + "_corrected"
	}
	return checked, nil
}

// Do not feed the invented quote, category or rationale back into the classifier.
// Only the generic correction is a control message; the source document is
// byte-identical and the existing fresh allow verification/Fusion still applies.
const auditEvidenceRepairFeedback = `EVIDENCE SOURCE REPAIR v1: 上次结果的引用未通过原文校验，不能据此认定攻击，也不能据此放行。本次只有一次修复机会。重新审计相同完整 request_text 及 request_context；不要沿用上次类别、理由或臆造引用。block/review 的 evidence 必须从当前 JSON 解码后的 request_text 逐字复制一处连续短原文，保持语言、空格和标点，不翻译、不概括、不拼接、不引用 system 指令、字段名或未出现在 request_text 的任务标题/摘要替代原文。request_context 用于理解任务，不替代 request_text 的引用来源。依据实际动作和对象判断，不能因为无法引用就默认 allow；明确无禁用操作才 allow，风险未解则 review 并引用真实相关文本。六字段输出，reason 和 evidence 尽量短于80字。已有连接表、代理连接记录按源端口做关联分析本身不是主动网络探测；主动建连枚举、扫描、绕过和混合禁用操作仍 block。` + "\n" + normalDevelopmentPolicy

func auditAdmissionAttempt(p AuditProfile, number int, diag auditOutputDiagnostics, d AuditDecision, err error) AuditAttempt {
	a := AuditAttempt{ProfileID: p.ID, ProfileName: p.Name, Model: p.Model, Attempt: number, Success: err == nil,
		OutputMode: diag.Mode, OutputMaxTokens: diag.MaxTokens, FinishReason: diag.FinishReason, ResponseContentBytes: diag.ResponseContentBytes,
		ResponseSource: diag.ResponseSource, ResponseID: diag.ResponseID}
	if err != nil {
		a.ErrorClass, a.HTTPStatus, a.Reason = auditModelErrorDetails(err)
		a.ResponsePreview = sanitizeAuditResponsePreview(diag.ResponsePreview)
		return a
	}
	d = cleanSemanticDecision(d)
	a.Decision, a.RiskCode, a.Reason, a.Evidence = d.Decision, d.RiskCode, d.Reason, d.Evidence
	a.Confidence, a.ConfidenceKind, a.ConfidenceLabel = d.Confidence, d.ConfidenceKind, d.ConfidenceLabel
	return a
}
