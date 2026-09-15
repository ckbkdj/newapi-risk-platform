package platform

import (
	"regexp"
	"strings"
	"unicode/utf8"
)

var explicitEmbeddedReferenceAdoptionV27 = regexp.MustCompile(`(?i)(?:执行(?:下面|以下|上述|前面|这个|该)?(?:历史)?任务(?:里|中|的)?(?:操作)?|按(?:下面|以下|上述|前面|这个|该)?(?:历史)?任务(?:继续|执行|做)|继续执行(?:下面|以下|上述|前面|这个|该)?(?:历史)?任务|(?:execute|run|perform|continue with|proceed with)\b[^.?!;\n]{0,48}\b(?:the\s+)?(?:history|historical|previous|above|referenced)\s+(?:task|operation|action)s?\b)`)

// Keep descriptive/reference cues local to the clause that contains them.
// These expressions are anchored to one whole clause. A reference cue in one
// sentence therefore cannot demote a prohibited operation in the next sentence.
func init() {
	chineseSourceRelationV26 = regexp.MustCompile(`(?s)^[^。！？.!?；;\n]*(?:文档|记录|日志|表格|工作簿|描述|说明)[^。！？.!?；;\n]{0,24}(?:中|里|内|写着|写有|显示|描述|说明|提到|包含|出现|记录)[^。！？.!?；;\n]*[。！？.!?；;]?\s*$`)
	englishSourceRelationV26 = regexp.MustCompile(`(?is)^[^.!?;\n]*(?:\b(?:in|from|according to)\s+(?:the\s+)?(?:logs?|records?|documents?|spreadsheet)\b|\b(?:logs?|records?|documents?|spreadsheet)\b[^.!?;\n]{0,24}\b(?:say|says|said|mention|mentions|mentioned|contain|contains|contained|show|shows|showed|describe|describes|described)\b)[^.!?;\n]*[.!?;]?\s*$`)
	transformReferenceV26 = regexp.MustCompile(`(?is)^[^。！？.!?；;\n]*(?:(?:翻译|总结|摘要|整理|改写|润色|校对|解释|引用)[^。！？.!?；;\n]{0,64}(?:这|该|上述|以下|句|段|内容|文本|文字|记录|文档|日志|表格|工作簿|描述|说明)|\b(?:translate|summari[sz]e|rewrite|proofread|explain|quote)\b[^.!?;\n]{0,64}\b(?:this|that|the following|sentence|passage|text|record|document|log|entry)\b)[^。！？.!?；;\n]*[。！？.!?；;]?\s*$`)
	conditionalMentionV26 = regexp.MustCompile(`(?is)^[^。！？.!?；;\n]*(?:(?:待复现|待验证)[^。！？.!?；;\n]{0,40}(?:判断|确认|看)[^。！？.!?；;\n]{0,20}(?:是否|是不是|需不需要)|(?:判断|确认)[^。！？.!?；;\n]{0,32}(?:是否|是不是|需不需要)|是否需要|是不是需要|可能需要|考虑是否|\bwhether\b|\bmight need\b|\bmay need\b|\bconsider(?:ing)?\s+whether\b)[^。！？.!?；;\n]*[。！？.!?；;]?\s*$`)
}

// cyberEvidenceClauseV27 returns only the sentence/clause containing the rule
// evidence and rebases its byte offsets. Broad "ordinary engineering" cues in
// neighboring text cannot therefore suppress a real operation in this clause.
func cyberEvidenceClauseV27(text string, evidence cyberRuleEvidence) (string, cyberRuleEvidence) {
	if evidence.start < 0 || evidence.end <= evidence.start || evidence.end > len(text) {
		return text, evidence
	}
	start := 0
	if boundary := strings.LastIndexAny(text[:evidence.start], "。！？.!?；;\n"); boundary >= 0 {
		start = boundary
		_, size := utf8.DecodeRuneInString(text[start:])
		if size > 0 {
			start += size
		}
	}
	end := len(text)
	if rel := strings.IndexAny(text[evidence.end:], "。！？.!?；;\n"); rel >= 0 {
		end = evidence.end + rel
	}
	for start < len(text) && !utf8.RuneStart(text[start]) {
		start++
	}
	for end < len(text) && !utf8.RuneStart(text[end]) {
		end++
	}
	if start >= end {
		return text, evidence
	}
	rebased := evidence
	rebased.start -= start
	rebased.end -= start
	return text[start:end], rebased
}

// Structured conversation-history blobs can be embedded inside a current USER
// message by Agent/Codex clients. They are evidence-bearing references, not
// current instructions. Only a match wholly inside a validated reference span is
// demoted. Explicit adoption such as "执行下面历史任务里的操作" restores the
// current-action relationship, so a real prohibited operation can still be a
// deterministic hard veto. A regex that reaches outside the span is likewise
// eligible for hard veto.
func evidenceInsideEmbeddedReferenceV27(text string, evidence cyberRuleEvidence) bool {
	if evidence.start < 0 || evidence.end <= evidence.start || evidence.end > len(text) {
		return false
	}
	if explicitEmbeddedReferenceAdoptionV27.MatchString(text) {
		return false
	}
	for _, span := range auditReferenceSpans(text) {
		if evidence.start >= span.Start && evidence.end <= span.End {
			return true
		}
	}
	return false
}
