package platform

import "regexp"

// Keep descriptive/reference cues local to the clause that contains them.
// A benign sentence such as "only analyze existing records" must not demote a
// later, independent operation such as "Scan the network with nmap" merely
// because both sentences are within a small byte window.
//
// These patterns deliberately stop at hard sentence/clause boundaries. The
// matched Cyber evidence still goes through the existing provenance/adoption
// logic; this only prevents a relation cue in a neighboring clause from
// changing the current clause's enforcement semantics.
func init() {
	chineseSourceRelationV26 = regexp.MustCompile(`(?:文档|记录|日志|表格|工作簿|描述|说明)[^。！？!?；;\n]{0,24}(?:中|里|内|写着|写有|显示|描述|说明|提到|包含|出现|记录)`)
	englishSourceRelationV26 = regexp.MustCompile(`(?i)(?:\b(?:in|from|according to)\s+(?:the\s+)?(?:logs?|records?|documents?|spreadsheet)\b|\b(?:logs?|records?|documents?|spreadsheet)\b[^.!?;\n]{0,24}\b(?:say|says|said|mention|mentions|mentioned|contain|contains|contained|show|shows|showed|describe|describes|described)\b)`)
	transformReferenceV26 = regexp.MustCompile(`(?i)(?:翻译|总结|摘要|整理|改写|润色|校对|解释|引用)[^。！？!?；;\n]{0,64}(?:这|该|上述|以下|句|段|内容|文本|文字|记录|文档|日志|表格|工作簿|描述|说明)|\b(?:translate|summari[sz]e|rewrite|proofread|explain|quote)\b[^.!?;\n]{0,64}\b(?:this|that|the following|sentence|passage|text|record|document|log|entry)\b`)
	conditionalMentionV26 = regexp.MustCompile(`(?i)(?:(?:待复现|待验证)[^。！？!?；;\n]{0,40}(?:判断|确认|看)[^。！？!?；;\n]{0,20}(?:是否|是不是|需不需要)|(?:判断|确认)[^。！？!?；;\n]{0,32}(?:是否|是不是|需不需要)|是否需要|是不是需要|可能需要|考虑是否|\bwhether\b|\bmight need\b|\bmay need\b|\bconsider(?:ing)?\s+whether\b)`)
}
