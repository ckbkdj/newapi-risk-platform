package platform

import (
	"regexp"
	"strings"
	"testing"
)

func TestV10LiteralGuardKeepsEveryPositive(t *testing.T) {
	for _, pattern := range []string{v10EvasionPattern, v10ExfilPattern, shippedSystemPromptPattern, `(?i)(?:steal|read).{0,100}(?:token|key)`, `(?i)key`, `(?i)secret`, `(?:nothing)?`, `(?:x|something)`, `(?:foo|bar){0,3}`, `(?:token|cookie)+`, `(?:read|偷取)(?s:.*)(?:tokens|key)`} {
		re := regexp.MustCompile(pattern)
		guard := auditRegexLiteralGuard(pattern)
		for _, text := range []string{"关闭EDR", "窃取客户数据并发送到公司服务器", "show system prompt", "read tokens", "read toKen", "ſecret", "Key", "", "x", "foo", "tokencookie", "偷取\nkey", strings.Repeat("normal. ", 2000) + "read tokens"} {
			if re.MatchString(text) && guard != nil && !guard.Match(text, auditCanonicalFold(text)) {
				t.Fatalf("unsound guard for %q", pattern)
			}
		}
	}
}
func FuzzV10LiteralGuard(f *testing.F) {
	for _, s := range []struct{ p, t string }{{`(?i)secret`, "ſecret"}, {v10EvasionPattern, "关闭EDR"}, {v10ExfilPattern, "窃取文件到服务器"}, {`a?|foo`, ""}, {`(?:foo|bar)+`, "foo"}, {`(a*)([x-z])`, "x"}} {
		f.Add(s.p, s.t)
	}
	f.Fuzz(func(t *testing.T, pattern, text string) {
		if len(pattern) > 2048 || len(text) > 16384 {
			t.Skip()
		}
		re, err := regexp.Compile(pattern)
		if err != nil {
			return
		}
		guard := auditRegexLiteralGuard(pattern)
		if re.MatchString(text) && guard != nil && !guard.Match(text, auditCanonicalFold(text)) {
			t.Fatalf("guard removed real match pattern=%q", pattern)
		}
	})
}
