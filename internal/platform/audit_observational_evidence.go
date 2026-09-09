package platform

import (
	"encoding/json"
	"regexp"
	"strings"
)

// Evidence shapes only. These never authorize forwarding or omit request data.
// Literal status-table reads can still support a prohibited larger task, which
// the existing one-recheck classifier must assess with the same task context.
var localStatusCommand = regexp.MustCompile(`(?i)^(?:netstat(?:\.exe)?(?:[\t ]+-(?:[abeno]+|p[\t ]+(?:tcp|udp|tcpv6|udpv6)|[lntup]+))*|ss(?:[\t ]+-[lntupae]+)+)(?:[\t ]*\|[\t ]*(?:Select-String|findstr|grep)(?:[\t ]+-Pattern)?[\t ]+(?:"[ :0-9|.]+"|'[ :0-9|.]+'))?[\t ]*$`)
var localCommandLiteral = regexp.MustCompile(`(?:"(?:cmd|command)"|\b(?:cmd|command))[\t ]*:[\t ]*("(?:[^"\\\r\n]|\\.)*")`)
var noKeyGuidance = regexp.MustCompile(`(?i)\bread[-‐‑–]only[\t ]+guidance[\t ]+(?:do|does)[\t ]+not[\t ]+require[\t ]+(?:an?[\t ]+)?API[ _-]?key\b`)

func observationalAuditEvidence(quote, source string) bool {
	if len(quote) < 4 || len(quote) > 4096 {
		return false
	}
	offset, found := 0, false
	// Examine every occurrence; a benign first occurrence must not mask a later
	// operational use of the same quote. On budget exhaustion do not reclassify.
	for count := 0; count < 32; count++ {
		rel := strings.Index(source[offset:], quote)
		if rel < 0 {
			return found
		}
		start := offset + rel
		end := start + len(quote)
		a := strings.LastIndex(source[:start], "\n") + 1
		b := len(source)
		if n := strings.IndexByte(source[end:], '\n'); n >= 0 {
			b = end + n
		}
		if b-a > 8192 {
			return false
		}
		line := source[a:b]
		weak := false
		for _, m := range noKeyGuidance.FindAllStringIndex(line, 32) {
			if a+m[0] <= start && a+m[1] >= end {
				weak = true
				break
			}
		}
		if !weak && localStatusCommand.MatchString(strings.TrimSpace(line)) {
			weak = true
		}
		if !weak {
			// Parse only JSON-compatible literal strings, including cmd:"..." in an
			// Agent tool script. No JS/shell is executed; interpolations do not match
			// the strict command shape, and sibling commands remain fully audited.
			for _, m := range localCommandLiteral.FindAllStringSubmatchIndex(line, 32) {
				if a+m[2]+1 > start || a+m[3]-1 < end {
					continue
				}
				suffix := strings.TrimSpace(line[m[3]:])
				if suffix != "" && suffix[0] != ',' && suffix[0] != '}' {
					continue
				}
				var cmd string
				if json.Unmarshal([]byte(line[m[2]:m[3]]), &cmd) == nil && localStatusCommand.MatchString(cmd) {
					weak = true
					break
				}
			}
		}
		if !weak {
			return false
		}
		found = true
		offset = start + 1
	}
	return false
}
