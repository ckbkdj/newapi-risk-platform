package platform

import (
	"regexp"
	"strings"
)

// Mask literal values, not function names. In v12, key = os.getenv("NAME")
// became key = [USER_PROVIDED_SECRET]("NAME"), destroying the action evidence.
// This is a source-preserving privacy transform, never an allow decision.
var credentialSymbol = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_.]*$`)
var credentialMember = regexp.MustCompile(`^(?:process\.env|os\.environ|config|session|credentials)\.[A-Za-z_][A-Za-z0-9_.]*$`)
var shortQuotedCredential = regexp.MustCompile(`(?i)((?:["'])?(?:private[_ -]?key|api[_ -]?key|access[_ -]?token|refresh[_ -]?token|authorization|password|secret|token|key)(?:["'])?[ \t]*[:=][ \t]*)("[A-Za-z0-9._~+\-/=]{1,}"|'[A-Za-z0-9._~+\-/=]{1,}')`)

var xmlCredentialLiteral = regexp.MustCompile(`(?i)(<(?:password|passphrase)>)([A-Za-z0-9._~+\-/=]+)(</(?:password|passphrase)>)`)

func maskCyberCredentialAssignments(text string) (string, int) {
	count := 0
	text = xmlCredentialLiteral.ReplaceAllStringFunc(text, func(match string) string {
		p := xmlCredentialLiteral.FindStringSubmatch(match)
		count++
		return p[1] + "[USER_PROVIDED_SECRET]" + p[3]
	})
	// Short/vendor/default credentials still require privacy protection. Retain
	// quotes and separators so configuration structure remains inspectable.
	text = shortQuotedCredential.ReplaceAllStringFunc(text, func(match string) string {
		p := shortQuotedCredential.FindStringSubmatch(match)
		if len(p[2]) <= 2 || strings.Contains(p[2], "[USER_PROVIDED_SECRET]") || strings.Contains(p[2], "[REDACTED]") {
			return match
		}
		count++
		return p[1] + p[2][:1] + "[USER_PROVIDED_SECRET]" + p[2][len(p[2])-1:]
	})
	var b strings.Builder
	last := 0
	for _, p := range secretAssignmentPattern.FindAllStringSubmatchIndex(text, -1) {
		prefix, value := text[p[2]:p[3]], text[p[4]:p[5]]
		quoted := strings.HasSuffix(prefix, "\"") || strings.HasSuffix(prefix, "'")
		tail := strings.TrimLeft(text[p[5]:], " \t")
		expression := !quoted && credentialSymbol.MatchString(value) && ((len(tail) > 0 && (tail[0] == '(' || tail[0] == '[')) || credentialMember.MatchString(value))
		if expression {
			continue
		}
		b.WriteString(text[last:p[4]])
		b.WriteString("[USER_PROVIDED_SECRET]")
		last = p[5]
		count++
	}
	if last == 0 {
		return text, count
	}
	b.WriteString(text[last:])
	return b.String(), count
}
