package platform

import "regexp"

var diagnosticPrivatePEM = regexp.MustCompile(`(?is)-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?(?:-----END [A-Z0-9 ]*PRIVATE KEY-----|$)`)

var diagnosticOpaqueLiteral = regexp.MustCompile(`[A-Za-z0-9+/_=-]{80,}`)

func redactAuditSecretDiagnostics(text string) string {
	text = diagnosticPrivatePEM.ReplaceAllString(text, "[REDACTED PRIVATE KEY]")
	text = secretAssignmentPattern.ReplaceAllString(text, "${1}[REDACTED]")
	// Also mask fragments of keys/encoded material in already-truncated model
	// output. These are logs only, never substituted into request_text.
	return diagnosticOpaqueLiteral.ReplaceAllString(text, "[REDACTED OPAQUE VALUE]")
}
