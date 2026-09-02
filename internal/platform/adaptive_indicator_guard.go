package platform

import (
	"net"
	"net/mail"
	"net/url"
	"regexp"
	"strings"
	"unicode"
)

var (
	adaptiveUUIDPattern = regexp.MustCompile(`(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	adaptiveHexPattern  = regexp.MustCompile(`(?i)^[0-9a-f]{20,}$`)
	adaptiveB64Pattern  = regexp.MustCompile(`^[A-Za-z0-9+/=_-]{24,}$`)
	adaptiveHostPattern = regexp.MustCompile(`(?i)^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$`)
)

func adaptiveIndicatorLooksSensitive(value string) bool {
	value = strings.TrimSpace(value)
	if value == "" {
		return true
	}
	if len(value) > 64 {
		return true
	}
	if net.ParseIP(value) != nil {
		return true
	}
	if adaptiveUUIDPattern.MatchString(value) || adaptiveHexPattern.MatchString(value) || adaptiveB64Pattern.MatchString(value) {
		return true
	}
	if adaptiveHostPattern.MatchString(value) {
		return true
	}
	if parsed, err := url.Parse(value); err == nil && parsed.Scheme != "" && parsed.Host != "" {
		return true
	}
	if strings.Contains(value, "@") {
		if _, err := mail.ParseAddress(value); err == nil {
			return true
		}
		// Even if it is not a syntactically valid mailbox, an @-bearing indicator
		// is too likely to contain user or tenant identity to persist as a rule.
		return true
	}
	for _, expression := range adaptiveSecretPatterns {
		if expression.MatchString(value) {
			return true
		}
	}

	var digits int
	var letters int
	var symbols int
	for _, character := range value {
		switch {
		case unicode.IsDigit(character):
			digits++
		case unicode.IsLetter(character):
			letters++
		case unicode.IsSpace(character):
		default:
			symbols++
		}
	}
	total := digits + letters + symbols
	if total == 0 {
		return true
	}
	// Reject ID-like or machine-generated fragments. Human-readable policy
	// indicators normally contain mostly letters/words; identifiers do not.
	if digits >= 6 && float64(digits)/float64(total) > 0.30 {
		return true
	}
	if total >= 24 && letters > 0 && symbols > 0 && strings.IndexByte(value, ' ') < 0 {
		return true
	}
	return false
}
