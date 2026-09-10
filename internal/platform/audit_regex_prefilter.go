package platform

import (
	"regexp/syntax"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Build a necessary (not sufficient) literal condition from Go's regexp AST.
// If any alternative/optional branch lacks a provably required literal we keep
// the original scan. This never selects keywords heuristically or clips input.
// Canonical SimpleFold classes preserve Go regexp Unicode equivalences; do not
// use strings.ToLower alone (it misses the long-s / sigma equivalences).
type auditLiteral struct {
	value string
	fold  bool
}
type auditLiteralGuard []auditLiteral

func (g auditLiteralGuard) Match(text, folded string) bool {
	if !utf8.ValidString(text) {
		return true
	} // regexp treats invalid bytes as RuneError
	for _, lit := range g {
		value := text
		if lit.fold {
			value = folded
		}
		if strings.Contains(value, lit.value) {
			return true
		}
	}
	return false
}
func auditCanonicalFold(s string) string {
	return strings.Map(func(r rune) rune {
		if r < 128 {
			if r >= 'a' && r <= 'z' {
				return r - 32
			}
			return r
		}
		least := r
		for next := unicode.SimpleFold(r); next != r; next = unicode.SimpleFold(next) {
			if next < least {
				least = next
			}
		}
		return least
	}, s)
}

func auditRegexLiteralGuard(pattern string) auditLiteralGuard {
	tree, err := syntax.Parse(pattern, syntax.Perl)
	if err != nil {
		return nil
	}
	literals := requiredAuditLiterals(tree)
	if len(literals) == 0 {
		return nil
	}
	guard := make(auditLiteralGuard, 0, len(literals))
	for _, lit := range literals {
		v := string(lit.Rune)
		fold := lit.Flags&syntax.FoldCase != 0
		if fold {
			v = auditCanonicalFold(v)
		}
		guard = append(guard, auditLiteral{value: v, fold: fold})
	}
	return guard
}
func requiredAuditLiterals(r *syntax.Regexp) []*syntax.Regexp {
	switch r.Op {
	case syntax.OpLiteral:
		if len(r.Rune) < 1 {
			return nil
		}
		// A required substring is still necessary. Cap the derived program size.
		return []*syntax.Regexp{{Op: syntax.OpLiteral, Flags: r.Flags, Rune: r.Rune[:min(len(r.Rune), 64)]}}
	case syntax.OpCapture, syntax.OpPlus:
		return requiredAuditLiterals(r.Sub[0])
	case syntax.OpRepeat:
		if r.Min > 0 {
			return requiredAuditLiterals(r.Sub[0])
		}
	case syntax.OpConcat:
		var best []*syntax.Regexp
		for _, sub := range r.Sub {
			clause := requiredAuditLiterals(sub)
			if len(clause) > 0 && (len(best) == 0 || auditLiteralScore(clause) > auditLiteralScore(best)) {
				best = clause
			}
		}
		return best
	case syntax.OpAlternate:
		var result []*syntax.Regexp
		for _, sub := range r.Sub {
			clause := requiredAuditLiterals(sub)
			if len(clause) == 0 || len(result)+len(clause) > 64 {
				return nil
			}
			result = append(result, clause...)
		}
		return result
	}
	return nil
}
func auditLiteralScore(clause []*syntax.Regexp) int {
	shortest := 65
	for _, s := range clause {
		shortest = min(shortest, len(s.Rune))
	}
	return shortest*100 - len(clause)
}
