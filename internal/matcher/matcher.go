// Package matcher provides wildcard-based matching for rule IDs, paths, etc.
package matcher

import (
	"path/filepath"
	"strings"
)

// Matcher represents a compiled list of string matchers with wildcard support.
type Matcher struct {
	patterns []string
}

// New creates a new matcher from a list of patterns.
//
// Supported syntax:
//   - Exact match: "sql-injection"
//   - Wildcard match: "sql-*", "*-injection"
//   - Negation: "!deprecated-*"
func New(patterns []string) *Matcher {
	return &Matcher{
		patterns: patterns,
	}
}

// Match reports whether the given value is accepted by the matcher.
//
// Negated patterns take precedence. If no patterns match, returns false.
func (m *Matcher) Match(value string) bool {
	var matched bool

	for _, pattern := range m.patterns {
		negated := strings.HasPrefix(pattern, "!")
		cleanPattern := strings.TrimPrefix(pattern, "!")

		match, err := filepath.Match(cleanPattern, value)
		if err != nil {
			continue // ignore invalid patterns
		}

		if match {
			if negated {
				return false // explicitly excluded
			}
			matched = true
		}
	}

	return matched
}

// AnyMatch reports whether at least one of the provided values matches.
func (m *Matcher) AnyMatch(values []string) bool {
	for _, val := range values {
		if m.Match(val) {
			return true
		}
	}
	return false
}

// MatchAll filters and returns all values that match the patterns.
func (m *Matcher) MatchAll(values []string) []string {
	var out []string
	for _, val := range values {
		if m.Match(val) {
			out = append(out, val)
		}
	}
	return out
}
