// Package matcher provides glob matching for rule IDs and project-relative paths.
package matcher

import (
	"regexp"
	"strings"
)

// Matcher represents a compiled list of glob patterns.
type Matcher struct {
	patterns []pattern
}

type pattern struct {
	negated bool
	re      *regexp.Regexp
}

// New compiles a list of patterns.
//
// Supported syntax:
//   - Exact match: "sql-injection", "cmd/main.go"
//   - "*" matches any run of characters except "/", "?" one such character
//   - "**" matches across directories: "**/*.pb.go", "pkg/**/gen", "testdata/**"
//   - A leading "/" anchors the pattern at the project root ("/vendor/")
//   - A trailing "/" matches everything under a directory (".idea/")
//   - Patterns without a slash match at any depth ("*.swp")
//   - Negation: "!deprecated-*"
//
// A pattern that matches a directory also matches every path below it.
// Invalid patterns are skipped.
func New(patterns []string) *Matcher {
	m := &Matcher{}
	for _, p := range patterns {
		negated := strings.HasPrefix(p, "!")
		re, err := Compile(strings.TrimPrefix(p, "!"))
		if err != nil || re == nil {
			continue
		}
		m.patterns = append(m.patterns, pattern{negated: negated, re: re})
	}
	return m
}

// Compile translates a glob pattern into an anchored regular expression.
// It returns nil for an empty pattern.
func Compile(glob string) (*regexp.Regexp, error) {
	glob = strings.TrimSpace(glob)
	if glob == "" || glob == "/" {
		return nil, nil
	}
	anchored := strings.HasPrefix(glob, "/")
	glob = strings.TrimPrefix(glob, "/")
	dirOnly := strings.HasSuffix(glob, "/")
	glob = strings.TrimRight(glob, "/")
	if strings.Contains(glob, "/") && !strings.HasPrefix(glob, "**/") {
		anchored = true
	}

	var b strings.Builder
	b.WriteString("^")
	if !anchored {
		b.WriteString("(?:.*/)?")
	}
	for i := 0; i < len(glob); {
		switch {
		case strings.HasPrefix(glob[i:], "**/") && (i == 0 || glob[i-1] == '/'):
			b.WriteString("(?:.*/)?")
			i += 3
		case glob[i:] == "/**":
			b.WriteString("(?:/.*)?")
			i += 3
		case strings.HasPrefix(glob[i:], "**"):
			b.WriteString(".*")
			i += 2
		case glob[i] == '*':
			b.WriteString("[^/]*")
			i++
		case glob[i] == '?':
			b.WriteString("[^/]")
			i++
		default:
			b.WriteString(regexp.QuoteMeta(glob[i : i+1]))
			i++
		}
	}
	if dirOnly {
		b.WriteString("/.*$")
	} else {
		b.WriteString("(?:/.*)?$")
	}
	return regexp.Compile(b.String())
}

// Match reports whether the given value is accepted by the matcher.
//
// Negated patterns take precedence. If no patterns match, returns false.
func (m *Matcher) Match(value string) bool {
	value = strings.TrimPrefix(value, "./")
	matched := false
	for _, p := range m.patterns {
		if !p.re.MatchString(value) {
			continue
		}
		if p.negated {
			return false
		}
		matched = true
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
