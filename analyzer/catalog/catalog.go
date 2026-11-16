// Package catalog documents every rule the analyzer reports: its stable
// code, category, default severity, classification, an explanation and a
// vulnerable and a fixed example. The CLI, editor integrations and the
// generated rule reference read it.
package catalog

import (
	"sort"
	"strings"
	"sync"

	"github.com/Voskan/codexsentinel/analyzer/result"
)

// Categories of rules.
const (
	CategorySecurity     = "security"
	CategoryReliability  = "reliability"
	CategoryArchitecture = "architecture"
	CategorySupplyChain  = "supply-chain"
	CategoryLicense      = "license"
	CategoryMetrics      = "metrics"
)

// RuleDoc documents one rule.
type RuleDoc struct {
	ID              string          `json:"id"`
	Code            string          `json:"code"`
	Title           string          `json:"title"`
	Category        string          `json:"category"`
	DefaultSeverity result.Severity `json:"default_severity"`
	CWE             string          `json:"cwe,omitempty"`
	OWASP           string          `json:"owasp,omitempty"`
	Summary         string          `json:"summary"`
	Explanation     string          `json:"explanation"`
	BadExample      string          `json:"bad_example"`
	GoodExample     string          `json:"good_example"`
	References      []string        `json:"references,omitempty"`
	HasAutoFix      bool            `json:"has_autofix"`
}

func allDocs() []RuleDoc {
	var out []RuleDoc
	out = append(out, securityDocs...)
	out = append(out, moreSecurityDocs...)
	out = append(out, reliabilityDocs...)
	out = append(out, supplyChainDocs...)
	out = append(out, architectureDocs...)
	out = append(out, metricsDocs...)
	return out
}

var index = sync.OnceValue(func() map[string]RuleDoc {
	out := map[string]RuleDoc{}
	for _, d := range allDocs() {
		out[strings.ToLower(d.ID)] = d
		out[strings.ToLower(d.Code)] = d
	}
	return out
})

// All returns every rule sorted by code. The slice is a copy.
func All() []RuleDoc {
	out := allDocs()
	for i := range out {
		out[i].References = append([]string(nil), out[i].References...)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Code < out[j].Code })
	return out
}

// Lookup finds a rule by ID ("sql-injection") or code ("CS001"), ignoring case.
func Lookup(idOrCode string) (RuleDoc, bool) {
	d, ok := index()[strings.ToLower(strings.TrimSpace(idOrCode))]
	if ok {
		d.References = append([]string(nil), d.References...)
	}
	return d, ok
}

// ByCategory returns the rules of one category sorted by code.
func ByCategory(category string) []RuleDoc {
	var out []RuleDoc
	for _, d := range All() {
		if strings.EqualFold(d.Category, category) {
			out = append(out, d)
		}
	}
	return out
}

// Similar returns up to limit rule IDs that resemble query, closest first,
// to suggest a correction for a mistyped ID.
func Similar(query string, limit int) []string {
	query = strings.ToLower(strings.TrimSpace(query))
	type scored struct {
		id    string
		score int
	}
	var all []scored
	for _, d := range All() {
		score := distance(query, d.ID)
		if strings.Contains(d.ID, query) || strings.Contains(query, d.ID) {
			score = 0
		}
		all = append(all, scored{d.ID, score})
	}
	sort.SliceStable(all, func(i, j int) bool { return all[i].score < all[j].score })
	var out []string
	for _, s := range all {
		if len(out) == limit || s.score > len(query)/2+2 {
			break
		}
		out = append(out, s.id)
	}
	return out
}

func distance(a, b string) int {
	prev := make([]int, len(b)+1)
	for j := range prev {
		prev[j] = j
	}
	for i := 1; i <= len(a); i++ {
		cur := make([]int, len(b)+1)
		cur[0] = i
		for j := 1; j <= len(b); j++ {
			cost := 1
			if a[i-1] == b[j-1] {
				cost = 0
			}
			cur[j] = min(prev[j]+1, cur[j-1]+1, prev[j-1]+cost)
		}
		prev = cur
	}
	return prev[len(b)]
}
