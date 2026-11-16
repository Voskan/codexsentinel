package catalog_test

import (
	"fmt"
	"go/parser"
	"go/token"
	"regexp"
	"strings"
	"testing"

	"github.com/Voskan/codexsentinel/analyzer"
	"github.com/Voskan/codexsentinel/analyzer/catalog"
	"github.com/Voskan/codexsentinel/analyzer/rules/builtin"
	"github.com/Voskan/codexsentinel/deps"
)

func TestEveryBuiltinRuleIsDocumented(t *testing.T) {
	ctx := analyzer.NewAnalyzerContext(nil, nil, nil, "", "", nil)
	builtin.RegisterAll(ctx)
	if len(ctx.Rules) == 0 {
		t.Fatal("no built-in rules registered")
	}
	for _, rule := range ctx.Rules {
		doc, ok := catalog.Lookup(rule.ID)
		if !ok {
			t.Errorf("rule %s is not in the catalog", rule.ID)
			continue
		}
		if doc.Title != rule.Title || doc.DefaultSeverity != rule.Severity || doc.Category != rule.Category {
			t.Errorf("%s: catalog %q/%s/%s, registered %q/%s/%s", rule.ID, doc.Title, doc.DefaultSeverity, doc.Category, rule.Title, rule.Severity, rule.Category)
		}
	}
}

func TestEngineRulesAreDocumented(t *testing.T) {
	ids := []string{
		"open-redirect", "tx-network-io", "lock-blocking-io",
		"dependency-vulnerability", "supply-chain-capability-escalation", "license-denied", "high-entropy-string",
		deps.RuleTyposquatting, deps.RuleLocalReplace, deps.RuleMissingChecksum, deps.RulePolicyDenied,
		deps.RuleYoungModule, deps.RuleRetracted, deps.RuleDeprecated,
		"arch-layer-violation", "arch-import-cycle", "arch-god-struct", "arch-boundary-type-leak",
		"high-complexity", "large-function", "large-file", "code-duplication", "global-variable", "dead-code",
		"ignore-missing-reason",
	}
	for _, id := range ids {
		if _, ok := catalog.Lookup(id); !ok {
			t.Errorf("rule %s is not in the catalog", id)
		}
	}
}

var codePattern = regexp.MustCompile(`^CS\d{3}$`)

func TestCatalogEntriesAreComplete(t *testing.T) {
	all := catalog.All()
	ids, codes := map[string]bool{}, map[string]bool{}
	for i, d := range all {
		if ids[d.ID] || codes[d.Code] {
			t.Errorf("duplicate id or code: %s %s", d.ID, d.Code)
		}
		ids[d.ID], codes[d.Code] = true, true
		if !codePattern.MatchString(d.Code) {
			t.Errorf("%s: malformed code %q", d.ID, d.Code)
		}
		if i > 0 && all[i-1].Code >= d.Code {
			t.Errorf("All is not sorted by code at %s", d.Code)
		}
		for name, value := range map[string]string{"title": d.Title, "category": d.Category, "summary": d.Summary, "explanation": d.Explanation, "bad example": d.BadExample, "good example": d.GoodExample, "severity": string(d.DefaultSeverity)} {
			if strings.TrimSpace(value) == "" {
				t.Errorf("%s: empty %s", d.ID, name)
			}
		}
		if d.BadExample == d.GoodExample {
			t.Errorf("%s: identical examples", d.ID)
		}
		if d.CWE != "" && !strings.HasPrefix(d.CWE, "CWE-") {
			t.Errorf("%s: malformed CWE %q", d.ID, d.CWE)
		}
	}
	for n := 1; n <= len(all); n++ {
		if code := fmt.Sprintf("CS%03d", n); !codes[code] {
			t.Errorf("code %s is missing; codes must be contiguous", code)
		}
	}
}

// Go examples of security and reliability rules must parse as Go source,
// either as declarations or as statements inside a function.
func TestExamplesParse(t *testing.T) {
	for _, d := range catalog.All() {
		if d.Category != catalog.CategorySecurity && d.Category != catalog.CategoryReliability {
			continue
		}
		for kind, src := range map[string]string{"bad": d.BadExample, "good": d.GoodExample} {
			if !parses(src) {
				t.Errorf("%s: %s example does not parse:\n%s", d.ID, kind, src)
			}
		}
	}
}

func parses(src string) bool {
	fset := token.NewFileSet()
	if _, err := parser.ParseFile(fset, "", "package p\n"+src, parser.AllErrors); err == nil {
		return true
	}
	_, err := parser.ParseFile(fset, "", "package p\nfunc _() {\n"+src+"\n}\n", parser.AllErrors)
	return err == nil
}

func TestLookup(t *testing.T) {
	for _, q := range []string{"sql-injection", "SQL-Injection", "CS001", "cs001", " cs001 "} {
		d, ok := catalog.Lookup(q)
		if !ok || d.ID != "sql-injection" || d.Code != "CS001" {
			t.Errorf("Lookup(%q) = %+v, %v", q, d, ok)
		}
	}
	if _, ok := catalog.Lookup("no-such-rule"); ok {
		t.Error("unknown rule found")
	}
	if got := catalog.Similar("sql-injectoin", 3); len(got) == 0 || got[0] != "sql-injection" {
		t.Errorf("Similar = %v", got)
	}
	if got := catalog.ByCategory("reliability"); len(got) != 7 {
		t.Errorf("reliability rules = %d", len(got))
	}
	all := catalog.All()
	all[0].Title = "changed"
	if d, _ := catalog.Lookup(all[0].ID); d.Title == "changed" {
		t.Error("All returned shared state")
	}
}
