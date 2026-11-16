package codex

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/Voskan/codexsentinel/analyzer/catalog"
)

func TestRulesListsCatalogAsJSON(t *testing.T) {
	out, err := runCLIOutput(t, "rules", "--format", "json")
	if err != nil {
		t.Fatal(err)
	}
	var rules []catalog.RuleDoc
	if err := json.Unmarshal([]byte(out), &rules); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, out)
	}
	if len(rules) != len(catalog.All()) {
		t.Errorf("listed %d rules, catalog has %d", len(rules), len(catalog.All()))
	}
}

func TestRulesFilters(t *testing.T) {
	out, err := runCLIOutput(t, "rules", "--category", "reliability", "--severity", "high", "--format", "json")
	if err != nil {
		t.Fatal(err)
	}
	var rules []catalog.RuleDoc
	if err := json.Unmarshal([]byte(out), &rules); err != nil {
		t.Fatal(err)
	}
	if len(rules) == 0 {
		t.Fatal("no high reliability rules listed")
	}
	for _, r := range rules {
		if r.Category != catalog.CategoryReliability || (!strings.EqualFold(string(r.DefaultSeverity), "high") && !strings.EqualFold(string(r.DefaultSeverity), "critical")) {
			t.Errorf("unexpected rule %s (%s, %s)", r.ID, r.Category, r.DefaultSeverity)
		}
	}
	table, err := runCLIOutput(t, "rules")
	if err != nil || !strings.Contains(table, "sql-injection") {
		t.Errorf("table output: err = %v\n%s", err, table)
	}
}

func TestExplainByIDAndCode(t *testing.T) {
	for _, arg := range []string{"sql-injection", "CS001", "cs001"} {
		out, err := runCLIOutput(t, "explain", arg)
		if err != nil {
			t.Fatalf("explain %s: %v", arg, err)
		}
		for _, want := range []string{"sql-injection", "CWE-89", "//codex:ignore sql-injection --"} {
			if !strings.Contains(out, want) {
				t.Errorf("explain %s lacks %q:\n%s", arg, want, out)
			}
		}
	}
}

func TestExplainUnknownRuleSuggests(t *testing.T) {
	_, err := runCLIOutput(t, "explain", "sql-injektion")
	if err == nil {
		t.Fatal("unknown rule accepted")
	}
	if !strings.Contains(err.Error(), "sql-injection") {
		t.Errorf("no suggestion in %v", err)
	}
}
